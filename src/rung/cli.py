#!/usr/bin/env python3
"""rung: the umbrella CLI. One entrypoint over the two stdlib-only tools in the
rung package (rung.gate and rung.run), upgraded to a gh / kubectl level of
robustness while staying stdlib-only, deterministic, and dependency-free:

    rung run    [global] SURFACE-ARGS     witness an execution, emit + gate a bundle
    rung attest [global] BUNDLE [POLICY]   record an independent attestation, re-gate
    rung gate   [global] BUNDLE [POLICY]   gate an already-authored bundle (JSON to stdout)
    rung check  [global] BUNDLE [POLICY]   alias for gate
    rung doctor [global] [BUNDLE]          read-only preflight; exit 0/2 only
    rung version                           schema major + gate sha256 + resolved paths
    rung skill  [global] [--print|--install DEST]  surface the packaged skill (harness-neutral)
    rung help / -h / --help                top-level usage

Global flags (a shared parent parser): --quiet/-q, --no-color. There is NO
--json flag: `gate`/`run` already print the JSON verdict to stdout
unconditionally, so a --json toggle would imply a mode that does not exist.

Contracts this dispatcher preserves, and never launders around:
  * stdout is DATA, stderr is diagnostics. `gate`/`check` stdout is exactly the
    gate's verdict bytes (we call gate.main in-process and let it print), never
    wrapped in an envelope.
  * exit codes are 0 pass / 30 block / 2 usage-or-cannot-evaluate, and nothing
    else. Delegated codes pass through untouched; doctor is 0/2 only; unknown or
    malformed usage is 2.
  * the gate only ever lowers trust: this dispatcher adds convenience and
    diagnostics, never a green light.
  * --quiet suppresses rung's OWN progress (chiefly doctor's ok-lines) but never
    the verdict and never a child's critical error (we do not muzzle the child's
    stderr, which would hide exactly what must be seen).
  * color is stderr-only, and only when stderr is a TTY, NO_COLOR is unset, and
    --no-color is absent; the verdict on stdout is never colored.

Each tool still runs standalone as a module (`python -m rung.gate`,
`python -m rung.run`); this dispatcher just spares you the module paths.
"""
import argparse
import difflib
import hashlib
import importlib.resources
import os
import pathlib
import platform
import shutil
import sys

# Every command word rung recognizes; the difflib pool for "did you mean" is the
# runnable subset (suggesting `help` on a typo is unhelpful).
COMMANDS = ("run", "attest", "gate", "check", "doctor", "version", "skill", "help")
_SUGGESTABLE = ("run", "attest", "gate", "check", "doctor", "version", "skill")


def _import_gate():
    from . import gate
    return gate


# Import the gate once, at load, so we can reuse its exit-code constants (the
# contract) everywhere. If the gate itself will not import, we fall back to the
# same literal contract values so the usage/help/doctor paths still work: doctor
# is precisely the surface meant to REPORT that gate.py is broken.
try:
    _GATE = _import_gate()
    _GATE_IMPORT_ERROR = None
    EXIT_PASS, EXIT_BLOCK, EXIT_USAGE = _GATE.EXIT_PASS, _GATE.EXIT_BLOCK, _GATE.EXIT_USAGE
except Exception as _e:  # pragma: no cover - exercised only on a broken gate.py
    _GATE = None
    _GATE_IMPORT_ERROR = _e
    EXIT_PASS, EXIT_BLOCK, EXIT_USAGE = 0, 30, 2


def _import_run():
    from . import run
    return run


def _import_attest():
    from . import attest
    return attest


# --- presentation (stderr only) -------------------------------------------

def _color_enabled(argv):
    """Color only if stderr is a TTY, NO_COLOR is unset, and --no-color is absent
    (scanned up to the probe separator so a probe's own --no-color is ignored)."""
    if not sys.stderr.isatty():
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    for a in argv:
        if a == "--":
            break
        if a == "--no-color":
            return False
    return True


def _paint(text, code, on):
    return "\x1b[" + code + "m" + text + "\x1b[0m" if on else text


def _error(msg, hint=None, example=None, color=False):
    """User-facing error in the Error: / Hint: / Example: shape, on stderr."""
    sys.stderr.write(_paint("Error:", "31", color) + " " + msg + "\n")
    if hint:
        sys.stderr.write("Hint: " + hint + "\n")
    if example:
        sys.stderr.write("Example: " + example + "\n")


_EXIT_LINE = "Exit codes: 0 pass, 30 block, 2 usage or cannot-evaluate."


def _build_parser():
    """Build the argparse tree. It renders top-level and per-command help (with
    examples + the exit-code contract in each epilog) and parses the
    dispatcher-owned commands; run/gate/check args are forwarded verbatim."""
    parent = argparse.ArgumentParser(add_help=False)
    # default=SUPPRESS so a global set before the subcommand is not reset to
    # False when the subparser (which shares these actions) parses.
    parent.add_argument("--quiet", "-q", action="store_true", default=argparse.SUPPRESS,
                        help="suppress rung's own progress (never the verdict or a critical error)")
    parent.add_argument("--no-color", action="store_true", default=argparse.SUPPRESS,
                        help="never colorize stderr (also honored via NO_COLOR and non-TTY)")

    parser = argparse.ArgumentParser(
        prog="rung", parents=[parent], allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Verification-evidence CLI: witness executions, gate bundles, self-check.",
        epilog=(
            "Examples:\n"
            "  rung gate bundle.json                 gate an authored bundle\n"
            "  rung run --rung 1 --surface cli -- mytool --check\n"
            "  rung doctor bundle.json               read-only preflight\n\n"
            + _EXIT_LINE),
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    sub.add_parser(
        "run", parents=[parent], add_help=True, allow_abbrev=False,
        help="witness an execution, emit + gate a bundle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Witness one execution (or an S0/S1 differential) and gate the emitted bundle.",
        epilog=(
            "Examples:\n"
            "  rung run --rung 1 --surface cli -- mytool --check\n"
            "  rung run --rung 1 --diff --surface cli -- baseline ::: changed\n\n"
            "All args after the command are passed through to rung.run verbatim,\n"
            "including everything after `--` (the probe argv). This dispatcher\n"
            "forwards them, so the full witness surface (--rung, --method,\n"
            "--surface, --diff, ...) is listed by `python -m rung.run -h`.\n\n"
            + _EXIT_LINE))

    sub.add_parser(
        "attest", parents=[parent], add_help=True, allow_abbrev=False,
        help="record an independent attestation on a bundle, then re-gate it",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Record an independent reviewer's attestation on an existing bundle, lift the "
                    "claim to context=independent, and re-gate. The amended bundle is printed to "
                    "stdout; the exit code is the gate's verdict.",
        epilog=(
            "Examples:\n"
            "  rung attest --model reviewer-x --verdict pass bundle.json\n"
            "  rung attest --panel a:pass,b:pass --verdict pass bundle.json\n"
            "  rung attest --model reviewer-x --lab lab-b --verdict pass bundle.json policy.json\n\n"
            "All args after the command are passed through to rung.attest verbatim; the\n"
            "full flag surface (--model/--panel, --verdict, --lab, --claim-id,\n"
            "--require-artifacts, --tier) is listed by `python -m rung.attest -h`.\n\n"
            + _EXIT_LINE))

    for name, blurb in (("gate", "gate an already-authored bundle"),
                        ("check", "alias for gate")):
        sub.add_parser(
            name, parents=[parent], add_help=True, allow_abbrev=False, help=blurb,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="Gate a bundle against a policy. The JSON verdict is printed to stdout.",
            epilog=(
                "Examples:\n"
                "  rung " + name + " bundle.json                  default policy\n"
                "  rung " + name + " bundle.json policy.json       explicit policy\n"
                "  rung " + name + " bundle.json --tier high       override risk tier\n\n"
                "stdout is exactly the gate verdict document; diagnostics go to stderr.\n\n"
                + _EXIT_LINE))

    d = sub.add_parser(
        "doctor", parents=[parent], add_help=True, allow_abbrev=False,
        help="read-only preflight; exit 0 or 2 only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Read-only preflight: Python version, gate.py/run.py import + sha256, and "
                    "(optionally) that a bundle parses. Never runs the gate; never exits 30.",
        epilog=(
            "Examples:\n"
            "  rung doctor                           environment only\n"
            "  rung doctor bundle.json               also check the bundle parses\n\n"
            + _EXIT_LINE))
    d.add_argument("bundle", nargs="?", help="optional bundle path to parse-check")

    sub.add_parser(
        "version", parents=[parent], add_help=True, allow_abbrev=False,
        help="schema major + gate sha256 + resolved paths",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Print the schema major this rung speaks, the pinned gate's sha256, and the "
                    "resolved paths of the running rung and gate.py.",
        epilog="Example:\n  rung version\n\n" + _EXIT_LINE)

    sk = sub.add_parser(
        "skill", parents=[parent], add_help=True, allow_abbrev=False,
        help="print or install the bundled rung skill (harness-neutral)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Surface the packaged rung skill (SKILL.md + references). The skill is plain "
                    "markdown and assumes no particular agent harness: print it into any agent's "
                    "context, or copy it into whatever directory your harness discovers skills in.",
        epilog=(
            "Examples:\n"
            "  rung skill                            print where the packaged skill lives\n"
            "  rung skill --print                    write SKILL.md to stdout (pipe into any agent)\n"
            "  rung skill --install .claude/skills/rung   copy the skill into a dir you name\n\n"
            "--install takes a destination directory YOU choose; rung bakes in no harness\n"
            "convention. For Claude Code that is usually .claude/skills/rung.\n\n"
            + _EXIT_LINE))
    skg = sk.add_mutually_exclusive_group()
    skg.add_argument("--print", dest="print_skill", action="store_true",
                     help="write SKILL.md to stdout")
    skg.add_argument("--install", metavar="DEST", default=None,
                     help="copy the skill tree into DEST (a directory you name)")
    sk.add_argument("--force", action="store_true",
                    help="with --install, replace DEST if it already exists (removes its current contents first)")

    sub.add_parser(
        "help", parents=[parent], add_help=True, allow_abbrev=False, help="show top-level usage",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Show the top-level usage.", epilog=_EXIT_LINE)

    return parser


# --- command shape ----------------------------------------------------------

def _command_token(argv):
    """The command is the first bare (non-flag) token before any `--`. Flags
    (global, -h, or unknown) are skipped so the command is still found after
    them; a `--` before any bare token means no command was given."""
    for a in argv:
        if a == "--":
            return None
        if a.startswith("-"):
            continue
        return a
    return None


def _has_help_flag(argv):
    for a in argv:
        if a == "--":
            return False
        if a in ("-h", "--help"):
            return True
    return False


def _reject_extras(command, extras, color):
    if extras:
        _error("unexpected argument(s) for " + command + ": " + " ".join(repr(e) for e in extras),
               hint="run `rung " + command + " -h` for its usage.",
               example="rung " + command, color=color)
        return True
    return False


# --- commands ---------------------------------------------------------------

def _version():
    g = _GATE
    sha = g.GATE_SHA256 if (g and g.GATE_SHA256) else "unknown"
    gate_path = str(pathlib.Path(g.__file__).resolve()) if g else "unknown"
    sys.stdout.write(
        "rung: schema " + (g.SCHEMA_MAJOR if g else "unknown") + "\n"
        "gate: " + sha + "\n"
        "rung path: " + str(pathlib.Path(__file__).resolve()) + "\n"
        "gate path: " + gate_path + "\n")
    return EXIT_PASS


def _file_sha256(path):
    try:
        return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _doctor(bundle, quiet, color):
    checks = []  # (passed, text)

    py_ok = sys.version_info >= (3, 9)
    checks.append((py_ok, "python " + platform.python_version() + " (need >= 3.9)"))

    if _GATE is None:
        checks.append((False, "gate.py import FAILED: " + str(_GATE_IMPORT_ERROR)))
    else:
        gsha = _GATE.GATE_SHA256 or "unknown"
        checks.append((True, "gate.py imports; sha256=" + gsha))

    run_mod = None
    try:
        run_mod = _import_run()
    except Exception as e:  # noqa: BLE001 - report any import failure, do not crash
        checks.append((False, "run.py import FAILED: " + str(e)))
    if run_mod is not None:
        rsha = _file_sha256(run_mod.__file__) or "unknown"
        checks.append((True, "run.py imports; sha256=" + rsha))

    try:
        attest_mod = _import_attest()
    except Exception as e:  # noqa: BLE001 - report any import failure, do not crash
        checks.append((False, "attest.py import FAILED: " + str(e)))
    else:
        asha = _file_sha256(attest_mod.__file__) or "unknown"
        checks.append((True, "attest.py imports; sha256=" + asha))

    if bundle is not None:
        if _GATE is None:
            checks.append((False, "cannot parse-check bundle: gate.py did not import"))
        else:
            try:
                _GATE._read_json(pathlib.Path(bundle), "bundle")
                checks.append((True, "bundle parses: " + bundle))
            except _GATE.GateInputError as e:
                checks.append((False, "bundle parse FAILED: " + str(e)))

    all_ok = all(passed for passed, _ in checks)
    for passed, text in checks:
        if passed and quiet:
            continue  # ok-lines are rung's own progress; --quiet mutes them
        label = _paint("ok  ", "32", color) if passed else _paint("FAIL", "31", color)
        sys.stderr.write(label + " " + text + "\n")

    if not all_ok:
        _error("doctor found a failing check", hint="see the FAIL line(s) above.",
               example="rung doctor path/to/bundle.json", color=color)
        return EXIT_USAGE
    return EXIT_PASS


# --- skill ------------------------------------------------------------------

def _skill_resource():
    """The packaged skill tree, resolved as an importlib.resources Traversable so
    it works identically from a checkout and from an installed (even zipped)
    wheel. May raise on a broken/absent package; callers translate to exit 2."""
    return importlib.resources.files(__package__ or "rung") / "data" / "skill"


def _copy_traversable(src, dest):
    """Recursively copy an importlib.resources Traversable tree to a filesystem
    dir, byte-for-byte. Uses only the Traversable API (iterdir/is_dir/read_bytes),
    so it needs no as_file() directory materialization (unsupported < 3.12)."""
    dest.mkdir(parents=True, exist_ok=True)
    for child in src.iterdir():
        target = dest / child.name
        if child.is_dir():
            _copy_traversable(child, target)
        else:
            target.write_bytes(child.read_bytes())


def _skill(print_skill, install_dest, force, color):
    """Surface the packaged skill. Harness-neutral: print its location, dump
    SKILL.md, or copy the tree into a directory the caller names. Exit 0/2 only,
    never 30 (nothing here is a gate verdict)."""
    try:
        res = _skill_resource()
    except Exception as e:  # noqa: BLE001 - a broken package must fail closed, not crash
        _error("cannot locate the bundled skill: " + str(e),
               hint="reinstall rung-ai, or run `rung doctor`.", color=color)
        return EXIT_USAGE

    if print_skill:
        try:
            sys.stdout.write((res / "SKILL.md").read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            _error("cannot read the bundled SKILL.md: " + str(e), color=color)
            return EXIT_USAGE
        return EXIT_PASS

    if install_dest is not None:
        dest = pathlib.Path(install_dest)
        if dest.exists() and not force:
            _error("refusing to overwrite existing " + str(dest),
                   hint="pass --force to replace it, or name a different directory.",
                   example="rung skill --install " + install_dest + " --force", color=color)
            return EXIT_USAGE
        try:
            # --force is a clean replace, not a merge: remove exactly what was
            # named first, so a reference file dropped/renamed across skill
            # versions cannot survive as an orphan the agent still loads. Only
            # the named path is touched (a symlink is unlinked, not followed).
            if dest.exists():
                if dest.is_dir() and not dest.is_symlink():
                    shutil.rmtree(dest)
                else:
                    dest.unlink()
            _copy_traversable(res, dest)
        except Exception as e:  # noqa: BLE001 - any I/O failure fails closed to 2
            _error("could not install the skill to " + str(dest) + ": " + str(e), color=color)
            return EXIT_USAGE
        sys.stderr.write("installed rung skill to " + str(dest) + "\n")
        return EXIT_PASS

    # No sub-flag: report where the packaged skill lives + how to use it. as_file
    # on the single SKILL.md file works on every version; its parent is the tree.
    try:
        with importlib.resources.as_file(res / "SKILL.md") as p:
            loc = str(pathlib.Path(p).parent)
    except Exception:  # noqa: BLE001 - display best-effort; never fail the command
        loc = "unknown"
    sys.stdout.write(
        "packaged rung skill: " + loc + "\n"
        "  rung skill --print                 write SKILL.md to stdout (read it into any agent)\n"
        "  rung skill --install <dir>         copy the skill into a directory you name\n"
        "                                     (Claude Code: .claude/skills/rung)\n")
    return EXIT_PASS


# --- dispatch ---------------------------------------------------------------

def main(argv=None):
    # argv is None exactly when the `[project.scripts] rung = rung.cli:main`
    # console-script wrapper invokes main() with no args; read sys.argv[1:]
    # ourselves so the installed `rung` command and `python -m rung.cli` agree.
    if argv is None:
        argv = sys.argv[1:]
    color = _color_enabled(argv)
    parser = _build_parser()
    cmd = _command_token(argv)

    if cmd is None:
        # -h/--help before any command -> top-level help on stdout (argparse
        # exits 0). Nothing (or globals only) -> usage error on stderr, exit 2.
        if _has_help_flag(argv):
            parser.parse_args(argv)  # prints help, raises SystemExit(0)
            return EXIT_PASS         # unreachable
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    if cmd == "help":
        parser.print_help(sys.stdout)
        return EXIT_PASS

    if cmd not in COMMANDS:
        match = difflib.get_close_matches(cmd, _SUGGESTABLE, n=1, cutoff=0.6)
        hint = ("did you mean " + repr(match[0]) + "?") if match else "run `rung help` for the command list."
        _error("unknown command " + repr(cmd), hint=hint,
               example="rung gate BUNDLE [POLICY]", color=color)
        return EXIT_USAGE

    # A valid command: let argparse own per-command -h and global-flag parsing.
    # parse_known_args preserves `--` and hands the tool args back as `extras`.
    args, extras = parser.parse_known_args(argv)
    quiet = getattr(args, "quiet", False)

    if args.command in ("gate", "check"):
        # In-process so stdout stays the exact verdict bytes; child stderr is
        # never muzzled (critical errors must survive --quiet).
        if _GATE is None:
            _error("gate.py failed to import: " + str(_GATE_IMPORT_ERROR),
                   hint="run `rung doctor` to diagnose.", color=color)
            return EXIT_USAGE
        # Fail closed on an unexpected gate-internal exception: it must not escape
        # as an exit-1 traceback (never an uncaught traceback), so map it to exit
        # 2 (cannot-evaluate). `except Exception` deliberately does not catch
        # SystemExit, so any in-contract exit still propagates.
        try:
            return _GATE.main(extras)
        except Exception as e:  # noqa: BLE001 - any gate-internal crash fails closed
            _error("gate failed to evaluate: " + type(e).__name__ + ": " + str(e),
                   hint="this is a gate-internal error; run `rung doctor` to diagnose.",
                   color=color)
            return EXIT_USAGE

    if args.command == "run":
        # An import failure would otherwise escape as an uncaught exception (exit
        # 1, out of contract), so guard it the same way the gate path does.
        try:
            run_mod = _import_run()
        except Exception as e:  # noqa: BLE001 - any import failure must fail closed
            _error("run.py failed to import: " + str(e),
                   hint="run `rung doctor` to diagnose.", color=color)
            return EXIT_USAGE
        # run.main uses argparse; a bad flag raises SystemExit(2), which is
        # in-contract and propagates (SystemExit is not an Exception). An
        # unexpected internal exception fails closed to exit 2, as the gate does.
        try:
            return run_mod.main(extras)
        except Exception as e:  # noqa: BLE001 - any run-internal crash fails closed
            _error("run failed to evaluate: " + type(e).__name__ + ": " + str(e),
                   hint="this is a run-internal error; run `rung doctor` to diagnose.",
                   color=color)
            return EXIT_USAGE

    if args.command == "attest":
        # Same posture as run/gate: in-process so stdout stays the exact amended
        # bundle bytes; an import failure or unexpected internal exception fails
        # closed to exit 2, while attest's in-contract SystemExit (argparse usage)
        # and its 0/30/2 returns propagate untouched.
        try:
            attest_mod = _import_attest()
        except Exception as e:  # noqa: BLE001 - any import failure must fail closed
            _error("attest failed to import: " + str(e),
                   hint="run `rung doctor` to diagnose.", color=color)
            return EXIT_USAGE
        try:
            return attest_mod.main(extras)
        except Exception as e:  # noqa: BLE001 - any attest-internal crash fails closed
            _error("attest failed to evaluate: " + type(e).__name__ + ": " + str(e),
                   hint="this is an attest-internal error; run `rung doctor` to diagnose.",
                   color=color)
            return EXIT_USAGE

    if args.command == "version":
        if _reject_extras("version", extras, color):
            return EXIT_USAGE
        return _version()

    if args.command == "doctor":
        if _reject_extras("doctor", extras, color):
            return EXIT_USAGE
        return _doctor(args.bundle, quiet, color)

    if args.command == "skill":
        if _reject_extras("skill", extras, color):
            return EXIT_USAGE
        return _skill(getattr(args, "print_skill", False), getattr(args, "install", None),
                      getattr(args, "force", False), color)

    # Unreachable: every command in COMMANDS is handled above.
    parser.print_help(sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
