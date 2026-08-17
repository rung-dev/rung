#!/usr/bin/env python3
"""Conformance tests for the `rung` umbrella CLI dispatcher (the packaged
`rung.cli` module, equivalently the installed `rung` console script), driven the
way PROJECT.md prescribes: shell out to the REAL CLI via `python -m rung.cli`
with src/ on PYTHONPATH and assert on exit code + stdout/stderr. We do NOT import
the dispatcher and call main() for the routing tests; the surface under test is
the command line.

What these lock down (the hard invariants the upgrade must not regress):
  * subcommand routing (run / gate / check / doctor / version / help);
  * `gate` (and its `check` alias) stdout is BYTE-IDENTICAL to running
    `python -m rung.gate` with the same args, and the exit code matches;
  * exit codes stay the 0/30/2 contract, with no fourth code ever;
  * unknown command -> exit 2 with a difflib "did you mean" on stderr;
  * help routing: top-level and per-command -h, `help`, empty argv, globals-only;
  * `-h`/`--help` after `--` is forwarded to the probe, never eaten by rung;
  * truthful `version` (schema major + gate sha + resolved paths), None-sha safe;
  * read-only `doctor` (exit 0 or 2 ONLY, never 30);
  * `--quiet` keeps the verdict and every critical error, muzzles only rung's
    own progress;
  * `--no-color` / NO_COLOR keep stdout free of ANSI; there is NO `--json` flag;
  * no em-dash leaks into any generated help/version/doctor text.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
# Drive the packaged dispatcher as `python -m rung.cli` (equivalently the
# installed `rung` console script) with src/ on PYTHONPATH; the repo-root `rung`
# file is gone under the src/ layout.
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
import rung.cli as cli    # in-process, for the crash / color unit tests
import rung.gate as gate  # in-process, for constants + resolved-path assertions

FLAGSHIP = REPO / "cases" / "sync-connector-stdio-purity" / "bundle.json"
GATE_PATH = Path(gate.__file__).resolve()  # what `rung version` should echo
RUNG_ARGV = [sys.executable, "-m", "rung.cli"]
GATE_ARGV = [sys.executable, "-m", "rung.gate"]

ESC = "\x1b["      # ANSI CSI introducer; must never touch stdout
EMDASH = "—"  # forbidden anywhere in published text


def _env(extra=None):
    """Subprocess env with src/ on PYTHONPATH and a clean color environment
    (individual tests override NO_COLOR)."""
    e = dict(os.environ)
    e["PYTHONPATH"] = str(SRC) + os.pathsep + e.get("PYTHONPATH", "")
    e.pop("NO_COLOR", None)
    if extra:
        e.update(extra)
    return e


def _boom(*_a, **_k):
    raise RuntimeError("boom")


class RungCLI(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    # -- helpers ------------------------------------------------------------
    def rung(self, *args, env=None, cwd=None):
        return subprocess.run(
            RUNG_ARGV + list(args),
            cwd=str(cwd or REPO), capture_output=True, text=True, env=_env(env),
        )

    def gate_cli(self, *args):
        return subprocess.run(
            GATE_ARGV + list(args),
            cwd=str(REPO), capture_output=True, text=True, env=_env(),
        )

    def fixture(self, name, body):
        p = self.tmp / name
        p.write_text(body)
        return p

    def block_bundle(self):
        # Empty claims -> the gate blocks (verdict block, exit 30), a stable way
        # to exercise the 30 code end to end.
        p = self.tmp / "block.json"
        p.write_text(json.dumps({
            "schema": "evidence-bundle/v1",
            "change": {"repo": "x", "s0": "a", "s1": "b", "producer": {"lab": "l"}},
            "claims": [], "gaps": [],
        }))
        return p

    def bad_bundle(self):
        p = self.tmp / "bad.json"
        p.write_text("{not valid json")
        return p

    # -- routing ------------------------------------------------------------
    def test_gate_stdout_byte_identical_to_gate_py(self):
        r = self.rung("gate", str(FLAGSHIP))
        g = self.gate_cli(str(FLAGSHIP))
        self.assertEqual(r.stdout, g.stdout, "rung gate stdout must equal gate.py stdout byte for byte")
        self.assertEqual(r.returncode, g.returncode)
        self.assertEqual(r.returncode, 0)
        self.assertNotIn(ESC, r.stdout, "no ANSI on the verdict stdout")

    def test_check_is_exact_alias_of_gate(self):
        c = self.rung("check", str(FLAGSHIP))
        g = self.rung("gate", str(FLAGSHIP))
        self.assertEqual(c.stdout, g.stdout)
        self.assertEqual(c.returncode, g.returncode)

    def test_gate_block_propagates_30(self):
        blk = self.block_bundle()
        r = self.rung("gate", str(blk))
        g = self.gate_cli(str(blk))
        self.assertEqual(r.returncode, 30)
        self.assertEqual(r.stdout, g.stdout)
        self.assertIn('"verdict": "block"', r.stdout)

    def test_run_routes_to_run_witness(self):
        fix = self.fixture("probe.py", "import sys\nsys.stdout.write('ok\\n')\n")
        out = self.tmp / "out"
        r = self.rung("run", "--rung", "3", "--surface", "cli", "--tier", "medium",
                      "--out", str(out), "--", sys.executable, str(fix), cwd=self.tmp)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        b = json.loads((out / "bundle.json").read_text())
        c = b["claims"][0]
        self.assertEqual(c["rung"], 3)
        self.assertEqual(c["context"], "author")
        self.assertEqual(c["surface"]["kind"], "cli")

    def test_run_missing_probe_reaches_run_usage_not_dispatcher(self):
        # No probe -> run.py's own usage error (proves the token routed to run.main,
        # not to the dispatcher's unknown-command path).
        r = self.rung("run", "--rung", "1", "--surface", "cli")
        self.assertEqual(r.returncode, 2)
        self.assertIn("rung run", r.stderr)
        self.assertNotIn("unknown command", r.stderr)

    # -- unknown command + difflib -----------------------------------------
    def test_unknown_command_suggests_and_exits_2(self):
        r = self.rung("gato")
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")
        low = r.stderr.lower()
        self.assertIn("gate", low, "difflib should suggest the closest command")
        self.assertIn("did you mean", low)
        self.assertIn("error:", low, "user-facing errors use the Error:/Hint:/Example: shape")

    def test_unknown_command_no_close_match_still_exits_2(self):
        r = self.rung("zzzzzzzz")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown command", r.stderr.lower())

    def test_no_prefix_autoexpansion(self):
        # `ru` must NOT silently expand to `run`; it is an unknown command.
        r = self.rung("ru")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown command", r.stderr.lower())

    # -- help routing -------------------------------------------------------
    def test_top_level_help_flags(self):
        for flag in ("-h", "--help"):
            r = self.rung(flag)
            self.assertEqual(r.returncode, 0, flag)
            low = r.stdout.lower()
            self.assertIn("usage", low)
            for cmd in ("run", "gate", "doctor", "version"):
                self.assertIn(cmd, low)

    def test_help_word(self):
        r = self.rung("help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("usage", r.stdout.lower())

    def test_empty_argv_is_usage_error(self):
        r = self.rung()
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage", r.stderr.lower())
        self.assertEqual(r.stdout, "")

    def test_globals_only_is_usage_error(self):
        # F3: globals present, no command token -> same usage error, exit 2.
        r = self.rung("--quiet")
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage", r.stderr.lower())

    def test_per_command_help_has_example_and_exit_contract(self):
        for cmd in ("run", "gate", "check", "doctor", "version"):
            r = self.rung(cmd, "-h")
            self.assertEqual(r.returncode, 0, cmd)
            low = r.stdout.lower()
            self.assertIn("example", low, f"{cmd} -h should carry an example")
            self.assertIn("30", r.stdout, f"{cmd} -h should state the exit-code contract")

    def test_help_after_double_dash_is_forwarded_to_probe(self):
        # `-h` after `--` belongs to the probe; the dispatcher must not eat it.
        fix = self.fixture("probe.py", "import sys\nsys.stdout.write('ok\\n')\n")
        out = self.tmp / "out"
        r = self.rung("run", "--rung", "1", "--surface", "cli", "--out", str(out),
                      "--", sys.executable, str(fix), "--help", cwd=self.tmp)
        self.assertNotIn("usage: rung run", r.stdout)
        self.assertNotIn("show this help message", r.stdout)
        self.assertIn(r.returncode, (0, 30))
        self.assertTrue((out / "bundle.json").exists(), "the run still executed")

    # -- version ------------------------------------------------------------
    def test_version_shape(self):
        r = self.rung("version")
        self.assertEqual(r.returncode, 0)
        self.assertIn(gate.SCHEMA_MAJOR, r.stdout)
        # gate sha (may be None in pathological cases; here it resolves) + path.
        self.assertIsNotNone(gate.GATE_SHA256)
        self.assertIn(gate.GATE_SHA256, r.stdout)
        self.assertIn(str(GATE_PATH), r.stdout, "version echoes the resolved gate.py path")
        self.assertNotIn(ESC, r.stdout)
        self.assertNotIn("None", r.stdout, "a None sha must render as 'unknown', never literal None")

    # -- doctor -------------------------------------------------------------
    def test_doctor_healthy_exit_0_reports_shas(self):
        r = self.rung("doctor")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        report = r.stdout + r.stderr
        low = report.lower()
        self.assertIn("python", low)
        self.assertIn(gate.GATE_SHA256, report, "doctor reports the gate.py sha")
        self.assertIn("run.py", report, "doctor reports run.py (its own sha, computed at runtime)")

    def test_doctor_unparseable_bundle_exit_2(self):
        bad = self.bad_bundle()
        r = self.rung("doctor", str(bad))
        self.assertEqual(r.returncode, 2)
        self.assertIn("error:", r.stderr.lower())

    def test_doctor_good_bundle_exit_0(self):
        r = self.rung("doctor", str(FLAGSHIP))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_doctor_never_returns_30(self):
        for args in (("doctor",), ("doctor", str(self.bad_bundle())),
                     ("doctor", str(self.block_bundle()))):
            r = self.rung(*args)
            self.assertIn(r.returncode, (0, 2), f"doctor {args} must be 0/2, never 30")

    # -- --quiet ------------------------------------------------------------
    def test_quiet_keeps_the_verdict(self):
        r = self.rung("--quiet", "gate", str(FLAGSHIP))
        g = self.gate_cli(str(FLAGSHIP))
        self.assertEqual(r.stdout, g.stdout, "--quiet never suppresses the verdict")
        self.assertEqual(r.returncode, 0)

    def test_quiet_keeps_child_critical_error(self):
        # F5: --quiet must not swallow a child's critical stderr.
        missing = self.tmp / "nope.json"
        r = self.rung("--quiet", "gate", str(missing))
        self.assertEqual(r.returncode, 2)
        self.assertIn("gate:", r.stderr, "gate's GateInputError still reaches stderr under --quiet")

    def test_quiet_keeps_doctor_failure_but_suppresses_progress(self):
        loud = self.rung("doctor")
        quiet = self.rung("--quiet", "doctor")
        self.assertEqual(loud.returncode, 0)
        self.assertEqual(quiet.returncode, 0)
        self.assertLess(len(quiet.stderr), len(loud.stderr),
                        "--quiet suppresses doctor's ok-line progress")
        # A failure still discloses under --quiet.
        fail = self.rung("--quiet", "doctor", str(self.bad_bundle()))
        self.assertEqual(fail.returncode, 2)
        self.assertIn("error:", fail.stderr.lower())

    # -- color / --json -----------------------------------------------------
    def test_no_color_and_NO_COLOR_keep_stdout_clean(self):
        for r in (self.rung("--no-color", "gate", str(FLAGSHIP)),
                  self.rung("gate", str(FLAGSHIP), env={"NO_COLOR": "1"}),
                  self.rung("gate", str(FLAGSHIP))):
            self.assertNotIn(ESC, r.stdout)
            self.assertNotIn(ESC, r.stderr)

    def test_color_enabled_gating(self):
        # The subprocess tests above never see a TTY (capture_output pipes
        # stderr), so the color-ON branch is unreachable there. Exercise the pure
        # gate directly on the imported rung.cli: color requires a TTY, no
        # NO_COLOR, and no --no-color.
        real_isatty = sys.stderr.isatty
        real_no_color = os.environ.get("NO_COLOR")
        try:
            sys.stderr.isatty = lambda: True
            os.environ.pop("NO_COLOR", None)
            self.assertTrue(cli._color_enabled([]), "TTY + no NO_COLOR + no flag paints")
            self.assertFalse(cli._color_enabled(["--no-color"]), "--no-color suppresses")
            os.environ["NO_COLOR"] = "1"
            self.assertFalse(cli._color_enabled([]), "NO_COLOR suppresses")
            os.environ.pop("NO_COLOR", None)
            sys.stderr.isatty = lambda: False
            self.assertFalse(cli._color_enabled([]), "non-TTY never paints")
        finally:
            sys.stderr.isatty = real_isatty
            if real_no_color is None:
                os.environ.pop("NO_COLOR", None)
            else:
                os.environ["NO_COLOR"] = real_no_color

    def _rung_module(self):
        # The dispatcher is now a proper package module (rung.cli), imported once
        # at the top of this file. No SourceFileLoader / sys.modules['gate'] pin
        # is needed anymore: `from . import gate` resolves rung.gate directly, so
        # the in-process module sees exactly the gate the CLI sees. Tests that
        # mutate its attributes restore them in a finally. The subprocess
        # fail-closed test below covers the real broken-gate path.
        return cli

    # -- delegated-tool crash must fail closed (E-C2) -----------------------
    def test_gate_internal_crash_fails_closed_to_2(self):
        # An unexpected exception from gate.main must not escape as an exit-1
        # traceback; the dispatcher maps it to exit 2 (cannot-evaluate).
        m = self._rung_module()
        orig = m._GATE.main
        m._GATE.main = _boom
        try:
            rc = m.main(["gate", "whatever.json"])
        finally:
            m._GATE.main = orig
        self.assertEqual(rc, 2)

    def test_run_internal_crash_fails_closed_to_2(self):
        m = self._rung_module()

        class _Stub:
            main = staticmethod(_boom)

        orig = m._import_run
        m._import_run = lambda: _Stub
        try:
            self.assertEqual(m.main(["run", "--", "x"]), 2)
        finally:
            m._import_run = orig

    def test_run_argparse_systemexit_still_propagates(self):
        # The catch-all must NOT swallow run.main's argparse SystemExit(2); that
        # is an in-contract usage exit (SystemExit is not an Exception).
        m = self._rung_module()

        class _Stub:
            @staticmethod
            def main(_extras):
                raise SystemExit(2)

        orig = m._import_run
        m._import_run = lambda: _Stub
        try:
            with self.assertRaises(SystemExit) as ctx:
                m.main(["run", "--", "x"])
        finally:
            m._import_run = orig
        self.assertEqual(ctx.exception.code, 2)

    def test_broken_gate_fails_closed_via_subprocess(self):
        # The real broken-gate guarantee, exercised end to end: an
        # unimportable gate.py, driven through the CLI as a subprocess (not an
        # in-process monkey-patch). This is immune to the sys.modules
        # namespace-package collision the unit-level crash tests can hit, and it
        # asserts the whole contract at once: gate/run/doctor fail closed to
        # exit 2 with NO uncaught traceback (never exit 1) and never a pass.
        sandbox = self.tmp / "sandbox"
        pkg = sandbox / "src" / "rung"
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("__version__ = '0.0.0'\n")
        # Real cli.py and run.py, but an unimportable gate.py (a
        # SyntaxError, which is an Exception, so cli's module-level guard catches
        # it and sets _GATE=None, and run.py's `from . import gate` propagates it
        # so run's import fails closed too).
        shutil.copy2(REPO / "src" / "rung" / "cli.py", pkg / "cli.py")
        shutil.copy2(REPO / "src" / "rung" / "run.py", pkg / "run.py")
        (pkg / "gate.py").write_text("def broken(:\n    pass\n")
        bundle = sandbox / "bundle.json"
        bundle.write_text("{}")

        def run(*args):
            env = dict(os.environ)
            env["PYTHONPATH"] = str(sandbox / "src") + os.pathsep + env.get("PYTHONPATH", "")
            return subprocess.run(
                [sys.executable, "-m", "rung.cli", *args],
                cwd=str(sandbox), capture_output=True, text=True, env=env,
            )

        TRACE = "Traceback (most recent call last)"

        # gate: fails closed to 2, no traceback, no verdict on stdout.
        g = run("gate", str(bundle))
        self.assertEqual(g.returncode, 2, g.stdout + g.stderr)
        self.assertNotIn(TRACE, g.stderr, "a broken gate must not surface a traceback")
        self.assertIn("error:", g.stderr.lower())
        self.assertNotIn('"verdict"', g.stdout, "a broken gate must never print a verdict")

        # run: an unimportable gate breaks run's own import too; still exit 2.
        rr = run("run", "--rung", "1", "--surface", "cli", "--", "echo", "hi")
        self.assertEqual(rr.returncode, 2, rr.stdout + rr.stderr)
        self.assertNotIn(TRACE, rr.stderr)

        # doctor: reports the failure (FAIL line + Error:), exit 2, never 30.
        d = run("doctor")
        self.assertEqual(d.returncode, 2, d.stdout + d.stderr)
        self.assertNotIn(TRACE, d.stderr)
        self.assertIn("fail", d.stderr.lower())

        # version: degrades to 'unknown' rather than crashing; still exit 0.
        v = run("version")
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
        self.assertNotIn(TRACE, v.stderr)
        self.assertIn("unknown", v.stdout.lower())

    def test_no_json_flag_exists(self):
        # F1: --json is not a rung flag. It must fail closed to exit 2, never
        # silently succeed as a no-op mode.
        r = self.rung("--json", "gate", str(FLAGSHIP))
        self.assertEqual(r.returncode, 2)

    # -- global contracts ---------------------------------------------------
    def test_exit_codes_are_the_only_three(self):
        blk = self.block_bundle()
        bad = self.bad_bundle()
        cases = [
            ("gate", str(FLAGSHIP)),
            ("gate", str(blk)),
            ("gate", str(bad)),
            ("gato",),
            ("version",),
            ("doctor",),
            ("doctor", str(bad)),
            ("--json", "gate", str(FLAGSHIP)),
            ("help",),
            (),
        ]
        for args in cases:
            r = self.rung(*args)
            self.assertIn(r.returncode, (0, 30, 2),
                          f"rung {args} returned out-of-contract {r.returncode}")

    def test_no_emdash_in_generated_text(self):
        texts = [self.rung("-h").stdout, self.rung("version").stdout,
                 self.rung("doctor").stderr]
        for cmd in ("run", "gate", "check", "doctor", "version"):
            texts.append(self.rung(cmd, "-h").stdout)
        for t in texts:
            self.assertNotIn(EMDASH, t, "no em-dash may appear in rung's own text")


if __name__ == "__main__":
    unittest.main()
