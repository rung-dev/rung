#!/usr/bin/env python3
"""rung run: witness one execution and emit a gate-checkable evidence bundle.

The point of this wrapper is a single inversion: an agent's cheapest path to a
rung claim should be to ACTUALLY RUN the surface, not to hand-write a bundle. So
`rung run` executes the probe, captures the bytes off the child's own fds, hashes
them, and emits an `evidence-bundle/v1` with those captures as artifacts, then
runs the gate over it and exits with the GATE's verdict.

What it proves vs what it takes on trust (be precise; the accuracy of this claim
is the product):
  * PROVES (witnessed): a child process launched via this exact argv and THESE
    EXACT BYTES came off its stdout/stderr. That kills the hand-typed-sha256
    fabrication of a capture: you can no longer paste a hash for bytes that were
    never produced.
  * DOES NOT prove WHICH program truly ran, nor that it is the subject surface.
    `cat file`, `echo`, `printf` emit bytes too, so a fabricated capture just
    moves to "emit the bytes via cat" -- squarely inside the surface-authenticity
    residue that is judge-only. To make that visible rather than laundered, the
    resolved path and hash of the launcher AND of every file argument (the real
    subject a `node`/`python`/`java` launcher actually ran) are recorded in
    `surface.executed`; authenticity of the surface is still not something this
    tool can decide.
  * DOES NOT witness the RUNG. Exec-with-output cannot tell a real-surface drive
    (rung 3) from an in-process import (rung 1) or a test runner (rung 2); they
    all exec and emit bytes. So the tool NEVER mints a rung. `--rung` and
    `--surface` are REQUIRED declared inputs: over-claiming is then a deliberate,
    logged act (`--rung 3 --surface cli`), never a silent default. A bare
    `rung run -- <cmd>` refuses to emit anything, so it can never satisfy a
    rung-3 policy.
  * REFUSES rung >= 3 with zero captured bytes on a process that RAN TO
    COMPLETION: observing nothing is not observation. (A process that produced
    nothing because it HUNG is diagnosed as a timeout, not as this refusal; see
    below.) The differential runner (`--diff`) is the rung-4 increment: it drives
    two runs (S0 baseline, S1 changed), captures each off its own fds, and emits a
    rung-4 bundle with exactly one s0_capture and one s1_capture. The GATE, not
    this tool, decides the delta polarity (change vs invariance) from the captured
    bytes; the runner only declares intent (`--expect-delta`) and never asserts
    the delta itself. Because a byte-level delta only proxies the claimed change
    when output is deterministic, each side is run twice and a side whose compared
    channel is not byte-stable is recorded as a blocker gap
    (`nondeterministic-output`), never emitted as a trustworthy delta. Rung 4
    without `--diff` is still refused (needs two runs).

Non-termination is a witnessed failure, handled BEFORE the empty-output refusal
so a silent hang is diagnosed as a hang, not as "nothing observed": on timeout
the tool forces the claim's verdict to `blocked` (which the gate blocks
unconditionally, with no `allow_dismiss_gaps` escape) and also attaches a blocker
gap for the audit trail. A witnessed hang therefore cannot go green under a
permissive policy.

Server surfaces: a correct persistent stdio server answers a request and then
keeps its stream open, so a plain run always hits the timeout. `--expect-frames
N` (stop after N newline-terminated stdout frames) or `--until-idle [SECS]` (stop
once the probe produced output and then went quiet) treat an answered-then-alive
process as a completed observation: the tool captures the frames, then kills the
still-running child, and does NOT record a timeout. `hung-producing-nothing`
still times out and blocks. `--expect-frames` counts newline-terminated lines, so
it fits line-delimited protocols (JSON-RPC / MCP over stdio); for non-newline
framing (LSP Content-Length) use `--until-idle`, which is framing-agnostic.

Trust posture, opposite of the gate's: the gate is safe to run on untrusted
input (it only hashes files). `rung run` EXECUTES its probe, so running it
against an adversarial repo is code execution. Keep it to trusted inputs; the
sandboxed production recorder is a separate, privileged tool (not this one).

Captures may contain secrets. Redaction before a bundle is committed/published is
an operator responsibility; this tool prints a reminder and does not scan. The
probe inherits this process's environment by default, so a token in the operator
env can surface in a capture; `--env-clear` runs the probe with a scrubbed,
minimal environment (PATH, HOME, locale, TERM, TMPDIR) to reduce that leakage.

Policy is loaded, parsed, AND hash-pinned BEFORE the probe executes, and the
pinned bytes are re-verified after the run (RUN-T1): the code being judged cannot
swap the policy out from under its own gate. A mid-run change to the policy file
is a block, not a silent honoring of the new policy.

Usage:
    rung run --rung N --surface KIND [options] -- <argv> [args...]
"""
from __future__ import annotations
import sys, os, json, time, signal, hashlib, pathlib, argparse, shutil, threading, subprocess, contextlib

try:  # package-relative under rung.*; bare fallback for a loose vendored copy
    from . import gate
except (ImportError, ValueError):
    import gate

SURFACES = ("cli", "server", "gui", "library", "agent", "ci")
DEFAULT_TIMEOUT = 60
# Executables (a node/java runtime) routinely dwarf the gate's 64 MiB artifact
# cap, so the provenance hash gets its own, larger ceiling. Past it the tool
# records WHY the hash is absent rather than a bare null (finding: "unavailable"
# was indistinguishable from "not attempted").
PROVENANCE_HASH_CAP = 512 * 1024 * 1024
# A probe can stream unbounded bytes (a chatty server, a runaway loop). Cap the
# ACCUMULATED capture so a bundle can never grow without bound, and mirror the
# gate's rule: truncation past the cap is RECORDED as a blocker gap, not
# silently dropped. Matches the gate's MAX_ARTIFACT_BYTES so a capture that the
# gate would refuse to hash never reaches it in the first place. Operators can
# tune it down for constrained environments via RUNG_MAX_CAPTURE_BYTES.
MAX_CAPTURE_BYTES = int(os.environ.get("RUNG_MAX_CAPTURE_BYTES", 64 * 1024 * 1024))
# The drain reads fixed-size chunks (not whole lines) so a newline-free or
# long-line stream cannot buffer unbounded bytes before the cap check runs; each
# read is bounded to this many bytes regardless of where newlines fall (RUN-D1).
CHUNK_BYTES = 65536
# Env keys kept when --env-clear is set: enough to launch and be locale-stable,
# nothing that typically carries a secret (tokens, keys, cloud creds).
ENV_CLEAR_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TMPDIR")


def _split_probe(argv: list[str]) -> tuple[list[str], list[str]]:
    """Everything after the first bare `--` is the probe argv, executed
    directly (no shell) so the captured bytes provably came off ITS fds."""
    if "--" not in argv:
        return argv, []
    i = argv.index("--")
    return argv[:i], argv[i + 1:]


def _parse(opts: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="rung run",
        description="Witness one execution and emit a gate-checkable bundle.",
    )
    # Witnessed dimensions are NOT declarable-by-default: the tool refuses to
    # guess a rung/surface it cannot witness.
    p.add_argument("--rung", type=int, required=True,
                   help="0..3 for a single run; 4 requires --diff (an S0/S1 differential / two runs).")
    p.add_argument("--surface", required=True, choices=SURFACES,
                   help="Declared consumer-surface class. The tool does not verify it.")
    # Declared risk/verdict inputs the gate already treats as trusted-on-assertion.
    p.add_argument("--tier", default="low", choices=gate.TIERS,
                   help="Risk tier (default low). Deflating it is a known judge-only concern.")
    p.add_argument("--verdict", default="pass", choices=gate.VERDICTS,
                   help="Declared verdict (default pass). fail/blocked lower trust; the gate decides ship/no-ship.")
    p.add_argument("--claim", default=None, help="Human description of the claim.")
    p.add_argument("--lab", default="local", help="Producing lab/org (change.producer.lab).")
    p.add_argument("--repo", default=None, help="Human description of the surface under change.")
    p.add_argument("--stdin", default=None, help="File fed to the probe's stdin (else /dev/null).")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                   help=f"Seconds before the probe is killed (0 = no limit; default {DEFAULT_TIMEOUT}).")
    # Server modes: stop on the first complete response instead of waiting out the
    # timeout on a process that correctly stays alive.
    p.add_argument("--expect-frames", type=int, default=None, metavar="N",
                   help="Server mode for NEWLINE-delimited protocols (JSON-RPC / MCP over "
                        "stdio): stop after N newline-terminated stdout frames; an "
                        "answered-then-alive process is success, not a hang. For non-newline "
                        "framing (e.g. LSP Content-Length, whose body has no trailing "
                        "newline) use --until-idle instead, or it will under-count and time out.")
    p.add_argument("--until-idle", type=float, nargs="?", const=2.0, default=None, metavar="SECS",
                   help="Server mode, framing-agnostic: stop once the probe has produced "
                        "output and then gone quiet for SECS (bare flag = 2.0). "
                        "Answered-then-idle is success. Prefer this for non-newline protocols.")
    # Differential (rung 4): two runs, one bundle. The probe argv after `--` is
    # split on a bare `:::` into S0 (baseline) and S1 (changed). The tool captures
    # both faithfully; the GATE decides the delta polarity from the bytes, so this
    # tool never asserts the delta itself.
    p.add_argument("--diff", action="store_true",
                   help="Rung-4 differential mode: split the probe on `:::` into S0 ::: S1, run "
                        "both, and emit a rung-4 bundle with one s0_capture and one s1_capture.")
    p.add_argument("--expect-delta", default="change", choices=("change", "invariance"),
                   help="Declared polarity for --diff: 'change' (S0/S1 must differ) or 'invariance' "
                        "(must match; a refactor / no-regression claim). Default change. The gate "
                        "decides pass/block from the captured bytes; this only declares intent.")
    p.add_argument("--diff-channel", default="stdout", choices=("stdout", "stderr", "both"),
                   help="Which captured channel the S0/S1 comparison uses (default stdout). Use "
                        "'both' (stdout+stderr, fixed order) for the strictest invariance check: a "
                        "change confined to a channel you did not compare is not witnessed.")
    p.add_argument("--s0-cwd", default=None, help="Working directory for the S0 (baseline) run.")
    p.add_argument("--s1-cwd", default=None, help="Working directory for the S1 (changed) run.")
    p.add_argument("--out", default="rung-out", help="Output dir for bundle.json + artifacts/ (default ./rung-out).")
    p.add_argument("--policy", default=None, help="Policy JSON (default: the bundled default policy).")
    p.add_argument("--env-clear", action="store_true",
                   help="Run the probe with a scrubbed, minimal environment (PATH, HOME, locale, TERM, TMPDIR) "
                        "instead of inheriting this process's env, so operator secrets in the env "
                        "do not leak into a capture (RUN-I1). Redaction of the captured bytes is "
                        "still an operator responsibility.")
    p.add_argument("--no-gate", action="store_true", help="Emit the bundle but do not run the gate.")
    return p.parse_args(opts)


def _scrubbed_env():
    """Minimal env for --env-clear: enough to launch and stay locale-stable,
    nothing that typically carries a secret."""
    return {k: os.environ[k] for k in ENV_CLEAR_KEEP if k in os.environ}


def _run_probe(argv, stdin_bytes, timeout, expect_frames, until_idle, env=None, cwd=None) -> dict:
    """Drive the probe on the single bounded Popen+drain path, capturing its own
    stdout/stderr/exit. Returns a dict: {stdout, stderr, returncode(int|None),
    timed_out, exited, frames, truncated, note}. Only a LAUNCH failure raises; a
    process that ran and exited nonzero / crashed / timed out is valid data (a
    probe that exits 2 can be correct behavior). With no framing flags this simply
    runs to completion. Every probe, plain or server, has its memory bounded near
    MAX_CAPTURE_BYTES during the run (the drain reads fixed-size chunks, so even a
    newline-free stream cannot buffer unbounded bytes) and its whole process group
    reaped on teardown (RUN-D1 / RUN-D2), so a runaway or orphan-spawning probe can
    neither flood RAM nor leak children."""
    return _run_probe_bounded(argv, stdin_bytes, timeout, expect_frames, until_idle, env, cwd)


def _run_probe_bounded(argv, stdin_bytes, timeout, expect_frames, until_idle, env=None, cwd=None) -> dict:
    """The single exec path. Drain both fds on threads and stop on the first of:
    the child's own exit (a plain CLI, or a server that terminates), the first N
    frames (--expect-frames), idle-after-output (--until-idle), the hard timeout,
    or the accumulated capture hitting MAX_CAPTURE_BYTES. With neither framing
    flag set, only exit / timeout / cap can fire, so this runs to completion.
    Memory is bounded inline as fixed-size chunks arrive, so a newline-free or
    long-line stream cannot flood RAM before the cap check (RUN-D1);
    start_new_session puts the
    probe in its own group so the whole tree is killed after capture (RUN-D2).
    Only the timeout branch is a hang."""
    proc = subprocess.Popen(
        argv,
        stdin=(subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, env=env, cwd=cwd,
    )
    out_buf, err_buf = bytearray(), bytearray()
    lock = threading.Lock()
    state = {"last": time.monotonic(), "frames": 0, "truncated": False}

    def drain(pipe, buf, is_stdout):
        try:
            # Read FIXED-SIZE chunks, never whole lines: readline would buffer an
            # entire line (up to the next newline or EOF) in RAM before the cap
            # check below could run, so a probe emitting a long or newline-free
            # stream could flood memory regardless of MAX_CAPTURE_BYTES (RUN-D1).
            # A chunked read bounds each step to CHUNK bytes; a "frame" is still a
            # newline, now counted by scanning each chunk. read1 (not read) returns
            # as soon as any data is available from a single underlying read, so a
            # small/slow server frame is seen promptly (keeping --until-idle and
            # --expect-frames responsive) instead of blocking for a full chunk.
            for chunk in iter(lambda: pipe.read1(CHUNK_BYTES), b""):
                with lock:
                    # Stop accumulating past the cap so memory (and the bundle)
                    # stay bounded; the drop is recorded as truncation (RUN-D1).
                    remaining = MAX_CAPTURE_BYTES - (len(out_buf) + len(err_buf))
                    if remaining <= 0:
                        state["truncated"] = True
                    else:
                        buf.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            state["truncated"] = True
                    state["last"] = time.monotonic()
                    if is_stdout:
                        state["frames"] += chunk.count(b"\n")
        except (ValueError, OSError):
            pass  # pipe closed under us when the child is killed
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    t_out = threading.Thread(target=drain, args=(proc.stdout, out_buf, True), daemon=True)
    t_err = threading.Thread(target=drain, args=(proc.stderr, err_buf, False), daemon=True)
    t_out.start()
    t_err.start()

    if stdin_bytes is not None:
        try:
            proc.stdin.write(stdin_bytes)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        try:
            proc.stdin.close()
        except OSError:
            pass

    start = time.monotonic()
    outcome = "timeout"
    while True:
        rc = proc.poll()
        with lock:
            frames, last, nbytes, truncated = (
                state["frames"], state["last"], len(out_buf) + len(err_buf), state["truncated"])
        now = time.monotonic()
        if rc is not None:
            outcome = "exited"
            break
        if truncated:  # hit the capture cap: stop, record truncation, kill it
            outcome = "capped"
            break
        if expect_frames is not None and frames >= expect_frames:
            outcome = "frames"
            break
        if until_idle is not None and nbytes > 0 and (now - last) >= until_idle:
            outcome = "idle"
            break
        if timeout and timeout > 0 and (now - start) >= timeout:
            outcome = "timeout"
            break
        time.sleep(0.02)

    if proc.poll() is None:  # answered-then-alive, idle, capped, or timed out: stop it
        _kill_group(proc)
    t_out.join(timeout=2)
    t_err.join(timeout=2)

    with lock:
        stdout, stderr, frames, truncated = (
            bytes(out_buf), bytes(err_buf), state["frames"], state["truncated"])
    notes = {
        "exited": f"exit {proc.returncode}",
        "frames": f"answered {frames} frame(s); server left running, killed after capture",
        "idle": "went idle after output; server left running, killed after capture",
        "capped": f"capture hit {MAX_CAPTURE_BYTES} bytes; truncated, server killed after capture",
        "timeout": f"timeout after {timeout}s (no complete response observed)",
    }
    return {
        "stdout": stdout, "stderr": stderr,
        "returncode": (proc.returncode if outcome == "exited" else None),
        "timed_out": (outcome == "timeout"), "exited": (outcome == "exited"),
        "frames": frames, "truncated": truncated, "note": notes[outcome],
    }


def _kill_group(proc) -> None:
    """Kill the probe's whole process group (RUN-D2). The probe is launched with
    start_new_session=True, so it leads its own group; signalling the group takes
    down any children it spawned (a server's workers), not just the leader.
    Falls back cleanly if the group is already gone."""
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        pgid = None
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if proc.poll() is not None:
            return
        try:
            if pgid is not None:
                os.killpg(pgid, sig)
            else:
                proc.send_signal(sig)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            continue


def _hash_capped(path: pathlib.Path):
    """Stream-hash up to PROVENANCE_HASH_CAP. Returns (hexdigest|None, status),
    where status distinguishes ok / too-big / unreadable so an absent hash is
    never mistaken for one that was not attempted."""
    h = hashlib.sha256()
    read = 0
    try:
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1024 * 1024)
                if not chunk:
                    break
                read += len(chunk)
                if read > PROVENANCE_HASH_CAP:
                    return None, f"exceeds-cap:{PROVENANCE_HASH_CAP}"
                h.update(chunk)
    except OSError as e:
        return None, f"unreadable:{type(e).__name__}"
    return h.hexdigest(), "ok"


def _resolve_one(arg: str, cwd=None):
    """Resolve one argv element to an existing file (directly or via PATH) and
    hash it, or None if it names no file. A relative path is resolved against
    `cwd` when given (the directory the probe actually ran in), NOT the runner's
    cwd, so a per-side --s0-cwd/--s1-cwd run hashes the file the probe truly
    executed rather than a same-named file that happens to sit in the runner's
    directory. cwd=None keeps the process-cwd resolution the single-run path has
    always used, so single-run bundles are byte-identical to before."""
    p = pathlib.Path(arg)
    if cwd is not None and not p.is_absolute():
        cand = pathlib.Path(cwd) / arg
        path = cand if (cand.exists() and cand.is_file()) else None
    else:
        path = p if (p.exists() and p.is_file()) else None
    if path is None:
        w = shutil.which(arg)
        path = pathlib.Path(w) if w else None
    if path is None:
        return None
    sha, status = _hash_capped(path)
    return {"arg": arg, "resolved": str(path), "sha256": sha, "sha256_status": status}


def _resolve_exec(argv: list[str], cwd=None) -> dict:
    """Record WHICH program actually ran. argv[0] is often an interpreter
    (`node`/`python`/`java`), so hashing it alone hides the real subject: `node
    cli.js` and `node evil.js` would look identical. So resolve/hash argv[0] AND
    every argv element that names an existing file (the subject the launcher
    ran). A target that is not a filesystem path (e.g. `python -m pkg.mod`) has no
    file to anchor, so `subjects` is empty there; that is the rung-2 test-runner
    shape and is simply not covered by the provenance anchor. Authenticity of the
    surface remains judge-only. `cwd` (the --s0-cwd/--s1-cwd the probe ran in) is
    threaded through so a relative subject is hashed where it actually ran, not
    where the runner sits; without it the anchor could record a same-named decoy."""
    launcher = _resolve_one(argv[0], cwd) or {
        "arg": argv[0], "resolved": None, "sha256": None, "sha256_status": "not-found"}
    subjects = []
    for a in argv[1:]:
        if a.startswith("-"):
            continue  # a flag, not a file
        r = _resolve_one(a, cwd)
        if r is not None:
            subjects.append(r)
    return {
        "argv0": argv[0],
        "resolved": launcher.get("resolved"),
        "sha256": launcher.get("sha256"),
        "sha256_status": launcher.get("sha256_status"),
        "subjects": subjects,  # the actual cli.js / .jar the launcher executed
    }


def _artifact(out: pathlib.Path, name: str, role: str, data: bytes) -> dict:
    (out / "artifacts").mkdir(parents=True, exist_ok=True)
    (out / "artifacts" / name).write_bytes(data)
    return {
        "id": name,
        "role": role,
        "media": "application/octet-stream",
        "uri": f"artifacts/{name}",
        "sha256": hashlib.sha256(data).hexdigest(),
        "summary": f"{len(data)} bytes captured off the probe's {role.split('_')[0]}",
    }


def _policy_path(ns, stack: contextlib.ExitStack):
    """Resolve the policy file to a real filesystem path. An explicit --policy
    wins and returns a plain path unchanged. Otherwise, when gating, materialize
    the bundled default via the SAME shared resolver gate.py uses (identical
    bundled-policy behavior), held open for the WHOLE run by `stack` so the
    launch-time pin (_pin_policy) and the post-run tamper re-read both see a live
    path. Returns None only for --no-gate with no explicit policy, where no
    default is needed. A resolution failure raises gate.GateInputError, which the
    caller turns into a fail-closed exit 2 before any probe runs."""
    if ns.policy:
        return pathlib.Path(ns.policy)
    if ns.no_gate:
        return None
    return stack.enter_context(gate.default_policy_path())


def _pin_policy(path: pathlib.Path) -> tuple[dict, str]:
    """Read, hash-pin, and parse the policy from ONE read of the bytes, so the
    hash and the parsed dict describe the exact same file contents. Returns
    (policy_dict, sha256_of_file_bytes) or raises gate.GateInputError. Called
    BEFORE the probe runs (RUN-T1): the code under test cannot swap the policy
    out from under its own gate, and the pinned sha lets a mid-run swap be
    detected rather than silently honored."""
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise gate.GateInputError(f"cannot read policy {path}: {e}")
    if len(raw) > gate.MAX_INPUT_BYTES:
        raise gate.GateInputError(f"policy {path} exceeds {gate.MAX_INPUT_BYTES} bytes")
    sha = hashlib.sha256(raw).hexdigest()
    try:
        policy = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as e:
        raise gate.GateInputError(f"cannot parse policy {path}: {type(e).__name__}: {e}")
    return policy, sha


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    opts_argv, probe = _split_probe(argv)
    ns = _parse(opts_argv)

    if not probe:
        print("rung run: no probe given (expected `-- <argv> ...`)", file=sys.stderr)
        return gate.EXIT_USAGE
    if ns.diff:
        if ns.rung != 4:
            print(f"rung run: --diff is the rung-4 differential mode; use --rung 4 "
                  f"(got --rung {ns.rung})", file=sys.stderr)
            return gate.EXIT_USAGE
    elif ns.rung == 4:
        print("rung run: refusing --rung 4 without --diff: rung 4 needs an S0/S1 differential "
              "(two runs); a single-run witness cannot earn it. Re-run with --diff and "
              "`-- <S0 argv> ::: <S1 argv>`.", file=sys.stderr)
        return gate.EXIT_USAGE
    elif not (0 <= ns.rung <= 3):
        print(f"rung run: refusing --rung {ns.rung}: rung must be 0..3 (or 4 with --diff)",
              file=sys.stderr)
        return gate.EXIT_USAGE
    if not ns.diff:
        # Differential-only flags silently dropped on a single run would discard
        # the operator's differential intent; reject them instead (fail closed).
        stray = [f for f, set_ in (("--expect-delta", ns.expect_delta != "change"),
                                   ("--diff-channel", ns.diff_channel != "stdout"),
                                   ("--s0-cwd", ns.s0_cwd is not None),
                                   ("--s1-cwd", ns.s1_cwd is not None)) if set_]
        if stray:
            print(f"rung run: {', '.join(stray)} only apply with --diff (the rung-4 "
                  f"differential mode)", file=sys.stderr)
            return gate.EXIT_USAGE
    if ns.expect_frames is not None and ns.expect_frames < 1:
        print("rung run: --expect-frames must be >= 1", file=sys.stderr)
        return gate.EXIT_USAGE
    if ns.until_idle is not None and ns.until_idle <= 0:
        print("rung run: --until-idle must be > 0", file=sys.stderr)
        return gate.EXIT_USAGE

    # Read the stdin file BEFORE the exec, so a missing --stdin file is reported
    # as an input error, not misattributed to a failed launch (finding #4).
    stdin_bytes = None
    if ns.stdin is not None:
        try:
            stdin_bytes = pathlib.Path(ns.stdin).read_bytes()
        except OSError as e:
            print(f"rung run: cannot read --stdin file {ns.stdin!r}: {e}", file=sys.stderr)
            return gate.EXIT_USAGE

    # Load, parse, AND hash-pin the policy BEFORE the probe executes (RUN-T1), so
    # the code being judged cannot swap the policy out from under its own gate.
    # A defect here fails closed to usage, before any code is run. The ExitStack
    # holds the bundled-default-policy materialization (importlib.resources
    # as_file) open for the WHOLE run, so the launch-time pin AND the post-run
    # tamper re-read in _finish both see a live path; an explicit --policy needs
    # no materialization and is unaffected. The stack spans every return below
    # (including the --diff early return) so the path is never torn down mid-run.
    with contextlib.ExitStack() as policy_stack:
        policy = policy_sha = None
        try:
            policy_file = _policy_path(ns, policy_stack)
        except gate.GateInputError as e:
            print(f"rung run: {e}", file=sys.stderr)
            return gate.EXIT_USAGE
        if not ns.no_gate:
            try:
                policy, policy_sha = _pin_policy(policy_file)
            except gate.GateInputError as e:
                print(f"rung run: {e}", file=sys.stderr)
                return gate.EXIT_USAGE

        # --- witness the execution ---------------------------------------------
        env = _scrubbed_env() if ns.env_clear else None
        if ns.diff:
            return _run_diff(ns, probe, stdin_bytes, env, policy, policy_sha, policy_file)
        try:
            res = _run_probe(probe, stdin_bytes, ns.timeout, ns.expect_frames, ns.until_idle, env)
        except (FileNotFoundError, PermissionError, NotADirectoryError, OSError) as e:
            # The process never launched: nothing was witnessed, so nothing is
            # emitted. This is the tool's only mechanical refusal on the run itself.
            print(f"rung run: probe did not launch ({e}); no bundle emitted", file=sys.stderr)
            return gate.EXIT_USAGE

        out_bytes, err_bytes = res["stdout"], res["stderr"]
        exit_note, timed_out = res["note"], res["timed_out"]

        # A witnessed non-termination is handled FIRST, before the empty-output
        # refusal, so a SILENT hang is diagnosed as a hang rather than "nothing
        # observed" (N1). It forces verdict=blocked, which the gate blocks
        # unconditionally (no allow_dismiss_gaps escape), so a witnessed hang cannot
        # go green under a permissive policy (N2); the blocker gap stays for audit.
        forced_verdict = None
        gaps = []
        if timed_out:
            forced_verdict = "blocked"
            gaps.append({
                "id": "timeout",
                "severity": "blocker",
                "desc": f"probe did not terminate; {exit_note}. Captures are partial "
                        f"and the run did not complete.",
                "dismissed": False,
            })
        elif ns.rung >= 3 and (len(out_bytes) + len(err_bytes)) == 0:
            # Observing nothing (from a process that RAN TO COMPLETION) is not
            # observation: refuse rather than mint a pass (finding #1).
            print(f"rung run: refusing rung {ns.rung}: the probe ran to completion but produced "
                  f"zero bytes on stdout/stderr; nothing was observed", file=sys.stderr)
            return gate.EXIT_USAGE

        # A capture truncated at the cap is RECORDED, not silent (RUN-D1): a blocker
        # gap so the safe default is to block (the gate blocks it unless a policy
        # explicitly allows dismissing blocker gaps), mirroring the gate's own
        # MAX_ARTIFACT_BYTES rule. Independent of the timeout branch above; a run
        # can both hit the cap and time out.
        if res.get("truncated"):
            gaps.append({
                "id": "capture-truncated",
                "severity": "blocker",
                "desc": f"probe output exceeded the {MAX_CAPTURE_BYTES}-byte capture cap; "
                        f"the capture is truncated and does not contain every byte the probe emitted.",
                "dismissed": False,
            })

        out = pathlib.Path(ns.out)
        artifacts = [
            _artifact(out, "stdout", "stdout_capture", out_bytes),
            _artifact(out, "stderr", "stderr_capture", err_bytes),
        ]

        executed = _resolve_exec(probe)
        executed["exit"] = res["returncode"]  # int, or null if we killed it / it timed out

        verdict = forced_verdict or ns.verdict
        probe_str = " ".join(probe)
        bundle = {
            "schema": gate.SCHEMA_MAJOR,
            "change": {
                "repo": ns.repo or f"driven via rung run: {probe[0]}",
                "s0": "n/a (single-run witness, no baseline)",
                "s1": f"working tree / as-invoked: {probe_str}",
                "producer": {"agent": "rung-run", "lab": ns.lab},
            },
            "claims": [{
                "id": "c1",
                "claim": ns.claim or f"Drove the {ns.surface} surface: {probe_str}",
                "risk_tier": ns.tier,
                "surface": {
                    "kind": ns.surface,
                    "how_reached": f"rung run direct-exec; {exit_note}",
                    # WHICH program actually ran (finding #3): makes a non-subject
                    # drive visible; authenticity of the surface remains judge-only.
                    "executed": executed,
                },
                "rung": ns.rung,
                # A self-run is BY DEFINITION author context; cross-lab is a judge's
                # job, never something the producer's own runner can assert.
                "context": "author",
                "verdict": verdict,
                "how_established": (
                    f"rung run executed `{probe_str}` directly (no shell); "
                    f"captured its own stdout/stderr; {exit_note}. "
                    f"The rung and surface are declared, not witnessed by this tool."
                ),
                "artifacts": artifacts,
            }],
            "gaps": gaps,
        }
        return _finish(bundle, out, policy, policy_sha, policy_file, ns.no_gate, exit_note)


def _finish(bundle: dict, out: pathlib.Path, policy, policy_sha, policy_file,
            no_gate: bool, note: str) -> int:
    """Shared tail for both the single-run and --diff paths: stamp the pinned
    policy, write the bundle + captures, then (unless --no-gate) re-verify the
    policy against the launch-time sha and run the gate, exiting with ITS
    verdict, never the probe's exit code."""
    # Stamp the pinned policy identity into the bundle so a verdict is
    # attributable to the exact policy bytes that were in force at launch
    # (RUN-T1). The gate ignores unknown top-level fields, so this is inert to it.
    if policy_sha is not None:
        bundle["policy_pin"] = {"path": str(policy_file), "sha256": policy_sha}

    out.mkdir(parents=True, exist_ok=True)
    (out / "bundle.json").write_text(json.dumps(bundle, indent=2, ensure_ascii=False))
    print(f"rung run: wrote {out / 'bundle.json'} ({note})", file=sys.stderr)
    print("rung run: captures may contain secrets; redact before publishing (operator responsibility)",
          file=sys.stderr)

    if no_gate:
        return gate.EXIT_PASS

    # --- run the gate over what we witnessed; exit with ITS verdict ------------
    # Re-verify the policy file against the sha pinned at launch (RUN-T1). If the
    # bytes changed during the run, the probe (or anything else) may have tried to
    # weaken the gate mid-flight: BLOCK on the tamper rather than honor the new
    # policy. We gate with the PINNED dict regardless, never a re-read of a file
    # that may now be swapped.
    try:
        now_raw = policy_file.read_bytes()
        now_sha = hashlib.sha256(now_raw).hexdigest()
    except OSError:
        now_sha = None
    if now_sha != policy_sha:
        result = gate._result(
            "block",
            [f"policy file changed during the run (pinned {policy_sha[:12]}…, "
             f"now {(now_sha[:12] + '…') if now_sha else 'unreadable'}); refusing to honor a "
             f"mid-run policy swap"],
            policy, gate.SCHEMA_MAJOR)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return result["exit_code"]
    try:
        result = gate.gate(bundle, policy, out.resolve())
    except gate.PolicyError as e:
        result = gate._result("block", [f"policy integrity error: {e}"], policy, gate.SCHEMA_MAJOR)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    # The wrapper's exit reflects the GATE verdict, never the probe's exit code.
    return result["exit_code"]


def _channel_real(res: dict, channel: str) -> bytes:
    """The bytes actually produced on the compared channel (no framing), used to
    decide whether anything was observed to diff."""
    if channel == "stdout":
        return res["stdout"]
    if channel == "stderr":
        return res["stderr"]
    return res["stdout"] + res["stderr"]


def _channel_artifact(res: dict, channel: str) -> bytes:
    """The bytes written as the s0_capture / s1_capture artifact. For 'both',
    stdout and stderr are joined in a FIXED order with a constant delimiter so the
    comparison is deterministic. The delimiter is in-band: a probe that emits the
    delimiter bytes on stdout could shift the apparent channel boundary, so 'both'
    resists an accidental cross-channel match but is not a hard guarantee against a
    probe that controls its own bytes (author-context; surface authenticity stays
    judge-only)."""
    if channel == "both":
        return res["stdout"] + b"\n--- rung-diff stderr ---\n" + res["stderr"]
    return _channel_real(res, channel)


def _run_diff(ns, probe, stdin_bytes, env, policy, policy_sha, policy_file) -> int:
    """Rung-4 differential: run S0 then S1, capture each off its own fds, and emit
    a rung-4 bundle with exactly one s0_capture and one s1_capture. This tool does
    NOT decide the delta: it captures both sides faithfully and lets the gate rule
    change/invariance from the bytes. Both sides reuse the single bounded exec
    path, so the memory-cap and process-group-reap guarantees carry over per run."""
    s0_argv, s1_argv = _split_sides(probe)
    if s1_argv is None:
        print("rung run: --diff needs two probe argvs separated by a bare ':::' "
              "(`-- <S0 argv> ::: <S1 argv>`)", file=sys.stderr)
        return gate.EXIT_USAGE
    if not s0_argv or not s1_argv:
        print("rung run: --diff got an empty side; need `-- <S0 argv> ::: <S1 argv>`",
              file=sys.stderr)
        return gate.EXIT_USAGE
    for flag, cwd in (("--s0-cwd", ns.s0_cwd), ("--s1-cwd", ns.s1_cwd)):
        if cwd is not None and not pathlib.Path(cwd).is_dir():
            print(f"rung run: {flag} {cwd!r} is not a directory", file=sys.stderr)
            return gate.EXIT_USAGE

    # Run each side, then RE-RUN it once to confirm the compared channel is
    # byte-stable. Byte-level polarity only proxies the claimed change when a
    # side's output is deterministic: a timestamp / PID / hash-seed would make
    # identical code read as a change, and an invariant refactor carrying
    # such noise would read as a delta. So a side whose two runs disagree on the
    # compared channel is recorded as a blocker gap rather than fed to the gate as
    # a trustworthy delta. This is FINDINGS.md's rung-4 normalization concern made
    # into a recorded gap instead of a silent normalization. A side that HUNG is
    # already a block, so its stability is moot and the re-run is skipped.
    sides = []  # (label, argv, cwd, res, stable)
    for label, argv, cwd in (("s0", s0_argv, ns.s0_cwd), ("s1", s1_argv, ns.s1_cwd)):
        try:
            res = _run_probe(argv, stdin_bytes, ns.timeout, ns.expect_frames, ns.until_idle, env, cwd)
        except (FileNotFoundError, PermissionError, NotADirectoryError, OSError) as e:
            print(f"rung run: {label} probe did not launch ({e}); no bundle emitted", file=sys.stderr)
            return gate.EXIT_USAGE
        stable = True
        if not res["timed_out"]:
            try:
                res2 = _run_probe(argv, stdin_bytes, ns.timeout, ns.expect_frames, ns.until_idle, env, cwd)
            except (FileNotFoundError, PermissionError, NotADirectoryError, OSError):
                res2 = None  # launched once but not again: not reproducible, treat as unstable
            stable = (res2 is not None and not res2["timed_out"]
                      and _channel_artifact(res2, ns.diff_channel) == _channel_artifact(res, ns.diff_channel))
        sides.append((label, argv, cwd, res, stable))

    # Per-side timeout / instability / truncation / empty, mirroring the single-run
    # contract. A timeout or a non-deterministic side forces verdict=blocked (the
    # gate blocks it unconditionally, exit 30); a truncated capture is a blocker
    # gap. An empty compared channel on a completed, stable run is a "cannot
    # evaluate" refusal (exit 2) -- but a WITNESSED BLOCK outranks it: if any side
    # already forced a block we still emit the blocked bundle rather than downgrade
    # a hang / instability to a usage refusal. None of this asserts the delta; the
    # gate still rules polarity from the bytes.
    gaps = []
    forced_verdict = None
    empties = []
    for label, argv, cwd, res, stable in sides:
        if res["timed_out"]:
            forced_verdict = "blocked"
            gaps.append({
                "id": "timeout", "severity": "blocker",
                "desc": f"{label} probe did not terminate; {res['note']}. Captures are partial "
                        f"and the run did not complete.",
                "dismissed": False})
            continue  # a hang: stability and emptiness are moot, it already blocks
        if not stable:
            forced_verdict = "blocked"
            gaps.append({
                "id": "nondeterministic-output", "severity": "blocker",
                "desc": f"{label} produced different bytes on the compared channel "
                        f"({ns.diff_channel}) across two identical runs; its output is not "
                        f"deterministic, so a byte-level S0/S1 delta cannot be trusted to reflect "
                        f"the claimed change. Pin the environment (or compare a stable channel) and "
                        f"re-run.",
                "dismissed": False})
        if res.get("truncated"):
            gaps.append({
                "id": "capture-truncated", "severity": "blocker",
                "desc": f"{label} probe output exceeded the {MAX_CAPTURE_BYTES}-byte capture cap; the "
                        f"capture is truncated and does not contain every byte {label} emitted.",
                "dismissed": False})
        if len(_channel_real(res, ns.diff_channel)) == 0:
            empties.append(label)
    if empties and forced_verdict is None:
        print(f"rung run: refusing rung 4: {', '.join(empties)} ran to completion but produced zero "
              f"bytes on the compared channel ({ns.diff_channel}); nothing was observed to diff. Try "
              f"--diff-channel both, or the channel the surface actually writes to.",
              file=sys.stderr)
        return gate.EXIT_USAGE

    out = pathlib.Path(ns.out)
    s0_res, s1_res = sides[0][3], sides[1][3]
    s0_bytes = _channel_artifact(s0_res, ns.diff_channel)
    s1_bytes = _channel_artifact(s1_res, ns.diff_channel)
    art_s0 = _artifact(out, "s0_capture", "s0_capture", s0_bytes)
    art_s1 = _artifact(out, "s1_capture", "s1_capture", s1_bytes)

    executed = {
        "s0": {**_resolve_exec(s0_argv, ns.s0_cwd), "exit": s0_res["returncode"], "cwd": ns.s0_cwd},
        "s1": {**_resolve_exec(s1_argv, ns.s1_cwd), "exit": s1_res["returncode"], "cwd": ns.s1_cwd},
    }
    s0_str, s1_str = " ".join(s0_argv), " ".join(s1_argv)
    exit_note = f"s0 {s0_res['note']}; s1 {s1_res['note']}"
    verdict = forced_verdict or ns.verdict
    bundle = {
        "schema": gate.SCHEMA_MAJOR,
        "change": {
            "repo": ns.repo or f"driven via rung run --diff: {s0_argv[0]}",
            "s0": (f"cwd={ns.s0_cwd}: " if ns.s0_cwd else "") + s0_str,
            "s1": (f"cwd={ns.s1_cwd}: " if ns.s1_cwd else "") + s1_str,
            "producer": {"agent": "rung-run", "lab": ns.lab},
        },
        "claims": [{
            "id": "c1",
            "claim": ns.claim or (f"Differential over the {ns.surface} surface "
                                  f"({ns.expect_delta}): S0 `{s0_str}` vs S1 `{s1_str}`"),
            "risk_tier": ns.tier,
            "surface": {
                "kind": ns.surface,
                "how_reached": f"rung run --diff direct-exec of two runs; {exit_note}",
                "executed": executed,
            },
            "rung": 4,
            # A self-run is BY DEFINITION author context, differential or not;
            # cross-lab is a judge's job, never the producer's own runner.
            "context": "author",
            "expected_delta": ns.expect_delta,
            "verdict": verdict,
            "how_established": (
                f"rung run --diff executed S0 `{s0_str}` then S1 `{s1_str}` directly (no shell); "
                f"captured each run's {ns.diff_channel}; {exit_note}. The rung, surface, and "
                f"expected_delta are declared; the delta polarity is decided by the gate from the "
                f"captured bytes, not asserted by this tool."
            ),
            "differential": {
                "channel": ns.diff_channel,
                "expected_delta": ns.expect_delta,
                # s0_observed / s1_observed ARE the capture hashes, so the gate's
                # "differential text contradicts capture bytes" check can never
                # spuriously fire (declared_same == bytes_same by construction),
                # while the polarity verdict is still the gate's, from the bytes.
                "s0_observed": art_s0["sha256"],
                "s1_observed": art_s1["sha256"],
                "s0": {"argv": s0_argv, "cwd": ns.s0_cwd, "exit": s0_res["returncode"],
                       "bytes": len(s0_bytes)},
                "s1": {"argv": s1_argv, "cwd": ns.s1_cwd, "exit": s1_res["returncode"],
                       "bytes": len(s1_bytes)},
                "note": ("faithful record of two runs; the gate decides change/invariance from the "
                         "s0_capture/s1_capture bytes, this block does not assert the delta"),
            },
            "artifacts": [art_s0, art_s1],
        }],
        "gaps": gaps,
    }
    return _finish(bundle, out, policy, policy_sha, policy_file, ns.no_gate, exit_note)


def _split_sides(probe: list[str]) -> tuple[list[str], list[str] | None]:
    """Split the --diff probe argv on the FIRST bare ':::' into (s0_argv,
    s1_argv). Returns (probe, None) when no separator is present so the caller
    can report the usage error."""
    if ":::" not in probe:
        return probe, None
    i = probe.index(":::")
    return probe[:i], probe[i + 1:]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
