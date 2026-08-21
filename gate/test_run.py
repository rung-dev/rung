#!/usr/bin/env python3
"""Conformance tests for `rung run`: witness -> emit -> gate -> exit.

These do NOT re-drive the real subject binaries (they are not in this repo, and
cannot be under the anonymization rules). They stand up tiny in-repo fixture
surfaces to prove the wrapper's contract:
  * it emits a gate-passing bundle when a real surface is DECLARED and driven;
  * its exit code is the GATE's verdict, never the probe's exit code;
  * it never launders unwitnessed activity up a rung (bare run emits nothing;
    a declared rung 0 stays unobserved);
  * it refuses a run that never launched, and refuses a differential without
    --diff (a differential needs two runs).
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
# Drive the packaged witness as `python -m rung.run` with src/ on PYTHONPATH; a
# bare `python src/rung/run.py` could not satisfy run.py's `from . import gate`
# nor the default-policy resolver, both of which need the `rung` package.
RUN_ARGV = [sys.executable, "-m", "rung.run"]


def _env_with_src(extra: dict = None) -> dict:
    e = dict(os.environ)
    e["PYTHONPATH"] = str(SRC) + os.pathsep + e.get("PYTHONPATH", "")
    if extra:
        e.update(extra)
    return e


class RunConformance(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    # -- helpers ------------------------------------------------------------
    def fixture(self, name: str, body: str) -> Path:
        p = self.tmp / name
        p.write_text(body)
        return p

    def run_it(self, *args: str, env: dict = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            RUN_ARGV + list(args),
            cwd=self.tmp, capture_output=True, text=True, env=_env_with_src(env),
        )

    def bundle(self) -> dict:
        return json.loads((self.tmp / ".rung" / "output" / "bundle.json").read_text())

    def bundle_exists(self) -> bool:
        return (self.tmp / ".rung" / "output" / "bundle.json").exists()

    # A CLI fixture that mimics the ctl case: prints an error to stderr and
    # exits 2. Exit 2 is CORRECT, pass-worthy behavior, not a failure.
    def cli_fixture(self) -> Path:
        return self.fixture("cli_fix.py",
                            "import sys\n"
                            "sys.stderr.write('error: --mode-a and --mode-b are mutually exclusive\\n')\n"
                            "sys.exit(2)\n")

    # -- tests --------------------------------------------------------------
    def test_cli_surface_declared_passes(self):
        # An author self-run (context author) clears LOW tier under the default
        # policy; medium+ would demand an independent review the runner can't mint.
        fix = self.cli_fixture()
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        b = self.bundle()
        c = b["claims"][0]
        self.assertEqual(c["rung"], 1)
        self.assertEqual(c["method"], "single")
        self.assertEqual(c["context"], "author")
        self.assertEqual(c["surface"]["kind"], "cli")
        # Both captures present and hash-matching (the gate re-verified them,
        # since it passed at rung 1 which requires >=1 resolvable artifact).
        roles = {a["role"] for a in c["artifacts"]}
        self.assertEqual(roles, {"stdout_capture", "stderr_capture"})

    def test_exit_code_is_gate_verdict_not_probe(self):
        # The probe exits 2, but the gate PASSES the bundle, so rung run exits 0.
        fix = self.cli_fixture()
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 0, "probe exit 2 must not become the wrapper's exit code")

    def test_bare_run_emits_nothing(self):
        # No --rung/--surface: the tool refuses to guess, so no bundle exists
        # and it can never satisfy an observed-rung policy. This is the headline
        # anti-laundering invariant.
        fix = self.fixture("noop.py", "print('ok')\n")
        r = self.run_it("--", sys.executable, str(fix))
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(self.bundle_exists())

    def test_declared_rung0_stays_unobserved(self):
        # v2 anti-laundering: rung 0 means "not a runtime observation of the real
        # surface". Declared at rung 0, the default floor (min_rung >= 1) BLOCKS
        # it. The tool records rung 0; it does not launder an un-observed check up
        # into an observation.
        fix = self.fixture("tests.py", "print('3 passed')\n")
        r = self.run_it("--rung", "0", "--surface", "ci", "--tier", "low",
                        "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        self.assertEqual(self.bundle()["claims"][0]["rung"], 0)

    def test_launch_failure_refuses(self):
        r = self.run_it("--rung", "1", "--surface", "cli",
                        "--", str(self.tmp / "does-not-exist-xyz"))
        self.assertEqual(r.returncode, 2)
        self.assertFalse(self.bundle_exists())

    def test_method_differential_without_diff_refused(self):
        # A differential cannot come from one run: --method differential without
        # --diff is refused (no bundle), pointing the operator at --diff.
        fix = self.cli_fixture()
        r = self.run_it("--rung", "1", "--method", "differential", "--surface", "cli",
                        "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 2)
        self.assertFalse(self.bundle_exists())
        self.assertIn("differential", (r.stdout + r.stderr).lower())
        self.assertIn("--diff", r.stdout + r.stderr)

    # --- producer.model (--model) -----------------------------------------
    # --model records WHICH model produced the change, verbatim, into
    # change.producer.model. It is optional and has no default: without it the
    # producer keeps its {agent, lab} shape (no model key, never null).
    def test_model_records_producer_model_single(self):
        fix = self.cli_fixture()
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--model", "some-model-v2", "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.bundle()["change"]["producer"]["model"], "some-model-v2")

    def test_model_records_producer_model_diff(self):
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "change",
                        "--model", "some-model-v2",
                        "--", *self._pyc("print('A')"), ":::", *self._pyc("print('B')"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.bundle()["change"]["producer"]["model"], "some-model-v2")

    def test_no_model_leaves_producer_shape_unchanged(self):
        fix = self.cli_fixture()
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        producer = self.bundle()["change"]["producer"]
        self.assertNotIn("model", producer)
        self.assertEqual(producer, {"agent": "rung-run", "lab": "local"})

    # --- differential (--diff), at rung 1 ----------------------------------
    # The runner captures both sides faithfully and lets the GATE rule the delta
    # polarity from the bytes; it never asserts change/invariance itself.
    def _pyc(self, code: str) -> list:
        return [sys.executable, "-c", code]

    def test_diff_change_passes(self):
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "change",
                        "--", *self._pyc("print('A')"), ":::", *self._pyc("print('B')"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        c = self.bundle()["claims"][0]
        self.assertEqual(c["rung"], 1)
        self.assertEqual(c["method"], "differential")
        self.assertEqual(c["context"], "author")
        self.assertEqual(c["expected_delta"], "change")
        self.assertEqual(sorted(a["role"] for a in c["artifacts"]),
                         ["s0_capture", "s1_capture"])
        # s0_observed/s1_observed are the capture hashes, so the gate's
        # contradiction check cannot spuriously fire.
        d = c["differential"]
        self.assertNotEqual(d["s0_observed"], d["s1_observed"])

    def test_diff_invariance_passes_on_identical(self):
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "invariance",
                        "--", *self._pyc("print('SAME')"), ":::", *self._pyc("print('SAME')"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.bundle()["claims"][0]["expected_delta"], "invariance")

    def test_diff_change_blocks_on_identical_bytes(self):
        # Two byte-identical captures cannot be minted into a change; the gate
        # blocks on the missing delta (exit 30).
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "change",
                        "--", *self._pyc("print('SAME')"), ":::", *self._pyc("print('SAME')"))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)

    def test_diff_invariance_blocks_on_delta(self):
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "invariance",
                        "--", *self._pyc("print('A')"), ":::", *self._pyc("print('B')"))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)

    def test_diff_requires_rung1(self):
        # --diff is the differential method at rung 1 (an observation); any other
        # rung is refused.
        r = self.run_it("--rung", "0", "--surface", "cli", "--diff",
                        "--", *self._pyc("print('a')"), ":::", *self._pyc("print('b')"))
        self.assertEqual(r.returncode, 2)
        self.assertFalse(self.bundle_exists())

    def test_diff_missing_separator_refused(self):
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff",
                        "--", *self._pyc("print('a')"))
        self.assertEqual(r.returncode, 2)
        self.assertFalse(self.bundle_exists())
        self.assertIn(":::", r.stderr)

    def test_diff_channel_selects_compared_bytes(self):
        # Identical stdout, differing stderr: channel stdout reads invariance,
        # channel stderr reads change. Proves the channel actually routes.
        s0 = self._pyc("import sys; print('OUT'); print('e0', file=sys.stderr)")
        s1 = self._pyc("import sys; print('OUT'); print('e1', file=sys.stderr)")
        r_inv = self.run_it("--rung", "1", "--surface", "cli", "--diff",
                            "--expect-delta", "invariance", "--diff-channel", "stdout",
                            "--out", "o_inv", "--", *s0, ":::", *s1)
        self.assertEqual(r_inv.returncode, 0, r_inv.stdout + r_inv.stderr)
        r_chg = self.run_it("--rung", "1", "--surface", "cli", "--diff",
                            "--expect-delta", "change", "--diff-channel", "stderr",
                            "--out", "o_chg", "--", *s0, ":::", *s1)
        self.assertEqual(r_chg.returncode, 0, r_chg.stdout + r_chg.stderr)

    def test_diff_empty_compared_channel_refused(self):
        # A side that writes only stderr offers nothing to diff on stdout.
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--diff-channel", "stdout",
                        "--", *self._pyc("import sys; print('err', file=sys.stderr)"),
                        ":::", *self._pyc("print('B')"))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(self.bundle_exists())
        self.assertIn("compared channel", r.stderr)

    def test_diff_per_side_cwd(self):
        # Same argv, two cwds: the before/after-a-change case. The files differ,
        # so a change claim passes.
        (self.tmp / "da").mkdir()
        (self.tmp / "da" / "f.txt").write_text("in-a\n")
        (self.tmp / "db").mkdir()
        (self.tmp / "db" / "f.txt").write_text("in-b\n")
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "change",
                        "--s0-cwd", str(self.tmp / "da"), "--s1-cwd", str(self.tmp / "db"),
                        "--", "cat", "f.txt", ":::", "cat", "f.txt")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_diff_timeout_blocks(self):
        # One side hangs: the timeout blocker gap forces a block even though the
        # completed side differs (a change claim would otherwise pass).
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--timeout", "1",
                        "--", *self._pyc("print('A')"),
                        ":::", *self._pyc("import time; print('B'); time.sleep(30)"))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        b = self.bundle()
        self.assertTrue(any(g["id"] == "timeout" and g["severity"] == "blocker"
                            for g in b.get("gaps", [])))
        self.assertEqual(b["claims"][0]["verdict"], "blocked")

    def test_diff_cwd_provenance_hashes_side_file(self):
        # Provenance regression: with --s0-cwd/--s1-cwd, the subject hash must be
        # of the file the probe ACTUALLY ran (resolved against the side's cwd),
        # not a same-named decoy sitting in the runner's cwd. `cat f.txt` names a
        # relative subject; if cwd is dropped, `f.txt` resolves to the decoy.
        import hashlib
        (self.tmp / "f.txt").write_text("DECOY\n")  # decoy in the runner's cwd
        (self.tmp / "da").mkdir()
        (self.tmp / "da" / "f.txt").write_text("REAL-A\n")
        (self.tmp / "db").mkdir()
        (self.tmp / "db" / "f.txt").write_text("REAL-B\n")
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "change",
                        "--s0-cwd", str(self.tmp / "da"), "--s1-cwd", str(self.tmp / "db"),
                        "--", "cat", "f.txt", ":::", "cat", "f.txt")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        ex = self.bundle()["claims"][0]["surface"]["executed"]
        decoy_sha = hashlib.sha256(b"DECOY\n").hexdigest()
        want_a = hashlib.sha256(b"REAL-A\n").hexdigest()
        want_b = hashlib.sha256(b"REAL-B\n").hexdigest()
        s0_sub = next(s for s in ex["s0"]["subjects"] if s["arg"] == "f.txt")
        s1_sub = next(s for s in ex["s1"]["subjects"] if s["arg"] == "f.txt")
        self.assertEqual(s0_sub["sha256"], want_a)
        self.assertEqual(s1_sub["sha256"], want_b)
        self.assertNotEqual(s0_sub["sha256"], decoy_sha)
        self.assertTrue(s0_sub["resolved"].endswith("da/f.txt"), s0_sub["resolved"])

    def test_diff_nondeterministic_side_blocks(self):
        # A byte-level delta only proxies the claimed change when a side is
        # deterministic. Two identical runs of a timestamped probe differ, so the
        # side is not self-stable: the runner records a nondeterministic-output
        # blocker gap and blocks (exit 30) instead of minting a spurious change.
        noisy = self._pyc("import time; print(time.time_ns())")
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "change",
                        "--", *noisy, ":::", *noisy)
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        b = self.bundle()
        self.assertTrue(any(g["id"] == "nondeterministic-output" and g["severity"] == "blocker"
                            for g in b.get("gaps", [])), b.get("gaps"))
        self.assertEqual(b["claims"][0]["verdict"], "blocked")

    def test_diff_empty_side_refused(self):
        # A bare ':::' with nothing before it is an empty S0 side: refuse, no bundle.
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff",
                        "--", ":::", *self._pyc("print('B')"))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(self.bundle_exists())
        self.assertIn("empty side", r.stderr)

    def test_diff_nondir_cwd_refused(self):
        # --s0-cwd must name a directory; a file (or missing path) is refused.
        notdir = self.fixture("afile", "x\n")
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--s0-cwd", str(notdir),
                        "--", *self._pyc("print('A')"), ":::", *self._pyc("print('B')"))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(self.bundle_exists())
        self.assertIn("not a directory", r.stderr)

    def test_diff_channel_both_catches_stderr_change(self):
        # --diff-channel both compares stdout+stderr, so a change confined to
        # stderr breaks an invariance claim that a stdout-only compare would miss.
        s0 = self._pyc("import sys; print('OUT'); print('e0', file=sys.stderr)")
        s1 = self._pyc("import sys; print('OUT'); print('e1', file=sys.stderr)")
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff",
                        "--expect-delta", "invariance", "--diff-channel", "both",
                        "--", *s0, ":::", *s1)
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)

    def test_diff_flags_require_diff(self):
        # The differential-only flags are rejected (not silently dropped) on a
        # single run, so an operator who forgets --diff does not get their intent
        # discarded.
        r = self.run_it("--rung", "1", "--surface", "cli", "--s0-cwd", str(self.tmp),
                        "--", *self._pyc("print('A')"))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(self.bundle_exists())
        self.assertIn("--diff", r.stderr)

    def test_diff_timeout_outranks_empty_channel(self):
        # Exit-code priority: one side hangs (a witnessed block) while the other
        # completes with an empty compared channel (which alone would refuse, exit
        # 2). The block outranks the refusal, so a blocked bundle is emitted (30),
        # not a usage refusal that would hide the hang.
        s0 = self._pyc("import sys; print('err', file=sys.stderr)")  # empty stdout
        s1 = self._pyc("import time; print('B'); time.sleep(30)")    # hangs
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--diff-channel", "stdout",
                        "--timeout", "1", "--", *s0, ":::", *s1)
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        self.assertTrue(self.bundle_exists())
        b = self.bundle()
        self.assertTrue(any(g["id"] == "timeout" and g["severity"] == "blocker"
                            for g in b.get("gaps", [])))
        self.assertEqual(b["claims"][0]["verdict"], "blocked")

    def test_server_surface_with_stdin(self):
        # A stdio server: reads a handshake on stdin, emits a JSON frame on
        # stdout. rung run feeds --stdin directly (no shell pipe), preserving
        # fd provenance of the captured frame.
        srv = self.fixture("server_fix.py",
                           "import sys\n"
                           "sys.stdin.readline()\n"
                           "sys.stdout.write('{\"jsonrpc\":\"2.0\",\"result\":{}}\\n')\n")
        handshake = self.fixture("hs.json", '{"jsonrpc":"2.0","method":"initialize"}\n')
        r = self.run_it("--rung", "1", "--surface", "server", "--tier", "low",
                        "--stdin", str(handshake), "--", sys.executable, str(srv))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        stdout_art = next(a for a in self.bundle()["claims"][0]["artifacts"]
                          if a["role"] == "stdout_capture")
        captured = (self.tmp / ".rung" / "output" / stdout_art["uri"]).read_text()
        self.assertIn("jsonrpc", captured)

    def test_empty_output_refused_at_rung1(self):
        # Finding #1: observing nothing is not observation. A rung-1 (observed)
        # claim over a silent probe must not mint a pass.
        fix = self.fixture("silent.py", "pass\n")
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(self.bundle_exists())
        self.assertIn("nothing was observed", r.stderr)

    def test_timeout_blocks_via_gap(self):
        # Finding #2: a hung probe is not a pass. It emits SOME bytes (so it is
        # past the empty-output refusal), then hangs; the timeout becomes a
        # blocker gap and the gate blocks.
        fix = self.fixture("hang.py",
                           "import sys, time\n"
                           "sys.stdout.write('starting\\n'); sys.stdout.flush()\n"
                           "time.sleep(30)\n")
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--timeout", "1", "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        gaps = self.bundle().get("gaps", [])
        self.assertTrue(any(g["severity"] == "blocker" and g["id"] == "timeout" for g in gaps))

    def test_default_path_timeout_reaps_process_group(self):
        # On the DEFAULT (plain) cli path, not just the server path: a
        # probe that spawns a grandchild and then hangs must have its WHOLE
        # process group reaped on timeout, not just the leader. The grandchild is
        # armed to write a sentinel well after the timeout; a reaped group means
        # the sentinel never appears. (SIGKILL to the leader alone does not
        # cascade to the group, so the old subprocess.run path leaked here.)
        sentinel = self.tmp / "gc_sentinel.txt"
        gc_code = "import time; time.sleep(5); open({!r}, 'w').write('leaked')".format(str(sentinel))
        probe = self.fixture(
            "leaker.py",
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', {!r}])\n".format(gc_code)
            + "sys.stdout.write('started\\n'); sys.stdout.flush()\n"
            "time.sleep(999)\n",
        )
        r = self.run_it("--rung", "1", "--surface", "cli", "--timeout", "1",
                        "--no-gate", "--", sys.executable, str(probe))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        time.sleep(6)  # outlast the grandchild's 5s arm-delay
        self.assertFalse(sentinel.exists(),
                         "grandchild outlived the timeout: process group was not reaped")

    def test_stdin_missing_file_is_distinct_error(self):
        # Finding #4: a missing --stdin file must not be misreported as a failed
        # launch of the probe.
        r = self.run_it("--rung", "1", "--surface", "server",
                        "--stdin", str(self.tmp / "no-such.json"),
                        "--", sys.executable, "-c", "print('hi')")
        self.assertEqual(r.returncode, 2)
        self.assertFalse(self.bundle_exists())
        self.assertIn("--stdin", r.stderr)
        self.assertNotIn("did not launch", r.stderr)

    def test_records_executed_program(self):
        # Finding #3: which program actually ran is recorded (resolved + hash),
        # so a non-subject drive is visible.
        fix = self.cli_fixture()
        self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                    "--", sys.executable, str(fix))
        ex = self.bundle()["claims"][0]["surface"]["executed"]
        self.assertEqual(ex["resolved"], str(Path(sys.executable)))
        self.assertRegex(ex["sha256"], r"^[0-9a-f]{64}$")

    def test_silent_hang_blocks_not_refused(self):
        # N1: a SILENT hang is diagnosed as a timeout (block, bundle emitted),
        # not the completed-but-silent "nothing observed" refusal. Same event
        # (zero bytes) but a different, truer cause than a probe that just exits.
        fix = self.fixture("silenthang.py", "import time\ntime.sleep(30)\n")
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--timeout", "1", "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        self.assertTrue(self.bundle_exists())
        b = self.bundle()
        self.assertEqual(b["claims"][0]["verdict"], "blocked")
        self.assertTrue(any(g["id"] == "timeout" and g["severity"] == "blocker"
                            for g in b.get("gaps", [])))
        self.assertNotIn("nothing was observed", r.stderr)

    def test_timeout_blocks_under_permissive_policy(self):
        # N2: verdict=blocked on timeout blocks UNCONDITIONALLY, even under a
        # policy that dismisses blocker gaps. A witnessed hang cannot go green.
        fix = self.fixture("hang.py",
                           "import sys, time\n"
                           "sys.stdout.write('starting\\n'); sys.stdout.flush()\n"
                           "time.sleep(30)\n")
        pol = self.fixture("permissive.json", json.dumps({
            "version": 2, "min_rung": {"low": 1, "medium": 1, "high": 1, "critical": 1},
            "require_context": {}, "no_skip_tiers": [], "allow_dismiss_gaps": True}))
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--timeout", "1", "--policy", str(pol),
                        "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        self.assertEqual(self.bundle()["claims"][0]["verdict"], "blocked")

    def test_server_frames_mode_passes(self):
        # Finding #1: a persistent server answers a frame then stays alive.
        # --expect-frames stops on the first frame and treats answered-then-alive
        # as success, so a healthy server no longer blocks on the timeout.
        srv = self.fixture("srv.py",
                           "import sys, time\n"
                           "sys.stdin.readline()\n"
                           "sys.stdout.write('{\"jsonrpc\":\"2.0\",\"result\":{}}\\n')\n"
                           "sys.stdout.flush()\n"
                           "time.sleep(30)\n")
        hs = self.fixture("hs.json", '{"jsonrpc":"2.0","method":"initialize"}\n')
        r = self.run_it("--rung", "1", "--surface", "server", "--tier", "low",
                        "--expect-frames", "1", "--stdin", str(hs), "--timeout", "10",
                        "--", sys.executable, str(srv))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        b = self.bundle()
        self.assertEqual(b.get("gaps", []), [])
        stdout_art = next(a for a in b["claims"][0]["artifacts"]
                          if a["role"] == "stdout_capture")
        captured = (self.tmp / ".rung" / "output" / stdout_art["uri"]).read_text()
        self.assertIn("jsonrpc", captured)

    def test_server_until_idle_passes(self):
        # Finding #1: --until-idle stops once the server produced output and went
        # quiet, treating answered-then-idle as success rather than a hang.
        srv = self.fixture("srv2.py",
                           "import sys, time\n"
                           "sys.stdin.readline()\n"
                           "sys.stdout.write('ready\\n'); sys.stdout.flush()\n"
                           "time.sleep(30)\n")
        hs = self.fixture("hs2.txt", "hello\n")
        r = self.run_it("--rung", "1", "--surface", "server", "--tier", "low",
                        "--until-idle", "0.5", "--stdin", str(hs), "--timeout", "10",
                        "--", sys.executable, str(srv))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.bundle().get("gaps", []), [])

    def test_until_idle_stops_on_non_newline_output(self):
        # --until-idle is framing-agnostic (the idle branch keys off nbytes>0 +
        # quiet, not on newlines), which is exactly why it is the
        # documented choice for non-newline protocols (LSP Content-Length). The
        # existing idle test emits 'ready\n'; this one emits output that never
        # contains a newline, then goes quiet. --expect-frames would under-count
        # and time out here; --until-idle must still stop and treat
        # answered-then-idle as success.
        srv = self.fixture("srv_nonl.py",
                           "import sys, time\n"
                           "sys.stdin.readline()\n"
                           "sys.stdout.write('READY-NO-NEWLINE'); sys.stdout.flush()\n"
                           "time.sleep(30)\n")
        hs = self.fixture("hs_nonl.txt", "hello\n")
        r = self.run_it("--rung", "1", "--surface", "server", "--tier", "low",
                        "--until-idle", "0.5", "--stdin", str(hs), "--timeout", "10",
                        "--", sys.executable, str(srv))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        b = self.bundle()
        self.assertEqual(b.get("gaps", []), [])
        stdout_art = next(a for a in b["claims"][0]["artifacts"]
                          if a["role"] == "stdout_capture")
        captured = (self.tmp / ".rung" / "output" / stdout_art["uri"]).read_text()
        self.assertEqual(captured, "READY-NO-NEWLINE")
        self.assertNotIn("\n", captured)  # idle fired with no newline in sight

    def test_newline_free_output_over_cap_is_bounded_and_blocked(self):
        # A newline-free (or very long) stream must not flood RAM before
        # the cap check. The drain reads fixed-size chunks (read1), never whole
        # lines, so the accumulated capture is bounded to MAX_CAPTURE_BYTES even
        # when no newline ever arrives; the truncation is RECORDED as a blocker
        # gap (not silent), so the gate blocks. The prior flood tests all emit
        # newline-terminated output, so this drives the readline-would-buffer
        # path the chunked read exists to prevent.
        cap = 4096
        blob = "x" * 200000  # newline-free, ~49x the cap
        fix = self.fixture("flood_nonl.py",
                           "import sys\n"
                           f"sys.stdout.write({blob!r}); sys.stdout.flush()\n")
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--", sys.executable, str(fix),
                        env={"RUNG_MAX_CAPTURE_BYTES": str(cap)})
        # A recorded truncation is a blocker gap, so the gate blocks (exit 30).
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        b = self.bundle()
        self.assertTrue(any(g["id"] == "capture-truncated" and g["severity"] == "blocker"
                            for g in b.get("gaps", [])))
        # The emitted capture is bounded to the cap despite the newline-free
        # 200000-byte stream: memory (and the bundle) stayed bounded.
        stdout_art = next(a for a in b["claims"][0]["artifacts"]
                          if a["role"] == "stdout_capture")
        captured = (self.tmp / ".rung" / "output" / stdout_art["uri"]).read_bytes()
        self.assertLessEqual(len(captured), cap)
        self.assertNotIn(b"\n", captured)

    def test_records_subject_program_and_exit(self):
        # Finding #2: for an interpreter-launched probe, the real subject file
        # (not just the interpreter) is resolved and hashed under
        # executed.subjects, so `python real.py` and `python evil.py` differ.
        # Finding #4: the child's exit is a structured integer, not free text.
        fix = self.cli_fixture()
        self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                    "--", sys.executable, str(fix))
        ex = self.bundle()["claims"][0]["surface"]["executed"]
        subs = ex["subjects"]
        sub = next(s for s in subs if s["resolved"] == str(fix))
        self.assertRegex(sub["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(sub["sha256_status"], "ok")
        self.assertEqual(ex["exit"], 2)  # cli_fixture exits 2

    def test_high_tier_blocks_author(self):
        # Self-report trap holds through the wrapper: an author rung-1 claim at
        # high tier needs an independent + cross-model review; the runner can mint
        # neither, so it blocks.
        fix = self.cli_fixture()
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "high",
                        "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)

    # -- policy is loaded and hash-pinned BEFORE the probe runs ------
    def permissive_policy(self) -> Path:
        # Passes a rung-1 cli claim: observed everywhere, author unconstrained
        # (require_context empty), so an author self-run clears any tier.
        return self.fixture("pol.json", json.dumps({
            "version": 2, "min_rung": {"low": 1, "medium": 1, "high": 1, "critical": 1},
            "require_context": {}, "no_skip_tiers": [], "allow_dismiss_gaps": False}))

    def strict_policy(self) -> Path:
        # Blocks the same author claim: every tier demands an independent context,
        # which an author self-run cannot supply.
        return self.fixture("strict.json", json.dumps({
            "version": 2, "min_rung": {"low": 1, "medium": 1, "high": 1, "critical": 1},
            "require_context": {"low": "independent", "medium": "independent",
                                "high": "independent", "critical": "independent"},
            "no_skip_tiers": [], "allow_dismiss_gaps": False}))

    def test_policy_pinned_into_bundle(self):
        # The exact policy bytes in force at launch are stamped into the
        # bundle so a verdict is attributable to them.
        fix = self.cli_fixture()
        pol = self.permissive_policy()
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--policy", str(pol), "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        pin = self.bundle()["policy_pin"]
        self.assertEqual(pin["path"], str(pol))
        import hashlib
        self.assertEqual(pin["sha256"], hashlib.sha256(pol.read_bytes()).hexdigest())

    def test_probe_cannot_swap_policy_mid_run(self):
        # The headline: a probe that overwrites the policy file to a
        # permissive one during the run must NOT get the permissive verdict. The
        # gate runs against the PINNED (strict) policy, and the swap is caught and
        # blocked rather than silently honored.
        pol = self.strict_policy()
        permissive = json.dumps({
            "version": 2, "min_rung": {"low": 1, "medium": 1, "high": 1, "critical": 1},
            "require_context": {}, "no_skip_tiers": [], "allow_dismiss_gaps": True})
        # The probe rewrites the policy file, then emits a byte (so it is a
        # completed, non-empty run), then exits 0.
        attacker = self.fixture("attacker.py",
                                f"import pathlib, sys\n"
                                f"pathlib.Path({str(pol)!r}).write_text({permissive!r})\n"
                                f"sys.stdout.write('done\\n')\n")
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--policy", str(pol), "--", sys.executable, str(attacker))
        # Blocked either by the strict floor (pinned dict) or the tamper check;
        # in no case does the swapped-in permissive policy grant a pass.
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        self.assertIn("changed during the run", r.stdout + r.stderr)

    def test_bad_policy_fails_closed_before_probe(self):
        # A malformed policy is a usage error caught BEFORE the probe is
        # ever launched (fail closed, no code run against a broken gate).
        marker = self.tmp / "probe-ran.marker"
        fix = self.fixture("marker.py",
                           f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
                           f"print('hi')\n")
        bad = self.fixture("bad.json", "{ not valid json ]")
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--policy", str(bad), "--", sys.executable, str(fix))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(marker.exists(), "probe must not run when the policy is unloadable")
        self.assertFalse(self.bundle_exists())

    # -- capture cap + truncation gap -------------------------------
    def test_capture_truncation_records_blocker_gap(self):
        # A probe that floods stdout past the cap is truncated, and the
        # truncation is recorded as an undismissed blocker gap (so it blocks by
        # default) rather than silently dropped.
        # Drive a real flood: emit well over the cap in small lines. To keep the
        # test fast we shrink the cap via the RUNG_MAX_CAPTURE_BYTES knob.
        flood = self.fixture("flood.py",
                            "import sys\n"
                            "buf = 'x' * 4096 + '\\n'\n"
                            "for _ in range(64):\n"
                            "    sys.stdout.write(buf)\n"
                            "sys.stdout.flush()\n")
        env = _env_with_src({"RUNG_MAX_CAPTURE_BYTES": "8192"})
        r = subprocess.run(
            RUN_ARGV + ["--rung", "1", "--surface", "cli", "--tier", "low",
             "--policy", str(self.permissive_policy()),
             "--until-idle", "0.3", "--timeout", "10", "--", sys.executable, str(flood)],
            cwd=self.tmp, capture_output=True, text=True, env=env)
        b = self.bundle()
        gaps = b.get("gaps", [])
        self.assertTrue(any(g["id"] == "capture-truncated" and g["severity"] == "blocker"
                            for g in gaps), gaps)
        # The captured stdout artifact is bounded at (roughly) the cap.
        stdout_art = next(a for a in b["claims"][0]["artifacts"] if a["role"] == "stdout_capture")
        captured = (self.tmp / ".rung" / "output" / stdout_art["uri"]).read_bytes()
        self.assertLessEqual(len(captured), 8192)
        # Undismissed blocker under a non-dismissing policy -> gate blocks.
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)

    # -- --env-clear scrubs the probe environment -------------------
    def test_env_clear_scrubs_secret_env(self):
        # A secret in the operator env must not reach the probe (and so
        # cannot leak into a capture) when --env-clear is set.
        leak = self.fixture("leak.py",
                            "import os\nprint('SECRET=' + os.environ.get('MY_SECRET','<absent>'))\n")
        env = _env_with_src({"MY_SECRET": "topsecret-token"})
        r = subprocess.run(
            RUN_ARGV + ["--rung", "1", "--surface", "cli", "--tier", "low",
             "--policy", str(self.permissive_policy()), "--env-clear",
             "--", sys.executable, str(leak)],
            cwd=self.tmp, capture_output=True, text=True, env=env)
        stdout_art = next(a for a in self.bundle()["claims"][0]["artifacts"]
                          if a["role"] == "stdout_capture")
        captured = (self.tmp / ".rung" / "output" / stdout_art["uri"]).read_text()
        self.assertIn("SECRET=<absent>", captured)
        self.assertNotIn("topsecret-token", captured)

    def test_env_inherited_without_flag(self):
        # Without --env-clear the probe inherits the env (baseline for the
        # scrub test above): the secret IS visible, confirming the flag is what
        # removes it.
        leak = self.fixture("leak2.py",
                            "import os\nprint('SECRET=' + os.environ.get('MY_SECRET','<absent>'))\n")
        env = _env_with_src({"MY_SECRET": "topsecret-token"})
        subprocess.run(
            RUN_ARGV + ["--rung", "1", "--surface", "cli", "--tier", "low",
             "--policy", str(self.permissive_policy()),
             "--", sys.executable, str(leak)],
            cwd=self.tmp, capture_output=True, text=True, env=env)
        stdout_art = next(a for a in self.bundle()["claims"][0]["artifacts"]
                          if a["role"] == "stdout_capture")
        captured = (self.tmp / ".rung" / "output" / stdout_art["uri"]).read_text()
        self.assertIn("topsecret-token", captured)

    # -- opt-in secret scan / redaction (--scan-secrets / --redact) -----
    # AWS's own documented example access-key id: matches the pattern, is not a
    # real credential, and is safe to embed in a public test.
    FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"

    def _secret_probe(self) -> list:
        # Clean stdout, a secret on STDERR (the dogfood leaked a token to stderr).
        return self._pyc(
            f"import sys; print('result ok'); print('token={self.FAKE_AWS}', file=sys.stderr)")

    def test_scan_secrets_blocks_on_leak(self):
        # --scan-secrets: an otherwise-passing rung-1 low claim blocks purely
        # because a capture contains a secret. The scan does NOT mutate (the
        # secret stays in the artifact), and the secret value never appears in a
        # gap desc, the verdict, or a diagnostic.
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low", "--scan-secrets",
                        "--", *self._secret_probe())
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        b = self.bundle()
        self.assertTrue(any(g["id"].startswith("secret-in-") and g["severity"] == "blocker"
                            for g in b.get("gaps", [])), b.get("gaps"))
        self.assertNotIn(self.FAKE_AWS, json.dumps(b.get("gaps", [])))
        self.assertNotIn(self.FAKE_AWS, r.stdout + r.stderr)
        # scan does not redact: the raw secret is still in the written artifact.
        err_art = next(a for a in b["claims"][0]["artifacts"] if a["role"] == "stderr_capture")
        captured = (self.tmp / ".rung" / "output" / err_art["uri"]).read_bytes()
        self.assertIn(self.FAKE_AWS.encode(), captured)

    def test_redact_masks_and_passes(self):
        # --redact: the secret is masked in the WRITTEN artifact (so its recorded
        # sha256 is of the redacted bytes), disclosed as an advisory gap that does
        # not block a claim that otherwise passes.
        import hashlib
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low", "--redact",
                        "--", *self._secret_probe())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        b = self.bundle()
        self.assertTrue(any(g["id"].startswith("redacted-") and g["severity"] == "advisory"
                            for g in b.get("gaps", [])), b.get("gaps"))
        err_art = next(a for a in b["claims"][0]["artifacts"] if a["role"] == "stderr_capture")
        captured = (self.tmp / ".rung" / "output" / err_art["uri"]).read_bytes()
        self.assertNotIn(self.FAKE_AWS.encode(), captured)
        self.assertIn(b"[REDACTED:", captured)
        # The gate re-verified the artifact, so the recorded hash IS of the
        # redacted bytes on disk (self-consistent, not the raw capture's hash).
        self.assertEqual(err_art["sha256"], hashlib.sha256(captured).hexdigest())

    def test_default_no_scan_keeps_exact_bytes(self):
        # Neither flag: the exact-bytes default is unchanged -- the secret is
        # written verbatim and no secret gap is recorded.
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--", *self._secret_probe())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        b = self.bundle()
        self.assertFalse(any(g["id"].startswith(("secret-in-", "redacted-"))
                             for g in b.get("gaps", [])), b.get("gaps"))
        err_art = next(a for a in b["claims"][0]["artifacts"] if a["role"] == "stderr_capture")
        captured = (self.tmp / ".rung" / "output" / err_art["uri"]).read_bytes()
        self.assertIn(self.FAKE_AWS.encode(), captured)

    def test_redact_and_scan_leaves_no_residual_blocker(self):
        # --redact --scan-secrets: redaction runs first, then the scan verifies no
        # residue. The secret is gone, so only the advisory (redaction) gap
        # remains and the claim passes.
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low",
                        "--redact", "--scan-secrets", "--", *self._secret_probe())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        ids = [g["id"] for g in self.bundle().get("gaps", [])]
        self.assertTrue(any(i.startswith("redacted-") for i in ids), ids)
        self.assertFalse(any(i.startswith("secret-in-") for i in ids), ids)

    def test_diff_redact_masks_both_captures_and_keeps_delta(self):
        # --diff --redact: both captures are masked, and a real (non-secret) delta
        # survives -- S0 prints A, S1 prints B, so the change claim still passes.
        s0 = self._pyc(f"print('A'); print('{self.FAKE_AWS}')")
        s1 = self._pyc(f"print('B'); print('{self.FAKE_AWS}')")
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "change",
                        "--redact", "--", *s0, ":::", *s1)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        b = self.bundle()
        for role in ("s0_capture", "s1_capture"):
            art = next(a for a in b["claims"][0]["artifacts"] if a["role"] == role)
            cap = (self.tmp / ".rung" / "output" / art["uri"]).read_bytes()
            self.assertNotIn(self.FAKE_AWS.encode(), cap)
            self.assertIn(b"[REDACTED:", cap)

    def test_diff_redact_collapse_of_real_delta_blocks(self):
        # The redaction-altered-differential guard's FIRING case: two runs that
        # differ ONLY in a secret-shaped token. Raw S0/S1 bytes differ (a real
        # change), but --redact rewrites both to the same [REDACTED:...] placeholder,
        # collapsing them to byte-identical captures. Left unguarded, that would
        # publish a false "invariance" (or defeat an --expect-delta change). The
        # guard compares raw-vs-redacted equality and forces a block.
        s0 = self._pyc("print('AKIAIOSFODNN7EXAMPL1')")
        s1 = self._pyc("print('AKIAIOSFODNN7EXAMPL2')")
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "change",
                        "--redact", "--", *s0, ":::", *s1)
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        b = self.bundle()
        self.assertTrue(any(g["id"] == "redaction-altered-differential"
                            and g["severity"] == "blocker"
                            for g in b.get("gaps", [])), b.get("gaps"))

    def test_redact_does_not_mask_nondeterminism(self):
        # Design guard: redaction is a publishing transform, not a determinism
        # fix. The determinism check runs on the RAW compared bytes, so a
        # nondeterministic side still trips nondeterministic-output even with
        # --redact (it does not paper over a real nondeterminism defect).
        noisy = self._pyc("import time; print(time.time_ns())")
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "change",
                        "--redact", "--", *noisy, ":::", *noisy)
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        self.assertTrue(any(g["id"] == "nondeterministic-output"
                            for g in self.bundle().get("gaps", [])))

    def test_scan_secrets_blocks_secret_in_argv(self):
        # Regression (STRIDE finding): a secret passed ON THE COMMAND LINE, not in
        # any capture, still lands in the bundle's echoed invocation fields
        # (change.s1, the claim, how_established). --scan-secrets must block it too,
        # not just capture leaks. The probe prints 'ok' and never echoes the token,
        # so the ONLY place the secret can appear is the argv metadata.
        probe = self._pyc("print('ok')") + [self.FAKE_AWS]
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low", "--scan-secrets",
                        "--", *probe)
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        b = self.bundle()
        self.assertTrue(any(g["id"] == "secret-in-invocation" and g["severity"] == "blocker"
                            for g in b.get("gaps", [])), b.get("gaps"))
        # the capture is clean -- this is purely the argv-leak path, not the capture one
        out_art = next(a for a in b["claims"][0]["artifacts"] if a["role"] == "stdout_capture")
        self.assertNotIn(self.FAKE_AWS.encode(), (self.tmp / ".rung" / "output" / out_art["uri"]).read_bytes())
        # and the secret value never leaks into a gap desc, the verdict, or stderr
        self.assertNotIn(self.FAKE_AWS, json.dumps(b.get("gaps", [])))
        self.assertNotIn(self.FAKE_AWS, r.stdout + r.stderr)

    def test_redact_masks_secret_in_argv(self):
        # --redact must mask a command-line secret out of EVERY echoed field, so the
        # value appears nowhere in the written bundle and the claim still passes.
        probe = self._pyc("print('ok')") + [self.FAKE_AWS]
        r = self.run_it("--rung", "1", "--surface", "cli", "--tier", "low", "--redact",
                        "--", *probe)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        b = self.bundle()
        self.assertNotIn(self.FAKE_AWS, json.dumps(b))
        self.assertIn("[REDACTED:", b["change"]["s1"])
        self.assertTrue(any(g["id"] == "redacted-invocation" and g["severity"] == "advisory"
                            for g in b.get("gaps", [])), b.get("gaps"))

    def test_diff_scan_secrets_blocks_secret_in_side_argv(self):
        # The diff path echoes each side's argv into differential.sN.argv and the
        # change.sN free text; a secret in one side's command line must block under
        # --scan-secrets. S0 prints A, S1 prints B (a real delta), and the secret
        # rides only on S1's argv (never printed).
        s0 = self._pyc("print('A')")
        s1 = self._pyc("print('B')") + [self.FAKE_AWS]
        r = self.run_it("--rung", "1", "--surface", "cli", "--diff", "--expect-delta", "change",
                        "--scan-secrets", "--", *s0, ":::", *s1)
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        b = self.bundle()
        self.assertTrue(any(g["id"] == "secret-in-s1-invocation" and g["severity"] == "blocker"
                            for g in b.get("gaps", [])), b.get("gaps"))
        self.assertNotIn(self.FAKE_AWS, json.dumps(b.get("gaps", [])))

    def test_bad_capture_cap_env_fails_closed(self):
        # A malformed RUNG_MAX_CAPTURE_BYTES must fail closed to exit 2 with a
        # diagnostic naming the variable, never an import-time traceback.
        for bad in ("not-an-int", "0", "-5"):
            p = self.run_it("--rung", "0", "--surface", "cli", "--", "true",
                            env={"RUNG_MAX_CAPTURE_BYTES": bad})
            self.assertEqual(p.returncode, 2, f"{bad!r}: {p.stderr}")
            self.assertNotIn("Traceback", p.stderr)
            self.assertIn("RUNG_MAX_CAPTURE_BYTES", p.stderr)

    def test_internal_exception_fails_closed_to_exit_2(self):
        # An unexpected exception inside main() must fail closed to exit 2 with a
        # one-line diagnostic, never a raw traceback, on the standalone module
        # path (`python -m rung.run`), matching the CLI dispatcher.
        driver = (
            "import sys, rung.run as r\n"
            "r.main = lambda argv=None: (_ for _ in ()).throw(RuntimeError('boom'))\n"
            "sys.exit(r._main_cli([]))\n"
        )
        p = subprocess.run([sys.executable, "-c", driver],
                           capture_output=True, text=True, env=_env_with_src())
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertIn("internal error", p.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
