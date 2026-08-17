#!/usr/bin/env python3
"""Adversarial regression suite for the rung reference gate.

Every test here encodes a concrete attack or gap surfaced by the adversarial
doc review and asserts the gate now handles it. Run:  python3 -m unittest -v
(from the gate/ dir) or  python3 gate/test_gate.py.  Stdlib only.
"""
from __future__ import annotations
import io, os, sys, json, hashlib, pathlib, tempfile, unittest, contextlib, subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "src"
# Import the packaged gate (src/ layout). Putting src/ on the path also lets the
# gate's importlib.resources default-policy resolver find src/rung/data/.
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
import rung.gate as gate

FLAGSHIP = REPO / "cases" / "sync-connector-stdio-purity" / "bundle.json"
DEFAULT_POLICY = json.loads((REPO / "policy" / "default.json").read_text())

GOOD_POLICY = {
    "version": 1,
    "require_context": {"high": "cross-lab", "critical": "cross-lab"},
    "no_skip_tiers": ["high", "critical"],
    "allow_dismiss_gaps": False,
    "min_rung": {"low": 2, "medium": 3, "high": 4, "critical": 4},
}


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class GateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="rung-test-"))

    def artifact(self, name: str, role: str, content: bytes) -> dict:
        p = self.tmp / name
        p.write_bytes(content)
        return {"id": name, "role": role, "uri": name, "sha256": sha(content), "summary": role}

    def bundle(self, claim: dict, gaps=None, lab="example-lab", schema="evidence-bundle/v1") -> dict:
        return {
            "schema": schema,
            "change": {"repo": "x", "s0": "s0", "s1": "s1", "producer": {"lab": lab}},
            "claims": [claim],
            "gaps": gaps or [],
        }

    def run_gate(self, bundle, policy=GOOD_POLICY):
        return gate.gate(bundle, policy, self.tmp)

    # --- baseline: the framework's own guarantees still hold ----------------
    def test_flagship_passes_at_medium(self):
        b = json.loads(FLAGSHIP.read_text())
        base = FLAGSHIP.parent
        self.assertEqual(gate.gate(b, DEFAULT_POLICY, base)["verdict"], "pass")

    def test_flagship_blocks_at_high_selfreport_trap(self):
        b = json.loads(FLAGSHIP.read_text())
        for c in b["claims"]:
            c["risk_tier"] = "high"
        r = gate.gate(b, DEFAULT_POLICY, FLAGSHIP.parent)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("cross-lab" in x for x in r["reasons"]))

    def test_tamper_blocks(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"banner\nframe")
        a1 = self.artifact("s1.txt", "s1_capture", b"frame")
        a1["sha256"] = sha(b"different")  # declared != actual
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "verdict": "pass", "artifacts": [a0, a1],
                 "differential": {"s0_observed": "banner", "s1_observed": "frame"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("mismatch" in x for x in r["reasons"]))

    # --- fail closed on policy ----------------------------------------------
    def test_policy_missing_independence_blocks(self):
        """A policy that omits an independence key entirely must fail closed:
        it cannot silently ship with the check disabled."""
        bad = dict(GOOD_POLICY)
        del bad["require_context"]
        with self.assertRaises(gate.PolicyError):
            gate.validate_policy(bad)

    def test_typo_key_blocks(self):
        bad = dict(GOOD_POLICY)
        del bad["require_context"]
        bad["require_ctx"] = {"high": "cross-lab"}
        with self.assertRaises(gate.PolicyError):
            gate.validate_policy(bad)

    # --- artifact uri path containment --------------------------------------
    def test_absolute_uri_blocked(self):
        claim = {"id": "c1", "risk_tier": "medium", "rung": 3, "context": "author",
                 "verdict": "pass",
                 "artifacts": [{"id": "a", "role": "log", "uri": "/etc/hostname",
                                "sha256": "0" * 64}]}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("escape" in x for x in r["reasons"]))

    def test_traversal_uri_blocked(self):
        claim = {"id": "c1", "risk_tier": "medium", "rung": 3, "context": "author",
                 "verdict": "pass",
                 "artifacts": [{"id": "a", "role": "log", "uri": "../../../../etc/hostname",
                                "sha256": "0" * 64}]}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("escape" in x for x in r["reasons"]))

    # --- schema validation --------------------------------------------------
    def test_empty_claims_blocks(self):
        b = self.bundle({"id": "x"})
        b["claims"] = []
        r = self.run_gate(b)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("no claims" in x for x in r["reasons"]))

    def test_unknown_schema_blocks(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"x")
        a1 = self.artifact("s1.txt", "s1_capture", b"y")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "verdict": "pass", "artifacts": [a0, a1],
                 "differential": {"s0_observed": "x", "s1_observed": "y"}}
        b = self.bundle(claim, schema="totally-wrong/v9")
        r = self.run_gate(b)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("schema" in x for x in r["reasons"]))

    # --- evidence is mandatory where load-bearing ---------------------------
    def test_unhashed_artifact_blocks(self):
        p = self.tmp / "cap.txt"
        p.write_bytes(b"hi")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 3, "context": "author",
                 "verdict": "pass",
                 "artifacts": [{"id": "a", "role": "log", "uri": "cap.txt"}]}  # no sha256
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("no sha256" in x for x in r["reasons"]))

    def test_rung3_without_artifact_blocks(self):
        claim = {"id": "c1", "risk_tier": "medium", "rung": 3, "context": "author",
                 "verdict": "pass", "artifacts": []}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("requires >=1 capture artifact" in x for x in r["reasons"]))

    # --- invariance polarity ------------------------------------------------
    def test_invariance_passes_when_unchanged(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"200 OK\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"200 OK\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "verdict": "pass", "expected_delta": "invariance",
                 "artifacts": [a0, a1],
                 "differential": {"s0_observed": "200 OK", "s1_observed": "200 OK"}}
        self.assertEqual(self.run_gate(self.bundle(claim))["verdict"], "pass")

    def test_invariance_blocks_on_unexpected_delta(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"200 OK\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"500 ERR\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "verdict": "pass", "expected_delta": "invariance",
                 "artifacts": [a0, a1],
                 "differential": {"s0_observed": "200 OK", "s1_observed": "500 ERR"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("unexpected S0/S1 delta" in x for x in r["reasons"]))

    def test_change_polarity_blocks_when_no_delta(self):
        """The original anti-gaming rule must survive for change-claims."""
        a0 = self.artifact("s0.txt", "s0_capture", b"ok\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"ok\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "verdict": "pass", "artifacts": [a0, a1],
                 "differential": {"s0_observed": "ok", "s1_observed": "ok"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("no S0/S1 delta" in x for x in r["reasons"]))

    # --- rung-4 polarity is decided by VERIFIED BYTES, not declared text -
    def test_change_identical_bytes_blocks(self):
        """A change-claim whose captures are byte-identical must block even when
        the declared differential lies that they differ (the fabrication that
        previously produced a false pass from genuine, hash-matching artifacts)."""
        a0 = self.artifact("s0.txt", "s0_capture", b"SAME\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"SAME\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "verdict": "pass", "expected_delta": "change", "artifacts": [a0, a1],
                 "differential": {"s0_observed": "banner present", "s1_observed": "banner gone"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("no S0/S1 delta" in x for x in r["reasons"]))
        self.assertTrue(any("contradicts capture bytes" in x for x in r["reasons"]))

    def test_invariance_differing_bytes_blocks(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"A\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"B\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "verdict": "pass", "expected_delta": "invariance", "artifacts": [a0, a1],
                 "differential": {"s0_observed": "same", "s1_observed": "same"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("unexpected S0/S1 delta" in x for x in r["reasons"]))

    def test_polarity_unverifiable_without_both_captures(self):
        """rung 4 cannot pass if the capture bytes cannot be compared."""
        a0 = self.artifact("s0.txt", "s0_capture", b"A\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "verdict": "pass", "expected_delta": "change", "artifacts": [a0],
                 "differential": {"s0_observed": "a", "s1_observed": "b"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("polarity unverifiable" in x for x in r["reasons"]))

    # --- rung-4 polarity needs ONE unambiguous pair, not role buckets -
    def test_duplicate_role_labels_cannot_fake_invariance(self):
        """Two genuine, distinct, hash-matching files each labeled BOTH
        s0_capture and s1_capture make the role buckets equal as sorted sets
        (sorted(s0)==sorted(s1)) and used to fake `invariance`. Requiring exactly
        one verified capture per role blocks it."""
        a0 = self.artifact("A.txt", "s0_capture", b"AAA\n")
        b0 = self.artifact("B.txt", "s0_capture", b"BBB\n")
        a1 = self.artifact("A.txt", "s1_capture", b"AAA\n")
        b1 = self.artifact("B.txt", "s1_capture", b"BBB\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "verdict": "pass", "expected_delta": "invariance",
                 "artifacts": [a0, b0, a1, b1],
                 "differential": {"s0_observed": "same", "s1_observed": "same"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("polarity unverifiable" in x for x in r["reasons"]))

    def test_padded_extra_capture_cannot_fake_change(self):
        """A real no-op (s0 and s1 byte-identical) padded with an extra distinct
        file in the s1 bucket makes sorted(s0) != sorted(s1) and used to fake
        `change`. The exactly-one-per-role rule blocks the padded bucket."""
        a0 = self.artifact("A.txt", "s0_capture", b"same\n")
        a1 = self.artifact("A2.txt", "s1_capture", b"same\n")   # byte-identical to A0
        c = self.artifact("C.txt", "s1_capture", b"padding\n")  # pad to make buckets differ
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "verdict": "pass", "expected_delta": "change",
                 "artifacts": [a0, a1, c],
                 "differential": {"s0_observed": "a", "s1_observed": "b"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("polarity unverifiable" in x for x in r["reasons"]))

    # --- policy value-type: a mistyped-but-present policy fails closed -------
    def test_policy_noninteger_min_rung_is_policy_error(self):
        """min_rung values must be ints 0..4; a string used to crash later on
        `rung < min_rung` (int < str -> TypeError -> exit 1). Now it's caught in
        validate_policy and surfaces as a policy-integrity block, not a crash."""
        bad = dict(GOOD_POLICY)
        bad["min_rung"] = {**GOOD_POLICY["min_rung"], "low": "2"}
        with self.assertRaises(gate.PolicyError):
            gate.validate_policy(bad)

    def test_policy_bad_context_value_is_policy_error(self):
        bad = dict(GOOD_POLICY)
        bad["require_context"] = {"high": "crosslab"}  # typo'd context
        with self.assertRaises(gate.PolicyError):
            gate.validate_policy(bad)

    def test_policy_bad_type_blocks_not_crashes(self):
        """End to end: a mistyped policy exits BLOCK (30), never a traceback/1."""
        p = self.tmp / "b.json"
        p.write_text(json.dumps(self.bundle(
            {"id": "c1", "risk_tier": "medium", "rung": 3, "context": "author",
             "verdict": "pass", "artifacts": []})))
        pol = self.tmp / "p.json"
        pol.write_text(json.dumps({**GOOD_POLICY,
                                   "min_rung": {**GOOD_POLICY["min_rung"], "low": "2"}}))
        self.assertEqual(self._exit([str(p), str(pol)]), gate.EXIT_BLOCK)

    # --- unknown/typo'd CLI flags fail closed to a usage error ----------
    def test_unknown_flag_is_usage_error(self):
        self.assertEqual(self._exit([str(FLAGSHIP), "--bogus"]), gate.EXIT_USAGE)

    def test_typo_tier_flag_is_usage_error(self):
        """A typo'd --teir=high used to be silently dropped, running the gate at
        the bundle-declared tier instead of the intended override."""
        self.assertEqual(self._exit([str(FLAGSHIP), "--teir=high"]), gate.EXIT_USAGE)

    # --- malformed input yields a verdict/usage, never a traceback ----------
    def _exit(self, argv):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return gate.main(argv)

    def test_unknown_tier_is_usage_error(self):
        self.assertEqual(self._exit([str(FLAGSHIP), "--tier", "bogus"]), gate.EXIT_USAGE)

    def test_trailing_tier_is_usage_error(self):
        self.assertEqual(self._exit([str(FLAGSHIP), "--tier"]), gate.EXIT_USAGE)

    def test_no_bundle_is_usage_error(self):
        self.assertEqual(self._exit([]), gate.EXIT_USAGE)

    def test_bad_json_is_usage_error(self):
        p = self.tmp / "bad.json"
        p.write_text("{not json")
        self.assertEqual(self._exit([str(p)]), gate.EXIT_USAGE)

    def test_missing_verdict_blocks_not_crashes(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"x")
        a1 = self.artifact("s1.txt", "s1_capture", b"y")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 4, "context": "author",
                 "artifacts": [a0, a1],
                 "differential": {"s0_observed": "x", "s1_observed": "y"}}  # no verdict
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")

    def test_exit_codes_pass_and_block(self):
        self.assertEqual(self._exit([str(FLAGSHIP)]), gate.EXIT_PASS)
        self.assertEqual(self._exit([str(FLAGSHIP), "--tier", "high"]), gate.EXIT_BLOCK)

    # --- pathological input fails closed to exit 2, never a traceback ----
    def test_deeply_nested_json_is_usage_error(self):
        p = self.tmp / "deep.json"
        p.write_text("[" * 20000 + "]" * 20000)
        self.assertEqual(self._exit([str(p)]), gate.EXIT_USAGE)

    def test_oversized_input_is_usage_error(self):
        p = self.tmp / "big.json"
        p.write_bytes(b"[" + b" " * (gate.MAX_INPUT_BYTES + 1) + b"]")
        self.assertEqual(self._exit([str(p)]), gate.EXIT_USAGE)

    # --- the verdict is bound to the exact gate + policy that produced it -
    def test_verdict_binds_gate_and_policy_hashes(self):
        r = gate.gate(json.loads(FLAGSHIP.read_text()), DEFAULT_POLICY, FLAGSHIP.parent)
        self.assertEqual(len(r["gate_sha256"]), 64)
        self.assertEqual(len(r["policy_sha256"]), 64)
        other = dict(DEFAULT_POLICY)
        other["min_rung"] = {**DEFAULT_POLICY["min_rung"], "low": 0}
        r2 = gate.gate(json.loads(FLAGSHIP.read_text()), other, FLAGSHIP.parent)
        self.assertNotEqual(r["policy_sha256"], r2["policy_sha256"])


class SelfHashProvenanceCase(unittest.TestCase):
    """Provenance (`gate_sha256`) must survive the packaging shape. A normal
    `pip install` unzips the wheel to real files, but running the gate from a
    wheel/zipapp on the path imports it via zipimport, where `__file__` points
    inside the archive and a plain filesystem read fails. The self-hash has to
    fall back to the module loader so `gate_sha256` stays non-null and
    byte-identical across install shapes; otherwise a rung-4 install-shape
    differential blocks on a spurious null-vs-hash delta. This regression was
    found by dogfooding rung on its own packaging.
    """

    def test_gate_sha256_survives_zipimport(self):
        import zipfile, importlib
        src_bytes = (SRC / "rung" / "gate.py").read_bytes()
        expected = hashlib.sha256(src_bytes).hexdigest()
        # sanity: the on-disk import already computes that hash
        self.assertEqual(gate.GATE_SHA256, expected)
        with tempfile.TemporaryDirectory(prefix="rung-zip-") as d:
            zip_path = os.path.join(d, "gate_pkg.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                # gate.py has no sibling imports, so it loads as a standalone
                # top-level module straight out of the zip.
                zf.writestr("gate_ziptest.py", src_bytes)
            sys.path.insert(0, zip_path)
            importlib.invalidate_caches()
            try:
                mod = importlib.import_module("gate_ziptest")
                self.assertEqual(type(mod.__loader__).__name__, "zipimporter")
                self.assertIsNotNone(
                    mod.GATE_SHA256,
                    "self-hash must survive zipimport via the loader fallback",
                )
                self.assertEqual(mod.GATE_SHA256, expected)
            finally:
                sys.path.remove(zip_path)
                sys.modules.pop("gate_ziptest", None)
                importlib.invalidate_caches()


class DeterminismCase(unittest.TestCase):
    """A verdict is only trustworthy if it is reproducible. The gate is a pure
    function, but Python's per-process hash randomization (PYTHONHASHSEED)
    reorders set/dict iteration over strings, which would corrupt output only
    if a set or dict is iterated *into* the result. The gate sorts or
    membership-tests every such collection; these tests lock that in by
    running the CLI under several distinct hash seeds and asserting the raw
    stdout bytes and exit code are identical each time. A future edit that
    leaks set-iteration order into `reasons` (or anywhere in the JSON) fails
    here.
    """
    SEEDS = ("0", "1", "2", "3", "1000003")

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="rung-determinism-"))

    def _run_under_seed(self, argv, seed):
        # Drive the packaged gate as `python -m rung.gate` with src/ on
        # PYTHONPATH; a bare `python src/rung/gate.py` could not import the
        # `rung` package the default-policy resolver needs.
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-m", "rung.gate", *argv],
            capture_output=True, env=env,
        )
        return (proc.returncode, proc.stdout)

    def _assert_seed_invariant(self, argv):
        results = {self._run_under_seed(argv, s) for s in self.SEEDS}
        self.assertEqual(
            len(results), 1,
            f"gate output varied across PYTHONHASHSEED for argv={argv}: "
            f"{len(results)} distinct (rc, stdout) results",
        )
        rc, out = next(iter(results))
        # sanity: it produced a real verdict, not an empty crash
        self.assertIn(json.loads(out)["verdict"], ("pass", "block"))
        return rc, out

    def test_pass_output_is_seed_invariant(self):
        self._assert_seed_invariant([str(FLAGSHIP)])

    def test_block_output_is_seed_invariant(self):
        self._assert_seed_invariant([str(FLAGSHIP), "--tier", "high"])

    def test_many_reasons_output_is_seed_invariant(self):
        """A bundle that trips several checks across multiple claims: the
        richest chance for a leaked iteration order to surface as reason
        reordering."""
        bundle = {
            "schema": "evidence-bundle/v1",
            "change": {"producer": {"lab": "lab-alpha"}},
            "claims": [
                {"id": "c1", "risk_tier": "high", "rung": 1,
                 "context": "author", "verdict": "fail"},
                {"id": "c2", "risk_tier": "critical", "rung": 4,
                 "context": "author", "verdict": "skip", "artifacts": []},
                {"id": "c3", "risk_tier": "medium", "rung": 3,
                 "context": "fresh-blind", "verdict": "pass", "artifacts": []},
            ],
            "gaps": [{"id": "g1", "severity": "blocker", "desc": "d"}],
        }
        p = self.tmp / "many.json"
        p.write_text(json.dumps(bundle))
        rc, _ = self._assert_seed_invariant([str(p)])
        self.assertEqual(rc, gate.EXIT_BLOCK)


class GateEntryFailClosed(unittest.TestCase):
    def test_internal_exception_fails_closed_to_exit_2(self):
        # An unexpected exception from main() (beyond the handled input/policy
        # errors) must map to exit 2 with a one-line diagnostic, never a raw
        # traceback, on the standalone `python -m rung.gate` path.
        orig = gate.main
        err = io.StringIO()
        try:
            gate.main = lambda argv=None: (_ for _ in ()).throw(RuntimeError("boom"))
            with contextlib.redirect_stderr(err):
                rc = gate._main_cli([])
        finally:
            gate.main = orig
        self.assertEqual(rc, gate.EXIT_USAGE)
        self.assertNotIn("Traceback", err.getvalue())
        self.assertIn("internal error", err.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
