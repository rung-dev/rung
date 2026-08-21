#!/usr/bin/env python3
"""Adversarial regression suite for the rung reference gate (evidence-bundle/v2).

Every test here encodes a concrete attack or gap surfaced by the adversarial
doc review and asserts the gate now handles it. Run:  python3 -m unittest -v
(from the gate/ dir) or  python3 gate/test_gate.py.  Stdlib only.

v2 model: RUNG is {0 not-runtime-observed, 1 observed}; the differential is a
METHOD (not a rung); CONTEXT is {author, independent} with cross-model /
cross-lab as separately-demanded decorrelation QUALIFIERS.
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

FLAGSHIP = REPO / "gate" / "cases" / "sync-connector-stdio-purity" / "bundle.json"
CROSS_MODEL_PANEL = REPO / "gate" / "cases" / "rung-cross-model-run-panel" / "bundle.json"
DEFAULT_POLICY = json.loads((REPO / "policy" / "default.json").read_text())

# A strict v2 policy: observed everywhere, independent + cross-lab at high/critical.
GOOD_POLICY = {
    "version": 2,
    "min_rung": {"low": 1, "medium": 1, "high": 1, "critical": 1},
    "require_context": {"high": "independent", "critical": "independent"},
    "require_cross_lab": ["high", "critical"],
    "no_skip_tiers": ["high", "critical"],
    "allow_dismiss_gaps": False,
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

    def bundle(self, claim: dict, gaps=None, lab="example-lab", schema="evidence-bundle/v2") -> dict:
        return {
            "schema": schema,
            "change": {"repo": "x", "s0": "s0", "s1": "s1", "producer": {"lab": lab}},
            "claims": [claim],
            "gaps": gaps or [],
        }

    def run_gate(self, bundle, policy=GOOD_POLICY):
        return gate.gate(bundle, policy, self.tmp)

    # --- baseline: the framework's own guarantees still hold ----------------
    def test_flagship_passes_at_low(self):
        """An honest author differential observation clears low tier under the
        default policy: rung 1, method=differential, author context."""
        b = json.loads(FLAGSHIP.read_text())
        self.assertEqual(gate.gate(b, DEFAULT_POLICY, FLAGSHIP.parent)["verdict"], "pass")

    def test_flagship_blocks_at_high_selfreport_trap(self):
        """The v2 independence trap: an author self-run cannot satisfy a tier that
        demands an independent (and cross-model) review, no matter how real the
        observation is."""
        b = json.loads(FLAGSHIP.read_text())
        for c in b["claims"]:
            c["risk_tier"] = "high"
        r = gate.gate(b, DEFAULT_POLICY, FLAGSHIP.parent)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("independent" in x for x in r["reasons"]))

    def test_cross_model_panel_passes_at_high(self):
        """The release-gate case reaches the top-right cell: an independent
        cross-model panel that ran the surface clears high under the default
        policy (which demands independent + a cross-model qualifier at high)."""
        b = json.loads(CROSS_MODEL_PANEL.read_text())
        r = gate.gate(b, DEFAULT_POLICY, CROSS_MODEL_PANEL.parent)
        self.assertEqual(r["verdict"], "pass", r["reasons"])

    def test_cross_model_panel_blocks_at_critical_needs_cross_lab(self):
        """The same case blocks at critical: a cross-model panel is not cross-lab,
        so the gate demands a cross-lab attestation there. One operator cannot mint
        critical."""
        b = json.loads(CROSS_MODEL_PANEL.read_text())
        for c in b["claims"]:
            c["risk_tier"] = "critical"
        r = gate.gate(b, DEFAULT_POLICY, CROSS_MODEL_PANEL.parent)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("cross-lab" in x for x in r["reasons"]), r["reasons"])

    def test_tamper_blocks(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"banner\nframe")
        a1 = self.artifact("s1.txt", "s1_capture", b"frame")
        a1["sha256"] = sha(b"different")  # declared != actual
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "verdict": "pass", "artifacts": [a0, a1],
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
        bad["require_ctx"] = {"high": "independent"}
        with self.assertRaises(gate.PolicyError):
            gate.validate_policy(bad)

    # --- artifact uri path containment --------------------------------------
    def test_absolute_uri_blocked(self):
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "context": "author",
                 "verdict": "pass",
                 "artifacts": [{"id": "a", "role": "log", "uri": "/etc/hostname",
                                "sha256": "0" * 64}]}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("escape" in x for x in r["reasons"]))

    def test_traversal_uri_blocked(self):
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "context": "author",
                 "verdict": "pass",
                 "artifacts": [{"id": "a", "role": "log", "uri": "../../../../etc/hostname",
                                "sha256": "0" * 64}]}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("escape" in x for x in r["reasons"]))

    def test_symlink_loop_uri_blocks_not_crashes(self):
        """STRIDE regression: a hostile artifact path (a symlink loop) is a defect
        in the producer's bundle, not a gate bug. Resolving/stat-ing it raises
        RuntimeError/OSError deep in the gate; that must fail closed to a per-claim
        BLOCK reason (consistent with every other unresolvable artifact), never an
        escaping traceback mislabelled as a 'gate-internal error'."""
        (self.tmp / "loop").symlink_to("loop")  # self-referential -> ELOOP on resolve
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "context": "author",
                 "verdict": "pass",
                 "artifacts": [{"id": "a", "role": "log", "uri": "loop", "sha256": "0" * 64}]}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        # The load-bearing property is a per-claim BLOCK with no escaping
        # traceback. The exact fail-closed reason is stdlib-version dependent:
        # on <=3.12 Path.exists() raises OSError (ELOOP) -> "cannot be checked";
        # on 3.13+ it swallows the OSError and returns False -> "uri not found".
        # Both name the artifact and fail closed, so accept either.
        self.assertTrue(any("cannot be resolved" in x or "cannot be checked" in x
                            or "uri not found" in x
                            for x in r["reasons"]), r["reasons"])

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
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "verdict": "pass", "artifacts": [a0, a1],
                 "differential": {"s0_observed": "x", "s1_observed": "y"}}
        b = self.bundle(claim, schema="totally-wrong/v9")
        r = self.run_gate(b)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("schema" in x for x in r["reasons"]))

    # --- evidence is mandatory where load-bearing ---------------------------
    def test_unhashed_artifact_blocks(self):
        p = self.tmp / "cap.txt"
        p.write_bytes(b"hi")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "context": "author",
                 "verdict": "pass",
                 "artifacts": [{"id": "a", "role": "log", "uri": "cap.txt"}]}  # no sha256
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("no sha256" in x for x in r["reasons"]))

    def test_rung1_without_artifact_blocks(self):
        """An observation (rung 1) must carry the capture it observed."""
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "context": "author",
                 "verdict": "pass", "artifacts": []}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("requires >=1 capture artifact" in x for x in r["reasons"]))

    # --- rung range: {0,1} only ---------------------------------------------
    def test_rung_out_of_range_blocks(self):
        """The v1 ladder is gone: rung 2/3/4 are no longer valid values."""
        for bad_rung in (2, 3, 4):
            claim = {"id": "c1", "risk_tier": "low", "rung": bad_rung, "context": "author",
                     "verdict": "pass", "artifacts": []}
            r = self.run_gate(self.bundle(claim))
            self.assertEqual(r["verdict"], "block", bad_rung)
            self.assertTrue(any("not an integer 0..1" in x for x in r["reasons"]), bad_rung)

    def test_rung_bool_blocks(self):
        """`True`/`False` are ints in Python (`True == 1`), so a JSON `true` rung
        must not sneak past the range check and be gated as a rung-1 observation."""
        for bad_rung in (True, False):
            claim = {"id": "c1", "risk_tier": "low", "rung": bad_rung, "context": "author",
                     "verdict": "pass", "artifacts": []}
            r = self.run_gate(self.bundle(claim))
            self.assertEqual(r["verdict"], "block", bad_rung)
            self.assertTrue(any("not an integer 0..1" in x for x in r["reasons"]), bad_rung)

    def test_rung0_needs_no_artifact(self):
        """rung 0 (declared not-observed) is not load-bearing, so it needs no
        capture; a low-tier rung-0 claim can pass under a min_rung-0 policy."""
        pol = {**GOOD_POLICY, "min_rung": {"low": 0, "medium": 1, "high": 1, "critical": 1}}
        claim = {"id": "c1", "risk_tier": "low", "rung": 0, "context": "author",
                 "verdict": "pass", "artifacts": []}
        self.assertEqual(self.run_gate(self.bundle(claim), pol)["verdict"], "pass")

    # --- method: single is fine, unknown method blocks, advisory methods pass ---
    def test_unknown_method_blocks(self):
        claim = {"id": "c1", "risk_tier": "low", "rung": 0, "method": "telepathy",
                 "context": "author", "verdict": "pass", "artifacts": []}
        pol = {**GOOD_POLICY, "min_rung": {"low": 0, "medium": 1, "high": 1, "critical": 1}}
        r = self.run_gate(self.bundle(claim), pol)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("method" in x and "not in" in x for x in r["reasons"]))

    def test_advisory_method_is_recorded_not_gated(self):
        """adversarial/fuzz/property have no mechanical anchor: recorded, never
        enforced. An observation tagged adversarial passes on its own merits."""
        a = self.artifact("cap.txt", "log", b"crash-repro\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "adversarial",
                 "context": "author", "verdict": "pass", "artifacts": [a]}
        self.assertEqual(self.run_gate(self.bundle(claim))["verdict"], "pass")

    def test_differential_method_requires_rung1(self):
        """differential is a way of EVALUATING an observation, so rung 0 + a
        differential is incoherent and blocks."""
        a0 = self.artifact("s0.txt", "s0_capture", b"a\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"b\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 0, "method": "differential",
                 "context": "author", "verdict": "pass", "artifacts": [a0, a1],
                 "differential": {"s0_observed": "a", "s1_observed": "b"}}
        pol = {**GOOD_POLICY, "min_rung": {"low": 0, "medium": 0, "high": 0, "critical": 0}}
        r = self.run_gate(self.bundle(claim), pol)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("requires rung 1" in x for x in r["reasons"]))

    def test_require_method_enforced(self):
        """A policy that demands method=differential at a tier blocks a single
        observation there."""
        a = self.artifact("cap.txt", "log", b"x\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "single",
                 "context": "author", "verdict": "pass", "artifacts": [a]}
        pol = {**GOOD_POLICY, "require_method": {"medium": "differential"}}
        r = self.run_gate(self.bundle(claim), pol)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("requires method=differential" in x for x in r["reasons"]))

    # --- invariance polarity ------------------------------------------------
    def test_invariance_passes_when_unchanged(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"200 OK\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"200 OK\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "verdict": "pass", "expected_delta": "invariance",
                 "artifacts": [a0, a1],
                 "differential": {"s0_observed": "200 OK", "s1_observed": "200 OK"}}
        self.assertEqual(self.run_gate(self.bundle(claim))["verdict"], "pass")

    def test_invariance_blocks_on_unexpected_delta(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"200 OK\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"500 ERR\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "verdict": "pass", "expected_delta": "invariance",
                 "artifacts": [a0, a1],
                 "differential": {"s0_observed": "200 OK", "s1_observed": "500 ERR"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("unexpected S0/S1 delta" in x for x in r["reasons"]))

    def test_change_polarity_blocks_when_no_delta(self):
        """The original anti-gaming rule must survive for change-claims."""
        a0 = self.artifact("s0.txt", "s0_capture", b"ok\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"ok\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "verdict": "pass", "artifacts": [a0, a1],
                 "differential": {"s0_observed": "ok", "s1_observed": "ok"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("no S0/S1 delta" in x for x in r["reasons"]))

    # --- differential polarity is decided by VERIFIED BYTES, not declared text -
    def test_change_identical_bytes_blocks(self):
        """A change-claim whose captures are byte-identical must block even when
        the declared differential lies that they differ (the fabrication that
        previously produced a false pass from genuine, hash-matching artifacts)."""
        a0 = self.artifact("s0.txt", "s0_capture", b"SAME\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"SAME\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "verdict": "pass", "expected_delta": "change",
                 "artifacts": [a0, a1],
                 "differential": {"s0_observed": "banner present", "s1_observed": "banner gone"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("no S0/S1 delta" in x for x in r["reasons"]))
        self.assertTrue(any("contradicts capture bytes" in x for x in r["reasons"]))

    def test_invariance_differing_bytes_blocks(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"A\n")
        a1 = self.artifact("s1.txt", "s1_capture", b"B\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "verdict": "pass", "expected_delta": "invariance",
                 "artifacts": [a0, a1],
                 "differential": {"s0_observed": "same", "s1_observed": "same"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("unexpected S0/S1 delta" in x for x in r["reasons"]))

    def test_polarity_unverifiable_without_both_captures(self):
        """A differential cannot pass if the capture bytes cannot be compared."""
        a0 = self.artifact("s0.txt", "s0_capture", b"A\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "verdict": "pass", "expected_delta": "change",
                 "artifacts": [a0],
                 "differential": {"s0_observed": "a", "s1_observed": "b"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("polarity unverifiable" in x for x in r["reasons"]))

    # --- differential polarity needs ONE unambiguous pair, not role buckets -
    def test_duplicate_role_labels_cannot_fake_invariance(self):
        """Two genuine, distinct, hash-matching files each labeled BOTH
        s0_capture and s1_capture make the role buckets equal as sorted sets
        (sorted(s0)==sorted(s1)) and used to fake `invariance`. Requiring exactly
        one verified capture per role blocks it."""
        a0 = self.artifact("A.txt", "s0_capture", b"AAA\n")
        b0 = self.artifact("B.txt", "s0_capture", b"BBB\n")
        a1 = self.artifact("A.txt", "s1_capture", b"AAA\n")
        b1 = self.artifact("B.txt", "s1_capture", b"BBB\n")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "verdict": "pass", "expected_delta": "invariance",
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
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "verdict": "pass", "expected_delta": "change",
                 "artifacts": [a0, a1, c],
                 "differential": {"s0_observed": "a", "s1_observed": "b"}}
        r = self.run_gate(self.bundle(claim))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("polarity unverifiable" in x for x in r["reasons"]))

    # --- policy value-type: a mistyped-but-present policy fails closed -------
    def test_policy_noninteger_min_rung_is_policy_error(self):
        """min_rung values must be ints 0..1; a string used to crash later on
        `rung < min_rung` (int < str -> TypeError -> exit 1). Now it's caught in
        validate_policy and surfaces as a policy-integrity block, not a crash."""
        bad = dict(GOOD_POLICY)
        bad["min_rung"] = {**GOOD_POLICY["min_rung"], "low": "1"}
        with self.assertRaises(gate.PolicyError):
            gate.validate_policy(bad)

    def test_policy_out_of_range_min_rung_is_policy_error(self):
        """A v1-era min_rung of 4 must now be rejected: the ladder is {0,1}."""
        bad = dict(GOOD_POLICY)
        bad["min_rung"] = {**GOOD_POLICY["min_rung"], "high": 4}
        with self.assertRaises(gate.PolicyError):
            gate.validate_policy(bad)

    def test_policy_bad_context_value_is_policy_error(self):
        bad = dict(GOOD_POLICY)
        bad["require_context"] = {"high": "cross-lab"}  # v1 value, no longer a context
        with self.assertRaises(gate.PolicyError):
            gate.validate_policy(bad)

    def test_policy_bad_qualifier_type_is_policy_error(self):
        bad = dict(GOOD_POLICY)
        bad["require_cross_model"] = {"high": True}  # must be a list of tiers
        with self.assertRaises(gate.PolicyError):
            gate.validate_policy(bad)

    def test_policy_require_context_bad_tier_key_is_policy_error(self):
        """A typo'd tier key in require_context (e.g. `hihg`) must fail closed, not
        silently leave the intended tier without an independence requirement.
        Mirrors the tier-key validation already done for min_rung / no_skip_tiers /
        require_cross_model / require_method."""
        bad = dict(GOOD_POLICY)
        bad["require_context"] = {"hihg": "independent"}
        with self.assertRaises(gate.PolicyError):
            gate.validate_policy(bad)

    def test_policy_bool_min_rung_is_policy_error(self):
        """`True`/`False` are ints in Python; a bool min_rung must be rejected so a
        JSON `true` cannot masquerade as a floor of 1 (or `false` as 0)."""
        for bad_val in (True, False):
            bad = dict(GOOD_POLICY)
            bad["min_rung"] = {**GOOD_POLICY["min_rung"], "low": bad_val}
            with self.assertRaises(gate.PolicyError):
                gate.validate_policy(bad)

    def test_policy_bad_type_blocks_not_crashes(self):
        """End to end: a mistyped policy exits BLOCK (30), never a traceback/1."""
        p = self.tmp / "b.json"
        p.write_text(json.dumps(self.bundle(
            {"id": "c1", "risk_tier": "medium", "rung": 1, "context": "author",
             "verdict": "pass", "artifacts": []})))
        pol = self.tmp / "p.json"
        pol.write_text(json.dumps({**GOOD_POLICY,
                                   "min_rung": {**GOOD_POLICY["min_rung"], "low": "1"}}))
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

    def test_v1_bundle_is_refused(self):
        """A v1 bundle is refused with a clear regenerate message (exit 2), not
        silently blocked: v2 changed the meaning of the integers."""
        p = self.tmp / "v1.json"
        p.write_text(json.dumps({"schema": "evidence-bundle/v1", "claims": []}))
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = gate.main([str(p)])
        self.assertEqual(rc, gate.EXIT_USAGE)
        self.assertIn("regenerate", err.getvalue().lower())

    def test_missing_verdict_blocks_not_crashes(self):
        a0 = self.artifact("s0.txt", "s0_capture", b"x")
        a1 = self.artifact("s1.txt", "s1_capture", b"y")
        claim = {"id": "c1", "risk_tier": "medium", "rung": 1, "method": "differential",
                 "context": "author", "artifacts": [a0, a1],
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

    # --- the SHIPPED default keeps its calibrated teeth ---------------------
    def test_default_policy_ships_calibrated_qualifiers(self):
        """A regression that drops a tier from the default's qualifier lists would
        silently weaken every operator who relies on it, so pin the shipped shape:
        observed everywhere, cross-model at high+critical, cross-lab at critical."""
        self.assertEqual(DEFAULT_POLICY["min_rung"],
                         {"low": 1, "medium": 1, "high": 1, "critical": 1})
        self.assertEqual(DEFAULT_POLICY["require_cross_model"], ["high", "critical"])
        self.assertEqual(DEFAULT_POLICY["require_cross_lab"], ["critical"])

    def test_default_policy_critical_demands_cross_lab(self):
        """Behavioral: under the SHIPPED default, a critical observation that is
        independent AND cross-model-attested but carries no cross-lab attestation
        still blocks: critical demands a cross-lab qualifier. Isolates the
        cross-lab teeth: every other check (min_rung, context, cross-model) passes,
        so the sole block reason is the missing cross-lab attestation."""
        a = self.artifact("cap.txt", "capture", b"observed\n")
        # cross-model ok and byte-bound (artifact_shas == the one verified hash),
        # but no lab: the sole remaining teeth are cross-lab.
        att = {"model": "reviewer-model", "verdict": "pass",
               "artifact_shas": [a["sha256"]]}
        claim = {"id": "c1", "risk_tier": "critical", "rung": 1, "method": "single",
                 "context": "independent", "verdict": "pass", "artifacts": [a],
                 "attestation": att}
        b = self.bundle(claim)
        b["change"]["producer"] = {"lab": "example-lab", "model": "prod-model"}
        r = self.run_gate(b, DEFAULT_POLICY)
        self.assertEqual(r["verdict"], "block", r["reasons"])
        self.assertTrue(any("cross-lab attestation" in x for x in r["reasons"]), r["reasons"])


class SelfHashProvenanceCase(unittest.TestCase):
    """Provenance (`gate_sha256`) must survive the packaging shape. A normal
    `pip install` unzips the wheel to real files, but running the gate from a
    wheel/zipapp on the path imports it via zipimport, where `__file__` points
    inside the archive and a plain filesystem read fails. The self-hash has to
    fall back to the module loader so `gate_sha256` stays non-null and
    byte-identical across install shapes; otherwise an install-shape differential
    blocks on a spurious null-vs-hash delta. This regression was found by
    dogfooding rung on its own packaging.
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
        reordering. Run under the bundled default policy (no policy arg)."""
        bundle = {
            "schema": "evidence-bundle/v2",
            "change": {"producer": {"lab": "lab-alpha"}},
            "claims": [
                {"id": "c1", "risk_tier": "high", "rung": 0,
                 "context": "author", "verdict": "fail"},
                {"id": "c2", "risk_tier": "critical", "rung": 1,
                 "context": "author", "verdict": "skip", "artifacts": []},
                {"id": "c3", "risk_tier": "medium", "rung": 0,
                 "context": "independent", "verdict": "pass", "artifacts": []},
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


class QualifierCase(unittest.TestCase):
    """v2: cross-model and cross-lab are decorrelation QUALIFIERS, not contexts.
    CONTEXT is the 2-value ordinal ladder {author, independent}; require_context
    enforces the floor. A required qualifier (require_cross_model /
    require_cross_lab, keyed by tier) additionally demands context=independent
    AND the qualifier's structural presence in the attestation (a reviewer
    model/lab that differs from the producer's, verdict=pass): presence, not
    authenticity, the same S1 residual as before.

    A required qualifier is also byte-bound: the attestation must carry
    artifact_shas equal to the gate's verified capture hashes, so a happy-path
    claim materializes a real capture and anchors to it. Structural-failure
    claims stay artifact-free (the anchor reason is additive, so their specific
    reason still fires). min_rung is relaxed to 0 to isolate the CONTEXT/qualifier
    checks from the rung/artifact/polarity checks."""

    PRODUCER_MODEL = "prod-model-x"
    REVIEWER_MODEL = "other-model-y"

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="rung-qualifier-"))

    # Demands a cross-model qualifier at `high`, rung floors relaxed to 0.
    POLICY = {
        "version": 2,
        "min_rung": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "require_context": {"high": "independent"},
        "require_cross_model": ["high"],
        "no_skip_tiers": [],
        "allow_dismiss_gaps": False,
    }
    # Demands a cross-lab qualifier at `high`.
    LAB_POLICY = {
        "version": 2,
        "min_rung": {"low": 0, "medium": 0, "high": 0, "critical": 0},
        "require_context": {"high": "independent"},
        "require_cross_lab": ["high"],
        "no_skip_tiers": [],
        "allow_dismiss_gaps": False,
    }

    def cm_bundle(self, claim, producer_model=PRODUCER_MODEL, lab="example-lab"):
        producer = {"lab": lab}
        if producer_model is not None:
            producer["model"] = producer_model
        return {
            "schema": "evidence-bundle/v2",
            "change": {"repo": "x", "s0": "s0", "s1": "s1", "producer": producer},
            "claims": [claim],
            "gaps": [],
        }

    def cm_claim(self, ctx, att, tier="high", artifacts=None):
        c = {"id": "c1", "risk_tier": tier, "rung": 0, "context": ctx, "verdict": "pass"}
        if att is not None:
            c["attestation"] = att
        if artifacts is not None:
            c["artifacts"] = artifacts
        return c

    def anchored_artifact(self, name="cap.txt", body="observed-bytes\n"):
        """Write a real capture under the bundle base and return (artifact, sha).
        A byte-bound qualifier needs the attestation's artifact_shas to equal the
        gate's verified hashes, so happy-path attestations anchor to this sha."""
        p = self.tmp / name
        p.write_text(body)
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        return {"id": "a1", "role": "stdout_capture", "uri": name, "sha256": sha}, sha

    def gate_cm(self, claim, producer_model=PRODUCER_MODEL, policy=None):
        return gate.gate(self.cm_bundle(claim, producer_model=producer_model),
                         policy or self.POLICY, self.tmp)

    # --- cross-model happy paths --------------------------------------------
    def test_cross_model_single_reviewer_passes(self):
        art, sha = self.anchored_artifact()
        att = {"model": self.REVIEWER_MODEL, "verdict": "pass", "artifact_shas": [sha]}
        r = self.gate_cm(self.cm_claim("independent", att, artifacts=[art]))
        self.assertEqual(r["verdict"], "pass", r["reasons"])

    def test_cross_model_panel_passes(self):
        art, sha = self.anchored_artifact()
        att = {"verdict": "pass", "artifact_shas": [sha], "panel": [
            {"model": "model-a", "verdict": "pass"},
            {"model": "model-b", "verdict": "pass"},
        ]}
        r = self.gate_cm(self.cm_claim("independent", att, artifacts=[art]))
        self.assertEqual(r["verdict"], "pass", r["reasons"])

    # --- the qualifier must be byte-bound to THESE captures -----------------
    def test_cross_model_unanchored_blocks_additively(self):
        """A structurally-valid reviewer whose attestation omits artifact_shas is
        not byte-bound: the qualifier blocks, and the reason is additive (the
        reviewer checks are not short-circuited)."""
        art, _sha = self.anchored_artifact()
        att = {"model": self.REVIEWER_MODEL, "verdict": "pass"}  # no artifact_shas
        r = self.gate_cm(self.cm_claim("independent", att, artifacts=[art]))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("not byte-bound" in x for x in r["reasons"]), r["reasons"])

    def test_cross_model_forged_binding_blocks(self):
        """artifact_shas present but not equal to the verified hashes (a verdict
        transplanted from another bundle) does not anchor."""
        art, _sha = self.anchored_artifact()
        att = {"model": self.REVIEWER_MODEL, "verdict": "pass",
               "artifact_shas": ["0" * 64]}
        r = self.gate_cm(self.cm_claim("independent", att, artifacts=[art]))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("not byte-bound" in x for x in r["reasons"]), r["reasons"])

    def test_cross_model_empty_anchor_does_not_clear(self):
        """An empty artifact_shas binds the verdict to no bytes; with a zero-artifact
        claim both sides would be the empty set, so an empty anchor must NOT pass."""
        att = {"model": self.REVIEWER_MODEL, "verdict": "pass", "artifact_shas": []}
        r = self.gate_cm(self.cm_claim("independent", att))  # no artifacts either
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("not byte-bound" in x for x in r["reasons"]), r["reasons"])

    # --- the qualifier needs an independent context -------------------------
    def test_cross_model_author_context_blocks(self):
        """A required cross-model qualifier cannot ride on an author context."""
        att = {"model": self.REVIEWER_MODEL, "verdict": "pass"}
        r = self.gate_cm(self.cm_claim("author", att))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("needs context=independent" in x for x in r["reasons"]))

    # --- cross-model structural failures (presence check) -------------------
    def test_cross_model_reviewer_equals_producer_blocks(self):
        att = {"model": self.PRODUCER_MODEL, "verdict": "pass"}
        r = self.gate_cm(self.cm_claim("independent", att))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("equals the producer model" in x for x in r["reasons"]))

    def test_cross_model_reviewer_not_pass_blocks(self):
        att = {"model": self.REVIEWER_MODEL, "verdict": "fail"}
        r = self.gate_cm(self.cm_claim("independent", att))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("need pass" in x for x in r["reasons"]))

    def test_cross_model_missing_attestation_blocks(self):
        r = self.gate_cm(self.cm_claim("independent", None))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("needs a cross-model attestation" in x for x in r["reasons"]))

    def test_cross_model_missing_producer_model_blocks(self):
        """model independence is undefined without knowing the producer's model."""
        att = {"model": self.REVIEWER_MODEL, "verdict": "pass"}
        r = self.gate_cm(self.cm_claim("independent", att), producer_model=None)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("needs change.producer.model" in x for x in r["reasons"]))

    def test_cross_model_panel_one_bad_reviewer_blocks(self):
        """A panel where even one reviewer shares the producer's model fails: the
        floor is ALL reviewers != producer, each verdict=pass."""
        att = {"verdict": "pass", "panel": [
            {"model": "model-a", "verdict": "pass"},
            {"model": self.PRODUCER_MODEL, "verdict": "pass"},
        ]}
        r = self.gate_cm(self.cm_claim("independent", att))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("equals the producer model" in x for x in r["reasons"]))

    def test_cross_model_panel_entry_missing_verdict_blocks(self):
        """A malformed panel entry (no verdict) fails closed, not silently pass."""
        att = {"verdict": "pass", "panel": [{"model": "model-a"}]}
        r = self.gate_cm(self.cm_claim("independent", att))
        self.assertEqual(r["verdict"], "block")

    def test_cross_model_empty_panel_blocks(self):
        att = {"verdict": "pass", "panel": []}
        r = self.gate_cm(self.cm_claim("independent", att))
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("needs a cross-model attestation" in x for x in r["reasons"]))

    # --- cross-lab qualifier ------------------------------------------------
    def test_cross_lab_qualifier_passes(self):
        art, sha = self.anchored_artifact()
        att = {"lab": "other-lab", "verdict": "pass", "artifact_shas": [sha]}
        r = self.gate_cm(self.cm_claim("independent", att, artifacts=[art]),
                         policy=self.LAB_POLICY)
        self.assertEqual(r["verdict"], "pass", r["reasons"])

    def test_cross_lab_unanchored_blocks(self):
        """A structurally-valid cross-lab attestation that omits artifact_shas is
        not byte-bound: it blocks even though the lab differs and verdict=pass."""
        art, _sha = self.anchored_artifact()
        att = {"lab": "other-lab", "verdict": "pass"}  # no artifact_shas
        r = self.gate_cm(self.cm_claim("independent", att, artifacts=[art]),
                         policy=self.LAB_POLICY)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("not byte-bound" in x for x in r["reasons"]), r["reasons"])

    def test_cross_lab_same_lab_blocks(self):
        att = {"lab": "example-lab", "verdict": "pass"}  # == producer lab
        r = self.gate_cm(self.cm_claim("independent", att), policy=self.LAB_POLICY)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("cross-lab attestation" in x for x in r["reasons"]))

    def test_cross_lab_author_context_blocks(self):
        att = {"lab": "other-lab", "verdict": "pass"}
        r = self.gate_cm(self.cm_claim("author", att), policy=self.LAB_POLICY)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("needs context=independent" in x for x in r["reasons"]))

    # --- context floor ------------------------------------------------------
    def test_author_rejected_under_independent_requirement(self):
        """A require_context floor of independent rejects an author context even
        with no qualifier demanded."""
        policy = {**self.POLICY, "require_cross_model": []}
        r = self.gate_cm(self.cm_claim("author", None), policy=policy)
        self.assertEqual(r["verdict"], "block")
        self.assertTrue(any("requires context >= independent" in x for x in r["reasons"]))

    def test_independent_satisfies_floor_with_no_qualifier(self):
        policy = {**self.POLICY, "require_cross_model": []}
        r = self.gate_cm(self.cm_claim("independent", None), policy=policy)
        self.assertEqual(r["verdict"], "pass", r["reasons"])

    def test_policy_accepts_qualifier_keys(self):
        gate.validate_policy(self.POLICY)     # must not raise
        gate.validate_policy(self.LAB_POLICY)  # must not raise


if __name__ == "__main__":
    unittest.main(verbosity=2)
