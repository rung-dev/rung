#!/usr/bin/env python3
"""Conformance tests for `rung attest`: amend an existing bundle with an
independent reviewer's attestation, re-gate in-process, exit with the gate's
verdict.

attest is driven as `python -m rung.attest` (a real subprocess) so the exit-code
contract and stdout/stderr discipline are tested end to end. A few gate-level
properties (the disclosed medium boundary, forged-binding rejection) are asserted
by calling the gate directly, since attest cannot itself produce those shapes.
"""
import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src"
DEFAULT_POLICY = REPO / "policy" / "default.json"
ATTEST_ARGV = [sys.executable, "-m", "rung.attest"]

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
import rung.gate as gate  # for gate-level assertions + shared constants


def _env_with_src(extra: dict = None) -> dict:
    e = dict(os.environ)
    e["PYTHONPATH"] = str(SRC) + os.pathsep + e.get("PYTHONPATH", "")
    if extra:
        e.update(extra)
    return e


class AttestConformance(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.tmp = Path(self._td.name)

    def tearDown(self):
        self._td.cleanup()

    # -- fixtures -----------------------------------------------------------
    def artifact(self, name="cap.txt", body="observed-bytes\n"):
        p = self.tmp / name
        p.write_text(body)
        sha = hashlib.sha256(body.encode()).hexdigest()
        return {"id": name, "role": "stdout_capture", "uri": name, "sha256": sha}, sha

    def claim(self, cid="c1", tier="medium", rung=1, arts=None, **extra):
        c = {"id": cid, "claim": "did a thing", "risk_tier": tier, "rung": rung,
             "context": "author", "method": "single", "verdict": "pass"}
        if arts is not None:
            c["artifacts"] = arts
        c.update(extra)
        return c

    def bundle(self, claims, producer_model=None, producer_lab="lab-a"):
        producer = {"agent": "rung-run", "lab": producer_lab}
        if producer_model is not None:
            producer["model"] = producer_model
        return {"schema": "evidence-bundle/v2",
                "change": {"repo": "x", "s0": "s0", "s1": "s1", "producer": producer},
                "claims": claims, "gaps": []}

    def write_bundle(self, b, name="bundle.json") -> Path:
        p = self.tmp / name
        p.write_text(json.dumps(b, indent=2))
        return p

    def attest(self, *args, stdin: str = None):
        return subprocess.run(
            ATTEST_ARGV + list(args), cwd=self.tmp,
            input=stdin, capture_output=True, text=True, env=_env_with_src(),
        )

    def out_bundle(self, r) -> dict:
        return json.loads(r.stdout)

    # -- happy paths --------------------------------------------------------
    def test_medium_author_lifts_to_independent_ships(self):
        """AC2: a medium author bundle attested by a different model ships."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 0, r.stderr)
        b = self.out_bundle(r)
        c = b["claims"][0]
        self.assertEqual(c["context"], "independent")
        self.assertEqual(c["attestation"]["model"], "reviewer-m")
        self.assertIn("artifact_shas", c["attestation"])  # present artifacts -> anchored

    def test_high_cross_model_anchored_satisfies(self):
        """AC3: an anchored single-model attestation from a different model clears
        the cross-model qualifier at high."""
        art, sha = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="high", arts=[art])],
                                           producer_model="producer-m"))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 0, r.stderr)
        c = self.out_bundle(r)["claims"][0]
        self.assertEqual(c["attestation"]["artifact_shas"], [sha])

    def test_critical_cross_lab_single_model_satisfies(self):
        """AC4: single --model + --lab != producer lab, anchored, clears critical."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="critical", arts=[art])],
                                           producer_model="producer-m", producer_lab="lab-a"))
        r = self.attest("--model", "reviewer-m", "--lab", "lab-b",
                        "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 0, r.stderr)
        c = self.out_bundle(r)["claims"][0]
        self.assertEqual(c["attestation"]["lab"], "lab-b")

    def test_panel_cannot_reach_critical(self):
        """AC4: a panel carries no lab, so it cannot satisfy cross-lab. Cross-model
        is satisfied, but critical still blocks (exit 30, bundle written)."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="critical", arts=[art])],
                                           producer_model="producer-m"))
        r = self.attest("--panel", "m1:pass,m2:pass", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        c = self.out_bundle(r)["claims"][0]
        self.assertIn("panel", c["attestation"])
        self.assertNotIn("lab", c["attestation"])

    def test_panel_cross_model_high_satisfies_no_top_model(self):
        """AC8: a panel writes panel[] with no top-level model; two distinct models
        clear cross-model at high."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="high", arts=[art])],
                                           producer_model="producer-m"))
        r = self.attest("--panel", "m1:pass,m2:pass", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 0, r.stderr)
        att = self.out_bundle(r)["claims"][0]["attestation"]
        self.assertEqual([e["model"] for e in att["panel"]], ["m1", "m2"])
        self.assertNotIn("model", att)

    # -- anchor / transplant defense ---------------------------------------
    def test_unanchored_absent_cross_model_blocks(self):
        """AC5: artifacts declared but unreachable -> unanchored downgrade; the
        cross-model qualifier is not cleared, so the gate blocks (exit 30). The
        bundle is written with the fixed disclosure note."""
        art, _ = self.artifact()
        (self.tmp / "cap.txt").unlink()  # make the declared artifact unreachable
        bp = self.write_bundle(self.bundle([self.claim(tier="high", arts=[art])],
                                           producer_model="producer-m"))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        att = self.out_bundle(r)["claims"][0]["attestation"]
        self.assertNotIn("artifact_shas", att)
        self.assertEqual(att["artifact_shas_note"],
                         "reviewer had no artifact access; verdict not byte-bound")

    def test_mismatch_refuses(self):
        """AC5/AC9: artifact present but recomputed sha != recorded -> refuse, exit
        2, empty stdout (integrity violation, no knob)."""
        art, _ = self.artifact()
        art["sha256"] = "0" * 64  # bundle records a sha the file does not have
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_require_artifacts_absent_refuses(self):
        """AC9: --require-artifacts flips the absent case from downgrade to refuse."""
        art, _ = self.artifact()
        (self.tmp / "cap.txt").unlink()
        bp = self.write_bundle(self.bundle([self.claim(tier="high", arts=[art])],
                                           producer_model="producer-m"))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass",
                        "--require-artifacts", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_gate_enforces_forged_binding(self):
        """AC5 (gate level): a bundle whose artifact_shas is present but not
        set-equal to the verified shas fails the qualifier, independent of attest."""
        art, _ = self.artifact()
        c = self.claim(tier="high", arts=[art], context="independent",
                       attestation={"model": "reviewer-m", "verdict": "pass",
                                    "artifact_shas": ["0" * 64]})
        b = self.bundle([c], producer_model="producer-m")
        policy = json.loads(DEFAULT_POLICY.read_text())
        res = gate.gate(b, policy, self.tmp)
        self.assertEqual(res["verdict"], "block")
        self.assertTrue(any("not byte-bound" in x for x in res["reasons"]), res["reasons"])

    def test_gate_medium_unanchored_still_ships(self):
        """AC6 (gate level, disclosed boundary): a medium claim with present
        artifacts and an attestation lacking artifact_shas still ships, because
        require_context checks the context value only."""
        art, _ = self.artifact()
        c = self.claim(tier="medium", arts=[art], context="independent",
                       attestation={"model": "reviewer-m", "verdict": "pass"})
        b = self.bundle([c])
        policy = json.loads(DEFAULT_POLICY.read_text())
        res = gate.gate(b, policy, self.tmp)
        self.assertEqual(res["verdict"], "pass", res["reasons"])

    # -- conditional model-independence floor ------------------------------
    def test_same_model_at_cross_model_tier_refuses(self):
        """AC9: reviewer model == producer model at a cross-model tier -> refuse."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="high", arts=[art])],
                                           producer_model="same-m"))
        r = self.attest("--model", "same-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_missing_producer_model_at_cross_model_tier_refuses(self):
        """AC9: no producer model at a cross-model tier -> refuse (independence
        undefined)."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="high", arts=[art])]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_same_model_at_medium_still_lifts(self):
        """AC9: the model floor is conditional; at medium (no cross-model required)
        a same-model attestation still lifts to independent."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])],
                                           producer_model="same-m"))
        r = self.attest("--model", "same-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.out_bundle(r)["claims"][0]["context"], "independent")

    def test_no_producer_model_at_medium_lifts(self):
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 0, r.stderr)

    # -- claim selection ----------------------------------------------------
    def test_multiclaim_without_claim_id_refuses(self):
        """AC7: a 2+-claim bundle needs --claim-id."""
        a1, _ = self.artifact("c1.txt")
        a2, _ = self.artifact("c2.txt")
        bp = self.write_bundle(self.bundle([
            self.claim("c1", tier="medium", arts=[a1]),
            self.claim("c2", tier="medium", arts=[a2]),
        ]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_claim_id_amends_only_target(self):
        """AC7: with --claim-id, only that claim is amended (context + attestation);
        the sibling stays author with no attestation."""
        a1, _ = self.artifact("c1.txt")
        a2, _ = self.artifact("c2.txt")
        bp = self.write_bundle(self.bundle([
            self.claim("c1", tier="low", arts=[a1]),
            self.claim("c2", tier="low", arts=[a2]),
        ]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass",
                        "--claim-id", "c2", str(bp))
        self.assertEqual(r.returncode, 0, r.stderr)
        claims = {c["id"]: c for c in self.out_bundle(r)["claims"]}
        self.assertEqual(claims["c1"]["context"], "author")
        self.assertNotIn("attestation", claims["c1"])
        self.assertEqual(claims["c2"]["context"], "independent")
        self.assertIn("attestation", claims["c2"])

    def test_claim_id_no_match_refuses(self):
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim("c1", tier="medium", arts=[art])]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass",
                        "--claim-id", "nope", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_claim_id_matches_multiple_refuses(self):
        a1, _ = self.artifact("c1.txt")
        a2, _ = self.artifact("c2.txt")
        bp = self.write_bundle(self.bundle([
            self.claim("dup", tier="medium", arts=[a1]),
            self.claim("dup", tier="medium", arts=[a2]),
        ]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass",
                        "--claim-id", "dup", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    # -- flag grammar -------------------------------------------------------
    def test_model_and_panel_mutually_exclusive(self):
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--model", "m", "--panel", "a:pass", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_neither_model_nor_panel_refuses(self):
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_verdict_required(self):
        """AC13: --verdict has no default; omitting it is a usage error, exit 2."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--model", "reviewer-m", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_panel_malformed_token_refuses(self):
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--panel", "m1pass", "--verdict", "pass", str(bp))  # no colon
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_panel_bad_verdict_refuses(self):
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--panel", "m1:bogus", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_panel_pass_over_dissenting_member_refuses(self):
        """A pass aggregate cannot sit over a non-pass panel member. At medium the
        gate never inspects members, so attest refuses the incoherent record itself
        (exit 2, writes nothing) rather than shipping a laundered independent pass."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--panel", "m1:pass,m2:fail", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertEqual(r.stdout, "")

    def test_panel_fail_aggregate_over_pass_members_allowed(self):
        """A fail/blocked aggregate is the operator lowering trust and is allowed
        regardless of member verdicts; it is recorded and the re-gate blocks (30)."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--panel", "m1:pass,m2:pass", "--verdict", "fail", str(bp))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        self.assertEqual(self.out_bundle(r)["claims"][0]["attestation"]["verdict"], "fail")

    def test_lab_with_panel_refuses(self):
        """--lab applies to the single-reviewer form; a panel has no single lab."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--panel", "m1:pass", "--lab", "lab-b", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    # -- verdict laundering / no-launder -----------------------------------
    def test_failing_verdict_no_launder(self):
        """AC10: a failing verdict is recorded but the gate blocks on it."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--model", "reviewer-m", "--verdict", "fail", str(bp))
        self.assertEqual(r.returncode, 30, r.stdout + r.stderr)
        self.assertEqual(self.out_bundle(r)["claims"][0]["attestation"]["verdict"], "fail")

    # -- bundle validity ----------------------------------------------------
    def test_malformed_bundle_refuses(self):
        bp = self.tmp / "bad.json"
        bp.write_text("{ not json")
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_v1_bundle_refuses(self):
        art, _ = self.artifact()
        b = self.bundle([self.claim(tier="medium", arts=[art])])
        b["schema"] = "evidence-bundle/v1"
        bp = self.write_bundle(b)
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    # -- how_established augmentation ---------------------------------------
    def test_how_established_augmented_not_replaced(self):
        art, _ = self.artifact()
        c = self.claim(tier="medium", arts=[art],
                       how_established="rung run drove the cli surface directly.")
        bp = self.write_bundle(self.bundle([c]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 0, r.stderr)
        he = self.out_bundle(r)["claims"][0]["how_established"]
        self.assertIn("rung run drove the cli surface directly.", he)
        self.assertIn("reviewer-m", he)

    def test_how_established_absent_gets_clause(self):
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("reviewer-m", self.out_bundle(r)["claims"][0]["how_established"])

    # -- policy passthrough, determinism, stdin -----------------------------
    def test_policy_passthrough_matches_gate(self):
        """AC11: attest's exit code matches `rung gate` under the same policy, run
        over the amended bundle written to a file (gate has no stdin)."""
        art, _ = self.artifact()
        # A custom policy: medium demands independent, no cross-model anywhere.
        policy = {"version": 2,
                  "min_rung": {"low": 1, "medium": 1, "high": 1, "critical": 1},
                  "require_context": {"medium": "independent"},
                  "no_skip_tiers": [], "allow_dismiss_gaps": False}
        pp = self.tmp / "policy.json"
        pp.write_text(json.dumps(policy))
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", str(bp), str(pp))
        self.assertEqual(r.returncode, 0, r.stderr)
        amended = self.tmp / "amended.json"
        amended.write_text(r.stdout)
        g = subprocess.run(
            [sys.executable, "-m", "rung.gate", str(amended), str(pp)],
            cwd=self.tmp, capture_output=True, text=True, env=_env_with_src(),
        )
        self.assertEqual(g.returncode, r.returncode)

    def test_tier_override_passthrough(self):
        """AC11: --tier participates in both attest's floor/gate and a downstream
        gate call."""
        art, _ = self.artifact()
        # Recorded as low, overridden to high: needs cross-model, producer model set.
        bp = self.write_bundle(self.bundle([self.claim(tier="low", arts=[art])],
                                           producer_model="producer-m"))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", "--tier", "high", str(bp))
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_tier_override_not_persisted_in_emitted_bundle(self):
        """--tier is a re-gate knob, not a bundle edit: the emitted bundle keeps the
        authored risk_tier on the target AND on un-attested siblings, so a review
        cannot silently downgrade a recorded tier downstream."""
        a1, _ = self.artifact("a1.txt", "one\n")
        a2, _ = self.artifact("a2.txt", "two\n")
        bp = self.write_bundle(self.bundle([
            self.claim("c1", tier="critical", arts=[a1]),
            self.claim("c2", tier="low", arts=[a2]),
        ]))
        r = self.attest("--model", "reviewer-m", "--verdict", "pass",
                        "--tier", "low", "--claim-id", "c2", str(bp))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        claims = {c["id"]: c for c in self.out_bundle(r)["claims"]}
        self.assertEqual(claims["c1"]["risk_tier"], "critical",
                         "un-attested sibling's recorded tier must be untouched")
        self.assertEqual(claims["c1"]["context"], "author")
        self.assertEqual(claims["c2"]["risk_tier"], "low",
                         "the target's authored tier must survive the --tier re-gate")
        self.assertEqual(claims["c2"]["context"], "independent")

    def test_skip_verdict_rejected(self):
        """A skipped review is not an affirming independent review: --verdict skip is
        not a valid reviewer verdict (argparse rejects it), exit 2, empty stdout."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--model", "reviewer-m", "--verdict", "skip", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_panel_skip_verdict_rejected(self):
        """A panel member cannot vote skip either."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="medium", arts=[art])]))
        r = self.attest("--panel", "modelA:pass,modelB:skip", "--verdict", "pass", str(bp))
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, "")

    def test_determinism_identical_bytes(self):
        """AC12: same bundle + same flags -> identical stdout bytes + exit."""
        art, _ = self.artifact()
        bp = self.write_bundle(self.bundle([self.claim(tier="high", arts=[art])],
                                           producer_model="producer-m"))
        r1 = self.attest("--panel", "m1:pass,m2:pass", "--verdict", "pass", str(bp))
        r2 = self.attest("--panel", "m1:pass,m2:pass", "--verdict", "pass", str(bp))
        self.assertEqual(r1.stdout, r2.stdout)
        self.assertEqual(r1.returncode, r2.returncode)

    def test_stdin_input(self):
        """Bundle read from stdin ('-') produces the same lift as a path input."""
        art, _ = self.artifact()
        b = self.bundle([self.claim(tier="medium", arts=[art])])
        r = self.attest("--model", "reviewer-m", "--verdict", "pass", "-",
                        stdin=json.dumps(b))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.out_bundle(r)["claims"][0]["context"], "independent")


if __name__ == "__main__":
    unittest.main(verbosity=2)
