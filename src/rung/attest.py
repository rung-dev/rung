#!/usr/bin/env python3
"""rung attest: record an independent reviewer's attestation on an existing
`evidence-bundle/v2` bundle, then re-gate it in-process.

attest is the only way to lift a claim from `author` to `independent`. It takes a
bundle a producer already made (via `rung run`, or by hand), attaches a reviewer's
verdict for exactly one claim, sets that claim's context to `independent`, and runs
the amended bundle back through the gate. Its exit code is the gate's verdict code,
so `rung attest ... | (save) | rung gate ...` agree.

The gate only ever lowers trust, and so does attest: a declared reviewer pass is
not minted into a gate pass; the gate still decides. attest refuses (exit 2, writes
nothing) when the request is incoherent (reviewer model equals the producer's at a
tier that demands model independence, the reviewer's recomputed artifact hash does
not match the bundle's, a malformed or v1 bundle, a multi-claim bundle with no
resolving --claim-id, --model with --panel). When the reviewer legitimately could
not read the artifacts, it does NOT refuse and does NOT mint a byte-bound pass:
it records the attestation unanchored with a fixed disclosure note, and the gate
then blocks at any tier that requires a byte-bound qualifier.

Reviewer byte-binding: an anchored attestation carries `artifact_shas`, the sorted
set of the target claim's artifact sha256 values the reviewer verified. The gate
compares that set against the hashes it re-verifies, so a reviewer's verdict cannot
be transplanted onto a different bundle. This is accountable, not unforgeable: that
the recorded bytes are the ones the reviewer saw rests on attest running where the
review happened, not on any cryptographic claim.

stdlib-only, deterministic: same (bundle, flags) yields the same amended bytes and
the same exit code. Exit codes: 0 pass, 30 block, 2 usage / cannot-evaluate.
"""
from __future__ import annotations
import argparse
import copy
import json
import sys
from pathlib import Path

from . import gate

# Fixed disclosure recorded when a reviewer had no access to the claim's artifacts.
# A fixed literal (no path, hostname, or timestamp) so the amended bytes stay
# deterministic; it also feeds the gate's unanchored-qualifier reason.
ARTIFACT_SHAS_NOTE = "reviewer had no artifact access; verdict not byte-bound"

# A reviewer states one of these, a strict subset of the gate's claim VERDICTS: an
# affirming pass, or a non-affirming fail/blocked that lowers the claim so the gate
# blocks. `skip` is excluded on purpose: a reviewer who skipped did not perform an
# independent review, so it must not lift a claim to a shippable independent pass
# (under a policy with no no_skip tier a skip claim verdict does not block, so
# accepting it would launder a non-review into independence).
ATTEST_VERDICTS = tuple(v for v in gate.VERDICTS if v != "skip")


class AttestError(Exception):
    """The request is incoherent or the input is unusable: refuse, exit 2."""


def _parse(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="rung attest",
        description="Record an independent reviewer's attestation on a bundle and re-gate it.",
    )
    who = p.add_mutually_exclusive_group(required=True)
    who.add_argument("--model", default=None,
                     help="Single reviewer model. The gate requires this != change.producer.model "
                          "at any tier that demands a cross-model qualifier.")
    who.add_argument("--panel", default=None, metavar="model:verdict,model:verdict",
                     help="Multi-reviewer panel as comma-separated model:verdict pairs. A "
                          "--verdict pass requires every member to pass; a dissenting member is "
                          "refused. A panel carries no lab, so it cannot satisfy a cross-lab "
                          "qualifier; use a single --model with --lab for that.")
    p.add_argument("--verdict", required=True, choices=ATTEST_VERDICTS,
                   help="The reviewer's verdict (required, no default): pass, fail, or blocked. "
                        "fail/blocked still block; skip is not a reviewer verdict (do not attest).")
    p.add_argument("--lab", default=None,
                   help="Reviewing lab for a single --model attestation. For a required cross-lab "
                        "qualifier the gate requires this != change.producer.lab. Not valid with --panel.")
    p.add_argument("--claim-id", default=None, dest="claim_id",
                   help="Which claim to attest. Required when the bundle has more than one claim; "
                        "must match exactly one.")
    p.add_argument("--require-artifacts", action="store_true", dest="require_artifacts",
                   help="Refuse (exit 2) rather than record an unanchored attestation when the "
                        "claim's artifacts cannot be read. Default: disclosed downgrade.")
    p.add_argument("--tier", default=None, choices=gate.TIERS,
                   help="Override every claim's risk_tier for the re-gate (mirrors `rung gate --tier`).")
    p.add_argument("bundle", nargs="?", default=None,
                   help="Bundle path, or - for stdin (default: stdin).")
    p.add_argument("policy", nargs="?", default=None,
                   help="Policy JSON (default: the bundled default policy).")
    return p.parse_args(argv)


def _read_bundle(bundle_arg):
    """Return (bundle, base_dir). base_dir is where the claim's artifacts resolve:
    the bundle file's parent for a path input, the cwd for stdin."""
    if bundle_arg is None or bundle_arg == "-":
        raw = sys.stdin.buffer.read()
        if len(raw) > gate.MAX_INPUT_BYTES:
            raise AttestError(f"bundle on stdin exceeds {gate.MAX_INPUT_BYTES} bytes")
        try:
            return json.loads(raw), Path(".").resolve()
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as e:
            raise AttestError(f"cannot parse bundle on stdin: {type(e).__name__}: {e}")
    path = Path(bundle_arg)
    try:
        bundle = gate._read_json(path, "bundle")
    except gate.GateInputError as e:
        raise AttestError(str(e))
    return bundle, path.resolve().parent


def _load_policy(policy_arg) -> dict:
    try:
        if policy_arg is not None:
            return gate._read_json(Path(policy_arg), "policy")
        with gate.default_policy_path() as pp:
            return gate._read_json(pp, "policy")
    except gate.GateInputError as e:
        raise AttestError(str(e))


def _parse_panel(spec: str) -> list:
    """Parse `model:verdict,model:verdict` into ordered (model, verdict) pairs.
    Input order is preserved (no sort, no dedup) so the amended bytes are stable."""
    pairs = []
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            raise AttestError("--panel has an empty entry (expected model:verdict)")
        if tok.count(":") != 1:
            raise AttestError(f"--panel entry {tok!r} must be model:verdict")
        model, verdict = (s.strip() for s in tok.split(":"))
        if not model:
            raise AttestError(f"--panel entry {tok!r} is missing a model")
        if verdict not in ATTEST_VERDICTS:
            raise AttestError(f"--panel verdict {verdict!r} not in {ATTEST_VERDICTS}")
        pairs.append((model, verdict))
    if not pairs:
        raise AttestError("--panel is empty")
    return pairs


def _select_claim(bundle: dict, claim_id) -> dict:
    """Resolve the single target claim (total rule). --claim-id must match exactly
    one claim whenever given; otherwise the bundle must hold exactly one claim."""
    if not isinstance(bundle, dict):
        raise AttestError("bundle is not an object")
    schema = bundle.get("schema")
    if schema == gate.SCHEMA_PRIOR:
        raise AttestError(f"bundle uses {gate.SCHEMA_PRIOR!r}; regenerate it with `rung run` "
                          f"(this tool scores {gate.SCHEMA_MAJOR})")
    if schema != gate.SCHEMA_MAJOR:
        raise AttestError(f"unknown or missing schema (need {gate.SCHEMA_MAJOR!r}, got {schema!r})")
    claims = bundle.get("claims")
    if not isinstance(claims, list) or not claims:
        raise AttestError("bundle has no claims")
    if claim_id is not None:
        matches = [c for c in claims if isinstance(c, dict) and c.get("id") == claim_id]
        if len(matches) != 1:
            raise AttestError(f"--claim-id {claim_id!r} matched {len(matches)} claims (need exactly 1)")
        return matches[0]
    if len(claims) != 1:
        raise AttestError(f"bundle has {len(claims)} claims; attest one at a time, pass --claim-id")
    if not isinstance(claims[0], dict):
        raise AttestError("claim is not an object")
    return claims[0]


def _evaluate_artifacts(claim: dict, base: Path):
    """Recompute the target claim's artifact hashes, mirroring the gate's own
    block-5 integrity pass (gate.gate, the artifact loop). It reuses the gate's
    hash + path primitives (_contained_path, sha256_file), so the two share their
    load-bearing logic and differ only in disposition: the gate emits block reasons,
    attest refuses (mismatch), downgrades (absent), or anchors (match). The set of
    hashes attest records as artifact_shas MUST equal the gate's verified_sha_set on
    the same bundle, or the anchor never clears; the anchored happy-path tests bind
    the two together, so one-sided drift here fails those tests rather than silently
    reopening the transplant gap. Returns one of:
      ("mismatch", None)          a present artifact's sha differs from the record
      ("match", [sorted shas])    every artifact resolved, existed, and matched
      ("absent", None)            no artifacts, or one could not be read/hashed
    A mismatch is an integrity violation and short-circuits (attest refuses)."""
    arts = claim.get("artifacts") or []
    if not arts:
        return ("absent", None)
    matched = []
    fully = True  # every artifact declared a sha, resolved, existed, and matched
    for a in arts:
        if not isinstance(a, dict):
            fully = False
            continue
        declared = a.get("sha256")
        if not declared:
            fully = False
            continue
        try:
            p = gate._contained_path(base, a.get("uri"))
        except ValueError:
            fully = False
            continue
        try:
            exists = p.exists() and p.is_file()
        except OSError:
            fully = False
            continue
        if not exists:
            fully = False
            continue
        try:
            actual = gate.sha256_file(p)
        except (ValueError, OSError):
            fully = False
            continue
        if actual != declared:
            return ("mismatch", None)
        matched.append(actual)
    if fully and matched:
        return ("match", sorted(set(matched)))
    return ("absent", None)


def _reviewer_models(ns, panel_pairs) -> list:
    return [ns.model] if ns.model is not None else [m for m, _ in panel_pairs]


def _model_floor(ns, bundle: dict, effective_tier, policy: dict, panel_pairs) -> None:
    """Conditional model-independence floor: only when the effective tier demands a
    cross-model qualifier. Refuses (exit 2) if the producer model is unknown or any
    reviewer model equals it. At tiers that need no cross-model qualifier, model
    independence is not load-bearing, so a bundle with no producer model still lifts."""
    require_cross_model = set(policy.get("require_cross_model") or [])
    if effective_tier not in require_cross_model:
        return
    change = bundle.get("change") if isinstance(bundle.get("change"), dict) else {}
    producer = change.get("producer") if isinstance(change.get("producer"), dict) else {}
    producer_model = producer.get("model")
    if not producer_model:
        raise AttestError(f"tier {effective_tier} requires a cross-model qualifier, but "
                          f"change.producer.model is absent (record it with `rung run --model`)")
    for m in _reviewer_models(ns, panel_pairs):
        if m == producer_model:
            raise AttestError(f"reviewer model {m!r} equals the producer model "
                              f"(no model independence at tier {effective_tier})")


def _build_attestation(ns, panel_pairs, anchor):
    """Build the attestation object. anchor is (state, shas): 'match' carries the
    sorted sha list to record as artifact_shas; 'absent' records the fixed note."""
    state, shas = anchor
    if ns.model is not None:
        att = {"model": ns.model, "verdict": ns.verdict}
        if ns.lab is not None:
            att["lab"] = ns.lab
    else:
        att = {"panel": [{"model": m, "verdict": v} for m, v in panel_pairs],
               "verdict": ns.verdict}
    if state == "match":
        att["artifact_shas"] = shas
    else:
        att["artifact_shas_note"] = ARTIFACT_SHAS_NOTE
    return att


def _attestation_clause(ns, panel_pairs, anchored: bool) -> str:
    if ns.model is not None:
        who = ns.model
    else:
        who = "a panel (" + ", ".join(m for m, _ in panel_pairs) + ")"
    bind = "byte-bound to the recorded captures" if anchored else \
        f"not byte-bound ({ARTIFACT_SHAS_NOTE})"
    return f"Independently attested by {who} with verdict {ns.verdict}; {bind}."


def _amend(claim: dict, att: dict, clause: str, reviewer_verdict: str) -> None:
    """Amend the target claim in place: lift context, attach the attestation, and
    AUGMENT how_established (never replace the run-origin sentence). A reviewer
    fail/blocked LOWERS the claim's own verdict so the gate blocks on it: attest,
    like the gate, only ever lowers trust, so a reviewer pass never raises a
    claim that already failed."""
    claim["context"] = "independent"
    claim["attestation"] = att
    if reviewer_verdict in ("fail", "blocked"):
        claim["verdict"] = reviewer_verdict
    existing = claim.get("how_established")
    claim["how_established"] = f"{existing} {clause}" if isinstance(existing, str) and existing else clause


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    ns = _parse(argv)  # argparse exits 2 on a usage error (missing --verdict, both/neither reviewer)
    try:
        if ns.panel is not None and ns.lab is not None:
            raise AttestError("--lab applies to a single --model attestation; a --panel has no single lab")
        panel_pairs = _parse_panel(ns.panel) if ns.panel is not None else None
        # A pass aggregate cannot sit over a dissenting panel member. The gate
        # blocks any non-pass member only at cross-model tiers; below them it never
        # inspects members, so refuse an incoherent record here (attest only lowers
        # trust, same reason skip is not a reviewer verdict). A fail/blocked
        # aggregate is the operator lowering and is allowed regardless of members.
        if panel_pairs is not None and ns.verdict == "pass":
            dissent = [m for m, v in panel_pairs if v != "pass"]
            if dissent:
                raise AttestError(f"--verdict pass but panel members {dissent} did not pass; "
                                  f"an aggregate pass cannot override a dissenting reviewer")

        bundle, base = _read_bundle(ns.bundle)
        policy = _load_policy(ns.policy)
        target = _select_claim(bundle, ns.claim_id)

        # --tier drives the re-gate (and the model floor below), mirroring `rung
        # gate --tier`. It is a gate-time knob, NOT a bundle edit: the override is
        # applied to a throwaway copy in the re-gate (see below), never written into
        # the emitted bundle, so a reviewer cannot silently rewrite the recorded
        # risk_tier of the target claim (let alone an un-attested sibling).
        effective_tier = ns.tier if ns.tier is not None else target.get("risk_tier")

        _model_floor(ns, bundle, effective_tier, policy, panel_pairs)

        state, shas = _evaluate_artifacts(target, base)
        if state == "mismatch":
            raise AttestError("reviewer's recomputed artifact sha256 does not match the bundle's "
                              "recorded sha256 (refusing to certify bytes that are not on record)")
        if state == "absent" and ns.require_artifacts:
            raise AttestError("--require-artifacts: the claim's artifacts could not be read, so the "
                              "attestation cannot be byte-bound")
        anchored = state == "match"

        att = _build_attestation(ns, panel_pairs, (state, shas))
        _amend(target, att, _attestation_clause(ns, panel_pairs, anchored), ns.verdict)
    except AttestError as e:
        print(f"attest: {e}", file=sys.stderr)
        return gate.EXIT_USAGE

    # Re-gate. --tier is applied only to a throwaway copy so the emitted bundle keeps
    # its authored risk_tier on every claim; without --tier the bundle is gated as-is.
    gate_bundle = bundle
    if ns.tier is not None:
        gate_bundle = copy.deepcopy(bundle)
        for c in gate_bundle.get("claims", []):
            if isinstance(c, dict):
                c["risk_tier"] = ns.tier
    try:
        result = gate.gate(gate_bundle, policy, base)
    except gate.PolicyError as e:
        result = gate._result("block", [f"policy integrity error: {e}"],
                              policy if isinstance(policy, dict) else {}, bundle.get("schema"))
    # stdout is the amended bundle (data); the gate verdict goes to stderr so a
    # block is legible without polluting the piped bundle bytes.
    print(json.dumps(bundle, indent=2, ensure_ascii=False))
    if result["verdict"] != "pass":
        print(f"attest: gate {result['verdict']}: {'; '.join(result['reasons'])}", file=sys.stderr)
    return result["exit_code"]


def _main_cli(argv: list[str] | None = None) -> int:
    """Standalone entry (`python -m rung.attest`). Fails closed to exit 2 on any
    unexpected exception, never a raw traceback; the in-contract 0/30/2 exits pass
    through and argparse's SystemExit is preserved. The `rung attest` command
    routes through the CLI dispatcher, which wraps this the same way."""
    try:
        return main(argv)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - fail closed, never a raw traceback
        print(f"rung attest: internal error: {type(e).__name__}: {e}", file=sys.stderr)
        return gate.EXIT_USAGE


if __name__ == "__main__":
    sys.exit(_main_cli(sys.argv[1:]))
