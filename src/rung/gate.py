#!/usr/bin/env python3
"""rung reference gate: a deterministic, replay-safe verdict over an
`evidence-bundle/v2` document.

No LLM. No network. Its ONLY I/O is resolving artifact hashes on disk, which
it treats as fixed input: (bundle, policy) -> same result, always.

Trust model (be precise):
  The gate can only ever *lower* trust RELATIVE TO WHAT THE BUNDLE CLAIMS. A
  claim cannot pass above its own declared rung, and any producer-declared
  verdict is ignored; the gate's printed output is the only verdict. It does
  NOT defend against a producer
  who lies in the bundle inputs (fabricated artifacts, a forged attestation
  string, a deflated risk_tier). Those are judge-only / v2-signing concerns.

What changed vs the first cut (all from the adversarial doc review):
  * FAILS CLOSED. Missing/unknown policy keys, unknown schema major, empty
    claims, and malformed structure BLOCK (or exit 2) instead of silently
    disabling enforcement or crashing with a traceback.
  * Artifact `uri` is path-contained: absolute paths and paths escaping the
    bundle dir (incl. via symlink) are rejected; reads are size-capped.
  * Evidence is mandatory where it is load-bearing: rung 1 (observed) needs >=1
    artifact, and every artifact must carry a resolvable sha256.
  * Invariance polarity: the differential METHOD is well-formed when "s0 differs
    IFF a delta was expected" (expected_delta: change|invariance), decided from
    exactly one verified s0_capture vs one s1_capture (a single pair, not role
    buckets), so no-regression / refactor claims can be verified by showing the
    surface is UNCHANGED.

v2 model (breaking vs v1): RUNG collapses to {0 not-runtime-observed, 1 observed};
differential is no longer a rung but an enforceable METHOD; CONTEXT collapses to
{author, independent} with cross-model / cross-lab as separately-demanded
decorrelation QUALIFIERS. A v1 bundle is refused with a clear regenerate message.

Usage:
    python3 gate.py <bundle.json> [policy.json] [--tier <override>]

Both the bundle and the policy are JSON, parsed with the stdlib `json` module:
no third-party dependency and no version floor beyond what `pathlib` needs
(Python 3.9+ for `is_relative_to`). Exit codes: 0 = pass, 30 = block, 2 = cannot
evaluate (bad args / unreadable or unparseable input).
"""
from __future__ import annotations
import sys, json, hashlib, pathlib, contextlib, importlib.resources

EXIT_PASS, EXIT_BLOCK, EXIT_USAGE = 0, 30, 2

SCHEMA_MAJOR = "evidence-bundle/v2"
# The prior schema major. A bundle stamped with this is refused with a clear
# "regenerate" message (exit 2) rather than silently blocked: v2 changed the
# meaning of the integers, so a v1 bundle cannot be honestly scored under v2.
SCHEMA_PRIOR = "evidence-bundle/v1"
TIERS = ("low", "medium", "high", "critical")
# CONTEXTS is a 2-value ordinal ladder of independence: author (the producer) <
# independent (a blind reviewer that is not the producer). RANK is derived from
# position, so require_context is satisfied by ANY context at least as
# independent as demanded (RANK[claim] >= RANK[required]); you never reject a
# stronger review. cross-model / cross-lab are NOT higher contexts. They are
# decorrelation QUALIFIERS on an independent review, demanded by the separate
# require_cross_model / require_cross_lab policy keys and checked as structural
# presence (a reviewer model/lab that differs from the producer, verdict=pass).
# author/independent themselves carry no checkable field.
CONTEXTS = ("author", "independent")
RANK = {c: i for i, c in enumerate(CONTEXTS)}
VERDICTS = ("pass", "fail", "blocked", "skip")
# METHOD is orthogonal to rung/context: HOW the observation was evaluated.
# "differential" is enforceable (the gate byte-compares the S0/S1 captures and
# checks the declared polarity); the rest are advisory (recorded, never gated:
# no mechanical anchor). "single" is one plain observation.
METHODS = ("single", "differential", "adversarial", "fuzz", "property")
KNOWN_POLICY_KEYS = {"version", "min_rung", "require_context", "no_skip_tiers",
                     "allow_dismiss_gaps", "require_cross_model", "require_cross_lab",
                     "require_method"}
# Cap on a single in-tree artifact we will hash (char devices / FIFOs are already
# rejected by is_file(); this caps a large regular file).
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
# Cap on the raw bundle/policy JSON we will parse (a DoS + parser-abuse guard).
MAX_INPUT_BYTES = 16 * 1024 * 1024


def _self_sha256() -> str | None:
    """Hash of this gate's own source, so a verdict is attributable to exact
    logic.

    Reads via a plain filesystem read on a normal install (the wheel is
    unzipped to real files), then falls back to the module loader when the
    source lives inside an archive (zipimport / zipapp / a wheel on the path),
    where `__file__` is not an openable file. Both paths hash the exact same
    source bytes, so the hash is stable across install shapes; if neither
    yields bytes it fails safe to None rather than crashing."""
    try:
        return hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
    except OSError:
        pass
    try:
        # zipimporter (and any importlib loader) serves the source bytes from
        # inside the archive; get_data accepts the full `__file__` path.
        data = __loader__.get_data(__file__)  # type: ignore[name-defined]
        return hashlib.sha256(data).hexdigest()
    except Exception:
        return None


GATE_SHA256 = _self_sha256()


class PolicyError(Exception):
    """Policy is structurally unusable: a trust-boundary integrity failure."""


class GateInputError(Exception):
    """Bundle/policy could not be read or parsed (exit 2, not a verdict)."""


@contextlib.contextmanager
def default_policy_path():
    """Yield a real filesystem path to the bundled default policy, materialized
    only for the duration of the context via importlib.resources.as_file().

    This is the ONE shared resolver both entrypoints use for the no-explicit-policy
    default, so installed and from-checkout behavior is identical. files() returns
    a Traversable (a real Path only for an unzipped install), so a plain
    files()/... would break under a zipimport; as_file() materializes a real path
    while it is read. A resolution failure at context ENTRY (missing package data,
    an unreadable resource, a zipimport extraction error) is translated to
    GateInputError so the caller's existing fail-closed catch turns it into a
    cannot-evaluate exit 2, never an uncaught traceback. The except is scoped to
    entry ONLY: an error raised by the caller's own body (while the path is read)
    must propagate unchanged, not be relabeled a policy-resolution failure."""
    try:
        res = importlib.resources.files(__package__ or "rung") / "data" / "default_policy.json"
        cm = importlib.resources.as_file(res)
        path = cm.__enter__()
    except Exception as e:  # noqa: BLE001 - any resolution failure fails closed to exit 2
        raise GateInputError(f"cannot resolve bundled default policy: {type(e).__name__}: {e}")
    try:
        yield path
    finally:
        cm.__exit__(None, None, None)


def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    read = 0
    with p.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            read += len(chunk)
            if read > MAX_ARTIFACT_BYTES:
                raise ValueError(f"artifact exceeds {MAX_ARTIFACT_BYTES} bytes")
            h.update(chunk)
    return h.hexdigest()


def _contained_path(base: pathlib.Path, uri: str) -> pathlib.Path:
    """Resolve `uri` under `base`, rejecting absolute paths and any escape
    (including via symlink). Returns the resolved path (may not exist)."""
    if not isinstance(uri, str) or not uri:
        raise ValueError("artifact uri missing or not a string")
    try:
        candidate = (base / uri).resolve()
    except (OSError, RuntimeError) as e:
        # A hostile/broken path (e.g. a symlink loop -> ELOOP / RuntimeError) is a
        # defect in the producer's bundle, not a gate bug. Surface it as a ValueError
        # so the caller turns it into a per-claim BLOCK reason -- consistent with
        # every other unresolvable-artifact case -- rather than an escaping traceback.
        raise ValueError(f"artifact uri cannot be resolved: {uri!r} ({type(e).__name__})")
    root = base.resolve()
    if not candidate.is_relative_to(root):
        raise ValueError(f"artifact uri escapes bundle dir: {uri!r}")
    return candidate


def _cross_model_reviewers(att) -> list | None:
    """Extract reviewer (model, verdict) pairs from an attestation, or None when
    it carries no cross-model reviewer info. A non-empty `panel` (list of
    {model, verdict}) wins; otherwise a single top-level `model` paired with the
    top-level `verdict`. A structurally malformed panel entry collapses to None
    (fail closed: the caller then reports a missing attestation)."""
    if not isinstance(att, dict):
        return None
    panel = att.get("panel")
    if isinstance(panel, list) and panel:
        pairs = []
        for e in panel:
            if not isinstance(e, dict):
                return None
            pairs.append((e.get("model"), e.get("verdict")))
        return pairs
    model = att.get("model")
    if model is not None:
        return [(model, att.get("verdict"))]
    return None


def _cross_model_reasons(cid, tier, att, producer_model) -> list:
    """Structural check for a cross-model qualifier (presence, not authenticity:
    the same S1 residual as cross-lab). Requires the producer's own model to be
    known, then >=1 reviewer model, each a non-empty string that differs from
    the producer's model, each with verdict=pass. Reviewers come from an
    attestation `panel` or a single `model`+`verdict`."""
    out: list = []
    if not producer_model:
        out.append(f"{cid}: cross-model qualifier needs change.producer.model "
                   f"(model independence is undefined without it)")
    reviewers = _cross_model_reviewers(att)
    if not reviewers:
        out.append(f"{cid}: tier {tier} needs a cross-model attestation "
                   f"(a panel[] or a model, with >=1 reviewer model != the "
                   f"producer model and verdict=pass)")
        return out
    for m, v in reviewers:
        if not isinstance(m, str) or not m:
            out.append(f"{cid}: cross-model reviewer is missing a model string")
            break
        if producer_model and m == producer_model:
            out.append(f"{cid}: cross-model reviewer model {m!r} equals the producer "
                       f"model (no model independence)")
            break
        if v != "pass":
            out.append(f"{cid}: cross-model reviewer {m!r} verdict={v!r} (need pass)")
            break
    return out


def validate_policy(policy: dict) -> None:
    """Fail closed: a policy that can't be trusted to enforce is an error."""
    if not isinstance(policy, dict):
        raise PolicyError("policy is not a table")
    unknown = set(policy) - KNOWN_POLICY_KEYS
    if unknown:
        raise PolicyError(f"unknown policy keys (typo? nesting?): {sorted(unknown)}")
    for key in ("min_rung", "require_context", "no_skip_tiers", "allow_dismiss_gaps"):
        if key not in policy:
            raise PolicyError(f"policy missing required key: {key}")
    min_rung = policy["min_rung"]
    if not isinstance(min_rung, dict) or not set(TIERS) <= set(min_rung):
        raise PolicyError("min_rung must be a table covering all tiers "
                          f"{TIERS}; got {sorted(min_rung) if isinstance(min_rung, dict) else min_rung}")
    rc = policy["require_context"]
    if not isinstance(rc, dict):
        raise PolicyError("require_context must be an object mapping tier -> context")
    # Value-type checks: a structurally present but mistyped policy must fail
    # closed here, not crash later when a value is used (e.g. `rung < min_rung`).
    for t in TIERS:
        rv = min_rung[t]
        if isinstance(rv, bool) or not isinstance(rv, int) or not (0 <= rv <= 1):
            raise PolicyError(f"min_rung[{t}] must be an integer 0..1; got {rv!r}")
    for t, ctx in rc.items():
        if t not in TIERS:
            raise PolicyError(f"require_context key {t!r} is not a tier from {TIERS}")
        if ctx not in CONTEXTS:
            raise PolicyError(f"require_context[{t}] must be one of {CONTEXTS}; got {ctx!r}")
    no_skip = policy["no_skip_tiers"]
    if not isinstance(no_skip, list) or any(t not in TIERS for t in no_skip):
        raise PolicyError(f"no_skip_tiers must be a list of tiers from {TIERS}; got {no_skip!r}")
    if not isinstance(policy["allow_dismiss_gaps"], bool):
        raise PolicyError(f"allow_dismiss_gaps must be a boolean; got {policy['allow_dismiss_gaps']!r}")
    # Optional decorrelation-qualifier requirements (lists of tiers) and the
    # optional per-tier method floor. Absent => not required; a typo'd key is
    # already caught by the unknown-keys check above.
    for key in ("require_cross_model", "require_cross_lab"):
        val = policy.get(key)
        if val is None:
            continue
        if not isinstance(val, list) or any(t not in TIERS for t in val):
            raise PolicyError(f"{key} must be a list of tiers from {TIERS}; got {val!r}")
    rm = policy.get("require_method")
    if rm is not None:
        if not isinstance(rm, dict):
            raise PolicyError("require_method must be an object mapping tier -> method")
        for t, m in rm.items():
            if t not in TIERS:
                raise PolicyError(f"require_method key {t!r} is not a tier from {TIERS}")
            if m not in METHODS:
                raise PolicyError(f"require_method[{t}] must be one of {METHODS}; got {m!r}")


def gate(bundle: dict, policy: dict, base: pathlib.Path) -> dict:
    """Pure verdict over (bundle, policy). Structural defects BLOCK; they never
    raise (except PolicyError, surfaced by the caller as a policy-integrity
    block). Returns a dict with the resolved policy echoed for auditability."""
    validate_policy(policy)
    reasons: list[str] = []
    min_rung = policy["min_rung"]
    require_context = policy["require_context"]
    no_skip = set(policy["no_skip_tiers"])
    allow_dismiss = bool(policy["allow_dismiss_gaps"])
    require_cross_model = set(policy.get("require_cross_model") or [])
    require_cross_lab = set(policy.get("require_cross_lab") or [])
    require_method = policy.get("require_method") or {}

    # --- bundle-level fail-closed checks -------------------------------------
    if not isinstance(bundle, dict):
        return _result("block", ["bundle is not an object"], policy, None)
    schema = bundle.get("schema")
    if schema != SCHEMA_MAJOR:
        reasons.append(f"unknown or missing schema (need {SCHEMA_MAJOR!r}, got {schema!r})")
    change = bundle.get("change")
    producer_lab = None
    producer_model = None
    if isinstance(change, dict):
        producer = change.get("producer") or {}
        producer_lab = producer.get("lab")
        # producer_model is only load-bearing when a cross-model qualifier is
        # demanded, so (unlike lab) its absence is flagged inside block #3, not
        # unconditionally here. Bundles need not declare a model otherwise.
        producer_model = producer.get("model")
    if not producer_lab:
        reasons.append("change.producer.lab is missing (independence is undefined without it)")
    claims = bundle.get("claims")
    if not isinstance(claims, list) or not claims:
        reasons.append("bundle has no claims (nothing verified => nothing ships)")
        claims = []

    for i, c in enumerate(claims):
        cid = c.get("id", f"#{i}") if isinstance(c, dict) else f"#{i}"
        if not isinstance(c, dict):
            reasons.append(f"{cid}: claim is not an object")
            continue

        tier = c.get("risk_tier")
        if tier not in TIERS:
            reasons.append(f"{cid}: risk_tier {tier!r} not in {TIERS}")
            continue  # tier drives every other check; can't score without it
        rung = c.get("rung")
        if isinstance(rung, bool) or not isinstance(rung, int) or not (0 <= rung <= 1):
            reasons.append(f"{cid}: rung {rung!r} not an integer 0..1")
            continue
        ctx = c.get("context")
        if ctx not in CONTEXTS:
            reasons.append(f"{cid}: context {ctx!r} not in {CONTEXTS}")
        method = c.get("method", "single")
        if method not in METHODS:
            reasons.append(f"{cid}: method {method!r} not in {METHODS}")

        # (1) rung floor
        if rung < min_rung[tier]:
            reasons.append(f"{cid}: rung {rung} < min_rung[{tier}]={min_rung[tier]}")

        # (2) verdict
        v = c.get("verdict")
        if v not in VERDICTS:
            reasons.append(f"{cid}: verdict {v!r} not in {VERDICTS}")
        elif v in ("fail", "blocked"):
            reasons.append(f"{cid}: verdict={v}")
        elif v == "skip" and tier in no_skip:
            reasons.append(f"{cid}: skip not allowed in tier {tier}")

        # (3) independence + decorrelation qualifiers. CONTEXT is a 2-value
        #     ordinal ladder (author < independent); require_context enforces the
        #     floor. cross-model / cross-lab are NOT higher contexts. They are
        #     qualifiers demanded separately: a required qualifier needs an
        #     independent context AND the qualifier's structural presence in the
        #     attestation (presence, not authenticity: the same S1 residual).
        att = c.get("attestation")
        req = require_context.get(tier)
        if req and RANK.get(ctx, -1) < RANK[req]:
            reasons.append(f"{cid}: tier {tier} requires context >= {req}, got {ctx}")
        if tier in require_cross_model:
            if ctx != "independent":
                reasons.append(f"{cid}: tier {tier} requires a cross-model qualifier, "
                               f"which needs context=independent (got {ctx})")
            else:
                reasons.extend(_cross_model_reasons(cid, tier, att, producer_model))
        if tier in require_cross_lab:
            if ctx != "independent":
                reasons.append(f"{cid}: tier {tier} requires a cross-lab qualifier, "
                               f"which needs context=independent (got {ctx})")
            elif not isinstance(att, dict) or att.get("lab") in (None, producer_lab) \
                    or att.get("verdict") != "pass":
                reasons.append(
                    f"{cid}: tier {tier} needs a cross-lab attestation "
                    f"(lab present and != {producer_lab!r}, verdict=pass)"
                )
        if tier in require_method and method != require_method[tier]:
            reasons.append(f"{cid}: tier {tier} requires method={require_method[tier]}, got {method}")

        # (4) evidence is mandatory where load-bearing: an observation (rung 1)
        #     must carry the capture it observed.
        artifacts = c.get("artifacts") or []
        if rung == 1 and not artifacts:
            reasons.append(f"{cid}: rung 1 (observed) requires >=1 capture artifact (none present)")

        # (5) artifact integrity: the gate's only I/O. Runs BEFORE the differential
        #     polarity check so that check can reason about VERIFIED bytes, not
        #     the producer's declared observations.
        #     verified_shas maps role -> sorted sha256 of every artifact that
        #     resolved, exists, and matched its declared hash.
        verified_shas: dict[str, list] = {}
        for a in artifacts:
            if not isinstance(a, dict):
                reasons.append(f"{cid}: malformed artifact entry")
                continue
            aid = a.get("id", "?")
            declared = a.get("sha256")
            if not declared:
                reasons.append(f"{cid}: artifact {aid} has no sha256 (unhashed evidence is not accepted)")
                continue
            try:
                p = _contained_path(base, a.get("uri"))
            except ValueError as e:
                reasons.append(f"{cid}: artifact {aid} {e}")
                continue
            try:
                exists = p.exists() and p.is_file()
            except OSError as e:
                # stat() on a hostile path (symlink loop, etc.) fails closed to a
                # block reason, not an escaping traceback.
                reasons.append(f"{cid}: artifact {aid} uri cannot be checked: {a.get('uri')} ({type(e).__name__})")
                continue
            if not exists:
                reasons.append(f"{cid}: artifact {aid} uri not found: {a.get('uri')}")
                continue
            try:
                actual = sha256_file(p)
            except (ValueError, OSError) as e:
                reasons.append(f"{cid}: artifact {aid} {e}")
                continue
            if actual != declared:
                reasons.append(
                    f"{cid}: artifact {aid} sha256 mismatch "
                    f"(declared {declared[:12]}…, actual {actual[:12]}…)"
                )
                continue
            verified_shas.setdefault(a.get("role"), []).append(actual)

        # (6) differential well-formedness (the enforceable METHOD), with
        #     invariance polarity decided by the VERIFIED capture bytes (not the
        #     producer's declared strings). Differential is a way of EVALUATING an
        #     observation, so it requires rung 1.
        if method == "differential":
            if rung != 1:
                reasons.append(f"{cid}: method=differential requires rung 1 (an observation), got rung {rung}")
            diff = c.get("differential")
            polarity = c.get("expected_delta", "change")
            if polarity not in ("change", "invariance"):
                reasons.append(f"{cid}: expected_delta {polarity!r} not in ('change','invariance')")
            if not isinstance(diff, dict):
                reasons.append(f"{cid}: method=differential requires a non-null differential")

            # Polarity is decided from ONE unambiguous S0/S1 pair. Require exactly
            # one verified capture per role: role buckets with 0, duplicate, or
            # padded captures let a producer force sorted(s0)==sorted(s1) (fake
            # invariance) or != (fake change) from genuine, hash-matching files.
            s0 = verified_shas.get("s0_capture", [])
            s1 = verified_shas.get("s1_capture", [])
            if len(s0) != 1 or len(s1) != 1:
                reasons.append(f"{cid}: differential polarity unverifiable: need exactly one "
                               f"resolvable, hash-matching s0_capture and one s1_capture "
                               f"(got {len(s0)} s0 / {len(s1)} s1)")
            else:
                bytes_same = s0[0] == s1[0]
                if polarity == "change" and bytes_same:
                    reasons.append(f"{cid}: differential change-claim shows no S0/S1 delta "
                                   f"(s0_capture and s1_capture artifacts are byte-identical)")
                if polarity == "invariance" and not bytes_same:
                    reasons.append(f"{cid}: differential invariance-claim shows an unexpected S0/S1 delta "
                                   f"(capture artifacts differ)")
                # the declared differential is a human record; if it contradicts
                # the bytes, the bundle is internally inconsistent -> block.
                if isinstance(diff, dict) and diff.get("s0_observed") is not None \
                        and diff.get("s1_observed") is not None:
                    declared_same = diff.get("s0_observed") == diff.get("s1_observed")
                    if declared_same != bytes_same:
                        reasons.append(f"{cid}: differential text contradicts capture bytes "
                                       f"(declared_same={declared_same}, bytes_same={bytes_same})")

    # undismissed blocker gaps
    if not allow_dismiss:
        for g in bundle.get("gaps", []) or []:
            if isinstance(g, dict) and g.get("severity") == "blocker" and not g.get("dismissed"):
                reasons.append(f"gap {g.get('id','?')}: undismissed blocker: {g.get('desc','')}")

    verdict = "pass" if not reasons else "block"
    return _result(verdict, reasons, policy, schema)


def _policy_sha256(policy) -> str | None:
    """Hash of the resolved policy, so a verdict is attributable to the exact
    policy that produced it."""
    if not isinstance(policy, dict):
        return None
    canonical = json.dumps(policy, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _result(verdict: str, reasons: list, policy: dict, schema) -> dict:
    return {
        "verdict": verdict,
        "exit_code": EXIT_PASS if verdict == "pass" else EXIT_BLOCK,
        "computed_by": "gate/v2",
        "gate_sha256": GATE_SHA256,        # exact gate logic that produced this
        "policy_sha256": _policy_sha256(policy),  # exact policy it was run under
        "schema": schema,
        "resolved_policy": {  # echoed so a misconfigured policy is visible
            "min_rung": policy.get("min_rung") if isinstance(policy, dict) else None,
            "require_context": policy.get("require_context") if isinstance(policy, dict) else None,
            "require_cross_model": policy.get("require_cross_model") if isinstance(policy, dict) else None,
            "require_cross_lab": policy.get("require_cross_lab") if isinstance(policy, dict) else None,
            "require_method": policy.get("require_method") if isinstance(policy, dict) else None,
            "no_skip_tiers": policy.get("no_skip_tiers") if isinstance(policy, dict) else None,
            "allow_dismiss_gaps": policy.get("allow_dismiss_gaps") if isinstance(policy, dict) else None,
        },
        "reasons": reasons,
    }


def _read_json(path: pathlib.Path, what: str):
    """Read and parse a JSON input, failing closed to exit 2 on any defect:
    unreadable, oversized, malformed, non-UTF-8, or pathologically nested
    (RecursionError), never an uncaught traceback."""
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise GateInputError(f"cannot read {what} {path}: {e}")
    if len(raw) > MAX_INPUT_BYTES:
        raise GateInputError(f"{what} {path} exceeds {MAX_INPUT_BYTES} bytes")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError) as e:
        raise GateInputError(f"cannot parse {what} {path}: {type(e).__name__}: {e}")


def _load(argv: list[str]):
    tier_override = None
    args: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--tier":
            if i + 1 >= len(argv):
                raise GateInputError("--tier requires a value")
            tier_override = argv[i + 1]
            i += 2
            continue
        if a.startswith("--tier="):
            tier_override = a.split("=", 1)[1]
            i += 1
            continue
        if a.startswith("--"):
            raise GateInputError(f"unknown option {a!r} (only --tier is supported)")
        args.append(a)
        i += 1

    if not args:
        raise GateInputError("usage: gate.py <bundle.json> [policy.json] [--tier <tier>]")
    if tier_override is not None and tier_override not in TIERS:
        raise GateInputError(f"--tier {tier_override!r} not in {TIERS}")

    bundle_path = pathlib.Path(args[0])
    bundle = _read_json(bundle_path, "bundle")
    if isinstance(bundle, dict) and bundle.get("schema") == SCHEMA_PRIOR:
        raise GateInputError(
            f"bundle uses {SCHEMA_PRIOR!r}, which this gate ({SCHEMA_MAJOR}) does not "
            f"score: the rung/method/context meanings changed in v2. Regenerate it "
            f"with `rung run`."
        )
    if len(args) > 1:
        # An explicit policy path wins and is read directly; the bundled-data
        # resolver never intercepts it.
        policy = _read_json(pathlib.Path(args[1]), "policy")
    else:
        # No explicit policy: read the bundled default via the shared resolver,
        # which yields a real filesystem path only while it is read, so this
        # works from an installed wheel (or zipimport) and not just a checkout.
        with default_policy_path() as policy_path:
            policy = _read_json(policy_path, "policy")

    if tier_override is not None and isinstance(bundle.get("claims"), list):
        claims = bundle["claims"]
        if len(claims) > 1:
            print(f"warning: --tier {tier_override} overrides risk_tier on all "
                  f"{len(claims)} claims", file=sys.stderr)
        for c in claims:
            if isinstance(c, dict):
                c["risk_tier"] = tier_override
    return bundle, policy, bundle_path.resolve().parent


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        bundle, policy, base = _load(argv)
    except GateInputError as e:
        print(f"gate: {e}", file=sys.stderr)
        return EXIT_USAGE
    try:
        result = gate(bundle, policy, base)
    except PolicyError as e:
        result = _result("block", [f"policy integrity error: {e}"], policy if isinstance(policy, dict) else {}, bundle.get("schema") if isinstance(bundle, dict) else None)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return result["exit_code"]


def _main_cli(argv: list[str] | None = None) -> int:
    """Standalone entry (`python -m rung.gate`). Runs main() but fails closed to
    exit 2 on any unexpected exception, never a raw traceback; the in-contract
    0/30/2 exits pass through and argparse's SystemExit is preserved."""
    try:
        return main(argv)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 - fail closed, never a raw traceback
        print(f"gate: internal error: {type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(_main_cli(sys.argv[1:]))
