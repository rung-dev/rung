# rung config reference: policy and bundle

Two JSON documents drive the gate: the **policy** (the ship bar) and the
**evidence bundle** (the claims). Both parse with the stdlib `json` module; no
third-party dependency, no Python 3.11 floor.

## The v2 model in one paragraph

v2 separates three ideas the v1 rung integer conflated. **RUNG** is now binary:
`0` = not a runtime observation of the real surface, `1` = observed. **METHOD**
is *how* the observation was evaluated: `single`, the enforceable
`differential`, or the advisory `adversarial` / `fuzz` / `property`. **CONTEXT**
is *who* checked it, a two-value ladder `author < independent`; `cross-model` and
`cross-lab` are not higher contexts but independence **qualifiers** demanded
separately by policy and satisfied by an attestation on an independent review.

## Policy

The gate takes a policy as an optional positional argument; omitted, it uses
rung's bundled default policy (the repo copy is `policy/default.json`; the
installed package ships its own copy as package data):

```json
{
  "version": 2,
  "min_rung": { "low": 1, "medium": 1, "high": 1, "critical": 1 },
  "require_context": { "medium": "independent", "high": "independent", "critical": "independent" },
  "require_cross_model": ["high", "critical"],
  "require_cross_lab": ["critical"],
  "no_skip_tiers": ["high", "critical"],
  "allow_dismiss_gaps": false
}
```

- `version` (int, optional): policy schema version. The gate accepts it but does
  not require it or check its value; it is a label for humans.
- `min_rung` (object, required): the minimum rung each risk tier must reach to
  ship. A claim below its tier's floor blocks. Every tier the gate uses must have
  an integer floor in `[0, 1]`. The default is `1` everywhere: shipped ⇒ observed.
- `require_context` (object, required): tiers where independence is mandatory, as
  a ladder: a tier is satisfied by any `context` at least as independent
  as the required value (RANK: `author` < `independent`). The one enforceable
  value beyond `author` is `"independent"` (the claim declares
  `context: independent`); `author`/`independent` themselves carry no checkable
  field, so this enforces *who claims to have checked*, not the quality of the
  review.
- `require_cross_model` (array, optional): tiers that demand a **cross-model
  qualifier**. A required qualifier needs `context: independent` **and** a
  structural attestation: `change.producer.model` is set, and the `attestation`
  names >= 1 reviewer model (via `model` or `panel[]`), each a non-empty string
  differing from `change.producer.model`, each `verdict: pass`.
- `require_cross_lab` (array, optional): tiers that demand a **cross-lab
  qualifier**. A required qualifier needs `context: independent` **and** an
  `attestation` whose `lab` is present and differs from `change.producer.lab`,
  `verdict: pass`.
- `require_method` (object, optional): a per-tier **exact** required method
  (tier → one of `single`|`differential`|`adversarial`|`fuzz`|`property`). This is
  equality, **not** a floor. Methods are unordered, so requiring `single` at a
  tier *rejects* a `differential` claim there. A claim whose `method` differs from
  the tier's required method blocks. Absent ⇒ any method is accepted.
- `no_skip_tiers` (array, required): tiers where a `skip` verdict is not allowed
  to pass.
- `allow_dismiss_gaps` (bool, required): default `false`. A blocker gap marked
  `dismissed:true` is always waived. When `false`, an *undismissed* blocker gap
  blocks; when `true`, even undismissed blocker gaps are ignored.

The default's approach (tunable per operator): routine work is an author
self-run (clears **low** only); medium demands an **independent** review; high
adds a **cross-model** qualifier; critical adds a **cross-lab** qualifier. So an
author `rung run` bundle passes at low and blocks at medium+ until an independent
reviewer attests.

**Fail-closed.** An unknown or missing key, a non-int `min_rung`, an
out-of-range floor, an unknown `require_context` value, a non-list
`no_skip_tiers`/`require_cross_model`/`require_cross_lab`, or a `require_method`
naming an unknown tier or method all block rather than shipping with a check
disabled. **Fail-closed is not fail-strict:** a structurally valid but non-enforcing
policy (empty `require_context`, all-zero `min_rung`, `allow_dismiss_gaps:true`)
is accepted, so pinning the policy is an operator responsibility. See
`policy/README.md` for the full field reference and per-tier calibration.

## Evidence bundle (evidence-bundle/v2)

One bundle per change, one entry per claim. The reference schema is
`schema/evidence-bundle-v2.schema.json` (JSON Schema, draft 2020-12), shipped as
optional reference material. **The gate does not validate against the schema:**
it string-compares the `schema` major and independently re-derives every
check that decides the verdict, so a schema-valid bundle is not necessarily gate-passing. A
bundle stamped `evidence-bundle/v1` is **refused** with a regenerate message
(exit 2), not silently blocked: the rung/method/context meanings changed in v2.

Smallest bundle that runs (a single low-tier observation, one artifact):

```json
{
  "schema": "evidence-bundle/v2",
  "change": { "producer": { "lab": "your-lab" } },
  "claims": [
    {
      "id": "c1", "risk_tier": "low", "rung": 1, "method": "single",
      "context": "author", "verdict": "pass",
      "artifacts": [
        { "id": "a1", "role": "capture", "media": "text/plain",
          "uri": "artifacts/out.txt", "sha256": "<64-hex>" }
      ]
    }
  ]
}
```

(A rung-0 claim needs no artifact; a rung-1 claim must carry the capture it
observed.)

### Top-level shape

- `schema` (required): must equal `"evidence-bundle/v2"`. An unknown major blocks
  (exit 30); the prior `evidence-bundle/v1` is refused (exit 2).
- `change` (required): `repo`, `s0`, `s1`, `producer.lab`. `producer.lab` is
  always enforced (cross-lab independence is defined relative to it), and
  `producer.model` is enforced when a cross-model qualifier is demanded (model
  independence is defined relative to it); the rest is advisory.
- `claims` (required): non-empty array. Each claim carries `id`, `claim`,
  `risk_tier` (`low`|`medium`|`high`|`critical`), `rung` (`0` or `1`), `method`
  (`single` default | `differential` | `adversarial` | `fuzz` | `property`),
  `context` (`author`|`independent`), `verdict` (`pass`|`fail`|`blocked`|`skip`),
  and optionally `expected_delta` (`change` default | `invariance`), `surface`,
  `artifacts[]`, `differential`, `attestation`.
- `gaps` (optional): each with `id`, `severity` (`advisory`|`blocker`), `desc`,
  optional `dismissed`.
- `policy_pin` (optional, advisory): `path` and `sha256` of the policy in force
  when `rung run` produced the bundle, recorded so a verdict is attributable to
  those exact policy bytes. The gate ignores it (it re-reads and hashes the policy
  it is given).

### Enforced vs advisory

The gate reads only a subset of the schema when deciding a verdict.

**Enforced** (affect the verdict):

- `schema`, `change.producer.lab`, `claims` (non-empty).
- Per claim: `risk_tier`, `rung`, `method`, `context`, `verdict`,
  `expected_delta`; `artifacts[]` `role`/`uri`/`sha256`;
  `differential.s0_observed`/`s1_observed` (cross-checked against capture bytes
  when `method: differential`); `attestation.lab`/`attestation.verdict` (required
  when policy demands a cross-lab qualifier for the tier);
  `attestation.model`/`attestation.panel[]` plus `change.producer.model` (required
  when policy demands a cross-model qualifier for the tier).
- Conditional, beyond the schema: `rung 1` (observed) requires >= 1 artifact;
  `method: differential` requires `rung 1` and **exactly one** `s0_capture` and
  **one** `s1_capture` (zero, duplicate, or padded captures block) plus a
  differential whose polarity is decided from the verified capture bytes; a
  cross-lab-qualifier tier requires a matching attestation on an independent
  context; a cross-model-qualifier tier requires an independent context and an
  attestation naming >= 1 reviewer model != `change.producer.model`, each
  `verdict: pass`.
- Gaps: `severity`, `dismissed` (an undismissed `blocker` gap blocks unless
  policy allows dismissal).

**Advisory** (in the schema for humans; the gate does not check them):

- `change.repo`/`s0`/`s1`/`diff_range`/`created_at`/`policy_ref`,
  `producer.agent` (and `producer.model`, unless a cross-model qualifier is
  demanded; then it is enforced).
- `claim.claim`, `claim.surface.*`, `claim.how_established`.
- `artifact.media`/`summary`, `differential.probe`/`observed_delta`,
  `attestation.judge_id`/`note`, `gap.why_unverified`.
- The advisory methods (`adversarial`/`fuzz`/`property`) are recorded but never
  gated: there is no mechanical anchor to enforce them.
- `id` and `gap.desc` are advisory too, but appear in the gate's human-readable
  reason output; they are not enforcement inputs.

### Artifacts and paths

- `uri` is a path relative to the bundle directory, never absolute. The gate
  resolves it under the bundle dir, rejects any escape or symlink, size-caps the
  read (64 MiB per artifact), and recomputes the sha256.
- `sha256` (required): the gate recomputes the artifact's hash and blocks on any
  mismatch or when it is absent, so it detects post-bundle **mutation**. The
  `^[0-9a-f]{64}$` format is a schema constraint, not a gate check. A matching
  hash is not evidence the file came from driving a real surface; that is
  judge-only.

### What the gate trusts on assertion (v2)

Nothing in the bundle is signed, so the gate detects post-bundle mutation but
not fabrication: `risk_tier`, `rung`, `method` (advisory methods especially),
`context` (`author`/`independent` carry no checkable field), `attestation.lab`,
`attestation.model`/`panel[].model` (the gate confirms a reviewer model differs
from the producer's; whether a different model ran, and whether same-lab models
fail independently, sit beyond what it can check), `surface.kind`, which claims were declared at all,
and two captures fabricated *consistently* are all trusted on assertion. The gate
enforces the *presence* of independence / a qualifier / a method; the
independence or quality it stands for is a judge's call. These are judge-only concerns until
signing lands. See `SECURITY.md` for the trust boundary.
