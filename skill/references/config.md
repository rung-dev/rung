# rung config reference: policy and bundle

Two JSON documents drive the gate: the **policy** (the ship bar) and the
**evidence bundle** (the claims). Both parse with the stdlib `json` module; no
third-party dependency, no Python 3.11 floor.

## Policy

The gate takes a policy as an optional positional argument; omitted, it uses
rung's bundled default policy (the repo copy is `policy/default.json`; the
installed package ships its own copy as package data):

```json
{
  "version": 1,
  "require_context": { "high": "cross-lab", "critical": "cross-lab" },
  "no_skip_tiers": ["high", "critical"],
  "allow_dismiss_gaps": false,
  "min_rung": { "low": 2, "medium": 3, "high": 4, "critical": 4 }
}
```

- `version` (int, optional): policy schema version. The gate accepts it but does
  not require it or check its value; it is a label for humans.
- `min_rung` (object): the minimum rung each risk tier must reach to ship. A
  claim below its tier's floor blocks. Every tier the gate uses must have an
  integer floor in `[0, 4]`.
- `require_context` (object): tiers where independence is mandatory. The only
  mechanically enforceable value is `"cross-lab"`: a claim at that tier blocks
  unless it declares `context: cross-lab` and the bundle carries an `attestation`
  whose `lab` differs from `change.producer.lab` and whose `verdict` is `pass`.
  Kept consistent with `min_rung`, this closes the self-report trap (a
  self-reported rung 4 blocks at high/critical until a cross-lab reviewer
  attests).
- `no_skip_tiers` (array): tiers where a `skip` verdict is not allowed to pass.
- `allow_dismiss_gaps` (bool): default `false`. A blocker gap marked
  `dismissed:true` is always waived. When `false`, an *undismissed* blocker gap
  blocks; when `true`, even undismissed blocker gaps are ignored.

**Fail-closed.** An unknown or missing key, a non-int `min_rung`, an
out-of-range floor, an unknown `require_context` value, or a non-list
`no_skip_tiers` all block or exit 2 rather than shipping with a disabled check.
**Fail-closed is not fail-strict:** a structurally valid but toothless
policy (empty `require_context`, all-zero `min_rung`, `allow_dismiss_gaps:true`)
is accepted, so pinning the policy is an operator responsibility. See
`policy/README.md` for the full field reference and per-tier calibration.

## Evidence bundle (evidence-bundle/v1)

One bundle per change, one entry per claim. The reference schema is
`schema/evidence-bundle-v1.schema.json` (JSON Schema, draft 2020-12), shipped as
optional reference material. **The gate does not validate against the schema:**
it string-compares the `schema` major and independently re-derives every
load-bearing check, so a schema-valid bundle is not necessarily gate-passing.

Smallest bundle that runs (a single low-tier claim, no artifacts):

```json
{
  "schema": "evidence-bundle/v1",
  "change": { "producer": { "lab": "your-lab" } },
  "claims": [
    { "id": "c1", "risk_tier": "low", "rung": 2, "context": "author", "verdict": "pass" }
  ]
}
```

### Top-level shape

- `schema` (required): must equal `"evidence-bundle/v1"`. An unknown major
  blocks (exit 30).
- `change` (required): `repo`, `s0`, `s1`, `producer.lab`. Only `producer.lab`
  is enforced (cross-lab independence is defined relative to it); the rest is
  advisory.
- `claims` (required): non-empty array. Each claim carries `id`, `claim`,
  `risk_tier` (`low`|`medium`|`high`|`critical`), `rung` (0 to 4), `context`
  (`author`|`fresh-blind`|`cross-lab`), `verdict`
  (`pass`|`fail`|`blocked`|`skip`), and optionally `expected_delta`
  (`change` default | `invariance`), `surface`, `artifacts[]`, `differential`,
  `attestation`.
- `gaps` (optional): each with `id`, `severity` (`advisory`|`blocker`), `desc`,
  optional `dismissed`.

### Enforced vs advisory

The gate reads only a subset of the schema when deciding a verdict. Authors
should know which is which.

**Enforced** (affect the verdict):

- `schema`, `change.producer.lab`, `claims` (non-empty).
- Per claim: `risk_tier`, `rung`, `context`, `verdict`, `expected_delta`;
  `artifacts[]` `role`/`uri`/`sha256`; `differential.s0_observed`/`s1_observed`
  (cross-checked against capture bytes at rung 4);
  `attestation.lab`/`attestation.verdict` (required when policy demands cross-lab
  for the tier).
- Conditional, beyond the schema: rung >= 3 requires >= 1 artifact; rung 4
  requires **exactly one** `s0_capture` and **one** `s1_capture` (zero,
  duplicate, or padded captures block) plus a differential whose polarity is
  decided from the verified capture bytes; a cross-lab tier requires a matching
  attestation.
- Gaps: `severity`, `dismissed` (an undismissed `blocker` gap blocks unless
  policy allows dismissal).

**Advisory** (in the schema for humans; the gate does not check them):

- `change.repo`/`s0`/`s1`/`diff_range`/`created_at`/`policy_ref`,
  `producer.agent`/`model`.
- `claim.claim`, `claim.surface.*`, `claim.how_established`.
- `artifact.media`/`summary`, `differential.probe`/`observed_delta`,
  `attestation.judge_id`/`note`, `gap.desc`/`why_unverified`.
- `id` and `gap.desc` appear in the gate's human-readable reason output but are
  not enforcement inputs.

### Artifacts and paths

- `uri` is a path relative to the bundle directory, never absolute. The gate
  resolves it under the bundle dir, rejects any escape or symlink, size-caps the
  read (64 MiB per artifact), and recomputes the sha256.
- `sha256` (required, `^[0-9a-f]{64}$`): detects post-bundle **mutation** only.
  It is not evidence the file came from driving a real surface; that is
  judge-only.

### What the gate trusts on assertion (v1)

Nothing in the bundle is signed, so the gate detects post-bundle mutation but
not fabrication: `risk_tier`, `context` (author/fresh-blind), `attestation.lab`,
`surface.kind`, which claims were declared at all, and two captures fabricated
*consistently* are all trusted on assertion. These are judge-only concerns until
signing lands. See the README's Threat model and limitations section.
