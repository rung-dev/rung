# Policy (`rung-policy/v1`)

A policy is a small JSON object. The gate is one deterministic function of
`(bundle, policy)`; the policy supplies the two data structures: a minimum rung
per risk tier, and where independence (context) is required. Using JSON keeps
one format and parser across bundles and policy, with no third-party dependency
and no Python 3.11 floor.

## Fields

| Key | Meaning |
|-----|---------|
| `version` | Policy format version (currently `1`). |
| `min_rung` | Object mapping each risk tier (`low`/`medium`/`high`/`critical`) to the minimum RUNG required to ship. Must cover all four tiers. |
| `require_context` | Object mapping a tier to the CONTEXT it requires. Only `cross-lab` is mechanically checkable (the claim must declare `context: cross-lab`, and the gate looks for an attestation whose `lab` differs from the producer's and whose `verdict` is `pass`). |
| `no_skip_tiers` | Tiers in which a claim with `verdict: "skip"` is not allowed. |
| `allow_dismiss_gaps` | If `false`, an undismissed `blocker` gap blocks even when every claim passes. |

## The default profile, and why it is calibrated this way

```json
{
  "version": 1,
  "require_context": { "high": "cross-lab", "critical": "cross-lab" },
  "no_skip_tiers": ["high", "critical"],
  "allow_dismiss_gaps": false,
  "min_rung": { "low": 2, "medium": 3, "high": 4, "critical": 4 }
}
```

- `low` = rung 2: a green test suite is enough for cosmetic/low-risk change.
- `medium` = rung 3: you must drive the real surface and observe it.
- `high` / `critical` = rung 4 **and** `require_context: cross-lab`.

`min_rung` and `require_context` are kept **consistent**: every tier that demands
rung 4 also demands independence, so the policy can never accept a *self-reported*
rung 4 at a high/critical tier. That is the **self-report trap**: a producer's
own rung-4 claim is real evidence, but at high risk it blocks until an independent
cross-lab reviewer attests.

## Fail-closed

The gate rejects a policy it cannot trust to enforce: unknown keys (a typo, or a
misplaced field), a missing required key, or a `min_rung` that does not cover all
four tiers all raise a policy-integrity error and **block** rather than silently
shipping with a check disabled.
