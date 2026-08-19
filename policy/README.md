# Policy (`rung-policy/v2`)

A policy is a small JSON object. The gate is one deterministic function of
`(bundle, policy)`. The policy supplies the ship bar: a minimum rung per risk
tier, where independence (context) is required, and which independence
qualifiers each tier demands. JSON keeps one format and parser across
bundles and policy, with no third-party dependency and no Python 3.11 floor.

The rung values (0 = not runtime-observed, 1 = observed), the methods
(`single`, `differential`, `adversarial`, `fuzz`, `property`), and the contexts
(`author`, `independent`) are defined in
[the skill](../skill/SKILL.md#the-three-concepts).

## Fields

| Key | Meaning |
|-----|---------|
| `version` | Policy format version (currently `2`). A human label; the gate does not check its value. |
| `min_rung` | Object mapping each risk tier (`low`/`medium`/`high`/`critical`) to the minimum RUNG required to ship, an integer in `[0, 1]`. Must cover all four tiers. |
| `require_context` | Object mapping a tier to the minimum CONTEXT it requires, on the ladder `author < independent`: a tier is satisfied by any context at least as independent. `author`/`independent` carry no checkable field, so this enforces *who is claimed to have checked*, not the review's quality. |
| `require_cross_model` | Array of tiers demanding a **cross-model qualifier**: the claim needs `context: independent` **and** `change.producer.model` set plus an attestation naming >= 1 reviewer model (via `model`/`panel[]`), each a non-empty string differing from the producer's model, `verdict: pass`. |
| `require_cross_lab` | Array of tiers demanding a **cross-lab qualifier**: the claim needs `context: independent` **and** an attestation whose `lab` is present and differs from the producer's, `verdict: pass`. |
| `require_method` | Optional object mapping a tier to a required METHOD (one of `single`/`differential`/`adversarial`/`fuzz`/`property`). A claim whose method differs blocks. Absent ⇒ any method accepted. |
| `no_skip_tiers` | Tiers in which a claim with `verdict: "skip"` is not allowed. |
| `allow_dismiss_gaps` | If `false`, an undismissed `blocker` gap blocks even when every claim passes. |

## The default profile, and why it is calibrated this way

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

- `min_rung` = `1` everywhere: **shipped ⇒ observed.** Every tier demands a
  runtime observation of the real surface; a rung-0 (not-observed) claim never
  clears the floor.
- `low` = an author self-run is enough: `min_rung 1`, no independence required.
- `medium` = `require_context: independent`: an independent review is required.
- `high` = independent **and** a **cross-model** qualifier.
- `critical` = independent **and both** a cross-model **and** a **cross-lab**
  qualifier.

`min_rung` and the context/qualifier requirements are kept **consistent**: every
tier above low demands independence, so the policy can never accept a
*self-reported* observation at medium or above. That is the **self-report trap**:
a producer's own rung-1 observation is real evidence, but at medium+ it blocks
until an independent reviewer attests, and at high/critical until that review
runs on a different model (and, at critical, a different lab).

## Fail-closed

The gate rejects a policy it cannot trust to enforce. These all raise a
policy-integrity error and **block** rather than silently shipping with a check
disabled: unknown keys (a typo, or a misplaced field), a missing required key, a
`min_rung` that does not cover all four tiers or is out of `[0, 1]`, an unknown
`require_context` value, a non-list
`no_skip_tiers`/`require_cross_model`/`require_cross_lab`, or a `require_method`
naming an unknown tier or method.
