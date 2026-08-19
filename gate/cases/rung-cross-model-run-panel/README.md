# Case: rung verifying itself (independent cross-model run panel)

*At which rung did your agent verify?* This case is the bottom-right cell of
rung's own grid: an **independent** party that **ran** the real surface, not merely
read it. It builds on the sibling
[`rung-self-verdict-determinism`](../rung-self-verdict-determinism/) case, which
proves the same determinism property in **author** context. Here the same property
is reproduced by a blind two-model panel that each drove the surface itself.

Everything here is real and re-checkable on your box. The artifact under test is
the gate's own verdict bytes, which carry only content-derived hashes and the
resolved policy (no filesystem paths), so the captures re-gate identically anywhere.

## The claim

> rung's gate verdict is deterministic across Python hash seeds, and that
> invariance was reproduced independently by a blind cross-model panel. Each
> reviewer ran on a model other than the producer's and drove rung's real gate
> surface itself with its own `rung run`, rather than re-deriving the verdict from
> the producer's captured bytes.

## How it was established (rung 1, differential method, independent, cross-model)

A blind two-model panel each ran `rung skill --print`, and, given **only** the
claim text and its risk tier, independently constructed a differential invariance
run of the gate under two `PYTHONHASHSEED` values:

```bash
rung run --rung 1 --surface cli --diff --expect-delta invariance \
  -- sh -c 'PYTHONHASHSEED=0 rung gate gate/cases/rung-self-verdict-determinism/bundle.json' \
  ::: sh -c 'PYTHONHASHSEED=1 rung gate gate/cases/rung-self-verdict-determinism/bundle.json'
```

Both reviewers reached **invariance** with the gate exiting 0:

- `claude-sonnet-4-5-20250929` ran the seeds 0 vs 42.
- `claude-haiku-4-5-20251001` ran the seeds 0 vs 1.

Neither is the producer model (`claude-opus-4-8`), so the panel supplies the
**cross-model** qualifier, and because each reviewer *ran* the surface rather than
reading the producer's artifacts, the reviewers' own observation is rung 1, not a
rung-0 review. The committed `artifacts/s0.stdout` and `artifacts/s1.stdout` are the
gate's stdout verdict the panel observed; they are byte-identical, so the invariance
holds. Corrupt one byte and the gate blocks with a sha256 mismatch naming the
artifact.

## What this case checks: high passes, critical blocks

```bash
# passes at its declared high tier: independent context + a cross-model panel
rung gate gate/cases/rung-cross-model-run-panel/bundle.json
#   -> verdict pass, exit 0

# re-scored critical: the panel is cross-model but not cross-lab, so it blocks
rung gate gate/cases/rung-cross-model-run-panel/bundle.json --tier critical
#   -> block: "tier critical needs a cross-lab attestation (lab present and
#      != 'rung-dev', verdict=pass)"
```

A cross-model panel takes this case to high. At critical the gate demands a reviewer
at a different lab, so the same case blocks there: cross-lab cannot be minted by one
operator. The gate holds its own maker to the bar it holds everyone.

## What the gate does and does not check here

The gate confirms the panel's **presence**: `context: independent`, at least one
reviewer model that differs from the producer's, each with `verdict: pass`. It does
**not** confirm the reviewers were blind, that they ran the surface, or that two
Anthropic models fail independently. Those are judge-only concerns,
recorded here as advisory gaps. See `SECURITY.md` for the trust boundary.
