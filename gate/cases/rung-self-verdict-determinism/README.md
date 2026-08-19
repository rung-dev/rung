# Case: rung verifying itself (verdict determinism)

*At which rung did your agent verify?* This case is rung turned on rung. The
subject under change is **the gate's own verdict**: does `rung gate` return the
same answer a reviewer will re-check, or does it wobble with something incidental
like Python's hash-seed?

Everything here is real and re-checkable on your box. Unlike a `rung run` capture
of a local binary (which records absolute paths and machine-specific hashes), the
artifact under test is the **gate's verdict bytes**, which carry only
content-derived hashes and the resolved policy, no filesystem paths. So the exact
captures below re-gate identically anywhere.

## The claim

> `rung gate`'s verdict on a fixed input bundle is byte-identical regardless of
> `PYTHONHASHSEED`. Dict and set ordering inside the gate does not leak into the
> output a reviewer re-checks.

## How it was established (rung 1, differential method, invariance)

`rung run --diff` ran the installed gate over the committed flagship bundle
(`gate/cases/sync-connector-stdio-purity/bundle.json`) twice: once under
`PYTHONHASHSEED=0`, once under `PYTHONHASHSEED=1`, comparing **both** channels
(stdout and stderr). Each side was run twice first for byte-stability. The gate,
not the producing tool, decides the polarity from the captured bytes.

- `artifacts/s0.stdout` = the verdict under `PYTHONHASHSEED=0`
- `artifacts/s1.stdout` = the verdict under `PYTHONHASHSEED=1`

They are byte-for-byte equal (identical sha256), so the claimed **invariance**
holds. The two files are pinned by sha256 in `bundle.json` and re-hashed by the
gate; corrupt one byte and the gate blocks with a mismatch naming the artifact.

## Why the differential method, not a single run

A single run proves the gate produced *some* verdict. It cannot prove the verdict
is stable, because a hash-seed-dependent ordering bug shows up only when you run
the same input a second way and diff. The invariance differential is the check
that would catch such a bug, and running it is how we know there isn't one here.
That is the same shape as the install-shape differential that once caught a real
`gate_sha256` self-hash bug (pinned by `SelfHashProvenanceCase` in
`gate/test_gate.py`); see `../../../VERIFYING-RUNG-WITH-RUNG.md` for that story.

## Run the gate yourself

```bash
# from repo root: stdlib only, no install
rung gate gate/cases/rung-self-verdict-determinism/bundle.json
#   -> verdict "pass", exit 0   (a low-tier author self-run: rung 1 clears low)

# same bundle, re-scored as a HIGH-risk change: the self-report trap
rung gate gate/cases/rung-self-verdict-determinism/bundle.json --tier high
#   -> verdict "block", exit 30
#   -> "c1: tier high requires context >= independent, got author"
#   -> "c1: tier high requires a cross-model qualifier, which needs context=independent (got author)"
```

The block at high is the limit for *this* case: it is a determinism check
rung ran on itself, so its context is **author**, and at high tier the gate holds
rung to the same bar as anyone's self-run. That block is about this one artifact,
not rung's evidence overall. rung was also reviewed independently, by blind
cross-model panels that never saw the author's reasoning, more than once and one of
them driven through [syncade](https://github.com/syncade-ai/syncade-ai), and each
cleared it. Author context here, independent cross-model there: the two-axis design
records which is which. See
[`VERIFYING-RUNG-WITH-RUNG.md`](../../../VERIFYING-RUNG-WITH-RUNG.md) for that record.
