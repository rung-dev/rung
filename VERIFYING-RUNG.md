# Verifying rung

rung grades how real a verification was and who checked it. So it's only fair to
turn the same question on rung: how real is the verification of rung itself, and
who did it? This page walks through the checks rung has been through, and what
each one does and doesn't catch.

The ladder (rungs 0 to 4) and the three contexts (author, fresh-blind,
cross-lab) are defined in the
[README](README.md#two-axes-how-real-and-who-checked).

Here's the short version. A blind code review and rungs 0 to 3 all missed the
bug in the same packaging change (rung 1 blocked, but only on the policy floor,
not the defect). The only check that caught the bug was the rung-4 differential,
because it ran the code two ways instead of reading it. And even
that was rung checking itself. Nobody at another lab has verified rung, so the
cross-lab column, the one rung says matters most, is still empty here.

## 1. External blind review (syncade)

Before merging, we ran the packaging change through
[syncade](https://github.com/syncade-ai/syncade-ai), a blind multi-judge review
orchestrator. It snapshots a committed revision into isolated worktrees and hands
each reviewer the diff with no author rationale attached: two independent model
reviewers, one of them adversarial, plus a separate synthesizer, and none of them
the author.

Result: verdict SHIP, zero findings on the diff.

But the reviewers never ran what they read, and that gap is why rung exists.
They read the diff and the committed tree, never built the wheel and ran it, so
they missed the provenance bug that dogfooding caught next. That's not a knock on the
review. Reading a change is not the same as running it. A blind review is a
rung-0 pass done fresh-blind (independent readers, no access to the author's
intent), not a runtime drive, and reading code can't surface a bug that only
shows up when the code runs in a different install shape.

## 2. Dogfooding: verifying rung with rung

Then we drove the packaging build up rung's own ladder, rungs 1 through 4, each
gated by the default policy.

| Rung | Probe | Verdict |
|-----:|-------|---------|
| 1 | import and call (`python -c "import rung..."`) | **block**: rung 1 < `min_rung[low]` = 2. The gate won't let an import-level check clear even the low-risk floor. |
| 2 | run the CLI (`rung version`) | **pass** |
| 3 | drive the real surface (`rung gate <bundle>`) | **pass** |
| 4a | determinism: same result across `PYTHONHASHSEED` | **pass** |
| 4b | install-shape invariance: pip-unzip vs zipimport-wheel | **block, then pass after the fix** |

The 4b probe ran `rung gate` on the same bundle under two install shapes, a
normal unzipped `pip install` and the wheel imported straight off the path via
zipimport, and let the gate decide the delta from the captured bytes. It blocked
on a real bug: `gate_sha256` was a hash under the unzipped install but `null`
under zipimport. The self-hash read its own source through `__file__` as a file,
which fails inside a zip, so the field that ties a verdict to the exact gate logic
came back empty in one install shape.

That's a real provenance bug, and nothing short of rung 4 found it: not the blind
review, not rungs 1 to 3. We fixed it by falling back to the module loader when
`__file__` isn't an openable file; `gate_sha256` is now non-null and identical
across install shapes, and the 4b check passes.

### What this doesn't prove

Every rung above is **author context**: rung ran the check on itself. That counts
as self-evidence, not independent review. Take the same rung-4 bundle, score it at
tier high, and it blocks, because the policy wants a
cross-lab attestation there and a self-run check can only ever claim author
context. So rung's verification of itself stops at author-context rung 4, plus one
fresh-blind reading pass. Nobody at another lab has attested to it, and rung is
upfront that cross-lab is the strongest kind of check, and it has none of that for
itself.

### Reproduction

We didn't commit the dogfood bundles: `rung run` records absolute paths and the
sha256 of local binaries, so they're machine-specific and wouldn't reproduce on
your box. Here's the shape of the 4b probe, given a built wheel and a venv
install:

```bash
rung run --rung 4 --surface cli --tier medium \
  --claim "rung gate verdict is invariant across install shape" \
  --diff --expect-delta invariance \
  -- "$VENV/bin/rung" gate "$BUNDLE" \
  ::: env PYTHONPATH="$WHEEL" python3 -m rung.gate "$BUNDLE"
```

Before the fix this blocked (exit 30) on an unexpected S0/S1 delta; after it, it
passes (exit 0). A regression test, `SelfHashProvenanceCase` in
`gate/test_gate.py`, pins the fix: it builds a real zipimport and checks the
self-hash survives it.

## Bottom line

The cheap, static checks passed the change. The one check that actually ran it
under different conditions caught what they missed. And rung's best claim about
itself is still only author context, with the cross-lab column empty. That's rung
measured by its own ruler: author context and no more.
