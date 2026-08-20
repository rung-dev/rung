# Verifying rung with rung

rung grades a verification on three axes: how real it was (**rung** 0 or 1), how
it was evaluated (**method**), and who evaluated it (**context**, author or
independent, with cross-model and cross-lab as qualifiers). A tool that makes those
claims should meet them itself: at which rung was rung verified, by what method,
in whose context?

This page answers with rung's own standard. Each check is labeled by how you confirm
it: a bundle you re-gate in this repo, a command you re-run, or a described record you
read on its own terms. The `$ rung gate` transcripts below are abbreviated to the
verdict and its reasons; the gate itself prints the full JSON verdict object (the
[README](README.md#what-rung-records) shows the shape).

The short version: rung was put through the discipline it asks of any change.
Blind, cross-model panels reviewed it independently more than once, one of them
driven through syncade, and cleared it. A differential run, the method rung enforces
for no-regression claims, drove the gate two ways and caught a real bug no single run
would show. Then a blind cross-model panel each drove the real surface itself,
reaching the cell rung reserves for high-risk change: an independent party that ran
the thing. Then rung's own gate scored that evidence, holding its author to the same
bar as everyone else: a real run earns the low tier, an independent cross-model run
reaches high, and critical stays reserved for a second lab. rung reports its own standing to the
rung, which is the point.

The three axes (rung {0,1}, method, and context with its qualifiers) are defined
in [the skill](skill/SKILL.md#the-three-concepts).

## Independent cross-model review: a blind panel cleared it

Before merging a change to rung's command dispatcher, we ran it through
[syncade](https://github.com/syncade-ai/syncade-ai), a blind multi-judge review
loop. It snapshots a committed revision into isolated worktrees and hands each
reviewer the diff with no author rationale: two fresh model reviewers (one Sonnet
on a standard pass, one Opus on an adversarial pass), a cold synthesizer, and a
leg that re-ran the full suite. None of them the author.

Result: **SHIP**, zero blockers, one minor test-harness finding (a namespace
fragility under an alternate invocation, since fixed; plus a subprocess-level
fail-closed test added). Under the adversarial pass the dispatcher contract held:
byte-exact verdict, the closed 0/30/2 exit contract, fail-closed on a broken
`gate.py`, `NO_COLOR` discipline. The falsification attempts failed.

That review clears two of rung's qualifiers by construction: it was **independent**
(no author state) and **cross-model** (Sonnet and Opus, two distinct models). The
run itself is a separate axis, one the differentials below cover: a review reads the
change, and reading is not running. Feed the panel back to rung as an attestation and
the gate scores it precisely. The bundle declares `rung: 0` (not a runtime
observation), `context: independent`, with the panel as its attestation:

```
$ rung gate blind-panel.json --tier high
block
  c1: rung 0 < min_rung[high]=1
  c1: cross-model reviewer model 'claude-opus-4-8' equals the producer model (no model independence)
```

The gate separates the two dimensions cleanly. Independence and cross-model are
satisfied; the rung floor is not, because no one ran the code, so the bundle blocks
at every tier on the floor alone (`rung 0 < min_rung=1`). Review and run are
different axes, and the gate never lets one stand in for the other.

Even on our own panel the cross-model check earned its keep. The real adversarial
pass ran on Opus, the same model that produced the change, and the gate flagged the
collision rather than credit a same-model reviewer as independent: model independence
means a reviewer whose model differs from the producer's. Swap the Opus pass for a
distinct model and the cross-model reason clears, leaving only the floor:

```
$ rung gate blind-panel-distinct.json --tier high
block
  c1: rung 0 < min_rung[high]=1          # the cross-model qualifier now passes; only the floor remains
```

So the cross-model qualifier is real, and the gate holds it against the change's own
author. A review supplies independence across models; the run axis is what the
differentials supply next. That division is why rung exists.

## A differential run caught a real bug

Then we drove rung against its own axes, each gated by the default policy. In v2
the "how real" axis is binary, so the old ladder collapses: an in-process import
is **rung 0** (not the CLI a caller invokes), while running the CLI and driving
the gate are both **rung 1** (observed). What used to be a top-of-ladder
differential is now the enforceable **differential method** at rung 1.

Two differentials matter, and both are re-checkable.

**1. Verdict determinism (committed, re-gateable here).**
`gate/cases/rung-self-verdict-determinism/` is a live case. It ran `rung gate`
over the committed flagship bundle twice, once under `PYTHONHASHSEED=0` and once
under `PYTHONHASHSEED=1`, and compared both output channels. The captured verdict
carries only content-derived hashes and the resolved policy, no filesystem paths,
so the bytes re-gate identically on any machine (unlike a capture of a local binary,
which records absolute paths). The two captures are byte-identical, so the
**invariance** holds: the gate's answer does not wobble with hash-seed-dependent
dict or set ordering. A single run could not have shown that; only running it two
ways and diffing can. Re-check it:

```
$ rung gate gate/cases/rung-self-verdict-determinism/bundle.json
pass
```

**2. The install-shape differential that caught a real bug.**
An earlier differential ran `rung gate` on the same bundle under two install
shapes, a normal unzipped `pip install` and the wheel imported straight off the
path via zipimport, and let the gate decide the delta from the captured bytes. It
**blocked** on a real defect: `gate_sha256` was a hash under the unzipped install
but `null` under zipimport. The self-hash read its own source through `__file__`
as a file, which fails inside a zip, so the field that ties a verdict to the exact
gate logic came back empty in one install shape. Nothing short of the differential
found it: not the blind read, not the single-observation rung-1 checks. The fix
falls back to the module loader when `__file__` is not an openable file;
`gate_sha256` is now non-null and identical across install shapes. The fix is
pinned by a regression test, `SelfHashProvenanceCase` in `gate/test_gate.py`,
which builds a real zipimport and asserts the self-hash survives it.

One more field note from running rung on a real CLI: witnessing a process with
`rung run` (direct exec, no shell) surfaced a non-zero exit that a piped `... | head`
had silently swallowed. The pipe dropped the real exit code; direct exec did not.
Exec-and-observe catches what shell pipelines quietly discard.

## An independent cross-model panel ran it, not read it

The blind panel at the top of this page is a review: it reads the change, so it sits
at rung 0. A differential is a run, but the author's. The cell rung reserves for
high-risk work is the one that is both: an independent party that *ran* the real
surface. rung has a committed case in that cell,
`gate/cases/rung-cross-model-run-panel/`.

A blind two-model panel (one Sonnet, one Haiku, neither the producer's Opus) was
handed `rung skill --print` and, given only the claim and its risk tier,
independently built its own differential-invariance `rung run` over the gate under
two hash seeds. Each drove the surface itself and reached invariance with the gate
exiting 0. Fed back as the claim's `attestation`, the panel supplies the cross-model
qualifier on an observation that is rung 1 for the reviewers too, not a rung-0 read.
So the case clears high:

```
$ rung gate gate/cases/rung-cross-model-run-panel/bundle.json
pass
```

Cross-model is not cross-lab. Both reviewers are models one operator drove, so the
same case blocks the moment it is scored critical:

```
$ rung gate gate/cases/rung-cross-model-run-panel/bundle.json --tier critical
block
  c1: tier critical needs a cross-lab attestation (lab present and != 'rung-dev', verdict=pass)
```

Critical stays reserved for a second organization, which one operator cannot mint.

## rung scores its own evidence

The gate does not exempt its author. Both differentials above are **author**
context, since rung ran the checks on itself, so at high tier the gate blocks them
the same way it blocks anyone's self-run:

```
$ rung gate gate/cases/rung-self-verdict-determinism/bundle.json --tier high
block
  c1: tier high requires context >= independent, got author
  c1: tier high requires a cross-model qualifier, which needs context=independent (got author)
```

That is the design working on its own maker: a real run clears the low tier, and
anything higher calls for an independent party. rung's evidence about itself lands
in three cells of its own grid, by three methods:

- **Independent and cross-model**, from the blind review panel: a review, rung 0.
- **A real run under a differential method**, from the author: rung 1, author.
- **An independent cross-model panel that ran the surface**: rung 1, independent, the
  top-right cell, cleared at high.

The top-right cell, an independent party running the real surface, is the bar
rung sets for high-risk change, and the cross-model run panel above reaches it at
high. Cross-lab, the strongest qualifier, is reserved for critical tier and asks
for a second organization. The gate refuses to let a same-lab review pose as one:

```
$ rung gate blind-panel-distinct.json --tier critical
block
  c1: rung 0 < min_rung[critical]=1
  c1: tier critical needs a cross-lab attestation (lab present and != 'rung-dev', verdict=pass)
```

Relabel a same-lab review as cross-lab and the lab-equality guard rejects it. The
moment a different-lab reviewer runs rung, the gate accepts the attestation. rung
states its own position to the rung and will not inflate it, which is the standard
it exists to hold every other change to.

## Reproduce

Both committed cases are fully re-checkable from a clean checkout, stdlib only:

```bash
# author self-run: passes low (rung 1, author, invariance differential)
rung gate gate/cases/rung-self-verdict-determinism/bundle.json

# same evidence, re-scored high: the self-report trap blocks author context
rung gate gate/cases/rung-self-verdict-determinism/bundle.json --tier high

# independent cross-model run panel: passes high (rung 1, independent, cross-model)
rung gate gate/cases/rung-cross-model-run-panel/bundle.json

# same panel, re-scored critical: blocks for want of a cross-lab reviewer
rung gate gate/cases/rung-cross-model-run-panel/bundle.json --tier critical
```

Corrupt any byte of an artifact and the gate blocks with a sha256 mismatch naming
it: the captures are content-addressed, not trusted. The blind-panel bundles shown
above illustrate the attestation mechanics (a rung-0 read blocks the floor by
design, so they are not committed as pass-expected cases); the shape is a
`rung: 0`, `context: independent` claim carrying the panel as its `attestation`.

## Bottom line

Four results: blind cross-model panels reviewed rung and cleared it; a differential
run caught a real bug a single run would have missed; a blind cross-model panel then
ran the surface itself and cleared high; and rung's own gate scored the whole record,
crediting the low tier, reaching high on an independent cross-model run, and reserving
critical for a second lab. **review proposes, running settles**, and rung holds itself to the
standard it asks of every change it grades.
