# Case: one commit, two polarities: a CLI usage-error double-print

A worked, reproducible example that exercises **both** rung-4 polarities from a
**single diff**, at the same real surface: a `change` claim (behavior differs
S0→S1) and an `invariance` claim (behavior must NOT differ). The subject is a
`*ctl`-style CLI control plane for a proprietary enterprise backend
(Node/TypeScript, built on the `commander` framework).

The fix: on a **usage error**, the shared error handler was re-logging a message
the CLI framework had *already* written to stderr, so human-mode users saw the
error printed multiple times. The fix detects framework-native errors and stays
silent in human mode, while deliberately leaving the `--json` machine channel
untouched.

That "leaving X untouched" is a verification claim in its own right, and it's the
tricky one: it's an **invariance** claim, and a naive rung-4 gate that *required*
an S0≠S1 delta would wrongly reject perfectly good evidence for it. This case
checks that the ladder handles both polarities end to end.

## The two claims

| Claim | Channel | Polarity | Rung-4 evidence |
|-------|---------|----------|-----------------|
| **c1** | human stderr | `change` | S0 prints the message **3×**, S1 prints it **1×** → S0 ≠ S1 |
| **c2** | `--json` stdout | `invariance` | S0 and S1 stdout are **byte-identical**, exit 2 both → S0 == S1 |

Both are rung 4, context author, risk tier medium. Both pass the default policy
(rung 4 ≥ medium's min_rung 3, no cross-lab required at medium).

## Why the lower rungs miss the human-mode bug

| Rung | Verdict on the double-print |
|-----:|-----------------------------|
| 0 | **pass**: the new branch reads correctly; the handler clearly suppresses the re-log |
| 1 | **pass**: call the error formatter in isolation and it returns one string |
| 2 | **pass**: unit tests assert on the formatter's return value / structured error, never on **how many times bytes hit fd 2** when the whole CLI runs |
| 3 | **catches it**: run the built binary, read raw stderr: the message is there **3×** |
| 4 | **attributes it**: 3× at S0, 1× at S1; the diff is what de-duplicated it |

The duplication only exists in the **seam between the framework's own error
printing and the app's error handler**: a place no unit test observes, because
a unit test never lets both run against the same real stderr.

## A rung-3 observation the commit message understates

The commit calls it a "double-print." Driving the real surface shows it is
actually a **triple** print in human mode: the framework's own `error: …` line,
**plus** the app's re-logged `✗ …` summary line, **plus** an indented `Error: …`
detail line. "Read the diff" would have accepted the commit's own wording; only
reading byte-for-byte off the surface reveals the true count. That is what rung
3+ exists to catch.

## What was driven

- Built S0 (parent of the fix) and S1 (the fix) in **isolated detached git
  worktrees** sharing one `node_modules`, so the working repo was never mutated.
- Drove each with a **credentials-free** usage error (two mutually-exclusive
  flags on one subcommand), which the CLI framework rejects **before** any
  backend connection is resolved. No enterprise backend, no secrets, no network.
- Captured raw **stderr** (human mode) and raw **stdout** (`--json` mode) plus
  the exit code, at both commits.

Artifacts: `artifacts/human-s0.stderr`, `human-s1.stderr`, `json-s0.stdout`,
`json-s1.stdout`. Their sha256 hashes are pinned in `bundle.json` and re-checked
by the gate. The two `--json` captures share **the same hash**: that byte-identity is what
the gate checks for the invariance claim (necessary, not sufficient; see Limits). Tool name, subcommand, and flag names are
genericized for anonymization; the byte-level properties under test (the human
message's repeat count, and the machine channel's byte-identity) are preserved
verbatim, and the exit code (2) is real.

## Run the gate yourself

```bash
# from repo root: stdlib only, no install
rung gate cases/ctl-usage-error-doubleprint/bundle.json
#   -> verdict "pass", exit 0   (both claims rung 4 >= medium's min_rung 3)

# re-scored as HIGH risk: the self-report trap blocks BOTH rung-4 author claims
rung gate cases/ctl-usage-error-doubleprint/bundle.json --tier high
#   -> verdict "block", exit 30: "tier high requires context=cross-lab, got author" (x2)
```

Corrupt any byte of any capture and the gate blocks with a sha256 mismatch
naming the artifact. Relabel `c2` as `expected_delta: change` and it blocks
(`rung 4 change-claim shows no S0/S1 delta`), because an unchanged machine
channel is the *wrong* evidence for a change claim; flip `c1` to `invariance`
and it blocks too (`unexpected S0/S1 delta`). The polarity has to match the
claim's intent, and the gate enforces that both ways.

## Limits (one recorded as a gap, one the gate can't check)

- **Gap `g1` (in the bundle):** only one *class* of usage error (framework-native
  mutually-exclusive flags) was driven end-to-end. The handler now also suppresses
  unknown-option, invalid-choice, and missing-argument errors; those share the
  changed code path but were reasoned about, not each driven.
- **Not gate-checkable: invariance provenance.** For an invariance claim,
  byte-identical artifacts are *necessary*, but the gate cannot distinguish "ran
  S0 and S1 independently and got identical output" from "ran once and copied the
  file." This is the invariance analogue of the general limit that a sha256 proves
  a capture wasn't mutated *after* bundling, not that it came from driving a real
  surface. Confirming that both runs happened is a judge-only concern
  (see the repo's `THREAT-MODEL.md`).
