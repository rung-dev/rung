# Case: one commit, two polarities: a CLI usage-error double-print

A worked, reproducible example that exercises **both** differential polarities
from a **single diff**, at the same real surface: a `change` claim (behavior
differs S0→S1) and an `invariance` claim (behavior must NOT differ). The subject
is a `*ctl`-style CLI control plane for a proprietary enterprise backend
(Node/TypeScript, built on the `commander` framework).

The fix: on a **usage error**, the shared error handler was re-logging a message
the CLI framework had *already* written to stderr, so human-mode users saw the
error printed multiple times. The fix detects framework-native errors and stays
silent in human mode, while deliberately leaving the `--json` machine channel
untouched.

That "leaving X untouched" is a verification claim in its own right, and the
tricky one: an **invariance** claim. A naive differential gate that *required*
an S0≠S1 delta would wrongly reject good evidence for it. This case checks that
the differential method handles both polarities end to end.

## The two claims

| Claim | Channel | Polarity | Differential evidence |
|-------|---------|----------|-----------------------|
| **c1** | human stderr | `change` | S0 prints the message **3×**, S1 prints it **1×** → S0 ≠ S1 |
| **c2** | `--json` stdout | `invariance` | S0 and S1 stdout are **byte-identical**, exit 2 both → S0 == S1 |

Both are rung 1 (observed), method `differential`, context author, risk tier low.
Both pass the default policy (rung 1 clears low's `min_rung`; low demands no
independence).

## Why everything short of a real-surface observation misses the human-mode bug

In v2, RUNG is binary: `0` = not a runtime observation of the real surface,
`1` = observed. Every check below the surface drive is **rung 0**, and every one
passes the double-print:

| Check | Rung | Verdict on the double-print |
|-------|-----:|-----------------------------|
| Read the diff, reason about it | 0 | **pass**: the new branch reads correctly; the handler clearly suppresses the re-log |
| Call the error formatter in isolation | 0 | **pass**: it returns one string |
| Run unit tests | 0 | **pass**: they assert on the formatter's return value / structured error, never on **how many times bytes hit fd 2** when the whole CLI runs |
| Drive the built binary, read raw stderr | 1 | **catches it**: the message is there **3×** |
| Differential method (S0 vs S1) | 1 | **attributes it**: 3× at S0, 1× at S1; the diff is what de-duplicated it |

The duplication only exists in the **boundary between the framework's own error
printing and the app's error handler**: a place no unit test observes, because
a unit test never lets both run against the same real stderr.

## A rung-1 observation the commit message understates

The commit calls it a "double-print." Driving the real surface shows it is
a **triple** print in human mode: the framework's own `error: …` line,
**plus** the app's re-logged `✗ …` summary line, **plus** an indented `Error: …`
detail line. "Read the diff" would have accepted the commit's own wording; only
reading byte-for-byte off the surface reveals the true count. That is what a
rung-1 (real-surface) observation exists to catch.

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
the gate checks for the invariance claim (necessary, not sufficient; see "Scope,
stated on the record" below for the judge-only part). Tool name, subcommand, and flag names are
genericized for anonymization; the byte-level properties under test (the human
message's repeat count, and the machine channel's byte-identity) are preserved
verbatim, and the exit code (2) is real.

## Run the gate yourself

```bash
# from repo root: stdlib only, no install
rung gate gate/cases/ctl-usage-error-doubleprint/bundle.json
#   -> verdict "pass", exit 0   (both claims rung 1; a low-tier author self-run)

# re-scored as HIGH risk: the self-report trap blocks BOTH author claims
rung gate gate/cases/ctl-usage-error-doubleprint/bundle.json --tier high
#   -> verdict "block", exit 30:
#      "c1/c2: tier high requires context >= independent, got author"
#      "c1/c2: tier high requires a cross-model qualifier, which needs context=independent (got author)"
```

Corrupt any byte of any capture and the gate blocks with a sha256 mismatch
naming the artifact. Relabel `c2` as `expected_delta: change` and it blocks
(`differential change-claim shows no S0/S1 delta`), because an unchanged machine
channel is the *wrong* evidence for a change claim; flip `c1` to `invariance`
and it blocks too (`differential invariance-claim shows an unexpected S0/S1
delta`). The polarity has to match the claim's intent, and the gate enforces
that both ways.

## Scope, stated on the record

- **Gap `g1` (in the bundle):** one *class* of usage error (framework-native
  mutually-exclusive flags) was driven end-to-end, and the rest are recorded as a
  gap. The handler now also suppresses unknown-option, invalid-choice, and
  missing-argument errors; those share the changed code path and were reasoned
  about rather than each driven.
- **A judge-only boundary: proving both runs happened.** For an invariance claim,
  byte-identical artifacts are *necessary*, and the gate stops there by design: it
  cannot distinguish "ran S0 and S1 independently and got identical output" from
  "ran once and copied the file." This is the invariance analogue of the general
  boundary: a sha256 proves a capture wasn't mutated *after* bundling, and whether
  it came from driving a real surface is a judge's call. Confirming that both runs happened is a
  judge-only concern (see the repo's `SECURITY.md`).
