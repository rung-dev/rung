# Case: stdout-purity of a stdio protocol server

*At which rung did your agent verify?* A worked, reproducible example of a real
defect that **every check short of observing the real surface passes**. The
subject is a hosted-calendar **sync connector exposed to AI assistants** over a
standard newline-delimited JSON-RPC-over-stdio protocol. On that transport,
**stdout is the protocol channel**: the first line a client reads must be a valid
protocol frame.

The bundle, artifacts, and gate output in this directory are real: the S0/S1
stdout captures were produced by driving the built server at two commits, then
redacted for anonymization. The rung-0 rows in the table below are described, not
re-run here. The evidence that carries the claim is the **rung-1 differential** (the fix
observed at the real surface, S0 vs S1), which is what the artifacts and gate
check.

## The claim

> The server's first stdout line is a valid JSON-RPC frame: no logging
> banner precedes the protocol stream, so a strict client can parse the
> initialize response.

## Why everything short of a real-surface observation passes it anyway

In v2, RUNG is binary: `0` = not a runtime observation of the real surface,
`1` = observed. Every "cheaper" check below is **rung 0** (it never reads file
descriptor 1 as the byte stream a client does) and every one of them passes this
defect:

| Check | Rung | Verdict on this defect |
|-------|-----:|------------------------|
| Read the diff, reason about it | 0 | **pass**: the handler returns a well-formed frame; the code looks correct |
| Import the serializer, call it | 0 | **pass**: the frame serializes to valid JSON in isolation |
| Run the test suite | 0 | **pass**: tests assert on parsed objects, never on **raw stdout byte 0** |
| Drive the real surface, read raw stdout | 1 | **catches it at S0**: line 1 is a logging banner, not JSON |
| Differential method (drive S0 and S1, diff the surface) | 1 | **attributes it**: the banner is present at S0, gone at S1; the change is what removed it |

The defect lives in the **boundary between a logging library's startup and the
protocol stream**: the one place no unit test looks, because a unit test never
reads file descriptor 1 as a byte stream the way a client does. Only rung 1 (a
runtime observation of the real surface) sees it; the **differential method**
then attributes it to the change.

## What was driven

- Built the fat JAR at **S0** (baseline, parent of the fix) and **S1** (the
  fix) in **isolated detached git worktrees**, so the working repo was never
  mutated.
- Drove each with a **credentials-free** `initialize` handshake piped to stdin
  under `timeout`; captured raw stdout.
- Compared **line 1**:
  - **S0** → `kotlin-logging: initializing... active logger factory: …`  ← not JSON
  - **S1** → a valid JSON-RPC `initialize` result frame  ← parses cleanly

The two captures are `artifacts/s0.stdout` and `artifacts/s1.stdout`; their
sha256 hashes are pinned in `bundle.json` and re-checked by the gate. The frame
**payloads** are genericized for anonymization (protocol/version/tool fields
redacted); the byte-level property under test (line 1 parses as JSON at S1 and
does **not** at S0) is preserved verbatim, and you can confirm it with
`python3 -c 'import json,sys; json.loads(open(sys.argv[1]).readline())' <file>`.

### One confound to flag

The fix-era build pinned a JDK-17 toolchain; only JDK 21 was available, so
both worktrees had the toolchain line patched to 21 **identically**. The JDK
affects the runtime JVM and classloading,
beyond the target bytecode, so a differential run under a *different* JDK than
either commit shipped with could in principle move runtime behavior. Two things
bound the risk here: the patch is byte-identical across S0 and S1 (so it cannot
*create* a delta between them), and the observed behavior (a logging library
emitting to stdout before the protocol stream) is a startup-ordering property
with no JDK-version dependency. Recorded in the bundle's `how_established`.

## Scope, recorded as a gap

This case drives what can be driven credentials-free, the **protocol handshake**
at the real surface, and records the rest as a gap. Live read and write operations
are auth-gated behind a provisioned test credential and mutate remote state, so the
right rung for them is a labeled mock rung or rung 0, carried as an **advisory gap**
(`g1`). Scoping each claim to the rung it
reached, and recording what was not driven, is the method the whole framework runs
on.

## Run the gate yourself

```bash
# from repo root: stdlib only, no install
rung gate gate/cases/sync-connector-stdio-purity/bundle.json
#   -> verdict "pass", exit 0   (a low-tier author self-run: rung 1 clears low)

# same bundle, re-scored as a HIGH-risk change: the self-report trap
rung gate gate/cases/sync-connector-stdio-purity/bundle.json --tier high
#   -> verdict "block", exit 30
#   -> "c1: tier high requires context >= independent, got author"
#   -> "c1: tier high requires a cross-model qualifier, which needs context=independent (got author)"
```

That second run shows the self-report trap in action: a **self-reported rung-1
observation** is real evidence, but at a high-risk tier the policy will not ship
on the producer's own word. It requires an **independent** review plus a
**cross-model** independence qualifier. Rung (how real), method (how evaluated),
and context (who evaluated) are independent axes, and the gate enforces each.

Corrupt any byte of an artifact and the gate blocks with a sha256 mismatch
naming the artifact: the captures are content-addressed, not trusted.
