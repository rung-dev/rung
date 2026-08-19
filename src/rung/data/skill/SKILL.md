---
name: rung
description: >-
  Grade and gate HOW REAL a verification was, HOW it was evaluated, and WHO
  checked it. Use when you need to claim, record, or enforce that a code change
  was verified: author or witness an evidence-bundle/v2 document and run rung's
  deterministic gate over it. Reach for this whenever a task ends in "verified"
  and that word has to mean something a checker can enforce, when wiring a
  ship/no-ship gate into CI, or when driving a real surface and capturing what
  it did as evidence.
---

# rung

**At which rung did your agent verify?**

rung grades *how real* a verification was, *how* it was evaluated, and *who*
checked it, then gates the result. It is a shared vocabulary, a portable JSON
evidence bundle, a declarative policy, and a single deterministic gate. It holds
no keys, signs nothing, and never phones home. The gate's only disk I/O is
reading the bundle and policy and re-hashing the artifacts they reference.

## The three concepts

A verification claim collapses three separate questions into one word. rung
pulls them apart into three separate concepts.

**RUNG: how real (0 or 1).** Binary.

| Rung | Meaning |
|-----:|---------|
| 0 | Not a runtime observation of the real surface: read-only reasoning, a unit called in isolation, or a green test suite |
| 1 | Drove the real surface and observed it (captured its actual bytes) |

**METHOD: how the observation was evaluated.** `single` (one observation, the
default); the enforceable `differential` (drove the surface twice and captured an
S0/S1 pair whose delta matches the declared polarity: they differ for a `change`
claim, byte-identical for an `invariance` / no-regression claim); and the
advisory `adversarial` / `fuzz` / `property` (recorded, never gated). Differential
is a **method at rung 1**, not a higher rung.

**CONTEXT: who evaluated.** Two values, `author` (the producer) and `independent`
(a reviewer with no producer state). `cross-model` and `cross-lab` are **not**
higher contexts. They are independence **qualifiers** a policy demands per-tier
(`require_cross_model` / `require_cross_lab`), each requiring `context:
independent` plus a structural attestation: a *cross-model* qualifier means the
independent reviewer ran on a *different model* than the producer; a *cross-lab*
qualifier means the reviewer was at a *different lab*. The gate checks the
qualifiers only for presence, never authenticity; `author` vs `independent` is the
producer's word, which nothing can check. See
[Producing a cross-model attestation](#producing-a-cross-model-attestation).

## When to use this skill

- You finished a change and need to say, in a way a checker can enforce, how real
  your verification was. Author a bundle, or let `rung run` witness one.
- You are gating a merge or a batch of machine-made claims and need a
  fail-closed, machine-readable verdict. Run `rung gate` in CI.
- You drove a CLI, server, GUI, library, agent, or CI surface and want the
  captured bytes recorded as evidence with a verdict attached. Use `rung run`.

If the task is only reasoning about code (rung 0) with no surface to drive,
say so plainly; do not dress it up as a higher rung.

## The two ways in

**1. Gate an already-authored bundle.** You (or another tool) write an
`evidence-bundle/v2` JSON document, then:

```bash
rung gate bundle.json                 # uses the bundled default policy
rung gate bundle.json policy.json     # or pin your own policy
```

**2. Witness a run.** Instead of driving the surface and hand-typing a sha256,
let `rung run` execute the probe, capture the exact bytes off its own
stdout/stderr, write the bundle, and gate it:

```bash
rung run --rung 1 --surface cli --tier low -- mytool --check
rung run --rung 1 --diff --surface cli --tier low -- mytool --old ::: mytool --new
```

`--rung` and `--surface` are required: the tool witnesses *bytes*, never a rung,
so it never mints one for you (a runtime observation is `--rung 1`; anything
short of it is `--rung 0` and needs no capture). The probe argv comes after a
bare `--`; in `--diff` mode (which sets `method: differential`) a bare `:::`
splits it into S0 (baseline) and S1 (changed).

See [references/cli.md](references/cli.md) for every subcommand and flag.

## The exit-code contract

Three codes, for both `rung gate` and `rung run`:

- `0` = pass (the only pass)
- `30` = block
- `2` = usage error / cannot-evaluate

**Only exit 0 is pass.** In any wrapper, treat both `30` and `2` as no-ship. A
wrapper that keys on `exit != 30` fails open on the `2`s. Never add a fourth
code.

## Ground rules

- **The gate only ever lowers trust.** A producer-declared `pass` grants
  nothing; only the gate's own checks pass a claim. A declared `fail`/`blocked`
  still blocks. New checks add block reasons, never a green light.
- **Never mint a rung or a surface you did not observe.** `rung run` witnesses
  bytes; it cannot tell a real-surface drive from an import, so over-claiming
  `--rung` is a deliberate, logged act, not a default.
- **Declare gaps, do not hide them.** An untested path, an un-driven surface, a
  truncated capture: record it as a gap. A blocker gap blocks unless policy
  explicitly allows dismissal.
- **Author context is not independence.** Self-witnessing tops out at `author`
  context, which under the default policy clears only the **low** tier. The
  `independent` context and the cross-model / cross-lab qualifiers each require a
  real independent attestation, which the gate checks for presence only. A
  cross-model qualifier (a different model, run blind) is the strongest
  independence a solo rung+Claude operator can self-produce without faking it; a
  cross-lab qualifier needs a different org, which you cannot mint for yourself.
- **Redact before publishing.** Captures routinely hold secrets, tokens, PII,
  and internal hostnames. `rung run --redact` masks obvious secrets in the written
  captures and `--scan-secrets` blocks one that still matches, but both are
  heuristic (precision over recall). A clean scan is *not* proof, so a final
  hand-review before publishing is still your job. Use `--env-clear` to run a probe
  with a scrubbed environment so operator-env tokens never enter a capture.
- **Pin the gate and the policy.** Run a trusted, version-pinned gate, never the
  subject repo's own copy (that is code execution as the judge). A structurally
  valid policy can still enforce nothing.

## Producing a cross-model attestation

A **cross-model qualifier** is the strongest independence a solo rung+Claude
operator can self-produce without faking it: the claim is `context: independent`
*and* a *different model* than the one that produced the change re-checks it, blind.
The gate checks this structurally (`context: independent`, a reviewer model present,
`!= change.producer.model`, `verdict: pass`), but presence is not proof the review
happened, was blind, or that the models fail independently. Those hold only if you
run the protocol below. Claiming the qualifier when no different model re-derived
the verdict is the same lie as forging a cross-lab attestation.

**The review contract**, what a cross-model qualifier `pass` must mean:

- The claim's `context` is `independent` (the qualifier is meaningless without it;
  the gate blocks a qualifier on an `author` claim).
- The reviewer runs on a model different from `change.producer.model`
  (a different model counts; the same model at a different temperature does not).
- The reviewer is **blind**: it sees the claim text, the risk tier, and the
  captured artifacts (S0/S1 bytes, logs, responses), and NOT the producer's
  reasoning, the producer's verdict, or this conversation's history.
- The reviewer re-derives the verdict *from the artifacts*: do the captured bytes
  establish the claim at rung 1 on their own? `pass` only if yes.
- A cross-model qualifier `pass` requires **every** reviewer model to pass. One
  `fail`, one `blocked`, or a reviewer sharing the producer's model voids it.

A reviewer may go further than re-deriving the verdict from the producer's captures:
it can drive the real surface itself with its own `rung run`. That makes the
reviewer's own observation rung 1, not a rung-0 read, the strongest independent
evidence a panel can supply.

**The protocol**, as the operating agent:

1. Set `change.producer.model` to the model that produced the change. Without it
   the gate cannot define model independence and blocks.
2. Spawn one or more reviewer subagents, each pinned to a model `!=` the
   producer's. For a panel, use two or more distinct non-producer models.
3. Give each reviewer only the claim, the risk tier, and the artifacts, never the
   producer's reasoning or verdict. Ask it to independently decide whether the
   artifacts establish the claim, returning `pass`/`fail` and a one-line reason.
4. Record it on the claim's `attestation`: a single reviewer as
   `{ "model": "<reviewer-model>", "verdict": "pass" }`, or a panel as
   `{ "panel": [ { "model": "...", "verdict": "pass" }, … ], "verdict": "pass" }`.
5. Gate it. The gate confirms every reviewer model differs from the producer's and
   every verdict is `pass`; anything else blocks.

Do not weaken the blindness to reach a pass. If a reviewer needs producer context
to agree, the claim does not earn the cross-model qualifier. Record a gap and
drop to the context and qualifier you achieved.

## Verifying a stdout-purity / log-leak fix (when nondeterminism IS the defect)

A common change is "diagnostics were leaking onto stdout; they now go to stderr,
so stdout is clean." The obvious move, `rung run --diff --expect-delta change`
across the pre-fix (S0) and post-fix (S1) surfaces, **will block**, and that is
correct, not a tool bug. Each side is run twice to confirm the compared channel
is byte-stable; a leaked wall-clock timestamp or PID makes S0's stdout differ
run-to-run, so the runner records a `nondeterministic-output` blocker. The guard
firing on S0 is the tool *observing the very defect you are fixing*: a byte
delta cannot prove the fix when S0 is nondeterministic by construction.

rung offers **no** silent or normalizing comparison to paper over this: forcing
two outputs to look equal is the fabrication the gate exists to prevent.
(`--redact` is the only disclosed transform, and it is for *secrets*, not
determinism.) So prove the fix as two facts about the **fixed side (S1)**, not as
an S0→S1 delta:

1. **Purity**: a single-run rung-1 witness of the fixed surface whose captured
   stdout is only protocol frames. For line-delimited protocols, `--expect-frames
   N` asserts the frame count; a leak inflates it, so a clean count is the signal.

   ```bash
   rung run --rung 1 --surface server --tier low --expect-frames 1 \
     --stdin init.json -- my-fixed-server
   ```

2. **Determinism**: a differential of the fixed surface *against itself* as an
   invariance claim (rung 1, `method: differential`). Two stable, byte-identical
   runs pass, witnessing that stdout is now byte-stable, i.e. the
   nondeterministic leak is gone:

   ```bash
   rung run --rung 1 --diff --expect-delta invariance --surface server --tier low \
     --stdin init.json -- my-fixed-server ::: my-fixed-server
   ```

The pre-fix dirtiness is context for the claim's prose and the diff/commit range,
not the evidence that carries the claim; S1's demonstrated purity and stability are. If you
must record the before/after transition itself, hand-author the bundle and let a
judge weigh it. The runner will not mint a change delta over a nondeterministic
baseline.

## Config reference

- [references/cli.md](references/cli.md): every `rung` subcommand, all flags,
  how to run without installing, and the exit-code contract in full.
- [references/config.md](references/config.md): the policy knobs
  (`policy/default.json`) and the `evidence-bundle/v2` bundle shape (enforced vs
  advisory fields).
- [references/surfaces.md](references/surfaces.md): what "the real surface" is
  per `--surface` kind, how to reach rung 1, and when to record a gap.
