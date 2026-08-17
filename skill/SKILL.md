---
name: rung
description: >-
  Grade and gate HOW REAL a verification was and WHO checked it. Use when you
  need to claim, record, or enforce that a code change was verified: author or
  witness an evidence-bundle/v1 document and run rung's deterministic gate over
  it. Reach for this whenever a task ends in "verified" and that word has to
  mean something a checker can enforce, when wiring a ship/no-ship gate into CI,
  or when driving a real surface and capturing what it did as evidence.
---

# rung

rung grades *how real* a verification was and *who* checked it, then gates the
result. It is a shared vocabulary, a portable JSON evidence bundle, a
declarative policy, and a single deterministic gate. It holds no keys, signs
nothing, and never phones home. The gate's only I/O is hashing artifacts on disk.

## The two axes

Verification claims collapse two questions into one word. rung pulls them apart.

**RUNG: how real (0 to 4).**

| Rung | Meaning |
|-----:|---------|
| 0 | Read-only reasoning about the code |
| 1 | Import the unit and call it |
| 2 | Test suite green |
| 3 | Drove the real surface and observed it |
| 4 | Drove the surface twice and captured an S0/S1 pair whose delta matches the declared polarity: they differ for a `change` claim, byte-identical for an `invariance` (no-regression) claim |

**CONTEXT: who evaluated.** `author` (the producer), `fresh-blind` (an
independent reviewer with no producer state), `cross-lab` (an independent
reviewer at a *different* lab). The gate can only mechanically check one of
these: `cross-lab`, and only its presence, never its authenticity. author vs
fresh-blind is the producer's word, which nothing can check.

## When to use this skill

- You finished a change and need to say, in a way a checker can enforce, how real
  your verification was. Author a bundle, or let `rung run` witness one.
- You are gating a merge or a batch of machine-made claims and need a
  fail-closed, machine-readable verdict. Run `rung gate` in CI.
- You drove a CLI, server, GUI, library, agent, or CI surface and want the
  captured bytes recorded as evidence with a verdict attached. Use `rung run`.

If the task is only reasoning about code (rung 0/1) with no surface to drive,
say so plainly; do not dress it up as a higher rung.

## The two ways in

**1. Gate an already-authored bundle.** You (or another tool) write an
`evidence-bundle/v1` JSON document, then:

```bash
rung gate bundle.json                 # uses the bundled default policy
rung gate bundle.json policy.json     # or pin your own policy
```

**2. Witness a run.** Instead of driving the surface and hand-typing a sha256,
let `rung run` execute the probe, capture the exact bytes off its own
stdout/stderr, write the bundle, and gate it:

```bash
rung run --rung 3 --surface cli --tier medium -- mytool --check
rung run --rung 4 --diff --surface cli --tier medium -- mytool --old ::: mytool --new
```

`--rung` and `--surface` are required: the tool witnesses *bytes*, never a rung,
so it never mints one for you. The probe argv comes after a bare `--`; in
`--diff` mode a bare `:::` splits it into S0 (baseline) and S1 (changed).

See [references/cli.md](references/cli.md) for every subcommand and flag.

## The exit-code contract

Exactly three codes, for both `rung gate` and `rung run`:

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
- **Author context is not independence.** Self-witnessing tops out at author
  context. cross-lab requires a real independent attestation, which the gate
  checks for presence only.
- **Redact before publishing.** Captures routinely hold secrets, tokens, PII,
  and internal hostnames. Redaction before a bundle is published is your job;
  the tool prints a reminder and does not scan. Use `--env-clear` to run a probe
  with a scrubbed environment.
- **Pin the gate and the policy.** Run a trusted, version-pinned gate, never the
  subject repo's own copy (that is code execution as the judge). A structurally
  valid policy can still be toothless.

## Config reference

- [references/cli.md](references/cli.md): every `rung` subcommand, all flags,
  how to run without installing, and the exit-code contract in full.
- [references/config.md](references/config.md): the policy knobs
  (`policy/default.json`) and the `evidence-bundle/v1` bundle shape (enforced vs
  advisory fields).
