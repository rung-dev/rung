# rung

**At which rung did your agent verify?**

rung grades *how real* a verification was and *who* checked it: a shared
vocabulary, a reference schema, and a deterministic gate.

## The problem

"Verified" gets used for two different things, and most reports use the one word
for both. "The tests pass" reads the same as "I ran the actual thing and watched
it work." "I checked it" reads the same as "someone independent checked it."
Those aren't the same claim. When they all sound alike, a change nobody ran can
pass for verified, and there's no shared way to say which one you have.

## Why "rung"

A rung is a step on a ladder. The core axis (0 to 4) is a ladder from reasoning
about the code up to driving the running surface (the real CLI, server, library
API, or GUI a user or program touches) and capturing
what it did. How far you climbed is how real your verification is, and you don't
get to claim the top while standing on the first. The name keeps the question in
front of you: which rung did you actually reach?

## Two axes: how real, and who checked

Pull them apart:

**RUNG: how real (0 to 4)**

| Rung | Meaning |
|-----:|---------|
| 0 | Read-only reasoning about the code |
| 1 | Import the unit and call it |
| 2 | Test suite green |
| 3 | Drove the real surface and observed it |
| 4 | Drove the surface **and** captured a baseline->candidate differential (S0 vs S1) consistent with the change |

A rung-4 claim has a polarity: a *change* claim requires S0 and S1 to differ,
while an *invariance* claim (a refactor, a dep bump, "no egress") requires them
to match.

**CONTEXT: who evaluated**

| Context | Meaning |
|---------|---------|
| author | The producer of the change |
| fresh-blind | An independent reviewer with no producer state |
| cross-lab | An independent reviewer at a **different** lab |

Put them on a grid, and the empty cell is the one to look at:

| rung ↓ · context → | author | fresh-blind | cross-lab |
|---|---|---|---|
| **2** tests green | generic CI | | |
| **3** drove the real surface | runtime-verification tools | | |
| **4** drove + S0/S1 differential | | | ← real *and* independent; what rung targets |

The axes are independent: "drove it blind, cross-lab" is not a higher rung, it is
a different cell (rung 3 to 4 × cross-lab). Generic CI sits at rung 2 × author,
and runtime-verification tools reach rung 3 × author: they drive the real surface,
but the producer still grades its own work. The right-hand column, real
verification done by someone other than the producer, is where almost nothing
lives today, and that is the column rung is built to name and reward.

The gate can *check* only one context, **cross-lab**, and only for presence, not
authenticity: it requires the claim to declare `context: cross-lab` and the
bundle to carry an attestation whose `lab` differs from the producer's and whose
`verdict` is `pass`. It does **not** verify that the attestation is authentic
(nothing is signed in v1; see Threat model). author vs fresh-blind is
the producer's word, which nothing can check; the gate treats both as "not
independent."

## What's here

```
schema/evidence-bundle-v1.schema.json   the portable per-claim record (JSON Schema, draft 2020-12)
policy/default.json                      declarative ship policy: min rung + independence per risk tier
src/rung/gate.py                         single-file, stdlib-only, dependency-free: gate(bundle, policy) -> verdict
src/rung/run.py                          `rung run`: drives a probe, captures its bytes, writes+gates the bundle
src/rung/cli.py                          the `rung` umbrella command (run / gate / check / doctor / version)
cases/                                   real, reproducible worked examples
skill/                                   an agent skill: how to use rung, plus a CLI and config reference
VERIFYING-RUNG.md                        rung applied to itself: an external blind review, then dogfooding
```

An **evidence bundle** records, per claim: the rung reached, the context, the
surface driven, content-addressed artifacts, the S0/S1 differential (for rung
4), a verdict, and any cross-lab attestation. Gaps are listed in the bundle, not left out.
`evidence-bundle/v1` is the stable interchange: additive fields stay within v1,
and a breaking change bumps the major (`/v2`).

The **gate** is a pure function of `(bundle, policy)`. Its only I/O is hashing
artifacts on disk. It can only ever **lower** trust: a claim cannot pass above
its own rung, and a producer cannot pass by declaring its own verdict: a declared
`pass` grants nothing (the gate's own checks are the only thing that can pass a
claim), while a declared `fail` or `blocked` still blocks. Exit `0` = pass, `30`
= block.

```bash
rung gate cases/sync-connector-stdio-purity/bundle.json
```

## Install

```bash
pip install rung-ai
```

The distribution is named `rung-ai` on PyPI; the import package and the installed
command are both `rung`. Installing puts a single
`rung` command on your PATH:

```bash
rung gate bundle.json          # gate an authored bundle
rung run --rung 3 --surface cli -- mytool --check
rung doctor                    # read-only preflight
rung version
```

The runtime is stdlib-only and dependency-free, and Python 3.9+ is the only
requirement. If you would rather not
install, the package is self-contained under `src/`: run it from a checkout with
`PYTHONPATH=src python3 -m rung.gate bundle.json` (likewise `-m rung.run`,
`-m rung.cli`), or vendor the single self-contained file `src/rung/gate.py` into
your own repo. Every `rung gate` / `rung run` example below is the installed
command; the module form is the drop-in equivalent.

## The default policy

```json
{
  "version": 1,
  "require_context": { "high": "cross-lab", "critical": "cross-lab" },
  "no_skip_tiers": ["high", "critical"],
  "allow_dismiss_gaps": false,
  "min_rung": { "low": 2, "medium": 3, "high": 4, "critical": 4 }
}
```

The policy is plain JSON: same format and stdlib parser as the bundles, no
third-party dependency and no Python 3.11 floor. `min_rung` maps each risk tier
to the minimum rung to ship, and `require_context` names the tiers where
independence is mandatory; kept consistent, they close the **self-report trap**
(a self-reported rung 4 blocks at high/critical until a cross-lab reviewer
attests). The gate fails closed on an unknown or missing key rather than shipping
with a disabled check. See [`policy/README.md`](policy/README.md) for the full
field reference, per-tier calibration rationale, and the self-report-trap detail.

## Enforced vs advisory fields

A schema-valid bundle is **not** necessarily gate-passing. The schema admits many
fields for humans and tooling; the gate only reads a subset when it decides a
verdict. Authors should know which is which.

**Enforced** (read by the gate; affect the verdict):

- Top-level: `schema` (must equal `"evidence-bundle/v1"`), `change.producer.lab`,
  `claims` (non-empty array).
- Per claim: `risk_tier`, `rung`, `context`, `verdict`, `expected_delta`,
  `artifacts[]` with each artifact's `role`/`uri`/`sha256`,
  `differential.s0_observed`/`s1_observed` (cross-checked against capture bytes at
  rung 4), `attestation.lab`/`attestation.verdict` (required when the policy
  demands cross-lab for the tier).
- Rung 4: needs exactly one `s0_capture` and one `s1_capture` artifact (zero,
  duplicate, or padded captures per role block); polarity (change vs invariance)
  is decided from that single verified pair of capture bytes.
- Gaps: `severity`, `dismissed` (an undismissed `blocker` gap blocks unless policy
  allows dismissal).

**Advisory** (in the schema for humans; the gate does **not** check them):

- `change.repo`/`s0`/`s1`/`diff_range`/`created_at`/`policy_ref`,
  `producer.agent`/`model`.
- `claim.claim`, `claim.surface.*`, `claim.how_established`.
- `artifact.media`/`summary`, `differential.probe`/`observed_delta`,
  `attestation.judge_id`/`note`, `gap.desc`/`why_unverified`.
- Note: `id` and `gap.desc` appear in the gate's human-readable reason output but
  are not enforcement inputs.

Conditional requirements the gate enforces **beyond** the schema: rung >= 3
requires >= 1 artifact; rung 4 requires exactly one `s0_capture` and one
`s1_capture` plus a differential with byte-verified polarity; a cross-lab tier
requires a matching attestation.

## Worked examples

Three real, reproducible cases, each driven at a different surface kind and every
bundle re-checkable by the gate in this repo:

- [`cases/sync-connector-stdio-purity/`](cases/sync-connector-stdio-purity/):
  **server (stdio)**, change polarity. A protocol server whose first stdout line
  was a logging banner instead of a protocol frame. Rungs 0 to 2 all pass it; rung 3
  catches it by reading byte one off the real stdio surface; rung 4 shows the
  S0->S1 differential. Carries a declared gap: the auth-gated, data-mutating ops
  were not driven.
- [`cases/ctl-usage-error-doubleprint/`](cases/ctl-usage-error-doubleprint/):
  **CLI**, one commit that exercises **both polarities**. Human-mode stderr
  *changes* (a usage error printed 3× -> 1×); the `--json` machine channel is
  *invariant* (byte-identical S0 vs S1, exit 2 both). The invariance claim is the
  reason `expected_delta` exists: a change-only rung-4 gate would wrongly reject
  perfectly good evidence for it.
- [`cases/ical-text-escaping-rfc5545/`](cases/ical-text-escaping-rfc5545/):
  **library boundary**, change polarity. RFC 5545 TEXT escaping in a calendar
  export library, driven through the public `generate()` API. Flags up front
  that the *GUI* export button (the surface a user taps) was not driven.

Each case README shows the exact gate invocations, including the high-tier block
on a self-reported rung-4 claim.

## When you need the gate

The vocabulary stands on its own. The deterministic gate earns its keep when you
can't take the producer's word for it:

- **Machine-made claims at volume.** When agents emit "verified" by the hundred
  and nobody reads each one, you want a fail-closed check that can say "you
  claimed rung 4 but there's no S0/S1 differential" and mean it. That is the case
  rung was built for.
- **Producers who inflate a claim.** A checker matters when the party making the
  claim benefits from overstating it. A declared `pass` grants nothing, a rung-4
  claim with no differential is caught, and a change claim whose bytes don't
  differ blocks. That raises the cost of a bogus claim to fabricating consistent
  capture bytes, which v1 does not detect (see the threat model); it also catches
  an innocent mislabel, so it's not only for bad actors.
- **Automated gating.** If ship/no-ship must block a merge, you need a
  machine-readable verdict, and vocabulary alone cannot fail a build.

## How to use rung

Three steps, none needing a dependency beyond Python 3.9+.

**1. Get the gate.** `pip install rung-ai` (see [Install](#install)), or, to keep
the gate as an auditable single file, vendor a trusted, pinned copy of
`src/rung/gate.py` into your repo. A standalone vendored `gate.py` has no bundled
default policy beside it, so gate with an explicit `--policy` (vendor
`policy/default.json` too, or point at your own); with no `--policy` a loose copy
fails closed to exit 2 rather than guessing. Either way, do not run the subject
repo's own copy (that is code execution as the judge, see the operator contract
below).

**2. Author a bundle.** After you drive the change through the real surface (rung
3 or 4, not an import), write one `evidence-bundle/v1` document. The smallest
thing that runs is a single low-tier claim with no artifacts:

```json
{
  "schema": "evidence-bundle/v1",
  "change": { "producer": { "lab": "your-lab" } },
  "claims": [
    { "id": "c1", "risk_tier": "low", "rung": 2, "context": "author", "verdict": "pass" }
  ]
}
```

Real bundles climb higher: rung 3 and 4 carry capture artifacts with their
sha256 and, at rung 4, an S0/S1 differential plus `expected_delta`. Rather than
author those by hand (and hand-type the hashes), let `rung run` drive the
surface and write the capture-backed bundle for you: `rung run --rung 3` for a
single-surface witness, `rung run --rung 4 --diff` for the S0/S1 differential
(see [Witnessing a run with `rung run`](#witnessing-a-run-with-rung-run) below).
The [`cases/`](cases/) bundles are working templates, and [Enforced vs advisory
fields](#enforced-vs-advisory-fields) is the field reference.

**3. Run the gate, and wire it into CI.**

```bash
rung gate bundle.json [policy.json]   # default policy if omitted
```

It prints a verdict and exits `0` (pass) or `30` (block); unreadable or malformed
input exits `2`. In CI, fail the build on anything that is not exit `0` (both
`30` and `2` block). The bundled
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) does exactly this. Pin
your `policy.json` too: a structurally valid policy can still be toothless (see
[Threat model and limitations](#threat-model-and-limitations)).

## Witnessing a run with `rung run`

`rung run` (`src/rung/run.py`) is the first-class way to earn a rung-3 or rung-4
bundle; hand-authoring (above) is the fallback for evidence a tool cannot drive.
Instead of driving the surface and then writing down a sha256, you let the tool
drive it and write the bundle for you: an agent's cheapest path to a rung claim
should be to *actually run the surface*, not to hand-type a hash for bytes that
were never produced. It executes
the probe directly (no shell), captures the exact bytes off the child's own
stdout/stderr, hashes them into an `evidence-bundle/v1`, then runs the gate over
that bundle and exits with the **gate's** verdict, never the probe's exit code.

```bash
# Drive a CLI surface, declare rung 3, let the tool witness + gate it.
rung run --rung 3 --surface cli --tier medium -- mytool --help
```

`--rung` and `--surface` are **required**: the tool witnesses *bytes*, never a
rung, so it never mints one for you. A bare `rung run -- <cmd>` emits nothing and
so can never satisfy a rung-3 policy; over-claiming (`--rung 3` on an import) is a
deliberate, logged act, not a silent default. Zero captured bytes at rung >= 3 on
a process that ran to completion is refused ("nothing observed"); a process that
*hung* is diagnosed as a timeout and blocked, not refused. What it does **not**
prove: which program ran (a `cat file` emits bytes too) and whether that is
the real subject surface. To keep that visible rather than laundered, the
resolved path and sha256 of the launcher and of every file argument are recorded
under `surface.executed`; surface authenticity stays judge-only.

**Server surfaces.** A correct persistent stdio server answers a request and then
keeps its stream open, so a plain run always hits `--timeout` and blocks. Two
flags treat *answered-then-alive* as a completed observation (capture the frames,
then kill the still-running child, record no timeout):

- `--expect-frames N`: stop after N newline-terminated stdout frames. Use it for
  **newline-delimited** protocols (JSON-RPC / MCP over stdio).
- `--until-idle [SECS]`: stop once the probe produced output and then went quiet
  for SECS (bare flag = 2.0s). It is **framing-agnostic**; prefer it for
  non-newline framing such as LSP `Content-Length`, where `--expect-frames` would
  under-count and time out.

```bash
# MCP/JSON-RPC stdio server: one initialize frame, then it stays alive.
rung run --rung 3 --surface server --tier medium \
  --expect-frames 1 --stdin initialize.json --timeout 10 -- my-mcp-server

# LSP-style Content-Length framing (no trailing newline): idle-bounded instead.
rung run --rung 3 --surface server --tier medium \
  --until-idle 2 --stdin handshake.bin --timeout 10 -- my-lsp-server
```

`hung-producing-nothing` still times out and blocks under both. A capture that
exceeds the 64 MiB cap is truncated and recorded as an undismissed
`capture-truncated` blocker gap (flagged in the bundle, never silently dropped);
`RUNG_MAX_CAPTURE_BYTES` tunes the cap (down for constrained environments, or up).

**Rung 4: witnessing a differential with `--diff`.** Rung 4 is a baseline vs
candidate differential, so it needs *two* runs, not one; `rung run` refuses
`--rung 4` without `--diff` (a single run cannot earn it). With `--diff`, the
probe argv is split on a bare `:::` into an S0 (baseline) side and an S1
(changed) side; the tool drives each on the same bounded exec path, captures each
off its own fds into exactly one `s0_capture` and one `s1_capture`, and emits a
rung-4 bundle. The key part: **the tool never asserts the delta**. It only
declares intent with `--expect-delta`, and the *gate* decides change-vs-invariance
polarity from the captured bytes.

```bash
# Change claim: S0 and S1 must differ on the compared channel.
rung run --rung 4 --diff --surface cli --tier medium \
  -- mytool --old-flag ::: mytool --new-flag

# Invariance claim (refactor / dep bump / "no behavior change"): must match.
rung run --rung 4 --diff --expect-delta invariance --surface cli --tier medium \
  --s0-cwd ./before --s1-cwd ./after -- mytool run ::: mytool run
```

- `--expect-delta change` (default) or `invariance`: the polarity you claim. The
  gate blocks a `change` that produced identical bytes and an `invariance` that
  differed; declaring `pass` yourself grants nothing.
- `--diff-channel stdout` (default) `| stderr | both`: which captured channel the
  comparison uses. Use `both` for the strictest invariance check; a change
  confined to a channel you did not compare is not witnessed.
- `--s0-cwd` / `--s1-cwd`: run each side in its own working directory (e.g. a
  before/after checkout). Relative probe paths are resolved and hashed where the
  probe ran, not where the runner sits.

**Determinism boundary (why `--diff` re-runs each side).** A byte-level S0/S1
delta only proxies the claimed change when each side's output is *deterministic*:
a timestamp, PID, or hash seed would make identical code read as a change, and an
invariant refactor that happens to emit such noise would read as a delta. So `rung
run --diff` runs each side **twice** and, if the compared channel is not
byte-stable across the two runs, records a `nondeterministic-output` **blocker
gap** and blocks (exit 30) rather than feeding an untrustworthy delta to the gate.
It does not silently normalize the noise away; it refuses to certify it. Pin the
environment (or point `--diff-channel` at a stable channel) and re-run. This is an
author-context witness; whether the two sides are the real before/after surface,
and independence, remain judge-only.

**Operator contract for `rung run`** (in addition to the gate's contract below;
`rung run` is the more privileged tool because it *executes* the probe):

- **Trusted code only (RUN-E0).** The gate is safe on untrusted input (it only
  hashes files); `rung run` **executes** its probe, so pointing it at an
  adversarial repo is arbitrary code execution. Keep it to trusted inputs. A
  sandboxed production recorder is a separate, privileged tool, not this one.
- **Policy integrity is enforced by the tool.** The policy is loaded, parsed, and
  hash-pinned *before* the probe runs, stamped into the bundle as `policy_pin`,
  and re-verified after the run: a probe that rewrites the policy file mid-run
  gets a block on the tamper, not a silently weakened gate. You still **pin the
  policy itself** (a structurally valid policy can be toothless).
- **Only exit 0 is pass (RUN-E2).** `rung run`'s exit is the gate verdict; treat
  both 30 (block) and 2 (usage / cannot-evaluate) as no-ship, exactly as for the
  gate.
- **Redaction and env scrubbing (RUN-I1/I2).** Captures can contain secrets;
  redacting before a bundle is published is an operator responsibility (the tool
  prints a reminder and does not scan). The probe inherits this process's
  environment by default, so a token in the operator env can surface in a
  capture; pass `--env-clear` to run the probe with a scrubbed, minimal
  environment (PATH, HOME, locale, TERM, TMPDIR).

## Threat model and limitations

The gate is a deterministic function of `(bundle, policy)` whose only I/O is
hashing artifacts on disk. Here is what that gets you, and what it does **not**. For the layered verification rung itself has been through (an external
blind review, and dogfooding rung on its own packaging, climbing its own ladder), see
[`VERIFYING-RUNG.md`](VERIFYING-RUNG.md).

**What the gate enforces.** It can only ever *lower* trust relative to what the
bundle claims. It gives a producer-declared `pass` no weight (its own checks are
the only thing that can pass a claim) while still blocking on a declared `fail` or
`blocked`, refuses a claim above its own rung, blocks a self-reported rung-4 at
high/critical until a cross-lab attestation is present, rejects artifacts whose
recomputed sha256 doesn't match, and **decides rung-4 polarity from a single
verified s0/s1 capture pair** (exactly one capture per role; duplicate or padded
captures block): a fabricated `differential` over genuine-but-identical artifacts
no longer passes, and declared text that contradicts the bytes blocks.
It contains artifact paths under the bundle dir (no absolute paths, traversal, or
symlink escape), size-caps reads, stamps each verdict with the `gate_sha256` and
`policy_sha256` that produced it, and **fails closed**: unknown/missing policy
keys, an unknown schema major, empty claims, malformed structure, or oversized /
pathologically nested input block or exit 2 rather than silently passing (or
crashing).

**What the gate trusts the producer for (v1).** Nothing in the bundle is signed,
so the gate detects post-bundle *mutation* but not *fabrication*. A producer who
lies is not caught by the gate; these are judge-only concerns until signing
lands. Specifically trusted-on-assertion:

- `risk_tier`: a deflated tier lowers the bar the claim must clear.
- `context` (`author`/`fresh-blind`): unverifiable; only `cross-lab` presence
  is checked, and only presence, not authenticity.
- `attestation.lab` / `attestation.verdict`: an unsigned string; a forged one
  passes the presence check.
- `sha256` + `uri`: proves the file wasn't changed *after* bundling, not that
  it came from driving a real surface.
- `surface.kind`: whether the thing driven *is* the real consumer surface (vs
  an internal proxy) is judge-only.
- *which* claims the producer chose to declare: an omitted claim is invisible.
- both s0/s1 captures fabricated *consistently*: the byte check catches a lying
  differential, not two captures forged to agree with each other.

**Operator contract (not enforced by code).** Run a trusted, version-pinned
`gate.py`, never the subject repo's own copy (that is code execution as the
judge). Treat **only exit 0 as pass**; both 30 (block) and 2 (cannot-evaluate)
must fail the build. Redact secrets and normalize non-deterministic fields before
an artifact enters a publishable bundle. Pin the policy: a structurally valid
policy can still be toothless.

**v2 direction.** DSSE / in-toto signing over the bundle would move
`attestation`, producer identity, `risk_tier`, artifact provenance, and the
verdict record itself from trusted-on-assertion to cryptographically verifiable,
closing the forged-attestation, Sybil, and non-repudiation gaps. Deliberately out
of scope for v1 to keep the gate dependency-free.

## Using rung with other tools

rung is deliberately narrow: it fixes the vocabulary and bundle format, and ships
one deterministic check. It defines what counts as having driven the real
surface, records the captured evidence, and grades how real it was. What it leaves to other tools is the rest
of the chain:

- the machinery that *performs* the drive (reaching the running system is what
  the upper rungs are about: a rung-3 or rung-4 claim does not exist without
  it); and
- the model-based judging that decides independence, which the gate can only
  *check for*, never perform.

Shipping neither is what keeps the gate dependency-free. So the practical flow is
a chain: a producer drives the change and writes a bundle, rung grades how real
that was, an independent judge attests, and rung re-checks the attestation. Two
projects sit on either side of that chain:

- **[devloop](https://github.com/kashzod/devloop)** produces the evidence. It
  runs an AI development loop (spec, plan, review, implement, verify) that ends in
  a verification of the running change; rung is the vocabulary and gate for saying
  how real that verification was (which rung it reached) and recording it as a
  portable bundle.
- **[syncade](https://github.com/syncade-ai/syncade-ai)** performs the
  independent judgment. It orchestrates blind, cross-judge review (isolated
  reviewers with no producer state, optional cross-model diversity) into one
  ship/no-ship verdict: the independence rung names on the CONTEXT axis but the
  deterministic gate can only *check for*, never perform. A reviewer at a
  different lab is the cross-lab independence the gate rewards, and what would
  stand behind a cross-lab attestation in the mostly-empty rung 3 to 4 × cross-lab
  cell.

These are examples of the layers on either side of rung, not a required stack.
Any producer that emits an `evidence-bundle/v1` and any judge that attests to one
composes the same way: rung is only the interchange format and the deterministic
gate between them.

## Prior art

The two-axis split is not new; rung names it and makes the cell checkable.
**GRADE / EBM** already separate the *quality* of evidence from the *strength* of
a recommendation, which is the model for splitting rung from policy: the RUNG
axis is a software analogue of GRADE's evidence-quality tiers. That *who*
evaluated is orthogonal to *how well* comes from **DO-178C / SIL** (independence
of verification from development) and **chain-of-custody** (the artifact trail),
which is where the CONTEXT axis originates. The **test pyramid** is the folk
version of the RUNG axis for the lower rungs. rung's contribution is the
two-axis vocabulary and a portable, checkable evidence bundle that names the
cell, especially the rung 3 to 4 × cross-lab cell that runtime-verification tools
and eval harnesses, running in author context, do not fill.

## License

Apache 2.0. See [`LICENSE`](LICENSE).
