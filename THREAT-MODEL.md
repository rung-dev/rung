# rung threat model and limitations

rung is a deterministic gate that reduces `(bundle, policy)` to a ship/no-ship
verdict. It can only ever *lower* the trust a bundle claims for itself: a declared
`pass` grants nothing, and every check it adds is a reason to block, never a reason
to pass. This document states what the gate
enforces, what the `rung run` witness enforces, what both trust on assertion in
v1, and where the trust boundaries sit. It expands the summary in the
[README](README.md#threat-model-and-limitations). For the layered verification
rung itself has been through (an external blind review, and dogfooding rung on
its own packaging), see [`VERIFYING-RUNG.md`](VERIFYING-RUNG.md).

## Posture

The gate is a pure function of `(bundle, policy)`; its only disk I/O is reading
the bundle and policy and re-hashing the artifacts they reference. It never
executes the subject, never reaches the network, and
holds no keys. Every check it adds is a new *block* reason, never a new pass: a
producer-declared `pass` grants nothing, and the gate's own checks are the only
thing that can pass a claim.

`rung run` is different in kind: it *executes* a probe to witness bytes. It is
trusted-input tooling (see the operator contract) whose job is to witness
honestly and never to mint a rung it did not observe.

## Actors and assets

The primary adversary is a **self-interested producer**: the party making the
claim benefits from overstating it, by inflating a rung, deflating a
`risk_tier`, forging an attestation, or omitting an inconvenient claim. The model
also considers a **supply-chain attacker** (substituting a weakened gate
upstream), a **forged-independence attacker** (a fabricated cross-lab attestation
or a consistently-forged pair of captures), a **malicious subject repo**
(arbitrary code when driven by `rung run`), and a **careless operator** (a
toothless policy, or treating a non-zero exit as pass).

Assets: the evidence bundle (integrity), the captured artifacts on disk
(confidentiality; they routinely hold secrets), the policy (integrity), the
cross-lab attestation (authenticity), and the verdict record (integrity).

## What the gate enforces

It can only ever *lower* trust relative to what the bundle claims. It gives a
producer-declared `pass` no weight (its own checks are the only thing that can
pass a claim) while still blocking on a declared `fail` or `blocked`, refuses a
claim above its own rung, blocks a claim at any tier the policy marks
`cross-lab` (by default, high and critical) unless a cross-lab attestation is
present, so a self-reported result cannot clear those tiers, rejects artifacts
whose recomputed sha256
doesn't match, and **decides rung-4 polarity from a single verified s0/s1 capture
pair** (exactly one capture per role; duplicate or padded captures block): a
fabricated `differential` over genuine-but-identical artifacts no longer passes,
and declared text that contradicts the bytes blocks. It contains artifact paths
under the bundle dir (no absolute paths, traversal, or symlink escape), size-caps
reads, stamps each verdict with the `gate_sha256` and `policy_sha256` that
produced it, and **fails closed**: unknown/missing policy keys, an unknown schema
major, empty claims, malformed structure, or oversized / pathologically nested
input block or exit 2 rather than silently passing (or crashing).

## What `rung run` enforces

The witness protects the honesty of the bytes it records, not the truth of the
claim:

- **It never mints a rung.** `--rung` is required; the tool witnesses bytes, not
  a rung. A process that ran to completion but produced zero bytes at rung >= 3
  is refused rather than passed; `--rung 4` without `--diff` is refused, because
  rung 4 is a two-run differential.
- **A witnessed hang is a block, not a pass.** On timeout the tool forces the
  claim verdict to `blocked` (which the gate blocks unconditionally) and records
  a gap, handled *before* the empty-output refusal so a silent hang is diagnosed
  as a hang rather than as "nothing observed".
- **A non-deterministic side blocks.** In `--diff` mode each side is run twice;
  if the compared channel is not byte-stable across the two runs, the tool
  forces the claim verdict to `blocked` and records a `nondeterministic-output`
  blocker gap, so the gate blocks the delta instead of trusting it.
- **Captures are bounded.** A capture over the 64 MiB cap (tunable via
  `RUNG_MAX_CAPTURE_BYTES`) is truncated and recorded as an undismissed
  `capture-truncated` blocker gap; the drain is chunked and the child process
  group is reaped, so a runaway child cannot exhaust memory or leak processes.
- **`--env-clear`** runs the probe with a scrubbed, minimal environment so a
  token in the operator environment cannot leak into a capture.
- **Errors fail closed to exit 2.** Any gate-internal, run-internal, or import
  exception maps to exit 2 (cannot-evaluate), never an exit-1 traceback; only the
  in-contract 0/30/2 exits propagate.

## What the gate trusts the producer for (v1)

Nothing in the bundle is signed, so the gate detects post-bundle *mutation* but
not *fabrication*. A producer who lies is not caught by the gate; these are
judge-only concerns until signing lands. Specifically trusted-on-assertion:

- `risk_tier`: a deflated tier lowers the bar the claim must clear.
- `context` (`author`/`fresh-blind`): unverifiable; only `cross-lab` presence is
  checked, and only presence, not authenticity.
- `attestation.lab` / `attestation.verdict`: an unsigned string; a forged one
  passes the presence check.
- `sha256` + `uri`: proves the file wasn't changed *after* bundling, not that it
  came from driving a real surface.
- `surface.kind`: whether the thing driven *is* the real consumer surface (vs an
  internal proxy) is judge-only.
- *which* claims the producer chose to declare: an omitted claim is invisible.
- both s0/s1 captures fabricated *consistently*: the byte check catches a lying
  differential, not two captures forged to agree with each other.

## Distribution and the gate's own integrity

rung ships as a PyPI package (`rung-ai`), a container image, a GitHub Action, and
a vendorable single `gate.py`. Substituting a weakened gate anywhere along that
path is a residual the gate cannot catch by itself; this is a deliberate v1
boundary, not an oversight.

- Each verdict is stamped with a `gate_sha256`. That hash is computed by the
  running gate over its **own** bytes, so it binds a verdict to the exact logic
  that produced it (useful for after-the-fact verdict inspection and for catching
  an *accidental* gate mismatch), but it is not an integrity check against a
  trusted root: a substituted gate hashes itself. Detecting substitution
  is an ecosystem concern, not something a self-run gate can assert.
- Distribution integrity is handled outside the gate. Releases publish over an
  OIDC Trusted Publisher with no long-lived token, and consumers should pin a
  version (`uses: rung-dev/rung@vX`, a pinned image digest, a pinned
  `rung-ai==X`). This is defense at the packaging layer, by design, not a gate
  check.

## Operator contract (guidance, not enforced by code)

Some of rung's guarantees hold only if the operator plays their part; the gate
cannot enforce these and does not pretend to.

- Run a trusted, version-pinned `gate.py`, never the subject repo's own copy
  (that is code execution as the judge).
- Treat **only exit 0 as pass**; both 30 (block) and 2 (cannot-evaluate) must
  fail the build. A wrapper that keys on `exit != 30` fails open on the 2s.
- Redact secrets and normalize non-deterministic fields before an artifact enters
  a publishable bundle. `rung run` prints a reminder and does not scan; use
  `--env-clear` to keep operator-environment tokens out of a capture.
- Pin the policy: a structurally valid policy can still be toothless (empty
  `require_context`, all-zero `min_rung`, `allow_dismiss_gaps:true`).
- `rung run` *executes* its probe, so point it only at trusted inputs; the gate
  (`rung gate`) is safe on untrusted input, as it only hashes files.

## v2 direction

DSSE / in-toto signing over the bundle would move `attestation`, producer
identity, `risk_tier`, artifact provenance, and the verdict record itself from
trusted-on-assertion to cryptographically verifiable, closing the
forged-attestation, Sybil, and non-repudiation gaps. Signing is also what would
move gate, package, and image substitution from a trusted-on-assertion residual
to a verifiable property, through the ecosystem's own trust root rather than the
gate. Signing is deliberately out of scope for v1 to keep the gate
dependency-free.

## How this model was derived

A STRIDE pass over the two trust boundaries that matter (producer to gate, and
subject-repo code to the `rung run` executor), cross-checked claim by claim
against `gate.py`, `run.py`, and `cli.py`. Every "the gate enforces X" statement
above maps to a specific check in the source.
