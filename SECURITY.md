# Security policy

rung's reference gate (`src/rung/gate.py`) is a deterministic, offline, stdlib-only
function of `(bundle, policy)` whose only I/O is hashing artifacts on disk. Its
trust model is in [`THREAT-MODEL.md`](THREAT-MODEL.md); please read it before
reporting, because the v1 trust boundary is explicit and
several "weaknesses" are documented, by-design limits rather than
vulnerabilities.

## In scope

A report is a vulnerability if it defeats a property the gate is supposed to
enforce. For example:

- A bundle that **should block but the gate passes** (exit 0) it: a claim scored
  above its own rung, a rung-4 polarity decided against the verified capture
  bytes, a missing cross-lab attestation treated as present, a required check
  silently skipped.
- **Path containment escape:** reading or hashing a file outside the bundle
  directory via a crafted `uri`, absolute path, or symlink.
- **Fail-open on bad input:** malformed, oversized, or pathological input that
  produces a crash/traceback or a wrong exit code instead of a clean block or
  exit 2.
- **Non-determinism:** the same `(bundle, policy)` yielding different verdicts or
  output bytes across runs, platforms, or hash seeds.

## Out of scope (documented v1 limits, not vulnerabilities)

These are stated plainly in [`THREAT-MODEL.md`](THREAT-MODEL.md). v1 detects
post-bundle mutation, not fabrication, and nothing in the bundle is signed:

- A **forged cross-lab attestation**: `attestation.lab` is an unsigned string, so
  a producer-supplied one passes the presence check. This is the headline v1
  limit; DSSE / in-toto signing is the v2 direction.
- **Sybil / label collusion**: two "labs" that are one entity.
- A producer that **fabricates both S0 and S1 captures consistently** so the byte
  check has nothing to catch.
- A **weak-but-valid policy** (for example an all-zero `min_rung`). Structurally
  valid is not the same as strict; pinning the policy is an operator concern.
- Running the **subject repository's own copy of the gate** instead of a trusted,
  pinned one. That is code execution as the judge, and an operator contract item.

If you are unsure whether something is in scope, report it and say so.

## How to report

Use GitHub's private vulnerability reporting on this repository (the **Security**
tab, then **Report a vulnerability**). Please do not open a public issue or pull
request for a gate bypass until a fix is available. Include the smallest bundle
and policy that reproduce the behavior, the exact gate invocation, and the
verdict you got versus the one you expected.
