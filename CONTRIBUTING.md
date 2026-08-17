# Contributing to rung

rung is a small, deliberately narrow project: a shared vocabulary, a reference
`evidence-bundle/v1` schema, a declarative policy, and a single-file
deterministic gate. Contributions are welcome, but the gate's value comes from a
few invariants, so most changes are judged against them first.

## Ground rules (what keeps the gate trustworthy)

The reference gate (`src/rung/gate.py`) must stay:

- **Dependency-free and stdlib-only.** No third-party imports, no network, no
  Python version floor beyond 3.9. It should drop into any CI unchanged.
- **A pure function of `(bundle, policy)`.** Its only I/O is hashing artifacts on
  disk. Same inputs, same verdict, on every platform and hash seed.
- **Fail-closed.** Unknown or missing policy keys, an unknown schema major, empty
  claims, malformed structure, or unreadable input must block or exit 2. Never a
  silent pass, never an uncaught traceback.
- **Trust-lowering only.** The gate may reduce trust relative to what a bundle
  claims; it must never raise it. A declared `pass` grants nothing, while a
  declared `fail` or `blocked` still blocks.

A change that weakens one of these will not be merged, however convenient.

## Run the tests

```bash
python3 gate/test_gate.py     # the gate suite
python3 gate/test_run.py      # the rung run conformance suite
cd gate && python3 -m unittest # or run every suite at once
```

The suite is adversarial: most tests map to a specific threat-model finding.
Every code change to the gate needs a test that encodes the behavior, and the
determinism tests (run under several `PYTHONHASHSEED` values) must stay green.

## Ways to contribute

- **A new worked case.** A real, reproducible example at a surface kind the
  existing cases do not cover. See below.
- **Gate hardening.** A concrete way to make the gate emit a wrong verdict, plus
  a regression test that pins the fix. Frame it against the trust boundary in
  [`THREAT-MODEL.md`](THREAT-MODEL.md).
- **Schema or policy clarification.** See the stability note below.
- **Docs.** Corrections and clarity. Keep the limitations stated plainly.

## Adding a worked case

A case is `cases/<name>/` with `bundle.json`, an `artifacts/` directory of
content-addressed captures, and a `README.md`. It must:

- pass (or block, if that's what it demonstrates) under `rung gate
  cases/<name>/bundle.json`, with the exact invocations shown in its README;
- carry captures whose `sha256` the gate recomputes, so the evidence is real;
- **redact and anonymize** those captures before committing. Strip secrets,
  tokens, and internal identifiers, and normalize non-deterministic fields
  identically across S0 and S1. Do not commit anything that names a private
  system or a real account.

## Changing the schema or policy

`evidence-bundle/v1` is the stable interchange other tools emit and read. Keep
changes additive within v1; a breaking change bumps the major (`/v2`). Any change
to what the gate reads must update the gate, its tests, the schema, and the
enforced/advisory documentation together, in one change.

## Prose style

Match the plain, direct voice of the existing docs: state limitations straight
instead of selling around them, and skip the marketing tone.

## Reporting a vulnerability

Do not open a public issue for a gate bypass. See [`SECURITY.md`](SECURITY.md).
