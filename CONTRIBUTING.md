# Contributing to rung

rung is a small, deliberately narrow project: a shared vocabulary, a reference
`evidence-bundle/v2` schema, a declarative policy, and a single-file
deterministic gate. Contributions are welcome, but the gate's value comes from a
few invariants, so most changes are judged against them first.

## Ground rules (what keeps the gate trustworthy)

The reference gate (`src/rung/gate.py`) must stay:

- **Dependency-free and stdlib-only.** No third-party imports, no network, no
  Python version floor beyond 3.9. It should drop into any CI unchanged.
- **A pure function of `(bundle, policy)`.** Its only disk I/O is reading the
  bundle and policy and re-hashing the artifacts they reference. Same inputs,
  same verdict, on every platform and hash seed.
- **Fail-closed.** Unknown or missing policy keys, an unknown schema major, empty
  claims, malformed structure, or unreadable input must block or exit 2. Never a
  silent pass, never an uncaught traceback.
- **Trust-lowering only.** The gate may reduce trust relative to what a bundle
  claims; it must never raise it. A declared `pass` grants nothing, while a
  declared `fail` or `blocked` still blocks.

A change that weakens one of these will not be merged, however convenient.

## Run the tests

```bash
# stdlib unittest; src/ must be on the path (there is no rung/__main__.py).
PYTHONPATH=src python3 -m unittest discover -s gate -p 'test_*.py'   # every suite
PYTHONPATH=src python3 -m unittest gate.test_gate                    # the gate suite only
PYTHONPATH=src python3 -m unittest gate.test_run                     # the rung run suite
```

The CLI entrypoints are `python3 -m rung.cli` (equivalently the installed `rung`
console script, `rung = rung.cli:main`), and `python3 -m rung.gate` /
`python3 -m rung.run`, all with `PYTHONPATH=src` from a checkout. The suite is
adversarial: most tests map to a specific trust-boundary property. Every code change
to the gate needs a test that encodes the behavior, and the determinism tests
(run under several `PYTHONHASHSEED` values) must stay green.

## Ways to contribute

- **A new worked case.** A real, reproducible example at a surface kind the
  existing cases do not cover. See below.
- **Gate hardening.** A concrete way to make the gate emit a wrong verdict, plus
  a regression test that pins the fix. Frame it against the trust boundary in
  [`SECURITY.md`](SECURITY.md).
- **Schema or policy clarification.** See the stability note below.
- **Docs.** Corrections and clarity. State each scope boundary plainly, as a
  division of labor.

## Adding a worked case

A case is `gate/cases/<name>/` with `bundle.json`, an `artifacts/` directory of
content-addressed captures, and a `README.md`. It must:

- pass (or block, if that's what it demonstrates) under `rung gate
  gate/cases/<name>/bundle.json`, with the exact invocations shown in its README;
- carry captures whose `sha256` the gate recomputes, so the evidence is real;
- **redact and anonymize** those captures before committing. Strip secrets,
  tokens, and internal identifiers, and normalize non-deterministic fields
  identically across S0 and S1. Do not commit anything that names a private
  system or a real account.

## Changing the schema or policy

`evidence-bundle/v2` is the stable interchange other tools emit and read. Keep
changes additive within v2; a breaking change bumps the major (the v1→v2 bump
was the last such, and it collapsed the rung ladder to `{0,1}`, moved
`differential` off the rung axis to a METHOD, and reduced CONTEXT to
`{author, independent}` with cross-model/cross-lab as qualifiers). Any change to
what the gate reads must update the gate, its tests, **both** schema copies
(`schema/evidence-bundle-v2.schema.json` and
`src/rung/data/schema/evidence-bundle-v2.schema.json`), **both** policy copies
(`policy/default.json` and `src/rung/data/default_policy.json`), and the
enforced/advisory documentation together, in one change. Each schema/policy pair
must stay byte-identical. `gate/test_packaging.py` guards this and will fail if
the copies drift.

## Prose style

Match the plain, direct voice of the existing docs: state each boundary straight
as a scope decision, and skip the marketing tone.

## Reporting a vulnerability

Do not open a public issue for a gate bypass. See [`SECURITY.md`](SECURITY.md).
