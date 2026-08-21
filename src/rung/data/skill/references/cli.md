# rung CLI reference

`rung` is one parent command over the two stdlib-only tools in the package
(`rung.gate` and `rung.run`). Everything below is stdlib-only, deterministic,
and dependency-free.

## Running rung

```bash
pip install rung-ai        # distribution is rung-ai on PyPI; the command is rung
rung <command> ...
```

Without installing, run it from a checkout with `src/` on the path (each form is
a drop-in equivalent of the installed command):

```bash
PYTHONPATH=src python3 -m rung.cli  <command> ...   # same as: rung <command>
PYTHONPATH=src python3 -m rung.gate bundle.json      # same as: rung gate ...
PYTHONPATH=src python3 -m rung.run  --rung 1 ...      # same as: rung run ...
```

## Exit codes (a contract, for gate and run)

- `0` pass, the only pass.
- `30` block. This includes an unknown schema major and a missing or unknown
  policy key: a malformed schema or policy blocks, it is not a usage error.
- `2` usage error / cannot-evaluate: an unknown flag, or unreadable,
  unparseable, or oversized input.

`doctor` only ever exits `0` or `2`. There is no fourth code. Treat both `30`
and `2` as no-ship.

## Global flags

Accepted before or with any subcommand (a shared parent parser):

- `--quiet`, `-q`: suppress rung's own progress lines (chiefly `doctor`'s
  ok-lines). Never suppresses the verdict on stdout or a child's critical stderr.
- `--no-color`: disable color. Color is stderr-only and only ever appears when
  stderr is a TTY, `NO_COLOR` is unset, and `--no-color` is absent; the verdict
  on stdout is never colored.

There is **no** `--json` flag: `gate` and `run` already print the JSON verdict
to stdout unconditionally.

## Subcommands

```
rung run    [global] SURFACE-ARGS -- <probe>   witness an execution, emit + gate a bundle
rung attest [global] BUNDLE [POLICY]            record an independent attestation, re-gate
rung gate   [global] BUNDLE [POLICY]            gate an authored bundle (JSON verdict to stdout)
rung check  [global] BUNDLE [POLICY]            alias for gate
rung doctor [global] [BUNDLE]                   read-only preflight; exit 0/2 only
rung skill  [global] [--print | --install DEST] [--force]   surface the packaged skill
rung version                                    schema major + gate sha256 + resolved paths
rung help / -h / --help                         top-level usage
```

stdout is data, stderr is diagnostics. `gate`/`check` stdout is the
gate's verdict bytes, never wrapped in an envelope. A typo'd command gets a
difflib "did you mean" suggestion.

### rung gate / rung check

```bash
rung gate <bundle.json> [policy.json] [--tier <tier>]
```

- `bundle.json` (required positional): the `evidence-bundle/v2` document.
- `policy.json` (optional positional): a policy file. Omitted, the bundled
  default policy is used. Note this is a **positional**, not `--policy`.
- `--tier <tier>`: override the risk tier used for the run
  (`low` | `medium` | `high` | `critical`). This is the **only** flag `gate`
  accepts; any other option exits `2`, so a typo'd flag is a usage error, never
  silently ignored.

Prints a JSON verdict to stdout and exits `0`/`30`/`2`.

### rung run

Executes the probe directly (no shell), captures the exact bytes off the child's
own stdout/stderr, hashes them into an `evidence-bundle/v2`, runs the gate over
that bundle, and exits with the **gate's** verdict (never the probe's exit code).
The probe argv comes after a bare `--`.

```bash
rung run --rung 1 --surface cli --tier low -- mytool --help
```

Required:

- `--rung <0|1>`: the rung being claimed. `0` = not a runtime observation of the
  real surface; `1` = observed. Required because the tool witnesses bytes, never a
  rung, and will not mint one.
- `--surface <kind>`: one of `cli`, `server`, `gui`, `library`, `agent`, `ci`.
- `--method <m>`: how the observation was evaluated, default `single`
  (`single` | `differential` | `adversarial` | `fuzz` | `property`).
  `differential` is enforceable and requires `--diff` (see below); the rest are
  advisory (recorded, never gated). `--method differential` without `--diff` is
  refused.

Declaration and origin:

- `--tier <tier>`: risk tier, default `low` (`low` | `medium` | `high` |
  `critical`).
- `--verdict <v>`: declared verdict, default `pass` (`pass` | `fail` | `blocked`
  | `skip`). A declared `pass` grants nothing; a declared `fail`/`blocked` still
  blocks.
- `--claim <str>`: human description of the claim.
- `--lab <str>`: producing lab/org (`change.producer.lab`), default `local`.
- `--repo <str>`: human description of the surface under change.

Execution:

- `--stdin <file>`: file fed to the probe's stdin (else `/dev/null`).
- `--timeout <secs>`: seconds before the probe is killed, default `60`
  (`0` = no limit). A hang is diagnosed as a timeout and blocked.
- `--env-clear`: run the probe with a scrubbed, minimal environment (PATH, HOME,
  locale, TERM, TMPDIR) so a token in the operator env cannot leak into a capture.
- `--redact`: **opt-in.** Mask likely secrets (private keys, provider key formats,
  keyword-anchored token/cookie/password values) in the written captures *before*
  hashing, with a fixed `[REDACTED:<category>]` placeholder; the recorded
  artifact and its sha256 are then of the redacted bytes, and the masking is
  disclosed as an *advisory* gap. Deterministic and safe to re-run. Heuristic
  (precision over recall): a clean pass is not proof, so hand-review still
  applies.
- `--scan-secrets`: **opt-in**, non-mutating. Scan each capture (after any
  `--redact`) and record a *blocker* gap for one that still matches a secret
  pattern, so an obvious live secret cannot pass the gate. `--scan-secrets` alone
  blocks the leak; `--redact --scan-secrets` blocks only a residue redaction
  missed. Same heuristic caveat: a clean scan is not proof of a clean capture.
- `--out <dir>`: output dir for `bundle.json` + `artifacts/`, default
  `./.rung/output`.
- `--policy <file>`: policy JSON, default the bundled default policy.
- `--no-gate`: emit the bundle but do not run the gate.

Server surfaces (a persistent server answers then stays alive, so a plain run
hits `--timeout`). These treat answered-then-alive as a completed observation
(capture frames, kill the child, record no timeout):

- `--expect-frames <N>`: stop after N newline-terminated stdout frames. For
  newline-delimited protocols (JSON-RPC / MCP over stdio). Counts newline-
  terminated *lines*, not parsed frames. Diagnostics leaking onto stdout (the
  defect a stdout-purity check targets) are counted too, so N may be reached early
  and the frame count inflated. That is a symptom of stdout contamination, not a
  miscount.
- `--until-idle [SECS]`: stop once the probe produced output then went quiet for
  SECS (bare flag = 2.0s). Framing-agnostic; prefer it for non-newline framing
  such as LSP `Content-Length`. A process that produced nothing still times out.

Differential method (`--diff`): the differential is an enforceable **method** at
rung 1, not a higher rung. It is a baseline vs candidate comparison, so it needs
two runs; `--diff` emits `method=differential` at `--rung 1`. With `--diff`, the
probe argv is split on a bare `:::` into an S0 (baseline) side and an S1
(changed) side. The tool captures each into exactly one `s0_capture` and one
`s1_capture`; the **gate**, not the tool, decides change-vs-invariance polarity
from the captured bytes.

- `--diff`: enable the differential method (`-- <S0 argv> ::: <S1 argv>`).
- `--expect-delta <change|invariance>`: the polarity you claim, default
  `change`. The gate blocks a `change` that produced identical bytes and an
  `invariance` that differed.
- `--diff-channel <stdout|stderr|both>`: which captured channel the comparison
  uses, default `stdout`. Use `both` for the strictest invariance check.
- `--s0-cwd <dir>` / `--s1-cwd <dir>`: run each side in its own working
  directory (e.g. a before/after checkout). Relative probe paths are resolved
  and hashed where the probe ran.

Each side is run **twice**; if the compared channel is not byte-stable across
the two runs, the tool records a `nondeterministic-output` blocker gap and
blocks rather than feeding an untrustworthy delta to the gate.

When the nondeterminism **is the defect under test**, e.g. verifying a
stdout-purity fix where the pre-fix (S0) surface leaks a timestamp onto stdout,
this guard will (correctly) block: S0 is nondeterministic by construction, so a
byte delta cannot prove the fix, and the guard firing is the tool observing the
defect. There is deliberately no silent/normalizing compare (forcing two outputs
equal is the fabrication the gate prevents; `--redact` is disclosed and for
secrets only). Instead prove the fix on the fixed side (S1): a single-run
`--expect-frames N` witness that stdout is only protocol frames, plus a
`--diff --expect-delta invariance` of the fixed surface against itself to witness
stdout is now byte-stable. See the skill's "Verifying a stdout-purity / log-leak
fix" section.

```bash
# MCP/JSON-RPC stdio server: one initialize frame, then it stays alive.
rung run --rung 1 --surface server --tier low \
  --expect-frames 1 --stdin initialize.json --timeout 10 -- my-mcp-server

# Change claim: S0 and S1 must differ on the compared channel.
rung run --rung 1 --diff --surface cli --tier low \
  -- mytool --old-flag ::: mytool --new-flag

# Invariance claim (refactor / dep bump): must match, in before/after checkouts.
rung run --rung 1 --diff --expect-delta invariance --surface cli --tier low \
  --s0-cwd ./before --s1-cwd ./after -- mytool run ::: mytool run
```

A capture that exceeds the 64 MiB cap is truncated and recorded as an undismissed
`capture-truncated` blocker gap; `RUNG_MAX_CAPTURE_BYTES` tunes the cap. A
non-integer or non-positive value fails closed: `rung run` exits `2` before the
probe runs, rather than falling back to a default cap.

**Operator note:** `rung run` *executes* its probe, so pointing it at an
untrusted repo is arbitrary code execution. Keep it to trusted inputs. The gate
(`rung gate`) is safe on untrusted input; it only hashes files.

### rung attest

Records an independent reviewer's verdict on an existing bundle, lifts the target
claim to `context: independent`, and re-gates in one step. It is the only way to
reach `independent`; the gate itself only ever lowers trust.

```bash
rung attest --model <reviewer-model> --verdict pass <bundle.json> [policy.json]
rung attest --panel modelA:pass,modelB:pass --verdict pass <bundle.json>
rung attest --model <reviewer-model> --lab lab-b --verdict pass <bundle.json>
```

- `--model` or `--panel` (exactly one): the single reviewer model, or a panel of
  `model:verdict` pairs. The gate requires each reviewer model `!=` the producer's
  at any tier that demands a cross-model qualifier. A panel with `--verdict pass`
  requires every member to pass; a dissenting member is refused (exit `2`).
- `--verdict` (required, no default): the reviewer's verdict. A `fail`/`blocked`
  lowers the claim and the re-gate blocks.
- `--lab` (single `--model` only): the reviewing lab, for a cross-lab qualifier.
  Not valid with `--panel` (a panel has no single lab).
- `--claim-id`: which claim to attest; required when the bundle has more than one.
- `--require-artifacts`: refuse (exit `2`) rather than record an unbound
  attestation when the claim's artifacts cannot be read.
- `--tier`: override every claim's risk tier for the re-gate, as `rung gate --tier`.
- `bundle` positional, or `-` / omitted for stdin; `policy` optional positional.

attest byte-binds the verdict to the artifacts it re-hashes, so a review cannot be
transplanted onto a different bundle. Run it where the review happened. If the
reviewer had no artifact access, the verdict is disclosed as unbound rather than
minted byte-bound; if a recomputed hash contradicts the bundle's, attest refuses
(exit `2`, writes nothing). The amended bundle prints to stdout; the exit code is
the gate's verdict (`0`/`30`/`2`).

### rung doctor

```bash
rung doctor [bundle.json]
```

Read-only preflight. Reports on the environment and, if given a bundle, whether
it parses as JSON (a parse check, not full bundle validation). Never runs the
gate and never ships a verdict; exits `0` (ok) or `2` (a problem worth fixing
first).

### rung skill

```bash
rung skill                                 # print where the packaged skill lives
rung skill --print                         # write SKILL.md to stdout (pipe into any agent)
rung skill --install <dir> [--force]       # copy the skill tree into a dir you name
```

Surfaces the packaged skill (`SKILL.md` + `references/`). The skill is plain
markdown and assumes no particular harness. `--print` streams `SKILL.md` to
stdout; `--install DEST` copies the tree into a directory you choose (`--force`
replaces `DEST` if it already exists). With no flag it prints the installed
skill's path. Exits `0`/`2`.

### rung version

Prints the schema major, the gate's own sha256 (bound into every verdict), and
the resolved filesystem paths of the `rung` and `gate` modules in use.
