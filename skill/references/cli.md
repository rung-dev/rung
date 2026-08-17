# rung CLI reference

`rung` is one umbrella command over the two stdlib-only tools in the package
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
PYTHONPATH=src python3 -m rung.run  --rung 3 ...      # same as: rung run ...
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
rung gate   [global] BUNDLE [POLICY]            gate an authored bundle (JSON verdict to stdout)
rung check  [global] BUNDLE [POLICY]            alias for gate
rung doctor [global] [BUNDLE]                   read-only preflight; exit 0/2 only
rung version                                    schema major + gate sha256 + resolved paths
rung help / -h / --help                         top-level usage
```

stdout is data, stderr is diagnostics. `gate`/`check` stdout is exactly the
gate's verdict bytes, never wrapped in an envelope. A typo'd command gets a
difflib "did you mean" suggestion.

### rung gate / rung check

```bash
rung gate <bundle.json> [policy.json] [--tier <tier>]
```

- `bundle.json` (required positional): the `evidence-bundle/v1` document.
- `policy.json` (optional positional): a policy file. Omitted, the bundled
  default policy is used. Note this is a **positional**, not `--policy`.
- `--tier <tier>`: override the risk tier used for the run
  (`low` | `medium` | `high` | `critical`). This is the **only** flag `gate`
  accepts; any other option exits `2`, so a typo'd flag is a usage error, never
  silently ignored.

Prints a JSON verdict to stdout and exits `0`/`30`/`2`.

### rung run

Executes the probe directly (no shell), captures the exact bytes off the child's
own stdout/stderr, hashes them into an `evidence-bundle/v1`, runs the gate over
that bundle, and exits with the **gate's** verdict (never the probe's exit code).
The probe argv comes after a bare `--`.

```bash
rung run --rung 3 --surface cli --tier medium -- mytool --help
```

Required:

- `--rung <int>`: the rung being claimed. Required because the tool witnesses
  bytes, never a rung, and will not mint one.
- `--surface <kind>`: one of `cli`, `server`, `gui`, `library`, `agent`, `ci`.

Declaration and provenance:

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
- `--out <dir>`: output dir for `bundle.json` + `artifacts/`, default
  `./rung-out`.
- `--policy <file>`: policy JSON, default the bundled default policy.
- `--no-gate`: emit the bundle but do not run the gate.

Server surfaces (a persistent server answers then stays alive, so a plain run
hits `--timeout`). These treat answered-then-alive as a completed observation
(capture frames, kill the child, record no timeout):

- `--expect-frames <N>`: stop after N newline-terminated stdout frames. For
  newline-delimited protocols (JSON-RPC / MCP over stdio).
- `--until-idle [SECS]`: stop once the probe produced output then went quiet for
  SECS (bare flag = 2.0s). Framing-agnostic; prefer it for non-newline framing
  such as LSP `Content-Length`. A process that produced nothing still times out.

Rung 4 differential (`--diff`): rung 4 is a baseline vs candidate differential,
so it needs two runs; `--rung 4` without `--diff` is refused. With `--diff`, the
probe argv is split on a bare `:::` into an S0 (baseline) side and an S1
(changed) side. The tool captures each into exactly one `s0_capture` and one
`s1_capture`; the **gate**, not the tool, decides change-vs-invariance polarity
from the captured bytes.

- `--diff`: enable differential mode (`-- <S0 argv> ::: <S1 argv>`).
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

```bash
# MCP/JSON-RPC stdio server: one initialize frame, then it stays alive.
rung run --rung 3 --surface server --tier medium \
  --expect-frames 1 --stdin initialize.json --timeout 10 -- my-mcp-server

# Change claim: S0 and S1 must differ on the compared channel.
rung run --rung 4 --diff --surface cli --tier medium \
  -- mytool --old-flag ::: mytool --new-flag

# Invariance claim (refactor / dep bump): must match, in before/after checkouts.
rung run --rung 4 --diff --expect-delta invariance --surface cli --tier medium \
  --s0-cwd ./before --s1-cwd ./after -- mytool run ::: mytool run
```

A capture that exceeds the 64 MiB cap is truncated and recorded as an undismissed
`capture-truncated` blocker gap; `RUNG_MAX_CAPTURE_BYTES` tunes the cap. A
non-integer or non-positive value fails closed: `rung run` exits `2` before the
probe runs, rather than falling back to a default cap.

**Operator note:** `rung run` *executes* its probe, so pointing it at an
untrusted repo is arbitrary code execution. Keep it to trusted inputs. The gate
(`rung gate`) is safe on untrusted input; it only hashes files.

### rung doctor

```bash
rung doctor [bundle.json]
```

Read-only preflight. Reports on the environment and, if given a bundle, whether
it parses as JSON (a parse check, not full bundle validation). Never runs the
gate and never ships a verdict; exits `0` (ok) or `2` (a problem worth fixing
first).

### rung version

Prints the schema major, the gate's own sha256 (bound into every verdict), and
the resolved filesystem paths of the `rung` and `gate` modules in use.
