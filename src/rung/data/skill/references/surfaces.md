# rung surfaces reference: what "the real surface" is, per kind

RUNG in v2 is binary: `0` = not a runtime observation of the real surface,
`1` = observed. A rung-1 claim rests on one word: **the real
surface**, the boundary a real consumer (a user, a client program, another agent)
meets. Observing anything short of it (reasoning about the diff,
importing a unit and calling it, a green test suite) is rung 0, no matter how
much code ran. This reference pins down what the real surface *is* for each
`--surface` kind, so "did you observe it?" has a crisp answer.

The rule is the same everywhere: **drive the boundary a consumer meets, and
read the exact bytes it produces.** The method (`single`, `differential`, …) and
the context (`author`, `independent`) are separate; this page is only about
reaching rung 1.

## `cli`: a command-line tool

- **Real surface:** the built binary invoked as a user invokes it, reading raw
  **stdout**, raw **stderr**, and the **exit code**.
- **Rung 0 (not this):** calling an internal command handler in-process; asserting
  on a parsed result object; a unit test of the arg parser.
- **Rung 1:** `rung run --rung 1 --surface cli -- mytool --check`. The tool
  executes the probe (no shell), captures fd 1 / fd 2 byte-for-byte, and the gate
  scores the emitted bundle.
- **Watch for:** how many times a message hits the stream, ordering, and the exit
  code: the things a return value hides. See
  [`gate/cases/ctl-usage-error-doubleprint/`](../../gate/cases/ctl-usage-error-doubleprint/).
- **Stdin / interactive:** feed a scripted session with `--stdin session.txt` and
  read the emitted stdout/stderr. A full-screen curses/TUI whose real surface is the
  rendered pane, not a byte stream, is closer to `gui`: drive it in a pty or terminal
  emulator and capture that, since a non-tty exec will not exercise the same code.

## `server`: a running server, driven over its wire

- **Real surface:** the wire a client meets. Two shapes, one rule (drive it as a
  client would, read the raw bytes back):

  **Stdio / pipe protocol (JSON-RPC, MCP, LSP).** stdout is the protocol channel;
  the first line a strict client reads must be a valid frame. The probe *is* the
  server: rung runs it and captures its stdout. A correct server answers then stays
  alive, so a plain run hits the timeout. Use `--expect-frames N` (newline-delimited)
  or `--until-idle` (framing-agnostic, e.g. LSP `Content-Length`) to treat
  *answered-then-alive* as a completed observation:

  ```bash
  rung run --rung 1 --surface server --tier low \
    --expect-frames 1 --stdin initialize.json --timeout 10 -- my-mcp-server
  ```

  **HTTP / socket API.** The observable is the response to a request, not the
  server's own stdout, and the lifecycle is two processes. Start the server
  yourself, poll it to ready, then witness a *client* request as the probe (the
  response is what rung captures):

  ```bash
  my-server & SRV=$!
  for i in $(seq 30); do curl -sf localhost:8080/health >/dev/null && break; sleep 1; done
  rung run --rung 1 --surface server --tier low -- \
    curl -sS -D - http://localhost:8080/api/thing
  kill "$SRV"
  ```

  rung witnesses the client exchange (`curl -D -` puts status + headers + body on
  stdout); it does not manage the server lifecycle. Bind a private port and a
  `mktemp -d` state dir so the run does not collide with the host.
- **Rung 0 (not this):** serializing a response object in isolation; asserting on
  parsed frames, never on raw byte 0 of the stream; reasoning that the route
  *should* return 200.
- **Watch for:** on the stdio channel, log/banner bytes leaking onto the protocol
  stream (the exact defect a stdout-purity check targets; `--expect-frames` counts
  lines, so leaked logs inflate the count, read a too-early N as contamination). On
  HTTP, confirm the status code first, since a 200-shaped body off the wrong branch
  looks like success. See
  [`gate/cases/sync-connector-stdio-purity/`](../../gate/cases/sync-connector-stdio-purity/).

## `library`: a package consumed through its public API

- **Real surface:** the **package boundary** (the public, exported API a caller
  imports), driven with realistic (including adversarial) input, reading the bytes
  or values it returns to a caller.
- **Rung 0 (not this):** calling a *private* internal (e.g. the escaper behind the
  public generator). Observing an internal is not observing the consumer's
  boundary; for a claim about emitted output, that is a non-surface check.
- **Rung 1:** compile the module and call the public entry point with the input
  that exercises the change, then read the emitted result.
- **Watch for:** the difference between "the helper returns the right string" and
  "the whole generator emits the right bytes for this input." See
  [`gate/cases/ical-text-escaping-rfc5545/`](../../gate/cases/ical-text-escaping-rfc5545/).

## `gui`: a graphical / interactive front end

- **Real surface:** the rendered UI a user drives (the button tapped, the flow
  from action to observable effect), exercised through a driver (emulator, browser
  automation, UI test harness) that reads what the user would see.
- **Rung 0 (not this):** unit-testing a view model or a handler; asserting the
  library the button *would* call. The wiring between the GUI and that library is
  what a non-GUI check cannot observe.
- **Rung 1:** drive the UI in a runner (browser automation, emulator, UI-test
  harness) and make the *driver* the probe:
  `rung run --rung 1 --surface gui -- python drive_ui.py`. rung captures what the
  driver prints, not pixels, so the driver has to emit the observation it made:
  the asserted post-state, plus the path or sha256 of the screenshot it took. A
  driver that prints `clicked Export -> file appeared, sha=...` gives the gate
  something to score; one that only exits 0 has told rung nothing. The screenshot
  is supplementary evidence a human opens, referenced from the captured stdout.
- **Gap:** if no emulator/device is available (or the app is read-only),
  the GUI surface is **undriven (rung 0)**. Record that as a gap rather than
  implying end-to-end coverage. The `ical` case does this for its export
  button.

## `agent`: an LLM/agent tool or tool-calling loop

- **Real surface:** the agent (or the tool it exposes) driven end-to-end with a
  real request, reading the actual tool call / output / side effect it produces,
  not a mocked model response.
- **Rung 0 (not this):** unit-testing the tool function directly; asserting on a
  stubbed model turn.
- **Rung 1:** exercise the agent through its real entry point and capture the
  observed behavior. Pin the run so the observation is stable enough to score: fix
  the decode where the runtime allows (temperature 0, a fixed seed) and assert on
  the *deterministic* part of the turn (the tool call it emitted, the side effect it
  caused, the final structured output), not the free-text prose. Capture that, not
  the whole transcript. Non-determinism is common here: the `--diff` re-run guard
  blocks a channel that is not byte-stable rather than certify a noisy delta, so
  point `--diff-channel` at the stable side effect, never the narration.

## `ci`: a pipeline / build/gate step

- **Real surface:** the pipeline step run the way CI runs it, reading its real
  output and exit status. Two ways to reach it:
  - **Locally, in a runner-matched env:** run the exact step command (same image,
    same env) as the probe:
    `rung run --rung 1 --surface ci -- ./scripts/ci-step.sh`. This is a `cli`
    observation held to the pipeline's environment; the value over `--surface cli`
    is the claim you are making, that *this is the CI step*, not an ad-hoc local run.
  - **The hosted run:** dispatch the workflow and witness the runner's own report,
    e.g. `rung run --rung 1 --surface ci -- gh run view <id> --log`. That captures
    what the platform executed, not a local approximation of it.
- **Rung 0 (not this):** reasoning about the YAML; running one script out of the
  pipeline's context and calling the pipeline verified.
- **Watch for:** a local step that passes only because your machine carries state
  the runner lacks (installed tools, cached credentials, a different working dir).

## Choosing the rung

The point is never to claim rung 1 everywhere. A change may touch several
surfaces; observe the ones you can, and **record the rest as gaps** (rung 0, with
`why_unverified`) instead of inflating a single claim to cover them.

rung has one answer for everything short of an observation: **rung 0 with a
recorded `why_unverified`**. It does not split "there was no surface to drive" (a
docs-only change) from "there was one but I could not reach it" (the build broke, no
device) the way a reviewer's SKIP vs BLOCKED verdict does. That distinction is a
judgment for the reviewer or the `/verify` layer above; the gate records only whether
the real surface was observed, and when it was not, the reason you gave. The framework
asks the same question on every claim: *at which rung did your agent verify?*
