# rung

[![PyPI](https://img.shields.io/pypi/v/rung-ai)](https://pypi.org/project/rung-ai/)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://pypi.org/project/rung-ai/)
[![CI](https://img.shields.io/github/actions/workflow/status/rung-dev/rung/ci.yml?branch=main&label=CI)](https://github.com/rung-dev/rung/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Did your AI agent run what it says it verified, or only claim it did?**

*At which rung did your agent verify?*

**rung is how an AI agent verifies its own work: it runs the real thing, captures what
happened, and turns that into a record you can re-check.**

```
  agent makes a change
        │
        ▼
  rung run ──►  drives the REAL surface (cli · server · library · gui · agent · ci)
        │        and captures the exact bytes it emitted
        ▼
  bundle.json ──  the record: what ran, what it printed, sha256 of each capture
        │
        │  (optional) rung attest ──►  a second model/lab re-checks the record,
        │                              lifting the claim to independent context
        ▼
  rung gate ──►  plain deterministic check, no AI, no network
        │
   ┌────┴────┐
 exit 0    exit 30
 (pass)    (blocked: "nothing shows you ran it")
```

## The problem: "verified" is a word, not a record

When an AI coding agent says *"✅ verified, works correctly,"* you can't tell what it did.
Maybe it ran the real program and watched it work. Maybe it read the code and decided it
should work. Maybe it ran a test that never touches the real thing. All three come back as
the same word, *verified*, so a change nobody ran can ship as verified, and you find out in
production.

That word is a self-report: the agent grades its own work and you take its word for it.
There's no record of what it did, so there's nothing to check.

> Agents work better when they can verify their own results. And "verified" only
> means something if you can say *how*.

An agent that runs its change and watches the result does better work than one that only
reasons about it. Verifying is how good agents get good. But a verification you can't
inspect is another claim: if the agent can't say *how* it checked (what it ran, what it
saw), then "verified" is a word, not a fact.

There are two ways to judge a change: **read** it and form an opinion, or **run** it and
watch what happens. An agent is the one actor that can cheaply *run* the change inside its
own loop, drive the real surface and read the bytes that come back. rung captures that run
and replaces the word with a record you, your CI, or the next reviewer can re-check instead
of trust. **Review proposes, running settles.**

## What rung records

rung records two things about a check, how real it was and who did it, then turns them into
a verdict a plain program can re-check:

- **Grades how real the check was.** Did your agent drive the *real* surface (the actual
  CLI, server, or API) and capture what it did? Or did it reason about the code, or run a
  test in isolation? Only running the real thing counts as *observed*.
- **Records who checked.** The agent that made the change, or an independent reviewer?
- **Gates it, deterministically.** A plain check reads the recorded evidence and passes or
  blocks: no AI, no judgment calls, no network. *"You claimed you verified this, but
  nothing shows you ran it"* → blocked.

The result is a claim you can re-check, not a sentence you have to trust. A verdict looks
like this: the same recorded run, scored as a high-risk change, blocks because it was the
author's own word, with nothing independent behind it.

```jsonc
$ rung gate claim.json --tier high
{
  "verdict": "block",
  "exit_code": 30,
  "reasons": [
    "c1: tier high requires context >= independent, got author",
    "c1: tier high requires a cross-model qualifier, which needs context=independent (got author)"
  ],
  "gate_sha256": "4f750b77…",     // which exact gate logic decided
  "policy_sha256": "4e6c2637…"    // under which exact policy
}
```

Every verdict pins the gate logic (`gate_sha256`) and policy (`policy_sha256`) that produced
it, so the decision can be reproduced and traced to a specific gate and policy.

*rung, as in a step on a ladder.* Those two things it records are two questions, and your
answers are your rung:

1. **Did anyone run the real thing?**
   rung **0** = no (reasoning, or tests in isolation) · rung **1** = yes (drove the real surface)
2. **Who checked: the author, or someone independent?**

|                                  | by the author        | independent                                    |
|----------------------------------|----------------------|------------------------------------------------|
| **rung 1**: ran the real thing   | it ran, self-checked | ★ **the aim**: ran it, independently confirmed |
| **rung 0**: reasoned / ran tests | you have its word    | a second read of the same diff                 |

> [!TIP]
> **The aim is the top-right cell**: a real run, confirmed by someone other than the author.

Most work sits in the bottom row instead, "verified" backed by reasoning, not by running
the real thing. Review moves you across that row (it adds a reader's judgment) but leaves
you at rung 0, where a change reads as verified though nobody ran it. Only running reaches
the top row, rung 1. A real run by the author still clears low-stakes changes; higher
stakes call for the top-right.

By default rung's policy says **shipped means observed**: nothing ships on reasoning alone,
and the more a change would cost if it's wrong, the more independence it asks for.

## Getting started

rung ships no agent of its own. You bring one you already use (Claude Code, an IDE
assistant, an SDK loop) and rung hands it a **skill**: a markdown prompt that turns
*"verify your work"* into *"drive the real thing with `rung run` and put the result on
record."* Three moves: install the tool, load that prompt into your agent, then let it
verify as it works.

**1. Install the tool.**

```bash
pip install rung-ai
```

(pipx, uv, Homebrew, a container image, or the GitHub Action: see
[Other ways to install and run](#other-ways-to-install-and-run).)

**2. Load the skill into your agent.** The skill is plain markdown that ships inside the
package: the instructions your agent reads as context. Installing it puts them where your
agent looks, so *verify* becomes *drive the real surface for this kind of change (cli,
server, library, gui, agent, ci) and record it*, not grade itself. Run `rung skill --print`
to read what it tells the agent:

```bash
rung skill --install <your-agent-skills-dir>   # copies SKILL.md + references/ (Claude Code, for example: .claude/skills/rung)
rung skill --print                             # or stream SKILL.md to stdout, straight into the agent's context
```

The prompt does more than name the command. It tells the agent **not to claim a rung it
didn't observe** (a surface it didn't drive is recorded as a gap, not inflated) and **how to
get a blind second-model review on record** when a change needs independent sign-off. The full
per-surface guidance is in [`SKILL.md`](skill/SKILL.md) and
[`references/surfaces.md`](skill/references/surfaces.md).

**3. Let the agent verify as it works.** From here it runs inside the agent's own loop:
you give it a task as usual, and instead of signing off with *"✅ verified,"* it runs the
real thing under rung, which captures what happened and checks it:

```bash
rung run --rung 1 --surface cli -- mytool --check
```

That runs `mytool --check`, captures what it printed, records it, and checks it against the
default policy. It exits **0** if the claim holds and non-zero if it doesn't, so the same
command is the agent's verify step *and* a CI gate: **fail on anything but `0`**, and a
change nobody ran can't ship as "verified."

Your agent sets the run's dimensions explicitly: **`--rung`** (`0` or `1`, was the real
surface observed), **`--surface`** (`cli`, `server`, `library`, `gui`, `agent`, `ci`), and
**`--method`** (`single`, or `differential` with `--expect-delta` and `--diff-channel` for
a before/after comparison). `rung run -h` lists the full set. There is no independence flag:
a self-run is always author context, and an independent cross-model review is attached to
the record separately with `rung attest` (below).

The exit code is a contract, so a gate step is unambiguous in CI:

| exit | meaning                                                              |
|-----:|---------------------------------------------------------------------|
|  `0` | pass, the only pass                                                  |
| `30` | blocked: the claim didn't hold (e.g. nothing shows the real run)     |
|  `2` | cannot evaluate: a usage error, or unreadable / unparseable input   |

Treat both `30` and `2` as no-ship.

Already have a recorded claim? Check it on its own:

```bash
rung gate claim.json
```

An author-context record is a self-run. To attach an independent review, a second
model or lab re-checks the recorded artifacts and records its verdict:

```bash
rung attest --model reviewer-x --verdict pass claim.json > reviewed.json
```

That lifts the claim to `independent` context and re-gates it, exiting with the gate's
verdict. It is the only way to reach `independent`; a reviewer with no access to the
recorded artifacts is disclosed as unbound, never minted into a byte-bound pass. A panel
(`--panel a:pass,b:pass`) or a cross-lab review (`--lab lab-b`) records the same way.

That's the whole surface: **`run`** to produce a checked record, **`attest`** to attach an
independent review, **`gate`** to check one.

## Who rung is for

- **Agent builders** who want their agent to self-verify with teeth: have it call `rung run`
  as its check step, so whoever reviews its work gets a record instead of a "trust me."
- **Teams shipping AI-written changes** who want "verified" in a PR to mean *a real run
  happened and is on record*: enforced at merge, not taken on faith.

## Why not tests, a linter, or an AI reviewer?

rung isn't any of those, and doesn't replace them:

- **Tests / CI** tell you a check passed. rung tells you a real run happened, and records
  it. Green CI on a suite that never touches the real surface is still rung 0.
- **Linters / type checkers** reason about the code. rung is about whether the *running*
  thing was observed.
- **AI reviewers / "judges"** read the change and give an opinion. rung runs it and records
  what happened, so a reviewer (human or AI) has something real to check instead of a
  self-report.

**Most tools grade your work. rung grades whether the check was real.**

## What rung doesn't claim

rung checks that the work was **shown**: that a real run happened and is recorded so anyone
can re-check it. It does **not** judge whether the check was clever or complete, and it does
**not** prove an independent reviewer was independent. It makes the claim **accountable**, so
you can catch a hollow "verified" where today you can't even look. Quality stays the
reviewer's call; rung's job is making the check itself accountable.

## FAQ

- **Do I need an AI agent, or a subscription?**
  No. rung is free and standalone: `pip install rung-ai`, no account, no API key, no
  network. It's built to be driven *by* an agent as its verify step, but that agent is
  yours to bring (Claude Code, an SDK loop, an IDE assistant) and is a separate product
  with its own cost that rung neither ships nor calls. You can also run rung by hand, with
  no agent at all.
- **Does rung call a model, or send my code anywhere?**
  No. The gate is a plain program: it reads your files, hashes them, and decides. No model,
  no network, nothing phones home. Any model cost lives on the agent side, which is yours.
- **Isn't this just running my tests?**
  Tests check behavior; rung checks that a check *happened* and is recorded. Keep your
  tests; rung records whether they (or a real run) observed the thing you're shipping.
- **What if the agent lies in the record?**
  rung re-derives what it can from the captured bytes and makes the rest re-checkable by a
  person. That makes a claim **accountable**, not unforgeable: you can catch a bad claim
  where today there's nothing to inspect.
- **Will it slow the agent down?**
  No. The gate is fast, local, and deterministic; the only cost is the run itself, the one
  you wanted the agent to do anyway.

## Other ways to install and run

`pip install rung-ai` is the short path; these are the alternatives.

- **pipx / uv**, for a system Python that blocks a bare `pip install` with
  `externally-managed-environment`:
  ```bash
  pipx install rung-ai                          # isolated, on PATH
  uv tool install rung-ai                        # same, via uv
  uvx --from rung-ai rung gate bundle.json       # run once, without installing
  ```
- **Homebrew** (macOS / Linux):
  ```bash
  brew tap rung-dev/tap
  brew install rung
  ```
- **Container.** A pinned image is published to GHCR on each release; its exit
  code is the gate verdict, so it drops into any runner that can pull an image:
  ```bash
  docker run --rm -v "$PWD:/w" -w /w ghcr.io/rung-dev/rung:0.6.0 gate bundle.json
  ```
- **GitHub Actions.** Gate a bundle with no install step via the published
  [action](https://github.com/marketplace/actions/rung-gate)
  (`uses: rung-dev/rung@v0.6.0`); it fails the build on anything but exit 0.
- **From a checkout**, no install, with `src/` on the path:
  ```bash
  PYTHONPATH=src python3 -m rung.cli gate bundle.json   # same as: rung gate ...
  ```

## Learn more

- [`policy/README.md`](policy/README.md): the default ship policy and how to tune it
- [`gate/cases/`](gate/cases/): real, re-checkable worked examples that also run in the test suite
- [`VERIFYING-RUNG-WITH-RUNG.md`](VERIFYING-RUNG-WITH-RUNG.md): rung turned on itself, at which rung, by what method, in whose context
- [`SECURITY.md`](SECURITY.md): the trust boundary, and what rung deliberately leaves to a judge

## License

Apache 2.0. See [`LICENSE`](LICENSE).
