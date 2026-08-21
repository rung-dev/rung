# rung

**Did your AI agent run what it says it verified, or only claim it did?**

*At which rung did your agent verify?*

**rung is how an AI agent verifies its own work: it runs the real thing, captures what happened, and turns that into a record you can re-check.**

> [!NOTE]
> **This npm entry is a pointer.** rung is a Python tool today, and a native npm
> package is in progress. For now, install it with pip / pipx / uv / Homebrew or
> run the container (see [Install](#install)). Running `npx rung-ai` prints these
> same instructions.

## The problem: "verified" is a word, not a record

When an AI coding agent says *"verified, works correctly,"* you cannot tell what it did. Maybe it ran the real program and watched it work. Maybe it read the code and decided it should work. Maybe it ran a test that never touches the real thing. All three come back as the same word, *verified*, so a change nobody ran can ship as verified, and you find out in production.

That word is a self-report: the agent grades its own work and you take its word for it. rung replaces the word with a record you, your CI, or the next reviewer can re-check instead of trust. **Review proposes, running settles.**

## What rung records

rung records two things about a check, then turns them into a verdict a plain program can re-check:

- **How real the check was.** Did the agent drive the *real* surface (the actual CLI, server, or API) and capture what it did, or only reason about the code? Only running the real thing counts as observed. rung **0** = read / reasoned, rung **1** = ran the real surface.
- **Who checked.** The author that made the change, or an independent reviewer?

|                                  | by the author        | independent                                    |
|----------------------------------|----------------------|------------------------------------------------|
| **rung 1**: ran the real thing   | it ran, self-checked | ★ **the aim**: ran it, independently confirmed |
| **rung 0**: reasoned / ran tests | you have its word    | a second read of the same diff                 |

The aim is the top-right cell: a real run, confirmed by someone other than the author. A plain, deterministic gate reads the recorded evidence and passes or blocks. No AI, no network. Exit **0** ships, **30** blocks, **2** means it could not evaluate.

## Install

```bash
pipx install rung-ai                          # isolated CLI on PATH (recommended)
uv tool install rung-ai                       # same, via uv
pip install rung-ai                           # into the current environment
brew tap rung-dev/tap && brew install rung    # Homebrew (macOS / Linux)
```

Run it with no install:

```bash
uvx --from rung-ai rung gate bundle.json
docker run --rm -v "$PWD:/w" -w /w ghcr.io/rung-dev/rung:0.6.0 gate bundle.json
```

Gate a bundle in CI with the published [GitHub Action](https://github.com/marketplace/actions/rung-gate) (`uses: rung-dev/rung@v0.6.0`); it fails the build on anything but exit 0.

## Learn more

- Site: https://rung-dev.github.io
- Source and docs: https://github.com/rung-dev/rung
- PyPI: https://pypi.org/project/rung-ai/

## License

Apache 2.0.
