#!/usr/bin/env node
"use strict";

// rung-ai on npm currently redirects to the working install. The gate and
// producer are a Python tool; a native npm build is in progress. This shim
// prints the install paths and exits 2 (rung's "cannot evaluate" code), so it
// never reads as a passing gate in a script.

var msg = [
  "",
  "  rung-ai on npm is a pointer while the native package is in progress.",
  "",
  "  Install the working tool one of these ways:",
  "",
  "    pipx install rung-ai                          # isolated CLI on PATH (recommended)",
  "    uv tool install rung-ai                       # same, via uv",
  "    pip install rung-ai                           # into the current environment",
  "    brew tap rung-dev/tap && brew install rung    # Homebrew (macOS / Linux)",
  "",
  "  Or run it with no install:",
  "",
  "    uvx --from rung-ai rung gate bundle.json",
  "    docker run --rm -v \"$PWD:/w\" -w /w ghcr.io/rung-dev/rung:0.5.1 gate bundle.json",
  "",
  "  Docs:  https://github.com/rung-dev/rung",
  "  Site:  https://rung-dev.github.io",
  "",
  ""
].join("\n");

process.stderr.write(msg);
process.exit(2);
