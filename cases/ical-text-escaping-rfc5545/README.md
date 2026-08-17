# Case: RFC 5545 TEXT escaping at a library boundary

A worked, reproducible example at a **library surface**: the kind where the
closest thing to a real consumer is the package's public API, not a CLI or a socket.
The subject is the iCalendar (RFC 5545) export library of a privacy-focused
open-source calendar app (a pure-JVM Kotlin module).

The fix corrects two ways the generator emitted **malformed TEXT values**:

1. A **bare carriage return** (from Windows/web paste, `\r\n` or a lone `\r`) in
   an event `DESCRIPTION` was passed through unescaped. A bare CR is a control
   character excluded from `VALUE-CHAR` (§3.1); a strict consumer can treat it as
   a premature line break and mis-parse the value.
2. `VALARM` `DESCRIPTION`, `SUMMARY`, and `RELATED-TO` were built with raw string
   interpolation, **bypassing escaping**. All three are TEXT-typed; a comma,
   semicolon, or backslash in server-authored alarm text (reachable on re-export
   of a synced event) corrupted the value.

## Why this is a library-surface case

Per the ladder, a library's real surface is its **package boundary**: you drive
the public export, not an internal function. The actual escaper (`escapeICalText`)
is private; driving *it* directly would be a rung-1 import-and-call of an
internal. Instead this case compiles the module and calls the **public
`generate()`** with adversarial input, then reads the emitted bytes: that is the
surface a real caller (the app's export/share path) meets.

## Why the lower rungs pass the bug

| Rung | Verdict |
|-----:|---------|
| 0 | **pass**: the escaper reads plausibly; the VALARM branch "obviously" emits text |
| 1 | **pass**: call `escapeICalText("a,b")` in isolation and it escapes the comma; the *private* function was never the bug: the bug was the VALARM branch **not calling it**, and the escaper **not handling CR** |
| 2 | **pass**: suites assert on parsed model round-trips or on the escaper's own output, not on the raw bytes emitted for a CR-bearing DESCRIPTION or an unescaped VALARM |
| 3 | **catches it**: drive `generate()`, read raw output: a bare CR sits inside the DESCRIPTION value and the VALARM text is unescaped |
| 4 | **attributes it**: the bare CR (count 2→0) and the VALARM escaping appear only after S1; the diff is what fixed them |

The defect lives where a unit test rarely looks: **the exact bytes a real
consumer receives**, assembled by the whole generator, not the return value of
one helper called in isolation.

## What was driven

- Built the module at S0 (parent of the fix) and S1 in **isolated detached git
  worktrees** (working repo untouched), compiling the main sources directly with
  the cached Kotlin compiler and the `ical4j` classpath: **no Android SDK, no
  app build, no network**.
- Called the **public `generate()` API** with an event whose `DESCRIPTION` is
  `"line one\r\nline two\rline three"` and a DISPLAY `VALARM` whose
  `DESCRIPTION`/`SUMMARY`/`RELATED-TO` carry a comma, a semicolon, and a
  backslash.
- Captured the emitted `VCALENDAR` string at both commits.

The observed differential (control chars shown):

```
S0  DESCRIPTION:line one^M\nline two^Mline three     ← 2 bare CRs (^M) inside the value
S1  DESCRIPTION:line one\nline two\nline three        ← 0 bare CRs; each collapsed to \n

S0  DESCRIPTION:Bring: pen, paper; and a backslash \ here    ← raw, corrupt
S1  DESCRIPTION:Bring: pen\, paper\; and a backslash \\ here  ← escaped
        (same for SUMMARY and RELATED-TO)
```

Artifacts `artifacts/s0.ics` and `artifacts/s1.ics` are the real emitted output;
their sha256 hashes are pinned in `bundle.json` and re-checked by the gate. The
only non-deterministic fields (`DTSTAMP` time, generated UIDs) were normalized to
`«redacted»` **identically** in both, so the artifact diff is exactly the fix.
The byte-level properties under test (2 lone CRs at S0 vs 0 at S1, and the three
escaped VALARM lines) are preserved verbatim. iCalendar property names are the
public RFC 5545 vocabulary; no app-internal identifiers appear in the captures.

## What this doesn't cover (recorded as gaps)

- **Gap `g1`: the GUI surface is undriven.** A *user* meets this change at the
  app's "Export / Share .ics" button in the Android GUI. This case drove the
  **library** boundary, not that button. A defect *between* the GUI and this
  library (wrong event assembled, export never invoked, file not shared) would
  not be caught here. With no emulator and a read-only app, the right rung for
  the GUI surface is **undriven (rung 0)**, and the bundle says so instead of
  implying end-to-end coverage.
- **Gap `g2`: one adversarial input.** RFC 5545 TEXT has further edge cases
  (trailing backslash, mixed CR/LF ordering, non-ASCII adjacent to escapes) not
  each driven.

## Run the gate yourself

```bash
# from repo root: stdlib only, no install
rung gate cases/ical-text-escaping-rfc5545/bundle.json
#   -> verdict "pass", exit 0   (rung 4 >= medium's min_rung 3)

# If a team classified export-corruption as HIGH risk, the SAME bundle blocks.
# author rung-4 is not enough at high; it needs a cross-lab attestation:
rung gate cases/ical-text-escaping-rfc5545/bundle.json --tier high
#   -> verdict "block", exit 30: "tier high requires context=cross-lab, got author"
```

Corrupt any byte of either capture and the gate blocks with a sha256 mismatch
naming the artifact.
