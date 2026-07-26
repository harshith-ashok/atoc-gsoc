# Attack Of The Clones — Wiki

**AOTC** turns a security patch into a clone-detection query: it mines the
*vulnerable* side of a diff, loosens it into a regex, and scans other
codebases for text that still looks like it. It is a triage helper, not a
vulnerability scanner — every hit is "a human should look at this," never
"this is exploitable."

This wiki is the deep-dive companion to the top-level
[README](../README.md), which stays a quickstart. Start here, then follow
whichever page matches what you're trying to understand or change.

## Pages

- **[Architecture](Architecture.md)** — the package layout, the data model
  (`Hunk`, `Patch`, `Signature`, `Finding`), and how the pipeline stages fit
  together.
- **[CLI Usage](CLI-Usage.md)** — every flag, environment variable, and
  example transcript, including what happens on the empty-signature path.
- **[Signature Generation](Signature-Generation.md)** — how `loosen()` turns
  a line of C or Python into a regex, what `has_trigram()` filters out, and
  a documented quirk in the confidence heuristic.
- **[Scanning Strategies](Scanning-Strategies.md)** — `LocalScanner` vs.
  `DebianCodeSearchScanner`: extension filters, ignored directories, the
  fix-present heuristic, and API rate-limit handling.
- **[CVE Tracker Mode](CVE-Tracker-Mode.md)** — the local `--cve` lookup:
  tracker JSON shapes, inline vs. file-path patches, and how it composes
  with `--dcs`.
- **[Testing](Testing.md)** — what each test module asserts and why, so a
  change to the regex-generation logic doesn't quietly break an invariant
  nobody wrote down.
- **[Limitations and Roadmap](Limitations-and-Roadmap.md)** — what this
  prototype cannot do yet, framed as concrete next research steps rather
  than just a disclaimer.

## The one-sentence mental model

```
patch --(atoc.patch_parser)--> Patch
      --(atoc.signatures)-----> [Signature, ...]
      --(atoc.scanner)--------> [Finding, ...]
      --(atoc.report)---------> report.json
```

Every arrow is a pure function or a small class with one public method, and
every stage is independently unit-tested — see [Testing](Testing.md).
