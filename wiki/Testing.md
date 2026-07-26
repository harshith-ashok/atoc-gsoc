# Testing

```bash
pip install -r requirements-dev.txt
pytest
```

32 tests, one file per `atoc/` module plus one for the CLI, all running in
well under a second (everything is either a pure function over in-memory
strings or a scan over a `tmp_path` fixture — no network calls in the
default run).

## `tests/test_patch_parser.py`

Covers the diff→`Patch` boundary: that diff metadata (`---`/`+++`/`@@`),
comments, and pure-whitespace/brace lines are excluded from
`removed`/`added`; that a multi-hunk diff produces one `Hunk` per `@@`
block with the right lines in the right hunk; and that `parse_file`
correctly reads `samples/patch.diff` end-to-end.

## `tests/test_signatures.py`

Covers `loosen()` (identifier/number abstraction while keeping function
names and keywords literal — verified by round-tripping the generated
regex against both the original line and a renamed variant with
`re.fullmatch`), `has_trigram()` (a fully-numeric line is rejected, a real
call is not), and `generate_signatures()`: no signatures from an add-only
hunk, both multi-line and single-line variants from a 2+-line removal,
cross-hunk deduplication, and the confidence heuristic (documented in
[Signature Generation](Signature-Generation.md), including its known
quirk).

## `tests/test_scanner.py`

Builds a small temp source tree with a still-vulnerable file, a
fixed-with-vulnerable-line-still-present file (to test the fix-present
*proximity* heuristic, not a "was it removed" check), a non-code file that
should never be scanned, and an ignored-directory file. Asserts: matches
are found only in real source files; ignored directories are never
descended into; `fix_present` is `True`/`False` correctly per file; repeat
signatures don't produce duplicate findings; and a narrowed `extensions`
tuple is respected.

## `tests/test_tracker.py`

Covers all three tracker JSON shapes (`CveTracker.load` accepting a bare
list, `{"patches": [...]}`, and `{"items": [...]}`), that an unsupported
shape raises `ValueError`, that `content` and file-path (`patch`) entries
both resolve correctly, that entries for other CVEs are excluded from a
lookup, and that an entry with neither `content` nor `patch` is silently
skipped rather than crashing.

## `tests/test_cli.py`

Calls `atoc.cli.run_local` / `run_demo` / `run_cve` and
`resolve_targets` directly rather than shelling out to `python3 main.py`,
so failures point at a Python traceback instead of a subprocess exit
code. Covers `--target` name resolution (both `name=path` and bare
`path`, and that nonexistent paths are dropped), that `--demo` runs
end-to-end and prints a signature, that a real local scan writes
`report.json` with the expected keys, that an add-only patch produces
*no* `report.json` (matching the documented CLI behavior), and that
`--cve` mode keys its report by CVE ID with per-finding `package` stamped
correctly.

## Adding a new test

If you touch `atoc/signatures.py` or `atoc/scanner.py`, prefer adding a
case to the existing module test file over a new end-to-end CLI test —
the unit-level tests pin down exactly *which* behavior changed, while a
CLI-level test only tells you *that* something did.
