# Scanning Strategies

`atoc/scanner.py` has two scanners with the same job (turn `list[Signature]`
into `list[Finding]`) against two different corpora.

## `LocalScanner`

Walks a directory tree with `os.walk`, pruning ignored directories
*before* descending into them (not just filtering afterward — important
for the local `curl`/`coreutils`/`openssh`/`openssl` clones in this repo,
which have large `.git`, `test`, and `build` trees you don't want to read
line-by-line).

- **Extensions scanned**: `.c`, `.h`, `.cpp`, `.py` by default, configurable
  via the constructor (`LocalScanner(extensions=(".c",))`).
- **Ignored directories**: `.git`, `.hg`, `.svn`, `__pycache__`, `tests`,
  `test`, `testing`, `examples`, `example`, `docs`, `doc`, `build`, `dist`,
  `vendor` — matched by directory *name*, at any depth.
- **Matching**: each signature's `vuln` regex is compiled with `re.DOTALL`
  and run against the whole file content (not line-by-line), because
  multi-line signatures need to match across a `\n`.
- **Fix-present heuristic**: on a match, a window of `context_window`
  lines (default 20) before and after the match is joined back into text,
  and the signature's `fix` regex is checked against *that window*, not
  the whole file. A `Finding.fix_present = True` means "the fix-shaped
  text is nearby," not "this exact vulnerable call was fixed" — it's a
  proximity heuristic, matching the project's stated goal of triage over
  verification.
- **Deduplication**: findings are keyed by `(file, line, signature.vuln)`,
  so overlapping signatures that both match the same line only produce one
  reported location per signature.

## `DebianCodeSearchScanner`

Queries `codesearch.debian.net`'s API instead of a local tree, so the
"target" is effectively "every package Debian has indexed."

- Skips `confidence == "low"` signatures outright — not worth the network
  round-trip.
- Handles rate limiting: HTTP 400 → sleep 5s and skip; HTTP 429 → sleep
  15s and skip; every request also sleeps 2s afterward regardless of
  outcome, to stay polite to a shared public service.
- Excludes hits from the `source_package` itself — you don't want the
  vulnerable package reporting itself as a "clone" of its own vulnerable
  code.
- Needs `DCS_API_KEY` in the environment for authenticated queries (the
  CLI passes it through from `os.environ` in `atoc/cli.py::run_cve`).

## Choosing between them

| | `LocalScanner` | `DebianCodeSearchScanner` |
|---|---|---|
| Corpus | Whatever you've cloned locally | All of Debian's indexed source |
| Network required | No | Yes |
| Good for | Fast iteration, CI, private/unpublished packages | Distribution-wide sweeps for a fixed patch |
| Invoked via | default mode, `--cve` without `--dcs` | `--cve ... --dcs` |

Both return the same `Finding` dataclass, so `atoc/report.py` doesn't need
to know or care which scanner produced a given result.
