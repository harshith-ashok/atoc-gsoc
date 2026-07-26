# CLI Usage

`python3 main.py` has three modes, chosen by which flags are present. They
are mutually exclusive in practice (`--demo` wins over `--cve`, which wins
over the default local-patch mode) — see `atoc/cli.py::main`.

## Flag reference

| Flag              | Applies to      | Meaning                                                                 |
|-------------------|-----------------|--------------------------------------------------------------------------|
| `--patch PATH`    | default mode    | Unified diff to mine for a vulnerable signature. Default: `samples/patch.diff` |
| `--target SPEC`   | default, `--cve`| `name=path` or bare `path`; repeatable. Without it, falls back to whichever of `curl/`, `coreutils/`, `openssh/`, `openssl/` exist locally |
| `--demo`          | standalone      | Runs the built-in demo patch, prints signatures + codesearch URLs, touches no source trees |
| `--cve CVE_ID`    | CVE mode        | Looks up `CVE_ID` in the tracker file and scans/queries for each patch found |
| `--tracker-file PATH` | CVE mode    | Tracker JSON to search (falls back to `$AOTC_TRACKER_FILE` if omitted) |
| `--dcs`           | CVE mode        | Query codesearch.debian.net instead of local target trees (reads `$DCS_API_KEY`) |

## Default local-patch mode

```bash
python3 main.py --patch samples/patch.diff
```

1. `patch_parser.parse_file` reads and parses the diff.
2. If the patch has no removed lines at all, `generate_signatures` returns
   `[]`, the CLI prints `No usable signatures were produced from this
   patch.` and **returns without writing `report.json`** — this is the
   documented behavior for add-only patches like `samples/curl.diff` (see
   the README's notes on sample diffs).
3. Otherwise, `LocalScanner().scan(...)` runs against every resolved
   target, results print to the terminal (top 5 non-fixed matches per
   target) and the full result set is written to `report.json`.

## Demo mode

```bash
python3 main.py --demo
```

Runs entirely offline against a built-in patch string (`atoc/cli.py::DEMO_PATCH`).
Verified output as of this rewrite:

```text
Removed: ['strcpy(dest, src);', 'buf[len] = 0;']

3 signature(s) generated:
  ...

Search URLs for codesearch.debian.net:
  https://codesearch.debian.net/search?q=...&match_mode=regexp
```

Three signatures come out of one two-line hunk: one multi-line signature
joining both removed lines, plus one single-line signature per removed
line (see [Signature Generation](Signature-Generation.md) for why).

## CVE mode

```bash
python3 main.py --cve CVE-TEST-0001 --tracker-file samples/tracker.json
python3 main.py --cve CVE-TEST-0001 --tracker-file samples/tracker.json --dcs
```

See [CVE Tracker Mode](CVE-Tracker-Mode.md) for the tracker file format and
what `--dcs` changes.

## `--target` resolution rules (`atoc/cli.py::resolve_targets`)

- No `--target` at all → every directory in `DEFAULT_TARGETS`
  (`curl`, `coreutils`, `openssh`, `openssl`) that actually exists on disk.
- `--target name=path` → scanned under the given display name.
- `--target path` (no `=`) → display name is `os.path.basename` of the
  absolute path.
- A path that doesn't exist is silently dropped, not an error — repeatable
  flags let you build up a partial target set without every one having to
  resolve.

## Exit behavior worth knowing

- `report.json` is only written when there's at least one signature
  (local mode) or at least one tracked patch (CVE mode) — a fully
  add-only patch produces neither a report nor a crash.
- Regexes that fail to compile (`re.error`, e.g. from a pathological
  patch) are silently skipped in the scanner rather than aborting the
  whole run — one bad signature shouldn't sink an entire scan.
