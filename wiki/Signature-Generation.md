# Signature Generation

`atoc/signatures.py` turns removed (vulnerable-side) lines from a `Patch`
into regexes loose enough to survive renaming and reformatting, but tight
enough to still mean something. This page walks through `loosen()`,
`has_trigram()`, and the confidence heuristic, including a quirk in the
latter that's worth knowing about before trusting the `confidence` field.

## `loosen(line)`

Tokenizes a line (strings, identifiers, numbers, whitespace, or single
punctuation characters) and rebuilds it as a regex:

| Token kind                                         | Becomes                     |
|-----------------------------------------------------|------------------------------|
| whitespace                                          | `\s*`                        |
| numeric literal (`10`, `42`)                        | `\d+`                        |
| identifier that is a keyword, `ALL_CAPS`, or immediately followed by `(` | escaped literal (kept as-is) |
| any other identifier                                | `[A-Za-z_]\w*`                |
| everything else (operators, punctuation, string/char literals) | escaped literal        |

So `strcpy(dest, src[10]);` loosens to a pattern that still requires the
literal function name `strcpy` and the surrounding punctuation, but treats
`dest`, `src`, and `10` as wildcards — it matches
`strcpy(buffer, other_src[42]);` just as well. `memcpy(dest, src[10]);`
does **not** match, because `strcpy` vs `memcpy` is a literal anchor, not
an abstracted identifier. See `tests/test_signatures.py::test_loosen_*`
for the exact assertions.

The "keep it if it's immediately followed by `(`" rule is what lets a
signature survive a variable rename but still insist on the same function
being called — that's the single most load-bearing heuristic in the whole
project.

## Multi-line vs. single-line signatures

For each hunk with removed lines, `generate_signatures` produces up to two
kinds of `Signature`:

- **Multi-line** (`multi=True`): if the hunk removed 2+ lines, up to 6 of
  them are loosened and joined with a connector, `[\s\S]{0,120}` — "up to
  120 characters of anything." This catches the whole vulnerable block
  even if unrelated lines were inserted between the two anchors by later
  refactoring.
- **Single-line** (`multi=False`): the first 4 removed lines each get
  their own standalone signature, so a scanner can still find the
  vulnerable call even in a copy that only kept one of the removed lines
  (e.g. the unsafe call survived, but the code around it diverged).

Both carry a `fix` regex built the same way from up to 2–4 added lines, so
a scanner can check whether the corresponding fix already appears near a
match (see [Scanning Strategies](Scanning-Strategies.md)).

Signatures are deduplicated by `(vuln, fix)` across hunks and patches, so a
CVE with two near-identical hunks (or a `--cve` batch with repeated
patches) doesn't produce redundant scan work or duplicate report rows.

## `has_trigram(pattern)`: rejecting over-abstracted signatures

If every token in a line abstracts away (pure numbers/operators, no
identifiers or literals), `loosen()` can produce a pattern that's
"technically a regex" but matches almost anything, e.g. `1 + 2;` loosens
to something with no literal signal left after removing the wildcard
character classes. `has_trigram` strips `\w`/`\W`/`\d`/`\D`/`\s`/`\S` and
the multi-line connector, then requires a run of at least 3 remaining
"real" characters (letters, digits, or common code punctuation). If
nothing survives that strip, the signature is dropped — see
`test_has_trigram_rejects_lines_with_no_identifier_left_to_anchor_on`.

## Confidence: `high` vs. `medium`, and a known quirk

`_confidence_for(vuln_pattern)` counts runs of 2+ alphanumeric characters
in the **generated regex text** and calls it `high` if there are 3 or
more, else `medium`. The intent is "a pattern with several distinctive
literal anchors (function names, macros) is more trustworthy than one with
only a single anchor."

**Caveat surfaced while writing the test suite for this rewrite:** the
wildcard class used for abstracted identifiers, `[A-Za-z_]\w*`, contains
the literal substring `Za` (from `A-Za-z`) as parseable text. Because the
confidence counter scans the *regex source*, not the *semantic* pattern,
every abstracted identifier contributes a spurious "literal run" toward
the `high` threshold — so a multi-line signature with 2–3 abstracted
variables can reach `high` confidence on structure alone, independent of
how distinctive the actual anchored text is. This is inherited from the
original prototype and preserved as-is rather than silently changed
mid-rewrite; it's called out here (and in
[Limitations and Roadmap](Limitations-and-Roadmap.md)) as a concrete thing
a real confidence/ranking model should fix, e.g. by counting matches
against the *pre-abstraction* line instead of the compiled regex text.
