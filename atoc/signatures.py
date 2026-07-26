"""Turn the removed (vulnerable) side of a patch into loose regex signatures.

The core trick is `loosen()`: it tokenizes a line of code and rebuilds it
as a regex where identifiers become `\\w+`, numeric literals become `\\d+`,
and whitespace becomes `\\s*` -- while keeping strong anchors (keywords,
ALL_CAPS macros, and anything immediately followed by `(`, i.e. function
names) intact. That lets a signature survive variable renaming and minor
reformatting without becoming so broad it matches everything.
"""
from __future__ import annotations

import re

from .models import Patch, Signature

# Allows up to 120 characters of anything between two anchored fragments,
# so a multi-line signature can tolerate reordered/rewrapped code between
# the lines it cares about.
_CONNECTOR = r'[\s\S]{0,120}'
_IDENTIFIER = r'[A-Za-z_]\w*'
_TOKEN_RE = re.compile(
    r'"(?:\\.|[^"])*"|\'(?:\\.|[^\'])*\'|[A-Za-z_]\w*|\d+|\s+|.'
)
_KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "NULL", "true", "false"}

# A minimum-viable "does this regex still contain enough literal signal to
# be useful" check -- three or more consecutive literal-ish characters
# after stripping the abstracted classes.
_TRIGRAM_RE = re.compile(r'[A-Za-z0-9_()\[\];,<>=!\-*&]{3,}')
_WILDCARD_CLASS_RE = re.compile(r'\\[wWdDsS]')
_CONNECTOR_RE = re.compile(r'\[\\s\\S\]\{[^}]+\}')


def loosen(line: str) -> str:
    """Convert one line of code into a loose regex pattern."""
    tokens = _TOKEN_RE.findall(line.strip())
    out: list[str] = []

    def next_non_space(index: int) -> str:
        for token in tokens[index + 1:]:
            if not token.isspace():
                return token
        return ""

    for index, token in enumerate(tokens):
        if token.isspace():
            out.append(r'\s*')
        elif re.fullmatch(r'\d+', token):
            out.append(r'\d+')
        elif re.fullmatch(r'[A-Za-z_]\w*', token):
            is_anchor = token in _KEYWORDS or token.isupper() or next_non_space(index) == "("
            out.append(re.escape(token) if is_anchor else _IDENTIFIER)
        else:
            out.append(re.escape(token))

    return "".join(out)


def has_trigram(pattern: str) -> bool:
    """Reject signatures that abstracted away almost everything literal."""
    stripped = _WILDCARD_CLASS_RE.sub("", pattern)
    stripped = _CONNECTOR_RE.sub("", stripped)
    return bool(_TRIGRAM_RE.search(stripped))


def _confidence_for(vuln_pattern: str) -> str:
    literal_runs = re.findall(r'[A-Za-z0-9]{2,}', vuln_pattern)
    return "high" if len(literal_runs) >= 3 else "medium"


def generate_signatures(patch: Patch) -> list[Signature]:
    """Generate deduplicated signatures for every hunk with removed lines.

    Two kinds of signature are produced per hunk:

    - a multi-line signature joining up to 6 removed lines with `_CONNECTOR`,
      when the hunk removes 2+ lines (catches a whole vulnerable block)
    - single-line signatures for up to the first 4 removed lines
      (catches the vulnerable call even if surrounding code changed)

    Each carries the corresponding "fix" regex (from added lines) so a
    scanner can tell whether the fix already appears nearby.
    """
    signatures: list[Signature] = []
    seen: set[tuple[str, str]] = set()

    def add(vuln: str, fix: str, multi: bool) -> None:
        key = (vuln, fix)
        if key in seen:
            return
        seen.add(key)
        signatures.append(Signature(
            vuln=vuln,
            fix=fix,
            multi=multi,
            confidence=_confidence_for(vuln) if multi else "medium",
        ))

    for hunk in patch.hunks:
        if not hunk.removed:
            continue

        if len(hunk.removed) >= 2:
            fragments = [loosen(line) for line in hunk.removed[:6] if loosen(line)]
            if len(fragments) >= 2:
                vuln = _CONNECTOR.join(fragments)
                if has_trigram(vuln):
                    fix_fragments = [loosen(line) for line in hunk.added[:4] if loosen(line)]
                    fix = _CONNECTOR.join(fix_fragments) if fix_fragments else ""
                    add(vuln, fix, multi=True)

        for line in hunk.removed[:4]:
            pattern = loosen(line)
            if not pattern or not has_trigram(pattern):
                continue
            fix_fragments = [loosen(line) for line in hunk.added[:2] if loosen(line)]
            fix = _CONNECTOR.join(fix_fragments) if fix_fragments else ""
            add(pattern, fix, multi=False)

    return signatures
