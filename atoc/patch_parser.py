"""Parse a unified diff into a `Patch` of removed/added/context lines.

Only lines that look like real code are kept: diff metadata (`---`, `+++`,
`@@`), comment-only lines, and pure-whitespace/brace noise are dropped so
downstream signature generation has less garbage to work with.
"""
from __future__ import annotations

import re
from pathlib import Path

from .models import Hunk, Patch

_SKIP_PREFIXES = ("//", "/*", "*", "*/", "#", "---", "+++", "@@")
_LOOKS_LIKE_CODE = re.compile(r'\(|\[|=|->|return\s|;$')


def is_code(line: str) -> bool:
    """Heuristic: does this diff line look like a real statement?"""
    line = line.strip()
    if not line or len(line) < 4:
        return False
    if line.startswith(_SKIP_PREFIXES):
        return False
    if re.fullmatch(r'[\{\}\s;]+', line):
        return False
    return bool(_LOOKS_LIKE_CODE.search(line))


def parse(text: str) -> Patch:
    """Parse unified-diff text into a `Patch`."""
    patch = Patch()
    hunk = Hunk()
    in_hunk = False

    for line in text.splitlines():
        if line.startswith("@@"):
            if in_hunk:
                patch.hunks.append(hunk)
            hunk = Hunk()
            in_hunk = True
        elif in_hunk:
            if line.startswith("-") and not line.startswith("---"):
                content = line[1:].strip()
                if is_code(content):
                    hunk.removed.append(content)
                    patch.removed.append(content)
            elif line.startswith("+") and not line.startswith("+++"):
                content = line[1:].strip()
                if is_code(content):
                    hunk.added.append(content)
                    patch.added.append(content)
            elif line.startswith(" "):
                hunk.context.append(line[1:].strip())

    if in_hunk:
        patch.hunks.append(hunk)

    return patch


def parse_file(path: str | Path) -> Patch:
    """Parse a unified diff from a file on disk."""
    with open(path, encoding="utf-8", errors="ignore") as handle:
        return parse(handle.read())
