"""Scan source trees (local or codesearch.debian.net) for signature matches."""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Iterator

import requests

from .models import Finding, Signature

DEFAULT_EXTENSIONS = (".c", ".h", ".cpp", ".py")
DEFAULT_IGNORED_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "tests", "test", "testing",
    "examples", "example", "docs", "doc", "build", "dist", "vendor",
}
DEBIAN_CODESEARCH_URL = "https://codesearch.debian.net/api/v1/search"


class LocalScanner:
    """Walks a local directory tree looking for signature matches."""

    def __init__(
        self,
        extensions: tuple[str, ...] = DEFAULT_EXTENSIONS,
        ignored_dirs: set[str] = DEFAULT_IGNORED_DIRS,
        context_window: int = 20,
    ) -> None:
        self.extensions = extensions
        self.ignored_dirs = ignored_dirs
        self.context_window = context_window

    def iter_source_files(self, root: str | Path) -> Iterator[Path]:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in self.ignored_dirs]
            for name in filenames:
                if name.endswith(self.extensions):
                    yield Path(dirpath) / name

    def scan(self, root: str | Path, signatures: list[Signature]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()

        compiled = [
            (sig, _compile(sig.vuln), _compile(sig.fix) if sig.fix else None)
            for sig in signatures
        ]
        compiled = [(sig, vuln_rx, fix_rx) for sig, vuln_rx, fix_rx in compiled if vuln_rx]

        for path in self.iter_source_files(root):
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = content.splitlines()

            for sig, vuln_rx, fix_rx in compiled:
                for match in vuln_rx.finditer(content):
                    line_no = content.count("\n", 0, match.start()) + 1
                    key = (str(path), line_no, sig.vuln)
                    if key in seen:
                        continue
                    seen.add(key)

                    start = max(0, line_no - self.context_window - 1)
                    end = min(len(lines), line_no + self.context_window)
                    nearby = "\n".join(lines[start:end])
                    fix_present = bool(fix_rx and fix_rx.search(nearby))

                    findings.append(Finding(
                        file=str(path),
                        line=line_no,
                        match=lines[line_no - 1].strip() if line_no <= len(lines) else "",
                        confidence=sig.confidence,
                        fix_present=fix_present,
                    ))

        return findings


class DebianCodeSearchScanner:
    """Queries codesearch.debian.net for signature matches across Debian source."""

    def __init__(self, api_key: str = "", base_url: str = DEBIAN_CODESEARCH_URL) -> None:
        self.api_key = api_key
        self.base_url = base_url

    def scan(self, signatures: list[Signature], source_package: str) -> list[Finding]:
        headers = {"x-dcs-apikey": self.api_key} if self.api_key else {}
        findings: list[Finding] = []

        for sig in signatures:
            if sig.confidence == "low":
                continue

            try:
                response = requests.get(
                    self.base_url,
                    headers=headers,
                    params={"query": sig.vuln, "match_mode": "regexp"},
                    timeout=30,
                )
                if response.status_code in (400, 429):
                    time.sleep(5 if response.status_code == 400 else 15)
                    continue
                response.raise_for_status()
            except requests.RequestException:
                continue
            finally:
                time.sleep(2)

            fix_rx = _compile(sig.fix) if sig.fix else None

            for item in response.json():
                if item.get("package") == source_package:
                    continue
                context = item.get("context", "")
                findings.append(Finding(
                    file=item.get("path", ""),
                    line=item.get("line", 0),
                    match=context.strip()[:200],
                    confidence=sig.confidence,
                    fix_present=bool(fix_rx and fix_rx.search(context)),
                    package=item.get("package", ""),
                ))

        return findings


def _compile(pattern: str) -> re.Pattern | None:
    try:
        return re.compile(pattern, re.DOTALL)
    except re.error:
        return None
