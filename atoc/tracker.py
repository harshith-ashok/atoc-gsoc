"""Local CVE -> patch lookup used by `--cve` mode.

This is a stub for a real Debian security-tracker integration: it reads a
flat JSON file (or a dict with a `patches`/`items` list) mapping CVE IDs to
either a patch file path or inline diff content.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TrackedPatch:
    cve: str
    package: str
    content: str
    source: str


class CveTracker:
    """In-memory view of a tracker JSON file, queryable by CVE ID."""

    def __init__(self, entries: list[dict]) -> None:
        self._entries = entries

    @classmethod
    def load(cls, path: str | Path | None = None) -> "CveTracker":
        tracker_path = path or os.environ.get("AOTC_TRACKER_FILE")
        if not tracker_path:
            return cls([])

        with open(tracker_path, encoding="utf-8") as handle:
            data = json.load(handle)

        if isinstance(data, list):
            return cls(data)
        if isinstance(data, dict):
            for key in ("patches", "items"):
                if isinstance(data.get(key), list):
                    return cls(data[key])
        raise ValueError(f"Unsupported tracker format in {tracker_path}")

    def patches_for(self, cve: str) -> list[TrackedPatch]:
        patches = []
        for entry in self._entries:
            if entry.get("cve") != cve:
                continue
            content = _read_patch_content(entry)
            if not content:
                continue
            patches.append(TrackedPatch(
                cve=cve,
                package=entry.get("package", "unknown"),
                content=content,
                source=entry.get("patch") or entry.get("path", ""),
            ))
        return patches


def _read_patch_content(entry: dict) -> str:
    if entry.get("content"):
        return entry["content"]
    patch_path = entry.get("patch") or entry.get("path")
    if not patch_path:
        return ""
    with open(patch_path, encoding="utf-8", errors="ignore") as handle:
        return handle.read()
