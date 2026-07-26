"""Typed data structures shared across the pipeline.

Every stage (parser -> signature generator -> scanner -> report) passes
one of these around instead of an ad-hoc dict, so the shape of a "patch"
or a "finding" is fixed and checkable rather than implicit.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class Hunk:
    """One `@@ ... @@` block of a unified diff."""

    removed: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)


@dataclass
class Patch:
    """A parsed unified diff: every hunk, plus flattened removed/added lines."""

    removed: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    hunks: list[Hunk] = field(default_factory=list)


@dataclass
class Signature:
    """A loose regex derived from the vulnerable (removed) side of a patch."""

    vuln: str
    fix: str = ""
    multi: bool = False
    confidence: str = "medium"

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Finding:
    """One place in a scanned tree where a signature matched."""

    file: str
    line: int
    match: str
    confidence: str
    fix_present: bool
    package: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        if data["package"] is None:
            del data["package"]
        return data
