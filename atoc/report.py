"""Terminal summaries and the `report.json` writer."""
from __future__ import annotations

import json
from pathlib import Path

from .models import Finding


def print_findings(name: str, findings: list[Finding]) -> None:
    clones = [f for f in findings if not f.fix_present]
    print(f"\n=== {name} ===")
    print(f"  matches: {len(findings)}, potential clones: {len(clones)}")
    for finding in clones[:5]:
        print(f"  {finding.file}:{finding.line} [{finding.confidence}] {finding.match[:80]}")


def write_report(report: dict[str, list[Finding]], path: str | Path = "report.json") -> None:
    serializable = {
        name: [finding.to_dict() for finding in findings]
        for name, findings in report.items()
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(serializable, handle, indent=2)
