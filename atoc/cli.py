"""Command-line interface wiring the pipeline stages together."""
from __future__ import annotations

import argparse
import os
import urllib.parse

from . import patch_parser, report
from .models import Patch
from .scanner import DebianCodeSearchScanner, LocalScanner
from .signatures import generate_signatures
from .tracker import CveTracker

DEFAULT_TARGETS = {
    "curl": "./curl",
    "coreutils": "./coreutils",
    "openssh": "./openssh",
    "openssl": "./openssl",
}
DEFAULT_PATCH_FILE = "samples/patch.diff"

DEMO_PATCH = """\
--- a/src/copy.c
+++ b/src/copy.c
@@ -10,6 +10,8 @@
 void safe_copy(char *dest, const char *src, size_t maxlen) {
-    strcpy(dest, src);
-    buf[len] = 0;
+    strncpy(dest, src, maxlen - 1);
+    dest[maxlen - 1] = '\\0';
 }
"""


def resolve_targets(target_args: list[str] | None) -> dict[str, str]:
    """Turn `--target name=path` / `--target path` args into {name: path}."""
    if not target_args:
        return {name: path for name, path in DEFAULT_TARGETS.items() if os.path.isdir(path)}

    targets = {}
    for raw in target_args:
        if "=" in raw:
            name, path = raw.split("=", 1)
        else:
            path = raw
            name = os.path.basename(os.path.abspath(path))
        if os.path.isdir(path):
            targets[name] = path
    return targets


def run_local(patch_path: str, targets: dict[str, str]) -> None:
    patch = patch_parser.parse_file(patch_path)
    print("Removed:", patch.removed)
    print("Added:  ", patch.added)

    signatures = generate_signatures(patch)
    print(f"\nGenerated {len(signatures)} signature(s)")
    if not signatures:
        print("No usable signatures were produced from this patch.")
        return

    scanner = LocalScanner()
    results = {}
    for name, path in targets.items():
        findings = scanner.scan(path, signatures)
        report.print_findings(name, findings)
        results[name] = findings

    report.write_report(results)
    print("\nSaved report.json")


def run_cve(cve: str, targets: dict[str, str], tracker_path: str | None, use_dcs: bool) -> None:
    tracker = CveTracker.load(tracker_path)
    tracked_patches = tracker.patches_for(cve)
    if not tracked_patches:
        print(f"No patches found for {cve}")
        return

    local_scanner = LocalScanner()
    dcs_scanner = DebianCodeSearchScanner(api_key=os.environ.get("DCS_API_KEY", ""))
    all_findings = []

    for tracked in tracked_patches:
        patch = patch_parser.parse(tracked.content)
        signatures = generate_signatures(patch)

        if use_dcs:
            findings = dcs_scanner.scan(signatures, source_package=tracked.package)
        else:
            findings = []
            for name, path in targets.items():
                for finding in local_scanner.scan(path, signatures):
                    finding.package = name
                    findings.append(finding)

        report.print_findings(tracked.package, findings)
        all_findings.extend(findings)

    report.write_report({cve: all_findings})
    print("Saved report.json")


def run_demo() -> None:
    patch: Patch = patch_parser.parse(DEMO_PATCH)
    print("Removed:", patch.removed)

    signatures = generate_signatures(patch)
    print(f"\n{len(signatures)} signature(s) generated:\n")
    for sig in signatures:
        print(f"  vuln: {sig.vuln}")
        if sig.fix:
            print(f"  fix:  {sig.fix}")
        print()

    print("Search URLs for codesearch.debian.net:")
    for sig in signatures[:2]:
        encoded = urllib.parse.quote(sig.vuln)
        print(f"  https://codesearch.debian.net/search?q={encoded}&match_mode=regexp")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="atoc",
        description="Find code clones of a vulnerability using its security patch.",
    )
    parser.add_argument("--demo", action="store_true", help="Run the built-in demo patch.")
    parser.add_argument("--cve", metavar="CVE_ID", help="Look up patches for this CVE in a tracker file.")
    parser.add_argument("--dcs", action="store_true", help="Use codesearch.debian.net instead of local trees.")
    parser.add_argument("--patch", default=DEFAULT_PATCH_FILE, help="Path to a unified diff to scan with.")
    parser.add_argument(
        "--target", action="append",
        help="Package path or name=path to scan. Repeatable.",
    )
    parser.add_argument(
        "--tracker-file",
        help="Path to a local tracker JSON file for --cve mode.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    targets = resolve_targets(args.target)

    if args.demo:
        run_demo()
    elif args.cve:
        run_cve(args.cve, targets, tracker_path=args.tracker_file, use_dcs=args.dcs)
    else:
        run_local(args.patch, targets)
