import argparse
import json
import os
import urllib.parse

from patch_parser import parse_file, parse
from signature import generate_signatures_v2
from scanner import scan_repo, scan_repo_v2, scan_codesearch

DEFAULT_TARGETS = {
    "curl": "./curl",
    "coreutils": "./coreutils",
    "openssh": "./openssh",
    "openssl": "./openssl",
}
PATCH_FILE = "samples/patch.diff"

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

def print_hits(name, results):
    clones = [r for r in results if not r.get("fix_present")]
    print(f"\n=== {name} ===")
    print(f"  matches: {len(results)}, potential clones: {len(clones)}")
    for r in clones[:5]:
        loc = r.get("file", r.get("path", "?"))
        print(
            f"  {loc}:{r.get('line')} [{r.get('confidence')}] {r.get('match', r.get('context',''))[:80]}")


def resolve_targets(target_args):
    if not target_args:
        return {
            name: path for name, path in DEFAULT_TARGETS.items()
            if os.path.isdir(path)
        }

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


def run_local(patch_path, targets):
    patch = parse_file(patch_path)
    print("Removed:", patch["removed"])
    print("Added:  ", patch["added"])

    sigs = generate_signatures_v2(patch)
    print(f"\nGenerated {len(sigs)} signatures")
    if not sigs:
        print("No usable signatures were produced from this patch.")
        return

    all_results = {}
    for name, path in targets.items():
        results = scan_repo_v2(path, sigs)
        print_hits(name, results)
        all_results[name] = results

    with open("report.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print("\nSaved report.json")


def run_cve(cve, targets, tracker_path=None, use_dcs=False):
    from tracker import get_patches, load_tracker
    tracker = load_tracker(tracker_path)
    patches = get_patches(cve, tracker=tracker)
    if not patches:
        print(f"No patches found for {cve}")
        return

    all_hits = []
    for p in patches:
        patch = parse(p["content"])
        sigs = generate_signatures_v2(patch)
        if use_dcs:
            key = os.environ.get("DCS_API_KEY", "")
            hits = scan_codesearch(
                sigs, source_package=p["package"], api_key=key)
        else:
            hits = []
            for name, path in targets.items():
                for r in scan_repo_v2(path, sigs):
                    r["package"] = name
                    hits.append(r)
        print_hits(p["package"], hits)
        all_hits.extend(hits)

    with open("report.json", "w") as f:
        json.dump({cve: all_hits}, f, indent=2)
    print("Saved report.json")


def run_demo():
    patch = parse(DEMO_PATCH)
    print("Removed:", patch["removed"])
    sigs = generate_signatures_v2(patch)
    print(f"\n{len(sigs)} signature(s) generated:\n")
    for s in sigs:
        print(f"  vuln: {s['vuln']}")
        if s["fix"]:
            print(f"  fix:  {s['fix']}")
        print()

    print("Search URLs for codesearch.debian.net:")
    for s in sigs[:2]:
        enc = urllib.parse.quote(s["vuln"])
        print(
            f"  https://codesearch.debian.net/search?q={enc}&match_mode=regexp")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--cve", metavar="CVE_ID")
    parser.add_argument("--dcs", action="store_true")
    parser.add_argument("--patch", default=PATCH_FILE)
    parser.add_argument("--target", action="append",
                        help="Package path or name=path. Can be passed multiple times.")
    parser.add_argument("--tracker-file",
                        help="Path to a local tracker JSON file for --cve mode.")
    args = parser.parse_args()
    targets = resolve_targets(args.target)

    if args.demo:
        run_demo()
    elif args.cve:
        run_cve(args.cve, targets, tracker_path=args.tracker_file,
                use_dcs=args.dcs)
    else:
        run_local(args.patch, targets)


if __name__ == "__main__":
    main()
