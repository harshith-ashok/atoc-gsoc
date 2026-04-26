from patch_parser import parse_patch_file
from signature import generate_signatures
from scanner import scan_repo
import json

TARGETS = {
    "curl": "./curl",
    "coreutils": "./coreutils"
}

PATCH_FILE = "samples/patch.diff"


def main():
    print("\n=== Parsing Patch ===\n")

    patch = parse_patch_file(PATCH_FILE)

    print("Removed (pattern source):")
    for l in patch["removed"]:
        print(" -", l)

    print("\nAdded (context/fix):")
    for l in patch["added"]:
        print(" +", l)

    if not patch["removed"]:
        print("\nERROR: No usable lines found in patch")
        return

    patterns = generate_signatures(patch["removed"])

    print("\nGenerated Regex Patterns:")
    for p in patterns:
        print(" ", p)

    all_results = {}

    for name, path in TARGETS.items():
        print(f"\n=== Scanning {name} ===")

        results = scan_repo(path, patterns)

        print(f"Found {len(results)} matches")

        for r in results[:5]:
            print(f"{r['file']}:{r['line']} -> {r['match']}")

        all_results[name] = results

    print("\nSaving report.json...\n")

    with open("report.json", "w") as f:
        json.dump(all_results, f, indent=2)

    print("Done.")


if __name__ == "__main__":
    main()
