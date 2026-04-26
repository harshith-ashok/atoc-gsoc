import re


def is_valid_code(line: str):
    line = line.strip()

    if not line:
        return False

    # Ignore comments
    if line.startswith("//") or line.startswith("/*") or line.startswith("*"):
        return False

    # Ignore preprocessor
    if line.startswith("#"):
        return False

    # Basic heuristic: looks like function call
    if "(" in line and ")" in line:
        return True

    return False


def extract_patch_data(patch_text: str):
    removed = []
    added = []

    for line in patch_text.splitlines():
        if line.startswith('-') and not line.startswith('---'):
            cleaned = line[1:].strip()
            if is_valid_code(cleaned):
                removed.append(cleaned)

        elif line.startswith('+') and not line.startswith('+++'):
            cleaned = line[1:].strip()
            if is_valid_code(cleaned):
                added.append(cleaned)

    # Fallback: if no removed lines, use added lines
    if not removed and added:
        removed = added[:]

    return {
        "removed": removed,
        "added": added
    }


def parse_patch_file(path: str):
    with open(path, 'r', errors='ignore') as f:
        content = f.read()

    return extract_patch_data(content)
