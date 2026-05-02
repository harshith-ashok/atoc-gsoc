import re

SKIP = ("//", "/*", "*", "*/", "#", "---", "+++", "@@")
CODE = re.compile(r'\(|\[|=|->|return\s|;$')


def is_code(line):
    line = line.strip()
    if not line or len(line) < 4:
        return False
    if any(line.startswith(p) for p in SKIP):
        return False
    if re.fullmatch(r'[\{\}\s;]+', line):
        return False
    return bool(CODE.search(line))


def parse(text):
    removed, added, hunks = [], [], []
    hunk = {"removed": [], "added": [], "context": []}
    in_hunk = False

    for line in text.splitlines():
        if line.startswith("@@"):
            if in_hunk:
                hunks.append(hunk)
            hunk = {"removed": [], "added": [], "context": []}
            in_hunk = True
        elif in_hunk:
            if line.startswith("-") and not line.startswith("---"):
                c = line[1:].strip()
                if is_code(c):
                    hunk["removed"].append(c)
                    removed.append(c)
            elif line.startswith("+") and not line.startswith("+++"):
                c = line[1:].strip()
                if is_code(c):
                    hunk["added"].append(c)
                    added.append(c)
            elif line.startswith(" "):
                hunk["context"].append(line[1:].strip())

    if in_hunk:
        hunks.append(hunk)

    return {"removed": removed, "added": added, "hunks": hunks}


def parse_file(path):
    with open(path, errors="ignore") as f:
        return parse(f.read())
