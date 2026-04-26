import os
import re

EXTENSIONS = ('.c', '.h', '.cpp')


def scan_repo(path, patterns):
    results = []

    for root, _, files in os.walk(path):
        for file in files:
            if file.endswith(EXTENSIONS):
                full = os.path.join(root, file)

                try:
                    with open(full, 'r', errors='ignore') as f:
                        content = f.read()
                except:
                    continue

                for pattern in patterns:
                    matches = re.finditer(pattern, content)

                    for match in matches:
                        line_num = content[:match.start()].count("\n") + 1

                        results.append({
                            "file": full,
                            "line": line_num,
                            "match": match.group(0)
                        })

    return results
