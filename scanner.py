import os
import re
import time
import requests

EXTS = (".c", ".h", ".cpp", ".py")
DCS_URL = "https://codesearch.debian.net/api/v1/search"
IGNORED_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", "tests", "test", "testing",
    "examples", "example", "docs", "doc", "build", "dist", "vendor"
}


def iter_source_files(path):
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for fname in files:
            if any(fname.endswith(e) for e in EXTS):
                yield os.path.join(root, fname)


def scan_repo(path, patterns):
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error:
            pass

    results = []
    for fpath in iter_source_files(path):
        try:
            with open(fpath, encoding="utf-8", errors="ignore") as handle:
                lines = handle.readlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for rx in compiled:
                if rx.search(line):
                    results.append(
                        {"file": fpath, "line": i, "match": line.strip()})
                    break
    return results


def scan_repo_v2(path, sigs, window=20):
    results = []
    seen = set()
    for sig in sigs:
        try:
            vuln_rx = re.compile(sig["vuln"], re.DOTALL)
        except re.error:
            continue
        fix_rx = None
        if sig.get("fix"):
            try:
                fix_rx = re.compile(sig["fix"], re.DOTALL)
            except re.error:
                pass

        for fpath in iter_source_files(path):
            try:
                with open(fpath, encoding="utf-8", errors="ignore") as handle:
                    content = handle.read()
            except OSError:
                continue
            file_lines = content.splitlines()

            for m in vuln_rx.finditer(content):
                lineno = content[:m.start()].count("\n") + 1
                start = max(0, lineno - window - 1)
                end = min(len(file_lines), lineno + window)
                nearby = "\n".join(file_lines[start:end])
                key = (fpath, lineno, sig["vuln"])
                if key in seen:
                    continue
                seen.add(key)
                fix_present = bool(fix_rx and fix_rx.search(nearby))
                results.append({
                    "file": fpath,
                    "line": lineno,
                    "match": file_lines[lineno - 1].strip() if lineno <= len(file_lines) else "",
                    "confidence": sig.get("confidence", "medium"),
                    "fix_present": fix_present,
                })
    return results


def scan_codesearch(sigs, source_package, api_key=""):
    headers = {"x-dcs-apikey": api_key} if api_key else {}
    hits = []

    for sig in sigs:
        if sig.get("confidence") == "low":
            continue
        try:
            resp = requests.get(DCS_URL, headers=headers,
                                params={"query": sig["vuln"],
                                        "match_mode": "regexp"},
                                timeout=30)
            if resp.status_code in (400, 429):
                time.sleep(5 if resp.status_code == 400 else 15)
                continue
            resp.raise_for_status()
        except requests.RequestException:
            continue
        finally:
            time.sleep(2)

        fix_rx = None
        if sig.get("fix"):
            try:
                fix_rx = re.compile(sig["fix"], re.DOTALL)
            except re.error:
                pass

        for item in resp.json():
            if item.get("package") == source_package:
                continue
            context = item.get("context", "")
            hits.append({
                "package": item.get("package", ""),
                "path": item.get("path", ""),
                "line": item.get("line", 0),
                "context": context,
                "confidence": sig.get("confidence"),
                "fix_present": bool(fix_rx and fix_rx.search(context)),
            })

    return hits
