import json
import os


def load_tracker(path=None):
    tracker_path = path or os.environ.get("AOTC_TRACKER_FILE")
    if not tracker_path:
        return []

    with open(tracker_path, encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, dict):
        if isinstance(data.get("patches"), list):
            return data["patches"]
        if isinstance(data.get("items"), list):
            return data["items"]
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported tracker format")


def _read_patch_content(entry):
    if entry.get("content"):
        return entry["content"]
    patch_path = entry.get("patch") or entry.get("path")
    if not patch_path:
        return ""
    with open(patch_path, encoding="utf-8", errors="ignore") as handle:
        return handle.read()


def get_patches(cve, tracker=None):
    patches = []
    for entry in tracker or []:
        if entry.get("cve") != cve:
            continue
        content = _read_patch_content(entry)
        if not content:
            continue
        patches.append({
            "cve": cve,
            "package": entry.get("package", "unknown"),
            "content": content,
            "source": entry.get("patch") or entry.get("path", ""),
        })
    return patches
