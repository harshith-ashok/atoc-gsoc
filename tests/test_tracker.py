import json

import pytest

from atoc.tracker import CveTracker


def test_load_returns_empty_tracker_when_no_path_or_env_var(monkeypatch):
    monkeypatch.delenv("AOTC_TRACKER_FILE", raising=False)
    tracker = CveTracker.load(None)
    assert tracker.patches_for("CVE-TEST-0001") == []


def test_load_accepts_bare_list_format(tmp_path):
    path = tmp_path / "tracker.json"
    path.write_text(json.dumps([
        {"cve": "CVE-TEST-0001", "package": "demo", "patch": None, "content": "diff-body"},
    ]))
    tracker = CveTracker.load(path)
    patches = tracker.patches_for("CVE-TEST-0001")
    assert len(patches) == 1
    assert patches[0].package == "demo"
    assert patches[0].content == "diff-body"


@pytest.mark.parametrize("wrapper_key", ["patches", "items"])
def test_load_accepts_dict_wrapped_formats(tmp_path, wrapper_key):
    path = tmp_path / "tracker.json"
    path.write_text(json.dumps({
        wrapper_key: [{"cve": "CVE-TEST-0001", "package": "demo", "content": "diff-body"}],
    }))
    tracker = CveTracker.load(path)
    assert len(tracker.patches_for("CVE-TEST-0001")) == 1


def test_load_rejects_unsupported_shape(tmp_path):
    path = tmp_path / "tracker.json"
    path.write_text(json.dumps({"unexpected": "shape"}))
    with pytest.raises(ValueError):
        CveTracker.load(path)


def test_patches_for_reads_patch_from_file_path(tmp_path):
    patch_file = tmp_path / "fix.diff"
    patch_file.write_text("--- a/f.c\n+++ b/f.c\n")
    tracker_file = tmp_path / "tracker.json"
    tracker_file.write_text(json.dumps([
        {"cve": "CVE-TEST-0002", "package": "demo", "patch": str(patch_file)},
    ]))

    tracker = CveTracker.load(tracker_file)
    patches = tracker.patches_for("CVE-TEST-0002")
    assert patches[0].content == "--- a/f.c\n+++ b/f.c\n"
    assert patches[0].source == str(patch_file)


def test_patches_for_ignores_entries_for_other_cves(tmp_path):
    path = tmp_path / "tracker.json"
    path.write_text(json.dumps([
        {"cve": "CVE-TEST-OTHER", "package": "demo", "content": "x"},
    ]))
    tracker = CveTracker.load(path)
    assert tracker.patches_for("CVE-TEST-0001") == []


def test_patches_for_skips_entries_with_no_readable_content(tmp_path):
    path = tmp_path / "tracker.json"
    path.write_text(json.dumps([
        {"cve": "CVE-TEST-0001", "package": "demo"},
    ]))
    tracker = CveTracker.load(path)
    assert tracker.patches_for("CVE-TEST-0001") == []
