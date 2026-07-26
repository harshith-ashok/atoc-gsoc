import json

from atoc import cli


def test_resolve_targets_accepts_name_equals_path(tmp_path):
    pkg_dir = tmp_path / "mypkg"
    pkg_dir.mkdir()
    targets = cli.resolve_targets([f"mypkg={pkg_dir}"])
    assert targets == {"mypkg": str(pkg_dir)}


def test_resolve_targets_derives_name_from_bare_path(tmp_path):
    pkg_dir = tmp_path / "mypkg"
    pkg_dir.mkdir()
    targets = cli.resolve_targets([str(pkg_dir)])
    assert targets == {"mypkg": str(pkg_dir)}


def test_resolve_targets_drops_nonexistent_paths(tmp_path):
    assert cli.resolve_targets([str(tmp_path / "does-not-exist")]) == {}


def test_run_demo_prints_generated_signature(capsys):
    cli.run_demo()
    out = capsys.readouterr().out
    assert "signature(s) generated" in out
    assert "strncpy" in out or "strcpy" in out


def test_run_local_writes_report_with_expected_shape(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    patch_file = tmp_path / "patch.diff"
    patch_file.write_text(
        "--- a/example.c\n+++ b/example.c\n@@\n"
        "- strcpy(dest, src);\n"
        "+ memcpy(dest, src, strlen(src) + 1);\n"
    )

    target_dir = tmp_path / "pkg"
    target_dir.mkdir()
    (target_dir / "file.c").write_text("strcpy(dest, src);\n")

    cli.run_local(str(patch_file), {"pkg": str(target_dir)})

    report_path = tmp_path / "report.json"
    assert report_path.exists()
    report = json.loads(report_path.read_text())
    assert "pkg" in report
    assert report["pkg"][0]["file"].endswith("file.c")
    assert report["pkg"][0]["confidence"] in {"medium", "high"}


def test_run_local_with_no_signatures_does_not_write_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    patch_file = tmp_path / "empty.diff"
    patch_file.write_text("--- a/f.c\n+++ b/f.c\n@@\n+ added_only_line();\n")

    cli.run_local(str(patch_file), {})

    assert not (tmp_path / "report.json").exists()


def test_run_cve_writes_report_keyed_by_cve_id(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    tracker_file = tmp_path / "tracker.json"
    tracker_file.write_text(json.dumps([
        {
            "cve": "CVE-TEST-0001",
            "package": "demo",
            "content": "--- a/f.c\n+++ b/f.c\n@@\n- strcpy(dest, src);\n+ memcpy(dest, src, n);\n",
        },
    ]))

    target_dir = tmp_path / "pkg"
    target_dir.mkdir()
    (target_dir / "file.c").write_text("strcpy(dest, src);\n")

    cli.run_cve("CVE-TEST-0001", {"pkg": str(target_dir)}, tracker_path=str(tracker_file), use_dcs=False)

    report = json.loads((tmp_path / "report.json").read_text())
    assert "CVE-TEST-0001" in report
    assert report["CVE-TEST-0001"][0]["package"] == "pkg"
