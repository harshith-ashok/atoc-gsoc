from atoc.models import Signature
from atoc.scanner import LocalScanner


def _make_tree(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "vulnerable.c").write_text(
        "void copy(char *dest, char *src) {\n"
        "    strcpy(dest, src);\n"
        "}\n"
    )
    (tmp_path / "src" / "fixed.c").write_text(
        "void copy(char *dest, char *src, size_t n) {\n"
        "    strcpy(dest, src);\n"
        "    strncpy(dest, src, n);\n"
        "}\n"
    )
    (tmp_path / "notes.txt").write_text("strcpy(dest, src); (mentioned in a doc, not code)")
    ignored = tmp_path / "tests"
    ignored.mkdir()
    (ignored / "helper.c").write_text("strcpy(dest, src);\n")
    return tmp_path


def _signature():
    return Signature(
        vuln=r"strcpy\s*\(\s*dest\s*,\s*src\s*\)\s*;",
        fix=r"strncpy\s*\(",
        multi=False,
        confidence="medium",
    )


def test_scan_finds_matches_in_source_files_only(tmp_path):
    root = _make_tree(tmp_path)
    findings = LocalScanner().scan(root, [_signature()])

    matched_files = {f.file for f in findings}
    assert any(f.endswith("vulnerable.c") for f in matched_files)
    assert any(f.endswith("fixed.c") for f in matched_files)
    assert not any(f.endswith("notes.txt") for f in matched_files)


def test_scan_skips_ignored_directories(tmp_path):
    root = _make_tree(tmp_path)
    findings = LocalScanner().scan(root, [_signature()])

    assert not any("tests" in f.file.split("/") for f in findings)


def test_scan_flags_fix_present_only_when_fix_pattern_is_nearby(tmp_path):
    root = _make_tree(tmp_path)
    findings = LocalScanner().scan(root, [_signature()])

    by_file = {f.file: f for f in findings}
    vulnerable = next(f for f in findings if f.file.endswith("vulnerable.c"))
    fixed = next(f for f in findings if f.file.endswith("fixed.c"))

    assert vulnerable.fix_present is False
    assert fixed.fix_present is True


def test_scan_deduplicates_repeated_matches(tmp_path):
    root = _make_tree(tmp_path)
    findings = LocalScanner().scan(root, [_signature(), _signature()])
    locations = [(f.file, f.line) for f in findings]
    assert len(locations) == len(set(locations))


def test_scan_respects_extension_filter(tmp_path):
    (tmp_path / "script.py").write_text("strcpy_wrapper = 'strcpy(dest, src);'\n")
    scanner = LocalScanner(extensions=(".c",))
    findings = scanner.scan(tmp_path, [_signature()])
    assert findings == []
