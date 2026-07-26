from atoc.patch_parser import is_code, parse, parse_file

MULTI_HUNK_DIFF = """\
--- a/src/copy.c
+++ b/src/copy.c
@@ -10,6 +10,8 @@
 void safe_copy(char *dest, const char *src, size_t maxlen) {
-    strcpy(dest, src);
-    buf[len] = 0;
+    strncpy(dest, src, maxlen - 1);
+    dest[maxlen - 1] = '\\0';
 }
@@ -30,3 +32,3 @@
-    unsafe_call(a, b);
+    safe_call(a, b);
"""


def test_is_code_rejects_diff_metadata_and_comments():
    assert not is_code("--- a/file.c")
    assert not is_code("+++ b/file.c")
    assert not is_code("@@ -1,2 +1,2 @@")
    assert not is_code("// a comment")
    assert not is_code("/* block comment")
    assert not is_code("# a python comment")
    assert not is_code("{")
    assert not is_code("")


def test_is_code_accepts_statements():
    assert is_code("strcpy(dest, src);")
    assert is_code("return foo(bar);")
    assert is_code("x = y + 1;")


def test_parse_splits_hunks_and_flattens_lines():
    patch = parse(MULTI_HUNK_DIFF)

    assert patch.removed == [
        "strcpy(dest, src);",
        "buf[len] = 0;",
        "unsafe_call(a, b);",
    ]
    assert patch.added == [
        "strncpy(dest, src, maxlen - 1);",
        "dest[maxlen - 1] = '\\0';",
        "safe_call(a, b);",
    ]
    assert len(patch.hunks) == 2
    assert patch.hunks[0].removed == ["strcpy(dest, src);", "buf[len] = 0;"]
    assert patch.hunks[1].removed == ["unsafe_call(a, b);"]
    assert "void safe_copy(char *dest, const char *src, size_t maxlen) {" in patch.hunks[0].context


def test_parse_ignores_non_code_lines():
    diff = """\
--- a/f.c
+++ b/f.c
@@ -1,2 +1,2 @@
-// old comment
-strcpy(dest, src);
+strncpy(dest, src, n);
"""
    patch = parse(diff)
    assert patch.removed == ["strcpy(dest, src);"]
    assert patch.added == ["strncpy(dest, src, n);"]


def test_parse_file_reads_sample_patch():
    patch = parse_file("samples/patch.diff")
    assert patch.removed == ["strcpy(dest, src);"]
    assert patch.added == ["memcpy(dest, src, strlen(src) + 1);"]
