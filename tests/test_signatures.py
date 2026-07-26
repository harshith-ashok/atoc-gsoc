import re

from atoc.models import Hunk, Patch
from atoc.signatures import generate_signatures, has_trigram, loosen


def test_loosen_preserves_function_name_and_abstracts_identifiers_and_numbers():
    pattern = loosen("strcpy(dest, src[10]);")
    assert re.search(r"strcpy", pattern)
    assert re.fullmatch(pattern, "strcpy(dest, src[10]);")
    # A renamed variable and a different index should still match.
    assert re.fullmatch(pattern, "strcpy(buffer, other_src[42]);")
    # A different function call must not match.
    assert not re.fullmatch(pattern, "memcpy(dest, src[10]);")


def test_loosen_keeps_keywords_and_macros_literal():
    pattern = loosen("if (x == NULL) return;")
    assert re.fullmatch(pattern, "if (x == NULL) return;")
    assert re.fullmatch(pattern, "if (y == NULL) return;")


def test_has_trigram_rejects_lines_with_no_identifier_left_to_anchor_on():
    # An all-numeric expression loosens to almost nothing but wildcards and
    # single punctuation characters -- there's no literal signal left to
    # search on, so it should be rejected.
    assert not has_trigram(loosen("1 + 2;"))
    assert has_trigram(loosen("strcpy(dest, src);"))


def _patch_with_hunk(removed, added):
    return Patch(hunks=[Hunk(removed=removed, added=added)])


def test_generate_signatures_skips_hunks_with_no_removed_lines():
    patch = _patch_with_hunk(removed=[], added=["memcpy(dest, src, n);"])
    assert generate_signatures(patch) == []


def test_generate_signatures_produces_single_and_multiline_variants():
    patch = _patch_with_hunk(
        removed=["strcpy(dest, src);", "buf[len] = 0;"],
        added=["strncpy(dest, src, maxlen - 1);", "dest[maxlen - 1] = '\\0';"],
    )
    signatures = generate_signatures(patch)

    assert any(sig.multi for sig in signatures)
    assert any(not sig.multi for sig in signatures)
    for sig in signatures:
        assert sig.fix  # added lines were available, so a fix pattern is set


def test_generate_signatures_deduplicates_identical_signatures():
    patch = Patch(hunks=[
        Hunk(removed=["strcpy(dest, src);"], added=["memcpy(dest, src, n);"]),
        Hunk(removed=["strcpy(dest, src);"], added=["memcpy(dest, src, n);"]),
    ])
    signatures = generate_signatures(patch)
    # Two hunks with an identical removed/added line must collapse to one
    # signature rather than being reported (and scanned for) twice.
    assert len(signatures) == 1


def test_generate_signatures_assigns_high_confidence_for_distinctive_multiline_blocks():
    patch = _patch_with_hunk(
        removed=[
            "openssl_decrypt_block(ctx, key, iv);",
            "memcpy(output_buffer, plaintext, block_size);",
        ],
        added=[],
    )
    signatures = generate_signatures(patch)
    multi = [sig for sig in signatures if sig.multi]
    assert multi and multi[0].confidence == "high"
