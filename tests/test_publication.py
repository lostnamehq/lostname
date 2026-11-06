"""The publication gate: private blocks stay out, labels are dropped, every path is classified."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import public_check  # noqa: E402
import publicize  # noqa: E402


def test_private_block_is_removed():
    src = "# T\npublic line\n<!-- private -->\nsecret plan\n<!-- /private -->\nmore public\n"
    out = publicize.render(src, "x.md")
    assert "secret plan" not in out and "public line" in out and "more public" in out
    assert out.startswith("<!-- Generated from x.md")


def test_unbalanced_markers_refuse():
    try:
        publicize.render("<!-- private -->\nno end\n", "x.md")
    except SystemExit as e:
        assert "unbalanced" in str(e)
    else:
        raise AssertionError("unbalanced markers must refuse")


def test_review_labels_dropped_and_unverified_spelled_out():
    one, two = "(" + "I" + ")", "(" + "C, T" + ")"  # built, so this public file carries no review label
    out = publicize.render(f"rule A {one} holds {two}; fact [U]\n", "x.md")
    assert one not in out and two not in out and "(unverified)" in out


def test_classification_first_match_wins_and_unclassified_is_none():
    rules = [("internal", "private/*"), ("generated", "docs/model.md"), ("public", "docs/*")]
    assert public_check.classify("private/src/model.md", rules) == "internal"
    assert public_check.classify("docs/model.md", rules) == "generated"
    assert public_check.classify("docs/index.md", rules) == "public"
    assert public_check.classify("secret.txt", rules) is None
