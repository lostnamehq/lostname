"""Private passages are removed whole or the build stops (red team 2, C2)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import publicize  # noqa: E402

GOOD = "public 1\n<!-- private -->\nSECRET\n<!-- /private -->\npublic 2\n"


def test_balanced_passage_is_removed():
    out = publicize.strip_private(GOOD, "t")
    assert "SECRET" not in out and "public 1" in out and "public 2" in out and "<!--" not in out


@pytest.mark.parametrize("src", [
    "a\n<!-- private -->\nSECRET1\n<!-- /private -->",            # closing marker on the last line, no newline
    "<!-- private -->\n<!-- private -->\nSECRET2\n<!-- /private -->\n<!-- /private -->\n",  # nested
    "text <!-- private --> SECRET3 <!-- /private --> text\n",     # inline
    "<!-- /private -->\nSECRET4\n<!-- private -->\n",             # reversed
    "<!-- private --> note\nSECRET5\n<!-- /private -->\n",        # text after the opening marker
    "<!-- private -->\nSECRET6\n",                                # never closed
])
def test_every_malformed_marker_refuses(src):
    try:
        out = publicize.strip_private(src, "t")
    except SystemExit:
        return
    assert "SECRET" not in out, f"leaked: {out!r}"
