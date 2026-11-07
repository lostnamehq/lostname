"""Publication gate holes from red team 2 (C4, C5)."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import public_check  # noqa: E402


def test_term_split_across_a_line_break_is_caught():
    pats = [re.compile(re.escape("Zyxw Client"), re.I)]
    assert public_check.scan_text("d.md", "Built for Zyxw Client.\n", pats)
    assert public_check.scan_text("d.md", "Built for Zyxw\nClient.\n", pats), "a wrapped term must be caught"
    assert not public_check.scan_text("d.md", "Built for nobody.\n", pats)


def test_missing_names_file_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setenv("LOSTNAME_NAMES_FILE", str(tmp_path / "typo.txt"))
    assert public_check.names_problem()
    names = tmp_path / "names.txt"
    names.write_text("Zyxwclient\n")
    monkeypatch.setenv("LOSTNAME_NAMES_FILE", str(names))
    assert public_check.names_problem() is None
