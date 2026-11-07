"""export.py never deletes outside an export (red team 2, C1). Only the guard is exercised: no export runs here."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import export  # noqa: E402


def test_target_guard(tmp_path):
    assert export.target_problem(export.ROOT) is not None
    assert export.target_problem(export.ROOT / "sub") is not None
    assert "contains this repository" in export.target_problem(export.ROOT.parent)
    empty = tmp_path / "empty"
    empty.mkdir()
    assert export.target_problem(empty) is None
    assert export.target_problem(tmp_path / "new") is None
    stray = tmp_path / "stray"
    stray.mkdir()
    (stray / "precious.txt").write_text("keep me")
    assert "not a clone" in export.target_problem(stray)
    clone = tmp_path / "clone"
    (clone / ".git").mkdir(parents=True)
    (clone / "README.md").write_text("old export")
    assert export.target_problem(clone) is None
