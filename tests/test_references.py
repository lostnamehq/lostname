"""Every RFC that Lostname's own code, docs and tools cite has an entry in docs/references.md (plan v0.1)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sources():
    for pattern in ("cmd/**/*.go", "internal/**/*.go", "tools/*.py", "deploy/**/*", "tests/*.py"):
        yield from (p for p in ROOT.glob(pattern) if p.is_file() and "testdata" not in p.parts)
    yield ROOT / "README.md"
    yield ROOT / "ROADMAP.md"
    yield from (p for p in (ROOT / "docs").glob("*.md") if p.name not in ("references.md", "prior-art.md"))


def test_every_cited_rfc_has_a_reference():
    refs = set(re.findall(r"RFC (\d{3,5})", (ROOT / "docs" / "references.md").read_text(encoding="utf-8")))
    missing = {}
    for p in sources():
        if p.name == "test_references.py":
            continue
        for n in re.findall(r"RFC ?(\d{3,5})", p.read_text(encoding="utf-8", errors="replace")):
            if n not in refs:
                missing.setdefault(n, p.relative_to(ROOT).as_posix())
    assert not missing, "cited without a docs/references.md entry: " + ", ".join(
        f"RFC {n} ({f})" for n, f in sorted(missing.items(), key=lambda x: int(x[0])))
