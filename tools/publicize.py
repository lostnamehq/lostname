"""Generate the public version of a mixed document.

Sources live in private/src/ and are written once. Private passages sit between `<!-- private -->` and
`<!-- /private -->` (on their own lines). Single-letter review labels from the design process are dropped and
`[U]` becomes "(unverified)". The output carries a header that says it is generated.

Usage: python tools/publicize.py            (regenerate every pair in PAIRS)
       python tools/publicize.py --check    (exit 1 if any generated file is out of date)
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAIRS = {
    "private/src/model.md": "docs/model.md",
    "private/src/prior-art.md": "docs/prior-art.md",
}
PRIVATE = re.compile(r"^[ \t]*<!-- private -->[ \t]*\n.*?^[ \t]*<!-- /private -->[ \t]*\n", re.S | re.M)
LABELS = [
    (re.compile(r" ?\((?:I|C|T|C, T|T, C)\)"), ""),
    (re.compile(r"\[U\]"), "(unverified)"),
]


def render(src: str, rel: str) -> str:
    if src.count("<!-- private -->") != src.count("<!-- /private -->"):
        raise SystemExit(f"{rel}: unbalanced private markers")
    out = PRIVATE.sub("", src)
    for pat, rep in LABELS:
        out = pat.sub(rep, out)
    out = re.sub(r"\n{3,}", "\n\n", out)
    return f"<!-- Generated from {rel} by tools/publicize.py. Edit the source, not this file. -->\n" + out


def main() -> int:
    check = "--check" in sys.argv
    stale = []
    for src_rel, dst_rel in PAIRS.items():
        if not (ROOT / src_rel).is_file():  # public clones carry only the generated file
            continue
        want = render((ROOT / src_rel).read_text(encoding="utf-8"), src_rel)
        dst = ROOT / dst_rel
        if check:
            if not dst.is_file() or dst.read_text(encoding="utf-8") != want:
                stale.append(dst_rel)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(want, encoding="utf-8", newline="\n")
            print(f"wrote {dst_rel}")
    if stale:
        print("out of date (run python tools/publicize.py): " + ", ".join(stale))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
