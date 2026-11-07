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
OPEN = re.compile(r"^[ \t]*<!-- private -->[ \t]*$")
CLOSE = re.compile(r"^[ \t]*<!-- /private -->[ \t]*$")
LABELS = [
    (re.compile(r" ?\((?:I|C|T|C, T|T, C)\)"), ""),
    (re.compile(r"\[U\]"), "(unverified)"),
]


def strip_private(src: str, rel: str) -> str:
    """Drop every private passage, line by line. A marker that is not alone on its line, a nested, reversed or
    unclosed marker, and any marker text left in the result all refuse the build (red team 2, C2): a passage is
    either removed whole or the build stops."""
    out, inside = [], 0
    for n, line in enumerate(src.splitlines(keepends=True), 1):
        bare = line.rstrip("\r\n")
        if OPEN.match(bare):
            if inside:
                raise SystemExit(f"{rel}:{n}: a private marker opens inside another (opened at line {inside})")
            inside = n
            continue
        if CLOSE.match(bare):
            if not inside:
                raise SystemExit(f"{rel}:{n}: a private marker closes with none open")
            inside = 0
            continue
        if "<!-- private" in line or "<!-- /private" in line:
            raise SystemExit(f"{rel}:{n}: a private marker must stand alone on its line")
        if not inside:
            out.append(line)
    if inside:
        raise SystemExit(f"{rel}:{inside}: a private marker is never closed")
    result = "".join(out)
    if "<!-- private" in result or "<!-- /private" in result:
        raise SystemExit(f"{rel}: private marker text survived the build")
    return result


def render(src: str, rel: str) -> str:
    out = strip_private(src, rel)
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
