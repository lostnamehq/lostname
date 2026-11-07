"""Publication gate: what may go public is decided per file, from the start.

1. Every tracked file is classified in `publication.txt` (public, verbatim, internal or generated). An unclassified file fails.
2. Public and generated files are scanned for denylist patterns (`private/deny_patterns.txt`, private) and, if the environment
   variable LOSTNAME_NAMES_FILE points to one, for every name in a names list kept outside git (client and other
   private domains, people).
3. Generated files must match their source (`tools/publicize.py --check`).

Reads only tracked files plus staged ones, so run it after `git add` (the pre-commit hook does).
Usage: python tools/public_check.py
"""
import fnmatch
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = (".png", ".ico", ".ttf", ".otf", ".woff", ".woff2", ".pdf")


def tracked() -> list[str]:
    out = subprocess.run(["git", "ls-files", "--cached"], cwd=ROOT, capture_output=True, text=True, check=True)
    return [p for p in out.stdout.splitlines() if p]


def classes() -> list[tuple[str, str]]:
    rules = []
    for line in (ROOT / "publication.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            cls, glob = line.split(None, 1)
            if cls not in ("public", "internal", "generated", "verbatim"):
                raise SystemExit(f"publication.txt: unknown class {cls!r}")
            rules.append((cls, glob))
    return rules


def classify(path: str, rules) -> str | None:
    for cls, glob in rules:  # first match wins
        if fnmatch.fnmatch(path, glob):
            return cls
    return None


def patterns() -> list[re.Pattern]:
    pats = []
    deny = ROOT / "private" / "deny_patterns.txt"
    if not deny.is_file():  # public clones have no denylist; classification and generation are still checked
        return pats
    for line in deny.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#"):
            pats.append(re.compile(line.strip(), re.I))
    names = names_file()
    if names and names.is_file():
        for n in names.read_text(encoding="utf-8").splitlines():
            if n.strip():
                # Whole words only: a company name must not block ordinary words that contain it.
                pats.append(re.compile(r"(?<![\w.-])" + re.escape(n.strip()) + r"(?![\w-])", re.I))
    return pats


def names_file() -> Path | None:
    """The client-names list: LOSTNAME_NAMES_FILE, else ~/.config/lostname/names.txt, one name per line, kept
    outside every repository."""
    env = os.environ.get("LOSTNAME_NAMES_FILE")
    if env:
        return Path(env)
    default = Path.home() / ".config" / "lostname" / "names.txt"
    return default if default.is_file() else None


def names_problem() -> str | None:
    """Red team 2, C4: a names file that is set but missing is an error, never a silently skipped check."""
    names = os.environ.get("LOSTNAME_NAMES_FILE")
    if names and not Path(names).is_file():
        return f"NAMES LOSTNAME_NAMES_FILE={names} does not exist: the client-names check cannot run"
    return None


def scan_text(rel: str, text: str, pats) -> list[str]:
    """Denylist hits per line, plus hits that only appear once line breaks are joined (red team 2, C5: Markdown
    renders a wrapped line as one, so a term split across two lines is still published)."""
    problems, per_line = [], {}
    for n, line in enumerate(text.splitlines(), 1):
        for pat in pats:
            if pat.search(line):
                per_line[pat.pattern] = per_line.get(pat.pattern, 0) + 1
                problems.append(f"DENY {rel}:{n}: /{pat.pattern}/ in: {line.strip()[:100]}")
    flat = re.sub(r"\s+", " ", text)
    for pat in pats:
        if len(pat.findall(flat)) > per_line.get(pat.pattern, 0):
            problems.append(f"DENY {rel}: /{pat.pattern}/ across a line break")
    return problems


def scan_tree(base: Path, rules) -> list[str]:
    """Scan every text file under base (an export target) for denylist patterns; verbatim files are skipped."""
    pats, problems = patterns(), []
    for p in sorted(base.rglob("*")):
        rel = p.relative_to(base).as_posix()
        if not p.is_file() or rel.startswith(".git/") or rel.lower().endswith(BINARY):
            continue
        if classify(rel, rules) == "verbatim":
            continue
        problems += scan_text(rel, p.read_text(encoding="utf-8", errors="replace"), pats)
    return problems


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    rules, pats, problems = classes(), patterns(), []
    for path in tracked():
        cls = classify(path, rules)
        if cls is None:
            problems.append(f"UNCLASSIFIED {path}: add it to publication.txt as public, internal or generated")
            continue
        if cls in ("internal", "verbatim") or path.lower().endswith(BINARY):
            continue
        if (ROOT / path).is_symlink():  # red team 2, C3: the content would come from the link's target
            problems.append(f"SYMLINK {path}: a public path may not be a symbolic link")
            continue
        problems += scan_text(path, (ROOT / path).read_text(encoding="utf-8", errors="replace"), pats)
    if why := names_problem():
        problems.append(why)
    gen = subprocess.run([sys.executable, str(ROOT / "tools" / "publicize.py"), "--check"], cwd=ROOT,
                         capture_output=True, text=True)
    if gen.returncode:
        problems.append("GENERATED " + gen.stdout.strip())
    for p in problems:
        print(p)
    print(f"public_check: {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
