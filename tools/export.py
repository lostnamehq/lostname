"""Export the public part of this repository into a separate directory, for the public GitHub repository.

Only tracked files classified public, verbatim or generated in publication.txt are copied; internal files never
leave. The target is a plain directory (normally a clone of the public repository): this script never commits or
pushes. The public repository has its own history and never receives this repository's history, which contains
private files.

After copying, the denylist gate runs over the target as a whole, so a public file can never carry a private term
even if it was classified wrongly.

Usage: python tools/export.py TARGET_DIR [--dry-run]
"""
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import public_check  # noqa: E402

EXPORTED = {"public", "verbatim", "generated"}


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    dry = "--dry-run" in sys.argv
    if len(args) != 1:
        print(__doc__)
        return 3
    target = Path(args[0]).resolve()
    if target == ROOT or ROOT in target.parents:
        print("export: the target must be outside this repository")
        return 3
    if public_check.main() != 0:
        print("export: refused, the publication gate fails on the source")
        return 1
    rules = public_check.classes()
    files = subprocess.run(["git", "ls-files", "--cached"], cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", check=True).stdout.splitlines()
    chosen = [f for f in files if public_check.classify(f, rules) in EXPORTED]
    held = [f for f in files if public_check.classify(f, rules) not in EXPORTED]
    print(f"export: {len(chosen)} file(s) public, {len(held)} held back")
    if dry:
        for f in chosen:
            print("  +", f)
        return 0
    target.mkdir(parents=True, exist_ok=True)
    # Remove previously exported files that are no longer public; never touch the target's .git.
    for p in sorted(target.rglob("*"), reverse=True):
        rel = p.relative_to(target).as_posix()
        if rel == ".git" or rel.startswith(".git/"):
            continue
        if p.is_file() and rel not in chosen:
            p.unlink()
        elif p.is_dir() and not any(p.iterdir()):
            p.rmdir()
    for f in chosen:
        dst = target / f
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / f, dst)
    problems = public_check.scan_tree(target, rules)
    for p in problems:
        print(p)
    print(f"export: target scan {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
