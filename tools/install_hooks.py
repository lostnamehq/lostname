"""Point git at the versioned hooks in tools/hooks (run once per clone)."""
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
subprocess.run(["git", "config", "core.hooksPath", "tools/hooks"], cwd=root, check=True)
print("core.hooksPath = tools/hooks")
