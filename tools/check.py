"""The one check that people and CI both run. It stops at the first failing step and says which one.

Steps:
- gofmt;
- go vet for every release target;
- staticcheck;
- go test (with -race on Linux, where cgo is available);
- a short fuzz pass on each fuzz target;
- govulncheck;
- the publication gate;
- the Python tests.

Tool versions are pinned here, and the Go toolchain is pinned in go.mod (GOTOOLCHAIN=local refuses any other).

Usage: python tools/check.py [--fast]   (--fast skips fuzzing and govulncheck, which need time or the network)
"""
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATICCHECK = "honnef.co/go/tools/cmd/staticcheck@v0.8.2"
GOVULNCHECK = "golang.org/x/vuln/cmd/govulncheck@v1.9.0"
TARGETS = [("linux", "amd64"), ("linux", "arm64"), ("windows", "amd64"), ("darwin", "arm64")]
FUZZ = [("./internal/zone", "FuzzRead"), ("./internal/fetch", "FuzzReadTSIGFile")]


def go() -> str:
    exe = shutil.which("go")
    if not exe:
        raise SystemExit("check: go not found on PATH; install the version in go.mod (golang.org/dl)")
    return exe


def run(name: str, cmd: list[str], env: dict | None = None) -> None:
    print(f"== {name}", flush=True)
    e = dict(os.environ, GOTOOLCHAIN="local", GOFLAGS="-mod=readonly", **(env or {}))
    r = subprocess.run(cmd, cwd=ROOT, env=e)
    if r.returncode:
        raise SystemExit(f"check: FAILED at '{name}' (exit {r.returncode})")


def main() -> int:
    fast = "--fast" in sys.argv
    g = go()
    out = subprocess.run([g, "env", "GOVERSION"], capture_output=True, text=True, cwd=ROOT,
                         env=dict(os.environ, GOTOOLCHAIN="local")).stdout.strip()
    mod = (ROOT / "go.mod").read_text().splitlines()
    # go.mod pins the toolchain: an explicit toolchain line, or else the go line at its full patch version.
    want = next((l.split()[1] for l in mod if l.startswith("toolchain ")),
                next("go" + l.split()[1] for l in mod if l.startswith("go ")))
    if out != want:
        raise SystemExit(f"check: Go is {out}, go.mod pins {want}; install {want} and put it first on PATH")
    fmt = subprocess.run([g, "fmt", "-n", "./..."], capture_output=True, text=True, cwd=ROOT)
    unformatted = subprocess.run(["gofmt", "-l", "cmd", "internal"], capture_output=True, text=True, cwd=ROOT).stdout
    if fmt.returncode or unformatted.strip():
        raise SystemExit("check: FAILED at 'gofmt': run gofmt -w on:\n" + unformatted)
    print("== gofmt: ok")
    for goos, goarch in TARGETS:
        run(f"vet {goos}/{goarch}", [g, "vet", "./..."], {"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"})
    run("staticcheck", [g, "run", STATICCHECK, "./..."])
    race = ["-race"] if platform.system() == "Linux" else []
    run("test", [g, "test", "-count=1", *race, "./..."])
    if not fast:
        for pkg, target in FUZZ:
            run(f"fuzz {target}", [g, "test", "-run=^$", f"-fuzz=^{target}$", "-fuzztime=20s", pkg])
        run("govulncheck", [g, "run", GOVULNCHECK, "./..."])
    run("publication gate", [sys.executable, "tools/public_check.py"])
    run("python tests", [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"])
    print("check: all steps passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
