"""The one check that people and CI both run. It stops at the first failing step and says which one.

Steps:
- gofmt;
- go vet for every release target;
- staticcheck;
- go test (with -race on Linux, where cgo is available);
- a short fuzz pass on each fuzz target;
- govulncheck;
- a reproducible build (linux/amd64 built twice, compared);
- the publication gate;
- the Python tests.

Tool versions are pinned here, and the Go toolchain is pinned in go.mod (GOTOOLCHAIN=local refuses any other).

Usage: python tools/check.py [--fast]   (--fast skips fuzzing and govulncheck, which need time or the network)
"""
import os
import platform
import shutil
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATICCHECK = "honnef.co/go/tools/cmd/staticcheck@v0.8.2"
GOVULNCHECK = "golang.org/x/vuln/cmd/govulncheck@v1.9.0"
# DNSControl (decision of 2026-11-06: the official release, pinned): the capability data (internal/target) and the
# print-ir fixture (internal/zone/testdata) come from this release. The release publishes checksums but no build
# attestation; the zip's SHA-256 was checked against its checksums.txt.
DNSCONTROL = {"tag": "v5.7.0", "commit": "f47338b466ef4465f01e7695bb3173063ac5d1f1", "released": "2026-10-21",
              "windows_amd64_zip_sha256": "328a4e9390921ac4177509b70d5c11b118c3147ebc2b137020d37c5a9f0d8680"}
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


def pinned_dnscontrol() -> None:
    """The DNSControl data in the tree must come from the pinned release."""
    src = json.loads((ROOT / "internal" / "target" / "dnscontrol.json").read_text(encoding="utf-8"))["source"]
    readme = (ROOT / "internal" / "zone" / "testdata" / "README.md").read_text(encoding="utf-8")
    if src["tag"] != DNSCONTROL["tag"] or src["commit"] != DNSCONTROL["commit"] or src.get("released") != DNSCONTROL["released"]:
        raise SystemExit(f"check: FAILED at 'dnscontrol pin': capability data from {src['tag']} {src['commit']}, "
                         f"pinned {DNSCONTROL['tag']} {DNSCONTROL['commit']}: regenerate with tools/capabilities.py")
    if DNSCONTROL["tag"] not in readme or DNSCONTROL["windows_amd64_zip_sha256"] not in readme:
        raise SystemExit("check: FAILED at 'dnscontrol pin': the print-ir fixture's README does not name the pinned "
                         "release and checksum: regenerate the fixture with that release")
    print(f"== dnscontrol pin: ok ({DNSCONTROL['tag']})")


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
        run("reproducible build", [sys.executable, "tools/build.py", "--check-repro"])  # docs/publishing.md
    pinned_dnscontrol()
    run("publication gate", [sys.executable, "tools/public_check.py"])
    run("python tests", [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"])
    print("check: all steps passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
