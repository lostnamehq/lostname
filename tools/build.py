#!/usr/bin/env python3
"""Build the release binaries reproducibly, with an SBOM per binary and SHA256SUMS.

Usage:
  python tools/build.py DIST_DIR            build every target into DIST_DIR
  python tools/build.py --check-repro       build linux/amd64 twice in two directories and compare (the gate runs this)

A build is reproducible when the same commit gives the same bytes on any machine: static (CGO_ENABLED=0), paths
trimmed (-trimpath), no build id (-buildid=), and the version and commit that Go stamps from git (debug.ReadBuildInfo),
which are the same for the same clean commit. Each binary gets a CycloneDX 1.6 SBOM read from its own build
information (`go version -m`), so it lists exactly the modules linked in. SHA256SUMS covers binaries and SBOMs.
Files are written atomically.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [("linux", "amd64"), ("linux", "arm64"), ("windows", "amd64"), ("darwin", "arm64")]
FLAGS = ["-trimpath", "-ldflags=-s -w -buildid="]


def atomic_write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def build(goos: str, goarch: str, out: Path) -> Path:
    name = f"lostname_{goos}_{goarch}" + (".exe" if goos == "windows" else "")
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": goos, "GOARCH": goarch, "GOFLAGS": "-mod=readonly"}
    tmp = out / (name + ".tmp")
    subprocess.run(["go", "build", *FLAGS, "-o", str(tmp), "./cmd/lostname"], cwd=ROOT, env=env, check=True)
    final = out / name
    os.replace(tmp, final)
    return final


def sbom(binary: Path) -> dict:
    """A CycloneDX 1.6 SBOM from the binary's own build information."""
    info = subprocess.run(["go", "version", "-m", str(binary)], capture_output=True, text=True, check=True).stdout
    main, deps, settings = None, [], {}
    for line in info.splitlines():
        f = line.split("\t")
        f = [x for x in f if x != ""]
        if not f:
            continue
        if f[0] == "mod":
            main = {"name": f[1], "version": f[2] if len(f) > 2 else "(devel)"}
        elif f[0] == "dep":
            d = {"name": f[1], "version": f[2], "hash": f[3] if len(f) > 3 else ""}
            deps.append(d)
        elif f[0] == "build" and "=" in f[1]:
            k, v = f[1].split("=", 1)
            settings[k] = v
    go_version = info.splitlines()[0].split(": ", 1)[1].strip()

    def component(name, version, kind="library", h=""):
        c = {"type": kind, "bom-ref": f"pkg:golang/{name}@{version}", "name": name, "version": version,
             "purl": f"pkg:golang/{name}@{version}"}
        if h.startswith("h1:"):
            c["hashes"] = [{"alg": "SHA-256", "content": h3(h)}]
        return c

    def h3(h):  # Go's h1: is base64 SHA-256 of the module's file list; CycloneDX wants hex
        import base64
        return base64.b64decode(h[3:]).hex()

    app = component(main["name"], main["version"], "application")
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, binary.name + hashlib.sha256(
            binary.read_bytes()).hexdigest())),
        "version": 1,
        "metadata": {"component": app, "properties": [
            {"name": "go:version", "value": go_version},
            *({"name": "go:build:" + k, "value": settings[k]} for k in sorted(settings))]},
        "components": [component(d["name"], d["version"], h=d["hash"]) for d in sorted(deps, key=lambda d: d["name"])],
        "dependencies": [{"ref": app["bom-ref"], "dependsOn": [f"pkg:golang/{d['name']}@{d['version']}"
                                                              for d in sorted(deps, key=lambda d: d["name"])]}],
    }
    return doc


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def release(dist: Path) -> int:
    dist.mkdir(parents=True, exist_ok=True)
    files = []
    for goos, goarch in TARGETS:
        b = build(goos, goarch, dist)
        s = dist / (b.name + ".cdx.json")
        atomic_write(s, (json.dumps(sbom(b), indent=1, sort_keys=False) + "\n").encode())
        files += [b, s]
        print(f"built {b.name} ({sha256(b)[:12]}) and its SBOM")
    sums = "".join(f"{sha256(f)}  {f.name}\n" for f in sorted(files, key=lambda f: f.name))
    atomic_write(dist / "SHA256SUMS", sums.encode())
    print(f"wrote {dist / 'SHA256SUMS'}")
    return 0


def check_repro() -> int:
    with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
        x, y = build("linux", "amd64", Path(a)), build("linux", "amd64", Path(b))
        if sha256(x) != sha256(y):
            print(f"build: NOT reproducible: {sha256(x)} vs {sha256(y)}")
            return 1
        print(f"== reproducible build: ok (linux/amd64 {sha256(x)[:12]}, built twice)")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--check-repro"]:
        return check_repro()
    if len(argv) == 1 and not argv[0].startswith("-"):
        return release(Path(argv[0]).resolve())
    print(__doc__)
    return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
