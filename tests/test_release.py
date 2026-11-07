"""The release path (docs/publishing.md): the workflow verifies the tag before anything else, builds twice and
compares, signs and attests, and keeps least privilege and pinned actions; the image is built from the reproducible
binaries; the notes come from CHANGELOG.md and name the image by digest."""
import importlib.util
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def workflow():
    return yaml.safe_load((ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8"))


def test_release_workflow_shape():
    doc = workflow()
    on = doc.get("on", doc.get(True))
    assert sorted(on) == ["push", "workflow_dispatch"] and list(on["push"]) == ["tags"], on
    assert doc["permissions"] == {"contents": "read"}
    job = doc["jobs"]["release"]
    assert job["permissions"] == {"contents": "write", "id-token": "write", "attestations": "write", "packages": "write"}
    steps = job["steps"]
    names = [s.get("name", s.get("uses", "")) for s in steps]
    runs = [s.get("run", "") for s in steps]
    verify = next(i for i, r in enumerate(runs) if "tag -v" in r)
    build = next(i for i, r in enumerate(runs) if "tools/build.py" in r)
    assert verify < build, "the tag signature must be checked before anything is built"
    assert "allowedSignersFile=lostname.allowed_signers" in runs[verify] and "Good \"git\" signature" in runs[verify]
    assert "dist-again" in runs[build] and "diff dist/SHA256SUMS dist-again/SHA256SUMS" in runs[build]
    # a binary stamped vcs.modified=true is refused; the build directories are ignored so they cannot cause it
    assert "vcs.modified=false" in runs[build]
    # on a tag push, the binary's own `version` must name that tag
    assert "version --json" in runs[build] and '"$got" = "$TAG"' in runs[build]
    ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/dist/" in ignored and "/dist-again/" in ignored
    # the build refuses a dirty checkout; the tag check writes outside it (v0.1.0-rc.1 stopped on this)
    assert "git status --porcelain" in runs[build]
    assert "$RUNNER_TEMP/tag-verify.txt" in runs[verify] and "tee tag-verify" not in runs[verify]
    joined = "\n".join(runs)
    assert "cosign sign-blob" in joined and "cosign sign --yes" in joined and "-format openvex" in joined
    assert sum("attest-build-provenance" in s.get("uses", "") for s in steps) == 2
    assert "SHA256SUMS.sigstore.json" in runs[-1] and "--verify-tag" in runs[-1], names
    # A manual run is a dry run: everything that verifies a tag, signs, pushes or publishes is for a tag push only.
    for s in steps:
        r = s.get("run", "") + s.get("uses", "")
        if any(x in r for x in ("tag -v", "cosign", "attest-build-provenance", "--push", "gh release")):
            assert s.get("if") == "github.event_name == 'push'", s.get("name", s.get("uses"))
    for s in steps:
        if "uses" in s:
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", s["uses"]), s["uses"]
        assert "${{" not in s.get("run", ""), "event data reaches run blocks through env only: " + s.get("name", "")


def test_dockerfile():
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    lines = [l for l in text.splitlines() if l and not l.startswith("#")]
    assert re.fullmatch(r"FROM [a-z0-9./:-]+@sha256:[0-9a-f]{64}", lines[0]), lines[0]
    assert not any(l.startswith("RUN") for l in lines), "no RUN: a multi-arch build needs no emulation"
    user = next(l for l in lines if l.startswith("USER "))
    assert re.fullmatch(r"USER [1-9][0-9]*:[1-9][0-9]*", user), "a numeric non-root user"
    copy = next(l for l in lines if l.startswith("COPY "))
    build = (ROOT / "tools" / "build.py").read_text(encoding="utf-8")
    assert "dist/lostname_linux_${TARGETARCH}" in copy and 'f"lostname_{goos}_{goarch}"' in build
    assert 'ENTRYPOINT ["/usr/local/bin/lostname"]' in lines


def notes_module():
    spec = importlib.util.spec_from_file_location("release_notes", ROOT / "tools" / "release_notes.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_release_notes():
    m = notes_module()
    log = "# Changelog\n\n## [Unreleased]\n\n## [0.1.0] - 2026-12-20\n### Added\n- lint, parity\n\n## [0.0.1] - x\n- old\n"
    digest = "sha256:" + "a" * 64
    out = m.notes("v0.1.0", digest, log)
    assert "- lint, parity" in out and "old" not in out and f"ghcr.io/lostnamehq/lostname@{digest}" in out
    # both cosign commands name the exact signer: the release workflow at this tag, not any workflow of the repository
    signer = "https://github.com/lostnamehq/lostname/.github/workflows/release.yml@refs/tags/v0.1.0"
    assert out.count(f"--certificate-identity {signer} ") == 2 and "identity-regexp" not in out
    # a candidate takes the coming release's notes; the test supplies them, the live changelog may have none
    m.unreleased = lambda: "### Upgrading\n- coming"
    rc = m.notes("v0.1.0-rc.1", digest, log)
    assert rc.startswith("Release candidate for v0.1.0") and "### Upgrading" in rc, rc[:200]
    for bad in [("v0.2.0", digest), ("0.1.0", digest), ("v0.1.0", "sha256:short"), ("v0.1.0-beta", digest)]:
        with pytest.raises(SystemExit):
            m.notes(bad[0], bad[1], log)
