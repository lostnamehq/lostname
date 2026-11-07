#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Release notes for a tag: the version's section of CHANGELOG.md, then how to verify what was published.

Usage: python tools/release_notes.py vX.Y.Z[-rc.N] IMAGE_DIGEST > notes.md

The release workflow runs it after the image is pushed, so the notes name the image by digest, the digest the CI
templates (deploy/ci) pin. It fails when CHANGELOG.md has no section for the version: run
`python tools/changelog.py release X.Y.Z` in the release pull request first. A release candidate (vX.Y.Z-rc.N) takes
the coming release's notes: the [Unreleased] section with the changelog fragments folded in.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "ghcr.io/lostnamehq/lostname"


def section(changelog: str, version: str) -> str:
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", changelog, re.M | re.S)
    if not m or not m.group(1).strip():
        raise SystemExit(f"release_notes: CHANGELOG.md has no section for {version}")
    return m.group(1).strip()


def notes(tag: str, digest: str, changelog: str) -> str:
    m = re.fullmatch(r"v(\d+\.\d+\.\d+)(-rc\.\d+)?", tag)
    if not m or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise SystemExit("release_notes: want vX.Y.Z[-rc.N] and sha256:<64 hex>")
    if m.group(2):
        body = (f"Release candidate for v{m.group(1)}: please try it and report problems before the release.\n\n"
                + unreleased())
    else:
        body = section(changelog, m.group(1))
    # the exact workflow and tag that signed: a pattern for the repository would accept any of its workflows
    signer = f"https://github.com/lostnamehq/lostname/.github/workflows/release.yml@refs/tags/{tag}"
    return f"""{body}

## Verify what you install

- Binaries: `sha256sum -c SHA256SUMS --ignore-missing`, then the checksums file's signature (Sigstore, keyless, made
  by this repository's release workflow for this tag):
  `cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity {signer} --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS`
- Build provenance (SLSA): `gh attestation verify <file> --repo lostnamehq/lostname`
- The tag: `git -c gpg.ssh.allowedSignersFile=lostname.allowed_signers tag -v {tag}`
- Container image: `{IMAGE}@{digest}`; verify it with
  `cosign verify {IMAGE}@{digest} --certificate-identity {signer} --certificate-oidc-issuer https://token.actions.githubusercontent.com`
- Each binary has a CycloneDX SBOM (`*.cdx.json`); `lostname.openvex.json` is govulncheck's statement on known
  vulnerabilities at release time.
"""


def unreleased() -> str:
    """The coming release's notes, as tools/changelog.py show renders them."""
    import subprocess
    return subprocess.run([sys.executable, str(ROOT / "tools" / "changelog.py"), "show"], check=True,
                          capture_output=True, text=True).stdout.strip()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 3
    sys.stdout.write(notes(argv[0], argv[1], (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
