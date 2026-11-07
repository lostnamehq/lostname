# Publishing a release

0. **Before the release:** `python tools/mutate.py` (every mutation of a rule must be caught by the tests; the
   release workflow runs it too) and `python tools/check.py` green.
1. **Release pull request.** On a branch, run `python tools/changelog.py release X.Y.Z`: it writes `## [X.Y.Z] -
   <date>` into `CHANGELOG.md` from the fragments in `changelog.d/` and removes them. Merge the pull request when CI
   is green.
2. **Signed tag.** A maintainer signs `vX.Y.Z` on the merge commit with the release key, whose public half is
   `lostname.allowed_signers`, and pushes the tag. Check it first:
   `git -c gpg.ssh.allowedSignersFile=lostname.allowed_signers tag -v vX.Y.Z`.
3. **Release workflow** (`.github/workflows/release.yml`) runs on the tag:
   - refuses a tag whose signature does not verify against `lostname.allowed_signers`;
   - runs the tests;
   - builds every binary twice with `tools/build.py` and refuses the release when the two `SHA256SUMS` differ: the
     build is reproducible (static, trimmed paths, no build id, the version Go stamps from the tag);
   - writes a CycloneDX SBOM per binary and an OpenVEX statement from govulncheck;
   - signs `SHA256SUMS` with Sigstore (keyless, the workflow's identity) and attests SLSA build provenance for the
     binaries;
   - builds the image for linux/amd64 and linux/arm64 from the same binaries (`Dockerfile`: Alpine for the shell
     CI jobs need, a numeric non-root user, nothing written inside), pushes it to `ghcr.io/lostnamehq/lostname`,
     signs it and attests its provenance;
   - creates the GitHub release with the binaries, `SHA256SUMS`, its signature bundle and the OpenVEX statement; the
     notes (`tools/release_notes.py`) name the image by digest and say how to verify each part.
4. **After the release:** `go install lostname.be/lostname/cmd/lostname@vX.Y.Z` from a clean machine, and the CI
   templates in `deploy/ci/` updated to the new image digest.

Check a build is reproducible on your own machine: `python tools/build.py --check-repro`. Try the whole workflow without
publishing: Actions > Release > Run workflow (a dry run: no tag check, signing, push or release).

## Release candidates
A tag `vX.Y.Z-rc.N` runs the same workflow and publishes a **prerelease**: same build, signatures, provenance and
image (tagged `vX.Y.Z-rc.N`), with the coming release's notes (the [Unreleased] section and the fragments). There is
no release pull request: the fragments stay until the release itself. Sign the rc tag on a merged commit of `main`
whose `ci` run passed, push it, then try the prerelease: `go install lostname.be/lostname/cmd/lostname@vX.Y.Z-rc.N`
on a clean machine, and every verification line in its notes.

