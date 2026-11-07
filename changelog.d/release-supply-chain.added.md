- Release supply chain: `tools/build.py` builds every binary reproducibly (checked in CI and in the push gate), with
  a CycloneDX SBOM per binary and `SHA256SUMS`; the release workflow verifies the signed tag, builds twice and
  compares, adds an OpenVEX statement, signs the checksums with Sigstore (keyless), attests SLSA provenance, and
  publishes a multi-arch image (`ghcr.io/lostnamehq/lostname`, non-root, nothing written inside) signed and attested
  the same way. `docs/publishing.md` describes the release process.
