- `lostname version` (also `--version`) prints the release and commit the binary was built from, read from Go's
  build information; `--json` follows `docs/schemas/version.schema.json`. `lostname help` (also `-h`, `--help`)
  prints the usage text and exits 0.
- The release workflow refuses a binary whose `version` does not name the tag being released.
