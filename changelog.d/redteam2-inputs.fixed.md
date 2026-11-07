- Inputs fail closed on holes the second red team found: `$GENERATE` hidden behind a carriage return or parentheses
  is refused; records outside class IN are refused; crafted `print-ir` input (a type number that disagrees with the
  type, a domain listed twice, trailing data, a line break in data, a record spliced into a name) is refused; the
  transfer's closing SOA must equal the opening one in full.
- The config refuses disabling or downgrading L-00, unknown rule ids, probe ports that are not 1-65535, and keys
  that match only when case is ignored. A baseline never hides an L-00 finding.
- Evidence bundles store inputs by role (`inputs/zone-...`, `inputs/baseline-...`), refuse two files for one path,
  include the origin in their name and take a numeric suffix rather than fail when a bundle of the same second
  exists; `Verify` refuses paths outside the bundle and needs `versions.json`. SARIF points at the input as a path
  relative to the working directory.
