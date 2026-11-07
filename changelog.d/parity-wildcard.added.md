- `parity` checks answers expanded from a wildcard: they must carry a signed NSEC or NSEC3 proof that the queried name
  itself does not exist (`wildcard-proof-missing` otherwise). The test server now synthesises wildcard answers.
