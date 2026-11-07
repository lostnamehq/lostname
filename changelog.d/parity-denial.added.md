- `parity` checks authenticated denial: NSEC and NSEC3 records in a negative answer must be signed by the server's
  keys and prove the NODATA or NXDOMAIN answer, wildcard included. A signed zone answering without them fails. A
  provider denying with NSEC next to one with NSEC3 is a risk.
