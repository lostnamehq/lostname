- `parity` fails closed on eleven cases the second red team found: the DS at a delegation and its glue are compared;
  a provider serving its own copy of a delegated child fails; TXT text keeps its spaces when compared; data at an
  empty non-terminal fails; a class other than IN never compares equal; a parent DS over a provider without keys
  fails (a stale DS, or an unsigned provider of several); the DNSKEY RRset must be the same over UDP and TCP;
  colliding key tags are all tried; a revoked key may only sign the DNSKEY RRset.
