- `parity` validates DNSSEC signatures: every RRSIG a server returns must be inside its validity window, made by a key
  in that server's own DNSKEY RRset, and cryptographically valid. Where the zone file is signed, every answer must
  carry one. A valid signature that expires sooner than `parity.min_signature_life_seconds` (default 6 hours) is a
  risk. Not yet: the chain to the parent's DS and authenticated denial.
