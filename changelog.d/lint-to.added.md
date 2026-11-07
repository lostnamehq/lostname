- `lint --to PROVIDER` says what will not survive a move to that provider: record types it does not serve (L-02),
  ALIAS records (L-03), and a missing SOA where the target needs one (L-01). The capabilities are DNSControl's provider
  matrix, pinned at v5.7.0. `lint --dnscontrol-ir FILE` reads the output of `dnscontrol print-ir` instead of a zone
  file; Lostname never runs DNSControl itself, because print-ir reads the credentials file.
