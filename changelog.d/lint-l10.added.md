- `lint` rule L-10: provider metadata on a record (DNSControl's `meta`, such as `CF_PROXY_ON` or a geo key) is a risk:
  a zone transfer or another provider does not carry it. The DNSControl reader keeps the metadata key names
  (`meta` in the zone) and refuses a key that is not a plain name.
