- `parity` checks L-19 at the providers: different CDS or CDNSKEY sets between two providers, or between one
  provider's servers, fail (`cds-differs`): a parent that scans CDS installs one of them, and the zone is bogus at
  the other. A set at one provider only is a risk (`cds-one-sided`). Whether the parent scans is not known, so the
  check judges as if it does.
