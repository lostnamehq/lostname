- `parity` checks the no-DS proof in referrals to insecure delegations of a signed zone (RFC 4035 3.1.4.1,
  RFC 5155 7.2.7): an NSEC at the cut with NS and without DS and SOA, a matching NSEC3, or under NSEC3 opt-out the
  closest provable encloser and an opt-out NSEC3 covering the next closer name. A referral without it fails
  (`referral-denial-missing`); one whose records prove nothing fails as `denial-invalid`.
