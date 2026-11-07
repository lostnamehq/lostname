- `lostname mail` reads the zone's mail records offline: SPF, DMARC, DKIM (only the selectors the zone publishes),
  MTA-STS, TLS-RPT, BIMI and DANE TLSA. It prints the posture and findings M-01 to M-11 (multiple or unparsable SPF
  and DMARC records, `+all`, `ptr`, `p=none`, broken DKIM keys, malformed MTA-STS and TLS-RPT records, TLSA usages not
  meant for SMTP), as JSON with a schema. Findings never quote record data.
- `lint` rule L-22: DANE TLSA on a mail host ties mail delivery to the DNSSEC handover (a note in a signed zone; a
  risk in an unsigned one, where the records do nothing).
