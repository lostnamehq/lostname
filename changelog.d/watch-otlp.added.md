- `watch` pushes the same metrics over OTLP/HTTP (JSON) when `watch.otlp_endpoint` is set, with the optional
  correlation attributes from `watch.resource`; a blind run sends no result data points.
- `watch` adds `lostname_dnssec_status` (secure, insecure, bogus, indeterminate, per provider) and
  `lostname_dnssec_signature_expiry_seconds`; `parity --json` reports each provider's earliest signature expiry.
- The alert rules ship as code in `deploy/alerts/lostname.rules.yaml`, each with severity, suggested autonomy, owner
  role and action.
