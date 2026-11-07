# Test data

- `print-ir-v5.7.0.json`: the output of `dnscontrol print-ir --pretty` for `dnsconfig.js`, made with DNSControl
  v5.7.0 (`dnscontrol_5.7.0_windows_amd64.zip`, SHA-256 `328a4e9390921ac4177509b70d5c11b118c3147ebc2b137020d37c5a9f0d8680`,
  checked against the release's `checksums.txt`; the release has no build attestation). The credentials file for that
  run named only the `NONE` and `BIND` provider types, with no secrets.
- `print-ir-v5.7.0-autodnssec.json`: the same for `dnsconfig-autodnssec.js` (with `AUTODNSSEC_ON`), same release.
- `print-ir-v5.7.0-meta.json`: the same for `dnsconfig-meta.js` (records with provider metadata: `CF_PROXY_ON` and a
  `geo_region` key), same release, made with `dnscontrol print-ir --config dnsconfig-meta.js --pretty`.
