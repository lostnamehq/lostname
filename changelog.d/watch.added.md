- `lostname watch` runs `lint` and `parity` on the zones in the config's `watch` section every
  `watch.interval_seconds` and serves the results on `/metrics` (OpenMetrics, `watch.listen`, loopback by default).
  A check that ends without a verdict leaves its result series out: absent, never zero. `--once` runs one round,
  prints the metrics and exits with the worst verdict's code.
