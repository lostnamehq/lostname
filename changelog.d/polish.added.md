- `lostname doctor` checks that the machine, network path and configuration can give verdicts: the configuration,
  the IPv4 and IPv6 interception probes, the watched zone files and catalogs, the salt and state files.
- `watch` logs its loop with structured messages (slog, text on stderr): failed deliveries, the state file, rounds.
- Golden files pin the exact output of `config`, `lint` and `mail`; a mutation suite (`tools/mutate.py`) checks that
  the tests catch a broken rule, and runs before every release.
