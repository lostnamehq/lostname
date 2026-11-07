- `parity` runs within limits for real providers: `parity.deadline_seconds` (900) for the whole run,
  `parity.max_queries_per_server` (5000) and `parity.pace_milliseconds` (0). A question a limit stops is a gap, so the
  run ends without a verdict, never with a partial pass. A server that answered and then stops answering or refuses is
  labelled "possibly rate limited". The report counts the queries per server (`queries`).
