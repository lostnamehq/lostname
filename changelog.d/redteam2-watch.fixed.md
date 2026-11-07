- `watch` fixes from the second red team: the interception gauge is raised when any zone's path is caught; a provider
  pair is only counted when both sides answered (a silent reference no longer reads as 0 mismatches); a zone listed
  twice is refused; a second `LostnameChecksSilent` rule covers checks without any success since `watch` started;
  label values use OpenMetrics escaping and provider names must be plain; `/metrics` answers GET and HEAD only, with
  read, write and idle timeouts; the OTLP push repeats the latest snapshot every 30 seconds so stacks with a short
  lookback keep seeing it.
