- Text output can no longer carry terminal control characters from zone data or server answers.
- `fetch` refuses a transfer that runs past `fetch.deadline_seconds` or grows past `fetch.max_records` (no verdict),
  one framed by another zone's SOA, or one with an SOA inside it.
- A zone file with `$GENERATE` is refused with the line number; expand it first.
- `parity` reports a provider's servers that serve the same data with different TTLs as `inconsistent-servers`.
