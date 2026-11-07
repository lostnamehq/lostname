- `lostname watch` sends each check run as an OpenTelemetry trace when `watch.traces` is on: a root span for the
  check and a span per DNS query (question, server, transport, response code; no answer data), to
  `watch.otlp_endpoint` at `/v1/traces`. Events carry the check's `traceparent`.
