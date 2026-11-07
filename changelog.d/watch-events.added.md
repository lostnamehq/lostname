- `lostname watch` sends events (CloudEvents 1.0, JSON) when `watch.events` names a transport: `http` posts each
  event in structured mode to `watch.events_endpoint`, `otlp` sends them as OTLP logs. Events say when a verdict
  changes, when a finding opens or closes and when the network path is intercepted; they carry no record data, and
  a check without a verdict closes no finding. The source is `lostname/<watch.instance>`.
- The parity report names the probe address that answered and the protocols it answered over (`interception`).
