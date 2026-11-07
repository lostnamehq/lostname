- First release. From v0.1.0 the command-line flags, exit codes, JSON report schemas (`lostname.*/v0`), configuration
  keys, metric names and labels, event types and trace attributes follow semantic versioning: a rename or removal
  is a breaking change and waits for a new major version (or, before 1.0, a new minor version with an entry here).
- The evidence behind this release is the test suite, a lab conformance run (OpenTelemetry Collector with Prometheus
  and with VictoriaMetrics) and in-process test servers. A parity run against real providers comes in v0.1.1. The
  exit-readiness SLO is modelled (`basis="modelled"`), not measured.
