# Fuzzing

Lostname uses Go's native fuzzing, not ClusterFuzzLite. Every input that comes from outside is a fuzz target:

| Target | Package | What it reads |
|---|---|---|
| `FuzzRead` | `internal/zone` | zone files, including the round trip back to zone-file form |
| `FuzzReadTSIGFile` | `internal/fetch` | TSIG key files |

`python tools/check.py` runs each target for a short time on every check, locally before a push and in CI. A crash
becomes a regression case under `testdata/fuzz/`, which then runs with every `go test`. The first run found a real
bug (a record without data that could be read but not written back), now covered by `testdata/fuzz/FuzzRead/`.

Why not ClusterFuzzLite yet: the parsers are small, and native fuzzing in the existing gate covers them without
another service. Continuous fuzzing comes with the first release, if the inputs grow (AXFR streams, provider exports).
