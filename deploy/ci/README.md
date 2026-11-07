# CI templates

Run `lostname parity` against a standby DNS provider on a schedule, in your own CI:

- `gitlab-ci.yml`: a GitLab CI job (copy it, or `include:` it from a release tag) for scheduled and manual pipelines.
- `github-parity.yml`: a GitHub Actions workflow; the findings go to code scanning.

Both run the release container image pinned by digest, keep the SARIF report and the evidence bundle, and fail on
findings (exit 1) and on a missing verdict (exit 2). Set the zone file, the origin and the two providers as CI
variables; for a signed zone, add the parent's servers so the DS chain is checked.

Published CI components (a GitHub Action, a GitLab CI catalog component) come later (ROADMAP, v0.2).
