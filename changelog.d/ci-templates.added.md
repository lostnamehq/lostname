- CI templates in `deploy/ci/` run `lostname parity` against a standby provider on a schedule: a GitLab CI job
  and a GitHub Actions workflow (findings to code scanning). Both run the release image pinned by digest, keep the
  SARIF report and the evidence bundle, and fail on findings and on a missing verdict.
