- `lint --baseline REPORT` compares with an earlier `lint --json` report of the same zone and reports, and judges, only
  what got worse: new findings and raised severities. The summary counts what was fixed. A report of another zone,
  or one that was itself made against a baseline, is refused.
