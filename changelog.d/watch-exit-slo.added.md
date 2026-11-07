- Exit readiness as an SLO: a watch zone with an `exit` block (`model`, `lock`, `target_seconds`) gets an `exit`
  check each round. The exit time is the simulator's (safe plan, registry-lock schedule, cache drain), with the
  zone's own DNSKEY TTL. New metrics `lostname_exit_time_seconds`, `lostname_exit_target_seconds` and the SLI
  `lostname_exit_ready`; alert rules on multi-window burn rates (`LostnameExitBudgetBurnFast`, `...Slow`).
