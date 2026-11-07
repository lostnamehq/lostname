- `watch.state_file` keeps the event tracker's state across restarts, so findings fixed while watch was down are
  closed; after its first round watch sends `be.lostname.watch.resync.v0` with every verdict and open finding.
