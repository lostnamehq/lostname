- `lint --evidence DIR` and `parity --evidence DIR` write an evidence bundle: the inputs, the report, for parity every
  DNS exchange per server and transport (what was asked, of whom, over which path, with which answer and when),
  `versions.json`, and a `MANIFEST.sha256` over all of it. The bundle appears whole or not at all, never overwrites
  an earlier one, and holds no credentials; it does show the zone's internal names.
