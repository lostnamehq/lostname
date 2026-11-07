- `watch.catalogs` checks the members of catalog zones (RFC 9432), each like a listed zone with the catalog's
  providers, parent and exit objective; the catalog is read every round and has its own `catalog` check. A member
  without a verdict does not stop the others, and a listed zone keeps its own settings.
