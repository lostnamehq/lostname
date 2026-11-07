- `watch.zone_id.salt_file` switches on the keyed-hash zone label: labels, event subjects and spans carry
  HMAC-SHA-256(salt, zone) instead of the zone's name, and owner names become relative to the zone.
