"""Generate internal/target/dnscontrol.json from DNSControl's provider feature tables.

Input: documentation/provider/index.md of a pinned DNSControl release (MIT licence), saved by the caller, for example
    gh api "repos/DNSControl/dnscontrol/contents/documentation/provider/index.md?ref=v5.7.0" -q .content | base64 -d

Usage: python tools/capabilities.py INDEX_MD TAG COMMIT RELEASED   (RELEASED: the release date, YYYY-MM-DD)

Only the record-type tables are read (DNS extensions, service discovery, security, DNSSEC). Each cell becomes "yes",
"no" or "unknown" (the matrix's own question mark). Lostname's observations that the matrix does not carry, such as a
provider that needs an SOA in the config (M0 finding F2), are added here, each with its source. The output is written
atomically and sorted, so a regeneration from the same input is byte-identical.
"""
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "internal" / "target" / "dnscontrol.json"
TABLES = ("DNS extensions", "Service discovery", "Security", "DNSSEC")
CELL = {chr(0x2705): "yes", chr(0x274C): "no", chr(0x2754): "unknown"}  # the matrix's check, cross, question mark

# Observations of our own, keyed by DNSControl provider name. Each says what and where it was seen.
NEEDS_SOA = {
    "POWERDNS": "the PowerDNS provider needs an SOA in the config since DNSControl v4.16; without one, push deletes "
                "the SOA and the zone stops being served while push reports success",  # Lostname M0 finding F2
}


def parse(text: str) -> dict:
    providers: dict = {}
    section, columns = None, []
    for line in text.splitlines():
        if line.startswith("### "):
            section = next((t for t in TABLES if line[4:].startswith(t)), None)
            columns = []
            continue
        if section is None or not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if cells[0] == "Provider name":
            columns = [re.sub(r"^\[`([A-Z0-9_]+)`\].*$", r"\1", c) for c in cells[1:]]
            continue
        m = re.match(r"^\[`([A-Z0-9_]+)`\]", cells[0])
        if not m or not columns:
            continue
        row = providers.setdefault(m.group(1), {})
        for col, cell in zip(columns, cells[1:]):
            if cell not in CELL:
                sys.exit(f"capabilities: unknown cell {cell!r} for {m.group(1)} {col}")
            row[col] = CELL[cell]
    if not providers:
        sys.exit("capabilities: no provider rows found; is this documentation/provider/index.md?")
    return providers


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__)
        return 3
    src, tag, commit, released = sys.argv[1:]
    providers = parse(Path(src).read_text(encoding="utf-8"))
    for name, why in NEEDS_SOA.items():
        if name not in providers:
            sys.exit(f"capabilities: observation for unknown provider {name}")
        providers[name]["_needs_soa"] = why
    doc = {
        "schema": "lostname.capabilities/v0",
        "source": {"project": "DNSControl (MIT licence)", "tag": tag, "commit": commit,
                   "released": released, "path": "documentation/provider/index.md", "tables": list(TABLES)},
        "values": "yes, no or unknown, as the source's feature tables give them; types the tables do not list "
                  "(A, AAAA, CNAME, MX, NS, TXT) are supported by every provider",
        "providers": {k: dict(sorted(v.items())) for k, v in sorted(providers.items())},
    }
    data = (json.dumps(doc, indent=1, ensure_ascii=True) + "\n").encode()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=OUT.parent)
    os.write(fd, data)
    os.fsync(fd)
    os.close(fd)
    os.replace(tmp, OUT)
    print(f"capabilities: {len(providers)} providers from DNSControl {tag} -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
