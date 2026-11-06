"""M0 glue: the DNSSEC facts an exit needs and neither DNSControl nor OctoDNS reports.

Per server: DNSKEY key tags and algorithms, CDS/CDNSKEY if published, and the DS the parent would need. Then the
question a provider switch must answer: does either server publish the other's key (multi-signer), or will the move
need an insecure window? Usage: python dnssec_facts.py ZONE HOST:PORT_A HOST:PORT_B
"""
import sys

import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rdatatype

ZONE = dns.name.from_text(sys.argv[1])
SERVERS = dict(zip("AB", [(hp.split(":")[0], int(hp.split(":")[1])) for hp in sys.argv[2:4]]))


def rrset(server, rtype):
    q = dns.message.make_query(ZONE, rtype, want_dnssec=True)
    r = dns.query.tcp(q, server[0], port=server[1], timeout=5)
    return [rr for rr in r.answer if rr.rdtype == dns.rdatatype.from_text(rtype)]


facts = {}
for n, srv in SERVERS.items():
    keys = [rd for rr in rrset(srv, "DNSKEY") for rd in rr]
    ksk = [k for k in keys if k.flags & 1]
    facts[n] = {
        "tags": sorted(dns.dnssec.key_id(k) for k in keys),
        "ksk_tags": sorted(dns.dnssec.key_id(k) for k in ksk),
        "algorithms": sorted({dns.dnssec.algorithm_to_text(k.algorithm) for k in keys}),
        "cds": [rd.to_text() for rr in rrset(srv, "CDS") for rd in rr],
        "ds_needed": [dns.dnssec.make_ds(ZONE, k, "SHA256").to_text() for k in ksk],
    }
    print(f"{n}: DNSKEY tags {facts[n]['tags']} (KSK {facts[n]['ksk_tags']}), algorithms {facts[n]['algorithms']}, "
          f"CDS published: {'yes' if facts[n]['cds'] else 'no'}")
    for d in facts[n]["ds_needed"]:
        print(f"   DS the parent needs for {n}: {d[:40]}...")
shared = set(facts["A"]["tags"]) & set(facts["B"]["tags"])
print(f"keys published by both: {sorted(shared) or 'none'}")
if not shared:
    print("VERDICT: independent signers with no shared keys. Switching NS at the parent needs either an insecure window "
          "(remove DS, wait the DS TTL, switch, add the new DS) or importing the other signer's DNSKEY into each "
          "provider first (multi-signer, RFC 8901). Neither DNSControl nor OctoDNS plans or checks this.")
