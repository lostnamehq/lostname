"""M0 glue: ask both lab servers directly for every name and type and compare what they serve.

Prints one line per RRset that differs, plus the DNSSEC facts per server. Signatures (RRSIG) are compared only for
presence, since each provider signs with its own keys. Usage: python parity_live.py ZONE HOST:PORT_A HOST:PORT_B
"""
import sys

import dns.message
import dns.query
import dns.flags
import dns.rcode
import dns.rdatatype

ZONE = sys.argv[1].rstrip(".") + "."
SERVERS = {n: (hp.split(":")[0], int(hp.split(":")[1])) for n, hp in zip("AB", sys.argv[2:4])}
NAMES = ["@", "_dmarc", "_sip._tcp", "long", "long-ttl", "mail", "_25._tcp.mail", "short", "sip", "sub", "ns1.sub",
         "www", "x.apps", "edge"]
TYPES = ["SOA", "NS", "A", "AAAA", "MX", "TXT", "CAA", "HTTPS", "NAPTR", "SRV", "TLSA", "CNAME", "DNSKEY", "CDS"]


DELEGATED = ("sub",)   # labels at or below a zone cut: the server answers with a referral, not authoritatively


def ask(server, name, rtype, referral_ok=False):
    q = dns.message.make_query(name, rtype, want_dnssec=True)
    r = dns.query.tcp(q, server[0], port=server[1], timeout=5)   # lab: Podman on Windows forwards TCP, not UDP
    data, sigs = set(), 0
    section = r.answer + (r.authority if rtype == "NS" or referral_ok else []) + (r.additional if referral_ok else [])
    for rr in section:
        if rr.rdtype == dns.rdatatype.RRSIG:
            sigs += len(rr)
        elif referral_ok and rr.rdtype in (dns.rdatatype.NS, dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.DS):
            data |= {(rr.ttl, f"{rr.name} {dns.rdatatype.to_text(rr.rdtype)} {rd.to_text()}") for rd in rr}
        elif rr.rdtype == dns.rdatatype.from_text(rtype) or rr.rdtype == dns.rdatatype.CNAME:
            data |= {(rr.ttl, rd.to_text()) for rd in rr}
    authoritative = bool(r.flags & dns.flags.AA)
    if r.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN) or not (authoritative or referral_ok):
        raise SystemExit(f"FAIL {server} {name} {rtype}: {dns.rcode.to_text(r.rcode())}, AA={authoritative}: "
                         "the server does not serve this zone authoritatively; no parity verdict possible")
    return dns.rcode.to_text(r.rcode()), data, sigs


def main():
    diffs, notes = 0, []
    for label in NAMES:
        name = ZONE if label == "@" else f"{label}.{ZONE}"
        below_cut = any(label == d or label.endswith("." + d) for d in DELEGATED)
        for t in TYPES:
            a, b = ask(SERVERS["A"], name, t, below_cut), ask(SERVERS["B"], name, t, below_cut)
            if label == "@" and t == "NS":
                notes.append(f"apex NS differs by design (each provider names its own servers): A {sorted(x[1] for x in a[1])}"
                             f" | B {sorted(x[1] for x in b[1])}")
                continue
            if t in ("DNSKEY", "CDS"):
                if a[1] or b[1]:
                    notes.append(f"{name} {t}: A {sorted(x[1][:40] for x in a[1])} | B {sorted(x[1][:40] for x in b[1])}")
                continue
            if t == "SOA":
                if a[1] or b[1]:
                    notes.append(f"{name} SOA: A {sorted(a[1])} | B {sorted(b[1])}")
                continue
            if a[:2] != b[:2]:
                diffs += 1
                print(f"DIFF {name} {t}: A {a[0]} {sorted(a[1])} | B {b[0]} {sorted(b[1])}")
            if (a[1] and not a[2]) or (b[1] and not b[2]):
                print(f"UNSIGNED {name} {t}: A sigs {a[2]}, B sigs {b[2]}")
    print(f"--- {diffs} differing RRsets")
    for n in notes:
        print("NOTE", n)


if __name__ == "__main__":
    main()
