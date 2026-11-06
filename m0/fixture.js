// M0 fixture zone: lostname.test (RFC 6761 reserved). Varied on purpose: what moves cleanly between providers?
var REG_NONE = NewRegistrar("none");
var PA = NewDnsProvider("lab_a", {"default_ns": ["ns1.provider-a.test.", "ns2.provider-a.test."]});
D("lostname.test", REG_NONE, DnsProvider(PA), AUTODNSSEC_ON,
  DefaultTTL(300),
  SOA("@", "ns1.provider-a.test.", "hostmaster.lostname.test.", 3600, 600, 604800, 300),
  A("@", "192.0.2.10"), AAAA("@", "2001:db8::10"),
  A("mail", "192.0.2.25"), MX("@", 10, "mail"),
  TXT("@", "v=spf1 mx -all"),
  TXT("long", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
  TXT("_dmarc", "v=DMARC1; p=reject; rua=mailto:dmarc@lostname.test"),
  CAA("@", "issue", "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456"),
  CAA("@", "iodef", "mailto:security@lostname.test"),
  SRV("_sip._tcp", 10, 60, 5060, "sip.lostname.test."), A("sip", "192.0.2.50"),
  TLSA("_25._tcp.mail", 3, 1, 1, "0000000000000000000000000000000000000000000000000000000000000000"),
  NAPTR("@", 100, 10, "U", "E2U+sip", "!^.*$!sip:info@lostname.test!", "."),
  HTTPS("@", 1, ".", "alpn=h2"),
  CNAME("www", "@"),
  CNAME("*.apps", "www"),
  NS("sub", "ns1.sub.lostname.test."), A("ns1.sub", "192.0.2.53"),
  A("short", "192.0.2.60", TTL(60)), A("long-ttl", "192.0.2.61", TTL(86400)),
  ALIAS("edge", "www.lostname.test.")
);
