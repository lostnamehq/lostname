var REG_NONE = NewRegistrar("none");
var DSP_BIND = NewDnsProvider("bind");
D("example.test", REG_NONE, DnsProvider(DSP_BIND),
    DefaultTTL(3600),
    AUTODNSSEC_ON,
    A("@", "192.0.2.10"),
    AAAA("@", "2001:db8::10"),
    MX("@", 10, "mail.example.test."),
    A("mail", "192.0.2.25"),
    TXT("@", "v=spf1 -all"),
    CNAME("www", "web.provider.invalid."),
    CAA("@", "issue", "letsencrypt.org"),
    SRV("_sip._tcp", 10, 5, 5060, "sip.example.test."),
    A("sip", "192.0.2.30", TTL(60)),
    ALIAS("apex-alias", "lb.provider.invalid."),
    NS("sub", "ns1.other.invalid."),
    DS("sub", 12345, 13, 2, "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
);
