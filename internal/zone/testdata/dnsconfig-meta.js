var REG_NONE = NewRegistrar("none");
var DSP_BIND = NewDnsProvider("bind");
D("example.test", REG_NONE, DnsProvider(DSP_BIND),
    DefaultTTL(3600),
    A("@", "192.0.2.10"),
    A("www", "192.0.2.40", CF_PROXY_ON),
    A("geo", "192.0.2.41", {"geo_region": "eu"}),
    A("plain", "192.0.2.42")
);
