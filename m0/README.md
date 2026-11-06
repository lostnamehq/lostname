# M0 lab

Two PowerDNS authoritative servers in Podman stand in for two providers. Credentials and lab keys live in git-ignored `*.local.*` files; runs live in git-ignored `runs/`.

```sh
# tools (outside git): DNSControl release binary checked against checksums.txt; OctoDNS and dnspython in a venv
gh release download v5.7.2 -R DNSControl/dnscontrol -p "dnscontrol_5.7.2_windows_amd64.zip" -p checksums.txt -D ../.tools
python -m venv ../.tools/venv && ../.tools/venv/Scripts/python -m pip install octodns==1.22.0 octodns-powerdns==1.2.0 dnspython==2.9.2

# lab: PowerDNS runs unprivileged in the image, so it listens on 5353 inside
podman run -d --name lostname-m0-a -p 15353:5353/tcp -p 15353:5353/udp -p 18081:8081 -e PDNS_AUTH_API_KEY=<key> docker.io/powerdns/pdns-auth-50:latest --local-port=5353
podman run -d --name lostname-m0-b -p 15354:5353/tcp -p 15354:5353/udp -p 18082:8081 -e PDNS_AUTH_API_KEY=<key> docker.io/powerdns/pdns-auth-50:latest --local-port=5353

# run
../.tools/venv/Scripts/python run_m0.py
podman rm -f lostname-m0-a lostname-m0-b
```

**Lab limits:**
- Podman on Windows forwards TCP but not UDP to the host, so the scripts query over TCP.
- There is no parent zone, so DS handling is computed, not exercised.

Findings: `FINDINGS.md`.
