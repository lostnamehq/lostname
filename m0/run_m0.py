"""M0 falsifier: one exit drill from lab provider A to lab provider B with only DNSControl and OctoDNS plus glue.

Steps (each logged with its exit code and output in runs/<stamp>/):
  1 seed A from fixture.js            4 load B (push twice)            7 live parity (parity_live.py)
  2 export A (get-zones zone + djs)   5 DNSControl preview on A and B  8 DNSSEC facts per server (DNSKEY, CDS, DS)
  3 glue: djs -> config for B         6 OctoDNS compare A vs B         9 MANIFEST.sha256
Usage: python run_m0.py   (lab servers from the README must be running; creds.local.json next to this file)
"""
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent / ".tools"
DC = str(TOOLS / "dnscontrol.exe")
PY = str(TOOLS / "venv" / "Scripts" / "python.exe")
OCTO = str(TOOLS / "venv" / "Scripts" / "octodns-compare.exe")
ZONE = "lostname.test"
CREDS = str(HERE / "creds.local.json")
RUN = HERE / "runs" / time.strftime("%Y%m%d-%H%M%S")
LOG = []


def step(n, title, cmd, out=None, ok_codes=(0,)):
    t0 = time.time()
    p = subprocess.run(cmd, capture_output=True, text=True, cwd=RUN)
    text = (p.stdout + p.stderr).replace("\x1b", "")
    text = re.sub(r"\[\d+m", "", text)
    if out:
        (RUN / out).write_text(text, encoding="utf-8")
    LOG.append({"step": n, "title": title, "cmd": [Path(c).name if i == 0 else c for i, c in enumerate(cmd)],
                "exit": p.returncode, "ok": p.returncode in ok_codes, "seconds": round(time.time() - t0, 1),
                "tail": text.strip().splitlines()[-6:]})
    print(f"[{n}] {title}: exit {p.returncode} ({LOG[-1]['seconds']} s)")
    return p.returncode, text


def glue_for_b(djs: str) -> str:
    """The glue M0 measures: what a human must change in get-zones output before it loads into B."""
    s = djs.replace('NewDnsProvider("lab_a", "")',
                    'NewDnsProvider("lab_b", {"default_ns": ["ns1.provider-b.test.", "ns2.provider-b.test."]})')  # metadata not exported
    s = s.replace("DSP_LAB_A", "DSP_LAB_B")
    s = s.replace(', {no_ns: "true"}', ', {no_ns: "true"}\n\t, AUTODNSSEC_ON')                     # DNSSEC state is not exported
    s = s.replace("\t, DnsProvider(DSP_LAB_B)", '\t, DnsProvider(DSP_LAB_B)\n\t, SOA("@", "ns1.provider-b.test.", '
                  '"hostmaster.lostname.test.", 3600, 600, 604800, 300)')                          # SOA is commented out
    return s


def main():
    RUN.mkdir(parents=True)
    keys = json.loads((TOOLS / "labkeys.local.json").read_text())
    for port in (18081, 18082):   # fresh zones on both servers
        subprocess.run(["curl", "-s", "-o", "NUL", "-X", "DELETE", "-H", f"X-API-Key: {keys['a']}",
                        f"http://127.0.0.1:{port}/api/v1/servers/localhost/zones/{ZONE}."])
    fixture = str(HERE / "fixture.js")
    step(1, "seed A (create)", [DC, "push", "--config", fixture, "--creds", CREDS], "1a-seed.txt")
    step(1, "seed A (records, DNSSEC)", [DC, "push", "--config", fixture, "--creds", CREDS], "1b-seed.txt")
    step(2, "export A as zone file", [DC, "get-zones", "--creds", CREDS, "--format=zone", "--out", "export-a.zone", "lab_a", "-", ZONE])
    step(2, "export A as djs", [DC, "get-zones", "--creds", CREDS, "--format=djs", "--out", "export-a.djs", "lab_a", "-", ZONE])
    djs = (RUN / "export-a.djs").read_text(encoding="utf-8")
    (RUN / "load-b.js").write_text(glue_for_b(djs), encoding="utf-8")
    step(4, "load B (create)", [DC, "push", "--config", "load-b.js", "--creds", CREDS], "4a-load.txt")
    step(4, "load B (records, DNSSEC)", [DC, "push", "--config", "load-b.js", "--creds", CREDS], "4b-load.txt")
    both = (RUN / "load-b.js").read_text(encoding="utf-8").replace(
        "var REG_CHANGEME", 'var DSP_LAB_A = NewDnsProvider("lab_a", {"default_ns": ["ns1.provider-a.test.", '
        '"ns2.provider-a.test."]});\nvar REG_CHANGEME', 1
    ).replace("\t, DnsProvider(DSP_LAB_B)", "\t, DnsProvider(DSP_LAB_A)\n\t, DnsProvider(DSP_LAB_B)")
    (RUN / "both.js").write_text(both, encoding="utf-8")
    step(5, "DNSControl preview A and B, expect no changes",
         [DC, "preview", "--config", "both.js", "--creds", CREDS, "--expect-no-changes", "--report", "preview-report.json"], "5-preview.txt")
    (RUN / "octodns.yaml").write_text(
        "providers:\n"
        f"  pdns_a: {{class: octodns_powerdns.PowerDnsProvider, host: 127.0.0.1, port: 18081, api_key: env/LAB_KEY}}\n"
        f"  pdns_b: {{class: octodns_powerdns.PowerDnsProvider, host: 127.0.0.1, port: 18082, api_key: env/LAB_KEY}}\n"
        f"zones:\n  {ZONE}.: {{sources: [pdns_a], targets: [pdns_b]}}\n", encoding="utf-8")
    import os
    os.environ["LAB_KEY"] = keys["a"]
    step(6, "OctoDNS compare A vs B", [OCTO, "--config-file", "octodns.yaml", "--a", "pdns_a", "--b", "pdns_b", "--zone", f"{ZONE}."], "6-octodns.txt")
    step(7, "live parity, every RRset", [PY, str(HERE / "parity_live.py"), ZONE, "127.0.0.1:15353", "127.0.0.1:15354"], "7-parity.txt")
    step(8, "DNSSEC facts", [PY, str(HERE / "dnssec_facts.py"), ZONE, "127.0.0.1:15353", "127.0.0.1:15354"], "8-dnssec.txt")
    (RUN / "steps.json").write_text(json.dumps(LOG, indent=1), encoding="utf-8")
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in sorted(RUN.iterdir()) if p.is_file()]
    (RUN / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"run: {RUN}")


if __name__ == "__main__":
    main()
