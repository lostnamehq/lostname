#!/usr/bin/env python3
"""Conformance run on a throwaway Linux box with Podman (docs/observability.md, "Conformance"). Copy it to the box
with, in the same directory: emit (a linux/amd64 build of tools/conformance/emit) and expected.json; run it as root.
Starts the OpenTelemetry Collector writing to Prometheus and to VictoriaMetrics, pushes the fixture once through the
Collector with Lostname's own OTLP code, then asks both stacks every query in expected.json. Prints one JSON report;
exit 0 only when both stacks answer every query as expected. Versions are pinned below; the box is destroyed after.
"""
import json
import subprocess
import sys
import time
import urllib.parse
import urllib.request

COLLECTOR = "docker.io/otel/opentelemetry-collector-contrib:0.163.2"
PROMETHEUS = "docker.io/prom/prometheus:v3.15.1"
VICTORIA = "docker.io/victoriametrics/victoria-metrics:v1.154.1"
STACKS = {"prometheus": "http://127.0.0.1:9090", "victoriametrics": "http://127.0.0.1:8428"}

COLLECTOR_CONFIG = """receivers:
  otlp:
    protocols:
      http:
        endpoint: 127.0.0.1:4318
exporters:
  prometheusremotewrite/prometheus:
    endpoint: http://127.0.0.1:9090/api/v1/write
  prometheusremotewrite/victoriametrics:
    endpoint: http://127.0.0.1:8428/api/v1/write
service:
  pipelines:
    metrics:
      receivers: [otlp]
      exporters: [prometheusremotewrite/prometheus, prometheusremotewrite/victoriametrics]
"""


def sh(*cmd, check=True):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if check and r.returncode:
        sys.exit(f"conformance: {' '.join(cmd)} failed: {r.stderr.strip()[-400:]}")
    return r.stdout


def wait_http(url, seconds=120):
    end = time.time() + seconds
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=3)
            return
        except Exception:
            time.sleep(2)
    sys.exit(f"conformance: {url} did not come up in {seconds}s")


def query(base, q):
    url = f"{base}/api/v1/query?{urllib.parse.urlencode({'query': q})}"
    with urllib.request.urlopen(url, timeout=10) as r:
        body = json.load(r)
    if body.get("status") != "success":
        return {"error": body}
    return [float(s["value"][1]) for s in body["data"]["result"]]


def main():
    sh("apt-get", "update", "-qq")
    sh("apt-get", "install", "-y", "-qq", "podman")
    with open("collector.yaml", "w", encoding="utf-8") as f:
        f.write(COLLECTOR_CONFIG)
    sh("podman", "run", "-d", "--name", "prom", "--network", "host", PROMETHEUS,
       "--config.file=/etc/prometheus/prometheus.yml", "--web.enable-remote-write-receiver",
       "--web.listen-address=127.0.0.1:9090")
    sh("podman", "run", "-d", "--name", "vm", "--network", "host", VICTORIA, "-httpListenAddr=127.0.0.1:8428")
    wait_http(STACKS["prometheus"] + "/-/ready")
    wait_http(STACKS["victoriametrics"] + "/health")
    sh("podman", "run", "-d", "--name", "otelcol", "--network", "host", "-v",
       f"{subprocess.os.getcwd()}/collector.yaml:/etc/otelcol/config.yaml:ro,Z", COLLECTOR,
       "--config=/etc/otelcol/config.yaml")
    time.sleep(10)
    sh("chmod", "+x", "emit")
    print(sh("./emit", "http://127.0.0.1:4318").strip(), file=sys.stderr)
    time.sleep(45)  # the Collector's batch interval, remote write, and VictoriaMetrics' default 30 s query latency
    expected = json.load(open("expected.json", encoding="utf-8"))["queries"]
    report = {"versions": {"collector": COLLECTOR, "prometheus": PROMETHEUS, "victoriametrics": VICTORIA},
              "results": [], "pass": True}
    for e in expected:
        row = {"q": e["q"], "want": e["want"]}
        for name, base in STACKS.items():
            got = query(base, e["q"])
            ok = (got == []) if e["want"] is None else (got == [float(e["want"])])
            row[name] = {"got": got, "ok": ok}
            report["pass"] = report["pass"] and ok
        report["results"].append(row)
    report["collector_log_tail"] = sh("podman", "logs", "--tail", "15", "otelcol", check=False)[-1500:]
    print(json.dumps(report, indent=1))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
