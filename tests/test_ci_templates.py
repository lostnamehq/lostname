"""The CI templates (deploy/ci) run the CLI as it is: every flag they pass exists in the usage text, the image is
pinned by digest, GitHub actions are pinned by commit, permissions are the least the job needs, and both run on a
schedule and keep the SARIF report whatever the verdict."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / "deploy" / "ci"


def usage_parity_flags() -> set:
    src = (ROOT / "cmd" / "lostname" / "main.go").read_text(encoding="utf-8")
    usage = src[src.index("const usage = `"):]
    usage = usage[:usage.index("`", len("const usage = `"))]
    block = usage[usage.index("lostname parity"):usage.index("lostname watch")]
    return set(re.findall(r"--[a-z][a-z-]*", block))


def flags_in(text: str) -> set:
    return set(re.findall(r"(?<![\w-])--[a-z][a-z-]*", text))


def test_gitlab_template():
    doc = yaml.safe_load((CI / "gitlab-ci.yml").read_text(encoding="utf-8"))
    job = doc["lostname-parity"]
    assert re.fullmatch(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}", doc["variables"]["LOSTNAME_IMAGE"])  # a real digest
    assert any("schedule" in r["if"] for r in job["rules"])
    script = "\n".join(job["script"])
    assert "lostname parity" in script and "exit $code" in script
    assert flags_in(script) <= usage_parity_flags(), flags_in(script) - usage_parity_flags()
    assert job["artifacts"]["when"] == "always" and "lostname-parity.sarif" in job["artifacts"]["paths"]


def test_github_template():
    text = (CI / "github-parity.yml").read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    on = doc.get("on", doc.get(True))  # YAML 1.1 reads a bare "on" as true
    assert "schedule" in on
    assert doc["permissions"] == {"contents": "read"}
    job = doc["jobs"]["parity"]
    assert job["permissions"] == {"contents": "read", "security-events": "write"}
    assert re.fullmatch(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}", job["container"]["image"])
    for step in job["steps"]:
        if "uses" in step:
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
    run = "\n".join(s.get("run", "") for s in job["steps"])
    assert flags_in(run) <= usage_parity_flags(), flags_in(run) - usage_parity_flags()
    upload = [s for s in job["steps"] if "upload-sarif" in s.get("uses", "")]
    assert upload and upload[0]["if"] == "always()"
    assert job["steps"][-1]["if"] == "always()" and "exit" in job["steps"][-1]["run"]
