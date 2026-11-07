"""The shipped alert rules follow the contract (docs/observability.md): every rule has a severity from the contract's
set, a suggested autonomy, an owner role and an action, and uses only metrics that `watch` emits."""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SEVERITIES = {"info", "warning", "critical", "compromise"}
AUTONOMY = {"autonomous", "notify", "gated", "human"}


def emitted() -> set:
    src = (ROOT / "internal" / "watch" / "metrics.go").read_text(encoding="utf-8")
    return set(re.findall(r'name: "(lostname_[a-z_]+)"', src))


def test_alert_rules():
    doc = yaml.safe_load((ROOT / "deploy" / "alerts" / "lostname.rules.yaml").read_text(encoding="utf-8"))
    rules = [r for g in doc["groups"] for r in g["rules"]]
    assert {r["alert"] for r in rules} == {"LostnameStandbyNotInParity", "LostnameSignatureExpirySoon",
                                           "LostnameDNSSECBogus", "LostnameChecksSilent", "LostnamePathIntercepted",
                                           "LostnameExitBudgetBurnFast", "LostnameExitBudgetBurnSlow",
                                           "LostnameWatchAbsent"}
    names = emitted()
    assert len(names) >= 10, names
    for r in rules:
        lab, ann = r["labels"], r["annotations"]
        assert lab["severity"] in SEVERITIES, r["alert"]
        assert lab["autonomy"] in AUTONOMY, r["alert"]
        assert lab.get("owner_role"), r["alert"]
        assert ann.get("action"), r["alert"]
        used = set(re.findall(r"lostname_[a-z_]+", r["expr"]))  # a stateset's label has its metric's name
        assert used <= names, (r["alert"], used - names)


def test_silence_covers_never_succeeded():
    """Red team 2, W4: a check without any success since watch started must still be able to alert."""
    doc = yaml.safe_load((ROOT / "deploy" / "alerts" / "lostname.rules.yaml").read_text(encoding="utf-8"))
    silent = [r["expr"] for g in doc["groups"] for r in g["rules"] if r["alert"] == "LostnameChecksSilent"]
    assert any("lostname_check_last_success_timestamp_seconds >" in e or "time() -" in e for e in silent)
    assert any('lostname_check_verdict="no_verdict"' in e and "unless" in e for e in silent)


def test_exit_burn_rates_use_two_windows():
    """OB-2: each burn-rate alert needs a long and a short window on the readiness SLI, both over the threshold."""
    doc = yaml.safe_load((ROOT / "deploy" / "alerts" / "lostname.rules.yaml").read_text(encoding="utf-8"))
    burn = {r["alert"]: r["expr"] for g in doc["groups"] for r in g["rules"] if "Burn" in r["alert"]}
    for name, expr in burn.items():
        windows = re.findall(r"avg_over_time\(lostname_exit_ready\[(\w+)\]\)", expr)
        assert len(windows) == 2 and windows[0] != windows[1] and " and " in expr, (name, expr)
