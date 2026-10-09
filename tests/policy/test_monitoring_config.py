"""Static checks on monitoring config that promtool/amtool don't cover."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
RULES = REPO / "deploy" / "prometheus" / "rules"


def _alerts() -> list[dict[str, Any]]:
    data = yaml.safe_load((RULES / "alerts.yml").read_text())
    return [r for g in data["groups"] for r in g["rules"] if "alert" in r]


def test_alerts_have_severity_and_summary() -> None:
    for rule in _alerts():
        assert rule["labels"]["severity"] in {"critical", "warning", "info"}, rule["alert"]
        assert rule["annotations"]["summary"], rule["alert"]


def test_service_alerts_carry_service_label_and_dashboard() -> None:
    # Sentinel groups incidents by `service`. Every shop-api alert must expose it,
    # either from the recorded series or as a static label.
    for rule in _alerts():
        if not rule["alert"].startswith("ShopApi"):
            continue
        assert "service" in rule["expr"] or rule["labels"].get("service"), rule["alert"]
        assert rule["annotations"]["dashboard_url"].endswith("/d/sentinel-shop-api")


def test_dashboard_json_is_up_to_date() -> None:
    script = REPO / "deploy" / "grafana" / "build_dashboards.py"
    spec = importlib.util.spec_from_file_location("build_dashboards", script)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name, content in module.render().items():
        committed = (REPO / "deploy" / "grafana" / "dashboards" / name).read_text()
        assert committed == content, f"{name} is stale: run deploy/grafana/build_dashboards.py"


def test_alertmanager_uses_secret_file_for_webhook_token() -> None:
    cfg = yaml.safe_load((REPO / "deploy" / "alertmanager" / "alertmanager.yml").read_text())
    for receiver in cfg["receivers"]:
        for hook in receiver.get("webhook_configs", []):
            auth = hook["http_config"]["authorization"]
            assert auth["credentials_file"].startswith("/run/secrets/")
            assert "credentials" not in auth
