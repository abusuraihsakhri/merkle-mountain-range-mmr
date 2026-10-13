"""Regression checks for the original telemetry commands and API."""
import csv
import json

import pytest

from agents.base import AuditTrail
from cli import main as legacy_main
from merkle_mountain_range.cli import main as packaged_main
from merkle_mountain_range.models import FrontierPayload


@pytest.mark.parametrize("value,critical", [
    ("False", False), ("false", False), ("0", False),
    ("No", False), ("TRUE", True), ("1", True)
])
@pytest.mark.parametrize("entry", [legacy_main, packaged_main])
def test_csv_boolean_tokens(tmp_path, capsys, entry, value, critical):
    source = tmp_path / "source.csv"
    target = tmp_path / "result.csv"
    with source.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "task_id", "target_identifier", "primary_metric",
            "secondary_metric", "is_critical_flag", "status_descriptor"
        ])
        writer.writeheader()
        writer.writerow({
            "task_id": "T-01", "target_identifier": "KEY-01",
            "primary_metric": 2, "secondary_metric": 1,
            "is_critical_flag": value, "status_descriptor": "NOMINAL"
        })
    assert entry(["batch", "-i", str(source), "-o", str(target)]) == 0
    with target.open(newline="", encoding="utf-8") as f:
        row = next(csv.DictReader(f))
    observed = row.get("overall_urgency") or row.get("overall_status")
    assert ("CRITICAL" in observed) is critical


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
def test_frontier_metrics_reject_nonfinite(value):
    with pytest.raises(ValueError, match="finite"):
        FrontierPayload("T-01", "KEY-01", value, 0, "NOMINAL")


def test_audit_key_random_when_not_configured(monkeypatch):
    monkeypatch.delenv("AUDIT_SECRET_KEY", raising=False)
    with pytest.warns(RuntimeWarning, match="ephemeral"):
        a = AuditTrail()
    with pytest.warns(RuntimeWarning, match="ephemeral"):
        b = AuditTrail()
    assert a.secret_key != b.secret_key
    a.log("worker", "local", "START", {"task_id": "T-01"})
    assert a.verify_integrity()
    assert not AuditTrail(secret_key="other-key").secret_key == a.secret_key


def test_http_smoke():
    from fastapi.testclient import TestClient
    from agents.api import app
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    response = client.get("/")
    assert response.status_code == 200
    assert "Merkle Mountain Range" in response.text
    assert client.get("/mmr.mjs").status_code == 200
    result = client.post("/api/audit", json={
        "task_id": "T-01", "target_identifier": "KEY-01",
        "primary_metric": 1, "secondary_metric": 1,
        "status_descriptor": "NOMINAL"
    })
    assert result.status_code == 200
    assert result.json()["overall_urgency"] == "ROUTINE"
