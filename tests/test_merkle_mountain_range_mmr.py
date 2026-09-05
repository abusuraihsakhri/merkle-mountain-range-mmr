"""
Automated Pytest Test Suite for Merkle Mountain Range Mmr.
Domain: Clinical & Biomedical AI
Standard: CAP / CLSI / ISO Standards
"""
import sys
import os
import tempfile
import math
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from agents.base import PHIGuard, AuditLogger, AuditTrail, SecurityException
from agents.models import SystemTaskPayload, UrgencyLevel, SystemIntegrityStatus
from agents.workers import InvariantQCWorker, SafetyEscalationWorker, ProtocolConformanceWorker
from agents.supervisor import SystemSupervisor
from cli import main


def test_phi_guard_enforcement():
    with pytest.raises(SecurityException):
        PHIGuard.assert_no_phi("Patient MRN-994827 blood culture positive for Staphylococcus")

    # Clean text passes
    PHIGuard.assert_no_phi("Analytical assay specimen KEY-001 optimal")


def test_specialized_workers():
    # Worker 1: QC Invariant
    p1 = SystemTaskPayload(task_id="T1", target_identifier="KEY-01", primary_metric=35.0)
    alerts1 = InvariantQCWorker.evaluate(p1)
    assert len(alerts1) == 1
    assert alerts1[0].urgency == UrgencyLevel.ELEVATED

    # Worker 2: Safety
    p2 = SystemTaskPayload(task_id="T2", target_identifier="KEY-02", primary_metric=10.0, is_critical_flag=True)
    alerts2 = SafetyEscalationWorker.evaluate(p2)
    assert len(alerts2) == 1
    assert alerts2[0].urgency == UrgencyLevel.CRITICAL_STAT

    # Worker 3: Protocol Conformance
    p3 = SystemTaskPayload(task_id="T3", target_identifier="KEY-03", primary_metric=10.0, status_descriptor="DISCORDANT_ANOMALY")
    alerts3 = ProtocolConformanceWorker.evaluate(p3)
    assert len(alerts3) == 1


def test_supervisor_consensus_and_audit():
    supervisor = SystemSupervisor(model_provider="mock")
    payload = SystemTaskPayload(
        task_id="TASK-PROD-01",
        target_identifier="KEY-PROD-01",
        primary_metric=12.0,
        secondary_metric=4.0,
        status_descriptor="NOMINAL"
    )
    dossier = supervisor.process_task(payload)
    assert dossier.overall_urgency == UrgencyLevel.ROUTINE
    assert dossier.integrity_status == SystemIntegrityStatus.VALIDATED
    assert dossier.audit_hash != ""

    # Verify cryptographic audit trail
    assert AuditLogger.verify_integrity() is True

    # CLI tests
    assert main(["audit", "--task-id", "CLI-TEST-01"]) == 0
    assert main(["chat", "Explain", "specifications"]) == 0
    assert main(["verify-audit"]) == 0


def test_metric_validation_rejects_nan():
    """NaN metric values should be rejected by validation."""
    with pytest.raises(ValueError, match="finite"):
        SystemTaskPayload(task_id="T-NAN", target_identifier="KEY-NAN", primary_metric=float("nan"))


def test_metric_validation_rejects_infinity():
    """Infinite metric values should be rejected by validation."""
    with pytest.raises(ValueError, match="finite"):
        SystemTaskPayload(task_id="T-INF", target_identifier="KEY-INF", primary_metric=float("inf"))


def test_metric_validation_rejects_negative_infinity():
    """Negative infinite metric values should be rejected by validation."""
    with pytest.raises(ValueError, match="finite"):
        SystemTaskPayload(task_id="T-NEG-INF", target_identifier="KEY-NEG-INF", secondary_metric=float("-inf"))


def test_empty_task_id_rejected():
    """Empty task_id should be rejected by validation."""
    with pytest.raises(ValueError, match="empty"):
        SystemTaskPayload(task_id="", target_identifier="KEY-01", primary_metric=10.0)


def test_empty_target_identifier_rejected():
    """Empty target_identifier should be rejected by validation."""
    with pytest.raises(ValueError, match="empty"):
        SystemTaskPayload(task_id="T1", target_identifier="", primary_metric=10.0)


def test_batch_command_with_phi_data():
    """Batch command should skip rows containing PHI."""
    csv_content = "task_id,target_identifier,primary_metric,secondary_metric,is_critical_flag,status_descriptor\n"
    csv_content += "TASK-001,TARGET-01,28.4,14.2,True,NOMINAL\n"
    csv_content += "TASK-002,Patient MRN-12345,12.0,4.1,False,NOMINAL\n"  # PHI violation
    csv_content += "TASK-003,TARGET-03,35.0,19.5,True,ANOMALY\n"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
        f.write(csv_content)
        input_path = f.name

    output_path = input_path.replace(".csv", "_output.csv")

    try:
        exit_code = main(["batch", "-i", input_path, "-o", output_path])
        assert exit_code == 0

        with open(output_path, mode="r", encoding="utf-8") as f:
            content = f.read()

        # Should have processed 2 rows (skipped the PHI-violating one)
        assert "TASK-001" in content
        assert "TASK-003" in content
        assert "MRN-12345" not in content
    finally:
        os.unlink(input_path)
        if os.path.exists(output_path):
            os.unlink(output_path)


def test_batch_command_with_clean_data():
    """Batch command should process all rows when no PHI is present."""
    csv_content = "task_id,target_identifier,primary_metric,secondary_metric,is_critical_flag,status_descriptor\n"
    csv_content += "TASK-001,TARGET-01,28.4,14.2,True,NOMINAL\n"
    csv_content += "TASK-002,TARGET-02,12.0,4.1,False,NOMINAL\n"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, encoding="utf-8") as f:
        f.write(csv_content)
        input_path = f.name

    output_path = input_path.replace(".csv", "_output.csv")

    try:
        exit_code = main(["batch", "-i", input_path, "-o", output_path])
        assert exit_code == 0

        with open(output_path, mode="r", encoding="utf-8") as f:
            content = f.read()

        assert "TASK-001" in content
        assert "TASK-002" in content
    finally:
        os.unlink(input_path)
        if os.path.exists(output_path):
            os.unlink(output_path)


def test_audit_trail_signature_verification():
    """Audit trail should verify HMAC signatures, not just chain linkage."""
    trail = AuditTrail(secret_key="test-secret-key")
    trail.log("test_actor", "test_tier", "TEST_EVENT", {"key": "value"})

    # Verify integrity passes for valid trail
    assert trail.verify_integrity() is True

    # Tamper with an entry
    trail.logs[0]["payload_hash"] = "tampered_hash"

    # Verify integrity fails after tampering
    assert trail.verify_integrity() is False


def test_audit_trail_chain_verification():
    """Audit trail should detect broken chain linkage."""
    trail = AuditTrail(secret_key="test-secret-key-2")
    trail.log("actor1", "tier1", "EVENT1", {"a": 1})
    trail.log("actor2", "tier2", "EVENT2", {"b": 2})

    # Verify chain is intact
    assert trail.verify_integrity() is True

    # Break the chain by modifying prev_hash
    trail.logs[1]["prev_hash"] = "broken_link"

    # Verify chain is broken
    assert trail.verify_integrity() is False


def test_phi_redaction():
    """PHIGuard should redact PHI from text."""
    text = "Patient John Doe MRN-12345 has phone 555-123-4567"
    redacted = PHIGuard.redact_phi(text)
    assert "John Doe" not in redacted
    assert "MRN-12345" not in redacted
    assert "555-123-4567" not in redacted
    assert "[REDACTED_IDENTIFIER]" in redacted
