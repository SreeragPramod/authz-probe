"""Unit tests for authz-probe core logic."""

import pytest
from authzprobe.verdict import evaluate_response, Verdict, VulnType, Severity
from authzprobe.policy import expand_env_vars


def test_verdict_bola_detection():
    """Verify that 200 OK leaking owner data is marked VULNERABLE."""
    evaluation = evaluate_response(
        status_code=200,
        body_text='{"owner": "alice", "data": "financial_records"}',
        target_owner="alice",
        requesting_identity="bob",
    )
    assert evaluation.verdict == Verdict.VULNERABLE
    assert evaluation.vuln_type == VulnType.BOLA
    assert evaluation.severity == Severity.HIGH


def test_verdict_secure_rejection():
    """Verify that 403 Forbidden is marked OK."""
    evaluation = evaluate_response(
        status_code=403,
        body_text='{"error": "Forbidden"}',
        target_owner="alice",
        requesting_identity="bob",
    )
    assert evaluation.verdict == Verdict.OK


def test_verdict_masked_404():
    """Verify that 404 Not Found is marked OK (secure info hiding)."""
    evaluation = evaluate_response(
        status_code=404,
        body_text='{"error": "Not found"}',
        target_owner="alice",
        requesting_identity="bob",
    )
    assert evaluation.verdict == Verdict.OK


def test_env_var_expansion(monkeypatch):
    """Verify that policy expansion extracts environment variables correctly."""
    monkeypatch.setenv("TEST_AUTH_TOKEN", "secret_jwt_123")
    raw_yaml = "auth_header: 'Bearer ${TEST_AUTH_TOKEN}'"
    expanded = expand_env_vars(raw_yaml)
    assert expanded == "auth_header: 'Bearer secret_jwt_123'"
