"""Tests for FastAPI endpoints, Demo Mode, rate limiting, and SSRF handling."""

from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from app import app
from api.limiter import rate_limiter
from triage.models import (
    DNSRecordItem,
    DNSRecords,
    RiskAssessment,
    RiskTier,
    TargetMetadata,
    TargetType,
    TriageReport,
)


@pytest.fixture
def client():
    rate_limiter.reset()
    return TestClient(app)


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "demo_mode" in data


def test_samples_list_endpoint(client):
    response = client.get("/api/samples")
    assert response.status_code == 200
    samples = response.json()
    assert len(samples) == 3
    ids = {s["id"] for s in samples}
    assert "bank_phish" in ids
    assert "crypto_drainer" in ids
    assert "benign_baseline" in ids


def test_get_sample_by_id(client):
    response = client.get("/api/samples/bank_phish")
    assert response.status_code == 200
    report = response.json()
    assert report["target"]["defanged_target"] == "hxxps://chase-secure-verify[.]top/auth/login"
    assert report["risk_assessment"]["score"] == 85
    assert report["risk_assessment"]["tier"] == "CRITICAL"


def test_get_nonexistent_sample_returns_404(client):
    response = client.get("/api/samples/nonexistent_case")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_triage_endpoint_mocked(client):
    mock_report = TriageReport(
        target=TargetMetadata(
            raw_target="hxxp://suspicious-test[.]com",
            normalized_target="http://suspicious-test.com",
            defanged_target="hxxp://suspicious-test[.]com",
            target_type=TargetType.DOMAIN,
            host="suspicious-test.com",
            defanged_host="suspicious-test[.]com",
            domain="suspicious-test.com",
        ),
        timestamp="2026-11-16T20:00:00Z",
        dns=DNSRecords(a_records=[DNSRecordItem(value="93.184.216.34", ttl=300)]),
        risk_assessment=RiskAssessment(score=10, tier=RiskTier.LOW),
    )

    with patch("app.engine.triage", return_value=mock_report):
        response = client.post("/api/triage", json={"target": "suspicious-test.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["target"]["defanged_target"] == "hxxp://suspicious-test[.]com"
        assert data["risk_assessment"]["score"] == 10


def test_triage_ssrf_rejection_loopback(client):
    response = client.post("/api/triage", json={"target": "127.0.0.1"})
    assert response.status_code == 400
    assert "SSRF Guardrail Violation" in response.json()["detail"]
    assert "Loopback address blocked" in response.json()["detail"]


def test_triage_ssrf_rejection_private_ip(client):
    response = client.post("/api/triage", json={"target": "192.168.1.1"})
    assert response.status_code == 400
    assert "SSRF Guardrail Violation" in response.json()["detail"]
    assert "Private IP address blocked" in response.json()["detail"]


def test_rate_limiter_exceeded(client):
    mock_report = TriageReport(
        target=TargetMetadata(
            raw_target="example.com",
            normalized_target="example.com",
            defanged_target="example[.]com",
            target_type=TargetType.DOMAIN,
            host="example.com",
            defanged_host="example[.]com",
            domain="example.com",
        ),
        timestamp="2026-11-16T20:00:00Z",
        dns=DNSRecords(),
        risk_assessment=RiskAssessment(score=0, tier=RiskTier.LOW),
    )

    with patch("app.engine.triage", return_value=mock_report):
        # 10 requests allowed
        for _ in range(10):
            res = client.post("/api/triage", json={"target": "example.com"})
            assert res.status_code == 200

        # 11th request must be rate limited
        res11 = client.post("/api/triage", json={"target": "example.com"})
        assert res11.status_code == 429
        assert "Rate limit exceeded" in res11.json()["detail"]
        assert "Retry-After" in res11.headers


def test_demo_mode_blocks_live_triage(client, monkeypatch):
    monkeypatch.setattr("app.DEMO_MODE_ONLY", True)

    response = client.post("/api/triage", json={"target": "example.com"})
    assert response.status_code == 403
    assert "Demo Mode" in response.json()["detail"]

    # Verify samples still work in Demo Mode
    sample_res = client.get("/api/samples/bank_phish")
    assert sample_res.status_code == 200


def test_export_markdown_endpoint(client):
    sample_res = client.get("/api/samples/bank_phish")
    report_dict = sample_res.json()

    response = client.post("/api/export/markdown", json=report_dict)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert "attachment; filename=" in response.headers["content-disposition"]
    assert "# Scam & Phishing Infrastructure Triage Report" in response.text


def test_serve_frontend_index(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Scam & Phishing" in response.text


# ------------------ Security Hardening Tests ------------------

def test_security_headers_present(client):
    """Verify defense-in-depth HTTP security headers on responses."""
    response = client.get("/api/health")
    assert response.status_code == 200
    headers = response.headers

    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "no-referrer"
    assert "camera=()" in headers.get("permissions-policy", "")
    assert "default-src 'self'" in headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in headers.get("content-security-policy", "")


def test_input_validation_rejects_control_characters(client):
    """Verify inputs with newlines, carriage returns, or null bytes are rejected."""
    bad_targets = [
        "example.com\n",
        "evil.com\r\ninjected-header: true",
        "test\x00domain.com",
    ]
    for target in bad_targets:
        response = client.post("/api/triage", json={"target": target})
        assert response.status_code == 422
        assert "control characters" in response.text.lower()


def test_input_validation_rejects_unsupported_schemes(client):
    """Verify schemes other than HTTP/HTTPS are rejected."""
    bad_schemes = [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "ftp://evil.com/payload",
        "gopher://127.0.0.1:70",
        "data:text/html,<script>",
    ]
    for target in bad_schemes:
        response = client.post("/api/triage", json={"target": target})
        assert response.status_code == 422


def test_input_validation_rejects_excessive_length(client):
    """Verify overly long inputs (>2048 chars) are rejected."""
    huge_url = "https://example.com/" + "a" * 2100
    response = client.post("/api/triage", json={"target": huge_url})
    assert response.status_code == 422
