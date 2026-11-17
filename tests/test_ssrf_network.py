"""Tests for SSRF guardrails, private IP blocking, timeouts, and redirect controls."""

from unittest.mock import MagicMock, patch
import pytest

from triage.network import (
    DEFAULT_TIMEOUT_SECONDS,
    DirectTargetAccessForbiddenError,
    SafeHttpClient,
    SSRFProtectionError,
    is_private_or_reserved_ip,
    resolve_and_validate_host,
)


def test_is_private_or_reserved_ip():
    # RFC 1918 Private ranges
    assert is_private_or_reserved_ip("10.0.0.1")[0] is True
    assert is_private_or_reserved_ip("172.16.0.1")[0] is True
    assert is_private_or_reserved_ip("172.31.255.255")[0] is True
    assert is_private_or_reserved_ip("192.168.1.100")[0] is True

    # Loopback
    assert is_private_or_reserved_ip("127.0.0.1")[0] is True
    assert is_private_or_reserved_ip("127.0.1.1")[0] is True
    assert is_private_or_reserved_ip("::1")[0] is True

    # Link-local / Cloud metadata
    assert is_private_or_reserved_ip("169.254.169.254")[0] is True
    assert is_private_or_reserved_ip("fe80::1")[0] is True

    # Carrier Grade NAT
    assert is_private_or_reserved_ip("100.64.0.1")[0] is True

    # Documentation ranges
    assert is_private_or_reserved_ip("192.0.2.1")[0] is True
    assert is_private_or_reserved_ip("198.51.100.1")[0] is True
    assert is_private_or_reserved_ip("203.0.113.1")[0] is True

    # Public IP Addresses (should pass)
    assert is_private_or_reserved_ip("8.8.8.8")[0] is False
    assert is_private_or_reserved_ip("1.1.1.1")[0] is False
    assert is_private_or_reserved_ip("93.184.216.34")[0] is False


def test_resolve_and_validate_host_blocks_metadata_host():
    with pytest.raises(SSRFProtectionError, match="metadata"):
        resolve_and_validate_host("metadata.google.internal")


def test_resolve_and_validate_host_blocks_resolved_private_ip(monkeypatch):
    # Mock socket.getaddrinfo to return a private IP
    def mock_getaddrinfo(host, port):
        return [(2, 1, 6, "", ("192.168.1.5", 80))]

    monkeypatch.setattr("socket.getaddrinfo", mock_getaddrinfo)
    with pytest.raises(SSRFProtectionError, match="Private IP address blocked"):
        resolve_and_validate_host("internal.corp")


def test_direct_target_access_forbidden():
    client = SafeHttpClient(target_host="evil-scam.com")

    # Attempting to fetch target domain directly should raise DirectTargetAccessForbiddenError
    with pytest.raises(DirectTargetAccessForbiddenError):
        client.get("https://evil-scam.com/payload")

    # Attempting to fetch subdomain of target should also be blocked
    with pytest.raises(DirectTargetAccessForbiddenError):
        client.get("https://login.evil-scam.com/token")


def test_direct_target_ip_access_forbidden(monkeypatch):
    client = SafeHttpClient(target_host="target.com", target_ips={"93.184.216.34"})

    # Host resolves to target IP
    def mock_getaddrinfo(host, port):
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("socket.getaddrinfo", mock_getaddrinfo)

    with pytest.raises(DirectTargetAccessForbiddenError):
        client.get("https://some-proxy.com/api")


def test_timeout_capped_at_five_seconds():
    client = SafeHttpClient(timeout=10.0)
    assert client.timeout == DEFAULT_TIMEOUT_SECONDS


def test_safe_http_client_disables_redirects(monkeypatch):
    client = SafeHttpClient()

    def mock_getaddrinfo(host, port):
        return [(2, 1, 6, "", ("8.8.8.8", 443))]

    monkeypatch.setattr("socket.getaddrinfo", mock_getaddrinfo)

    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    with patch.object(client.session, "get", return_value=mock_resp) as mock_get:
        resp = client.get("https://rdap.org/domain/example.com")
        # Ensure allow_redirects=False was passed
        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        assert kwargs["allow_redirects"] is False
        assert resp.status_code == 302


def test_validated_redirects_blocks_malicious_hop(monkeypatch):
    client = SafeHttpClient()

    # Step 1: rdap.org resolves to public IP
    # Step 2: Redirect Location points to private IP
    def mock_getaddrinfo(host, port):
        if host == "rdap.org":
            return [(2, 1, 6, "", ("1.1.1.1", 443))]
        elif host == "internal.evil.com":
            return [(2, 1, 6, "", ("10.0.0.5", 443))]
        return [(2, 1, 6, "", ("8.8.8.8", 443))]

    monkeypatch.setattr("socket.getaddrinfo", mock_getaddrinfo)

    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"Location": "https://internal.evil.com/registry"}

    with patch.object(client.session, "get", return_value=mock_resp):
        with pytest.raises(SSRFProtectionError, match="Private IP address blocked"):
            client.get_with_validated_redirects("https://rdap.org/domain/example.com")


def test_triage_engine_rejects_private_and_loopback_targets():
    from triage.engine import TriageEngine

    engine = TriageEngine()

    with pytest.raises(SSRFProtectionError, match="Loopback address blocked"):
        engine.triage("127.0.0.1")

    with pytest.raises(SSRFProtectionError, match="Private IP address blocked"):
        engine.triage("192.168.1.1")

    with pytest.raises(SSRFProtectionError, match="Private IP address blocked"):
        engine.triage("hxxp://10.0.0.1/admin")

    with pytest.raises(SSRFProtectionError, match="Cloud metadata IP address blocked"):
        engine.triage("169.254.169.254")

    with pytest.raises(SSRFProtectionError, match="loopback/metadata host"):
        engine.triage("http://localhost:8080/secret")

