"""Tests for Certificate Transparency discovery via crt.sh."""

from unittest.mock import MagicMock
from triage.ct_logs import CTEnricher
from triage.network import SafeHttpClient


def test_ct_enricher_parses_subdomains():
    mock_client = MagicMock(spec=SafeHttpClient)
    enricher = CTEnricher(client=mock_client)

    sample_crt_data = [
        {
            "id": 1,
            "common_name": "example.com",
            "name_value": "*.example.com\nexample.com",
        },
        {
            "id": 2,
            "common_name": "login.example.com",
            "name_value": "login.example.com\napi.example.com",
        },
        {
            "id": 3,
            "common_name": "dev.admin.example.com",
            "name_value": "dev.admin.example.com",
        },
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = sample_crt_data
    mock_client.get.return_value = mock_resp

    discovery = enricher.discover_subdomains("example.com")
    assert discovery.queried is True
    assert discovery.subdomain_count == 3
    assert discovery.subdomains == ["api.example.com", "dev.admin.example.com", "login.example.com"]


def test_ct_enricher_handles_http_error():
    mock_client = MagicMock(spec=SafeHttpClient)
    enricher = CTEnricher(client=mock_client)

    mock_resp = MagicMock()
    mock_resp.status_code = 504
    mock_client.get.return_value = mock_resp

    discovery = enricher.discover_subdomains("example.com")
    assert discovery.queried is True
    assert "504" in (discovery.error or "")
