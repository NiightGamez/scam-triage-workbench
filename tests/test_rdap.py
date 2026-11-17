"""Tests for RDAP parsing and domain age calculations."""

from unittest.mock import MagicMock
from triage.network import SafeHttpClient
from triage.rdap import RDAPEnricher


def test_rdap_parses_dates_and_registrar():
    mock_client = MagicMock(spec=SafeHttpClient)
    enricher = RDAPEnricher(client=mock_client)

    sample_rdap = {
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:38Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "RESERVED-Internet Assigned Numbers Authority"],
                    ],
                ],
            }
        ],
        "status": ["clientDeleteProhibited", "clientTransferProhibited"],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = sample_rdap
    mock_client.get_with_validated_redirects.return_value = mock_resp

    info = enricher.lookup_domain("example.com")
    assert info.queried is True
    assert info.registrar == "RESERVED-Internet Assigned Numbers Authority"
    assert info.creation_date == "1995-08-14T04:00:00Z"
    assert info.expiration_date == "2030-08-13T04:00:00Z"
    assert info.age_days is not None
    assert info.age_days > 10000
    assert info.days_until_expiration is not None
    assert info.days_until_expiration > 0
    assert "clientDeleteProhibited" in info.status


def test_rdap_handles_404_not_found():
    mock_client = MagicMock(spec=SafeHttpClient)
    enricher = RDAPEnricher(client=mock_client)

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_client.get_with_validated_redirects.return_value = mock_resp

    info = enricher.lookup_domain("unregistered-domain-12345.xyz")
    assert info.queried is True
    assert "unregistered" in (info.error or "").lower()
