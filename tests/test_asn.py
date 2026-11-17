"""Tests for ASN and hosting enrichment."""

from unittest.mock import MagicMock
import dns.rdatatype
from triage.asn import ASNEnricher


def test_asn_enricher_cymru_dns(monkeypatch):
    enricher = ASNEnricher()

    def mock_resolve(qname, rdtype):
        mock_ans = MagicMock()
        qname_str = str(qname)
        if "origin.asn.cymru.com" in qname_str:
            txt1 = MagicMock()
            txt1.strings = [b"15169 | 8.8.8.0/24 | US | arin | 2014-03-14"]
            mock_ans.__iter__.return_value = [txt1]
            return mock_ans
        elif "asn.cymru.com" in qname_str:
            txt1 = MagicMock()
            txt1.strings = [b"15169 | US | arin | 2000-03-30 | GOOGLE, US"]
            mock_ans.__iter__.return_value = [txt1]
            return mock_ans
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(enricher.resolver, "resolve", mock_resolve)

    res = enricher.lookup_ip("8.8.8.8")
    assert res.ip == "8.8.8.8"
    assert res.defanged_ip == "8[.]8[.]8[.]8"
    assert res.asn == "AS15169"
    assert res.bgp_prefix == "8.8.8.0/24"
    assert res.country_code == "US"
    assert res.registry == "ARIN"
    assert res.as_name == "GOOGLE, US"


def test_asn_enricher_blocks_private_ip():
    enricher = ASNEnricher()
    res = enricher.lookup_ip("192.168.1.1")
    assert res.asn is None
    assert "private" in (res.error or "").lower()
