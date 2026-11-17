"""Tests for DNS resolution, SPF and DMARC extraction."""

from unittest.mock import MagicMock
import dns.rdatatype
import dns.resolver
from triage.dns_enricher import DNSEnricher


def test_dns_enricher_parses_records(monkeypatch):
    enricher = DNSEnricher()

    def mock_resolve(qname, rdtype):
        mock_ans = MagicMock()
        mock_ans.ttl = 300

        if rdtype == dns.rdatatype.A:
            item1 = MagicMock()
            item1.to_text.return_value = "93.184.216.34"
            mock_ans.__iter__.return_value = [item1]
            return mock_ans

        if rdtype == dns.rdatatype.MX:
            mx1 = MagicMock()
            mx1.exchange.to_text.return_value = "mail.example.com."
            mx1.preference = 10
            mock_ans.__iter__.return_value = [mx1]
            return mock_ans

        if rdtype == dns.rdatatype.TXT:
            if str(qname).startswith("_dmarc"):
                txt1 = MagicMock()
                txt1.strings = [b"v=DMARC1; p=reject; sp=reject;"]
                mock_ans.__iter__.return_value = [txt1]
                return mock_ans
            else:
                txt1 = MagicMock()
                txt1.strings = [b"v=spf1 -all"]
                mock_ans.__iter__.return_value = [txt1]
                return mock_ans

        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(enricher.resolver, "resolve", mock_resolve)

    records = enricher.resolve("example.com", "example.com")
    assert len(records.a_records) == 1
    assert records.a_records[0].value == "93.184.216.34"
    assert records.a_records[0].ttl == 300
    assert records.spf_record == "v=spf1 -all"
    assert records.dmarc_record == "v=DMARC1; p=reject; sp=reject;"
    assert len(records.mx_records) == 1
    assert records.mx_records[0].host == "mail.example.com"
    assert records.mx_records[0].preference == 10
    assert "93.184.216.34" in records.resolved_ips


def test_dns_enricher_handles_nxdomain(monkeypatch):
    enricher = DNSEnricher()

    def mock_resolve(qname, rdtype):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(enricher.resolver, "resolve", mock_resolve)

    records = enricher.resolve("nonexistent.invalid", "nonexistent.invalid")
    assert records.a_records == []
    assert records.spf_record is None
    assert records.dmarc_record is None
