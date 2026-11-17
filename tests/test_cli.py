"""Tests for CLI entrypoint and report formatting."""

import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import MagicMock, patch

from triage.engine import TriageEngine
from triage.models import (
    CTDiscovery,
    DNSRecordItem,
    DNSRecords,
    IPEnrichment,
    RDAPInfo,
    RiskAssessment,
    RiskTier,
    TargetMetadata,
    TargetType,
    TriageReport,
)
from triage.reporter import to_json, to_markdown

# Import triage.py CLI script explicitly
triage_script_path = Path(__file__).parent.parent / "triage.py"
spec = importlib.util.spec_from_file_location("triage_script", triage_script_path)
triage_cli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(triage_cli)


def sample_report() -> TriageReport:
    target = TargetMetadata(
        raw_target="hxxp://suspicious-login[.]xyz/verify",
        normalized_target="http://suspicious-login.xyz/verify",
        defanged_target="hxxp://suspicious-login[.]xyz/verify",
        target_type=TargetType.URL,
        scheme="http",
        host="suspicious-login.xyz",
        defanged_host="suspicious-login[.]xyz",
        domain="suspicious-login.xyz",
        subdomain=None,
        suffix="xyz",
        path="/verify",
    )
    dns = DNSRecords(
        a_records=[DNSRecordItem(value="1.2.3.4", ttl=300)],
        spf_record=None,
        dmarc_record=None,
        resolved_ips=["1.2.3.4"],
    )
    rdap = RDAPInfo(
        queried=True,
        registrar="NameCheap",
        creation_date="2026-11-01T00:00:00Z",
        age_days=15,
        days_until_expiration=350,
    )
    ct = CTDiscovery(
        queried=True,
        subdomain_count=1,
        subdomains=["admin.suspicious-login.xyz"],
    )
    ip_e = [
        IPEnrichment(
            ip="1.2.3.4",
            defanged_ip="1[.]2[.]3[.]4",
            asn="AS12345",
            as_name="HOSTING-CO",
            country_code="US",
            bgp_prefix="1.2.3.0/24",
        )
    ]
    ra = RiskAssessment(
        score=60,
        tier=RiskTier.HIGH,
        flags=[],
    )
    return TriageReport(
        target=target,
        timestamp="2026-11-16T20:00:00Z",
        dns=dns,
        rdap=rdap,
        ct_logs=ct,
        ip_enrichments=ip_e,
        risk_assessment=ra,
    )


def test_to_json_valid_schema():
    rep = sample_report()
    json_str = to_json(rep)
    data = json.loads(json_str)
    assert data["target"]["defanged_target"] == "hxxp://suspicious-login[.]xyz/verify"
    assert data["risk_assessment"]["score"] == 60
    assert data["dns"]["resolved_ips"] == ["1.2.3.4"]


def test_to_markdown_contains_key_sections():
    rep = sample_report()
    md = to_markdown(rep)
    assert "# Scam & Phishing Infrastructure Triage Report" in md
    assert "hxxp://suspicious-login[.]xyz/verify" in md
    assert "Passive DNS Infrastructure" in md
    assert "Domain Registration & RDAP" in md
    assert "Hosting Infrastructure & ASN" in md
    assert "SSRF Guardrail Statement" in md


def test_cli_end_to_end(tmp_path):
    report_file = tmp_path / "test_report.md"
    rep = sample_report()

    test_args = [
        "triage.py",
        "hxxp://suspicious-login[.]xyz/verify",
        "-o",
        str(report_file),
        "-f",
        "markdown",
        "-q",
    ]

    with patch.object(sys, "argv", test_args):
        with patch.object(TriageEngine, "triage", return_value=rep):
            ret = triage_cli.main()
            assert ret == 0
            assert report_file.exists()
            content = report_file.read_text()
            assert "Scam & Phishing Infrastructure Triage Report" in content
            assert "hxxp://suspicious-login[.]xyz/verify" in content


def test_cli_json_export(tmp_path):
    json_file = tmp_path / "test_report.json"
    rep = sample_report()

    test_args = [
        "triage.py",
        "hxxp://suspicious-login[.]xyz/verify",
        "-o",
        str(json_file),
        "-f",
        "json",
        "-q",
    ]

    with patch.object(sys, "argv", test_args):
        with patch.object(TriageEngine, "triage", return_value=rep):
            ret = triage_cli.main()
            assert ret == 0
            assert json_file.exists()
            data = json.loads(json_file.read_text())
            assert data["target"]["host"] == "suspicious-login.xyz"
