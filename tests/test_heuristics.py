"""Tests for heuristic risk flags and scoring engine."""

from triage.defang import parse_target
from triage.heuristics import HeuristicEngine
from triage.models import CTDiscovery, DNSRecordItem, DNSRecords, RDAPInfo, RiskSeverity, RiskTier


def test_heuristic_benign_domain():
    target = parse_target("example.com")
    dns = DNSRecords(
        a_records=[DNSRecordItem(value="93.184.216.34", ttl=3600)],
        spf_record="v=spf1 -all",
        dmarc_record="v=DMARC1; p=reject;",
    )
    rdap = RDAPInfo(
        age_days=10000,
        creation_date="1995-08-14T04:00:00Z",
        days_until_expiration=1500,
    )
    ct = CTDiscovery(subdomain_count=2, subdomains=["api.example.com"])

    engine = HeuristicEngine()
    assessment = engine.evaluate(target, dns, rdap, ct)

    assert assessment.score == 0
    assert assessment.tier == RiskTier.LOW
    assert len(assessment.flags) == 0


def test_heuristic_high_risk_scam_domain():
    target = parse_target("hxxps://login-secure-appleid-verification[.]top/auth")
    dns = DNSRecords(
        a_records=[
            DNSRecordItem(value="1.2.3.4", ttl=30),
            DNSRecordItem(value="1.2.3.5", ttl=30),
        ],
        spf_record=None,  # Missing SPF
        dmarc_record=None,  # Missing DMARC
        min_ttl=30,  # Fast flux
    )
    rdap = RDAPInfo(
        age_days=5,  # Registered 5 days ago!
        creation_date="2026-11-10T00:00:00Z",
        days_until_expiration=25,  # Expiring soon
    )
    ct = CTDiscovery(
        subdomain_count=60,
        subdomains=["billing.login-secure-appleid-verification.top"],
    )

    engine = HeuristicEngine()
    assessment = engine.evaluate(target, dns, rdap, ct)

    assert assessment.score >= 75
    assert assessment.tier == RiskTier.CRITICAL

    flag_ids = {f.id for f in assessment.flags}
    assert "DOMAIN_NEW_REGISTRATION" in flag_ids
    assert "SUSPICIOUS_KEYWORDS" in flag_ids
    assert "SUSPICIOUS_TLD" in flag_ids
    assert "FAST_FLUX_INDICATOR" in flag_ids
    assert "SPF_MISSING" in flag_ids
    assert "DMARC_MISSING" in flag_ids


def test_heuristic_permissive_spf_and_dmarc():
    target = parse_target("some-domain.com")
    dns = DNSRecords(
        a_records=[DNSRecordItem(value="93.184.216.34", ttl=300)],
        spf_record="v=spf1 +all",
        dmarc_record="v=DMARC1; p=none;",
    )
    rdap = RDAPInfo(age_days=500)

    engine = HeuristicEngine()
    assessment = engine.evaluate(target, dns, rdap)

    flag_ids = {f.id for f in assessment.flags}
    assert "SPF_PERMISSIVE_ALL" in flag_ids
    assert "DMARC_PERMISSIVE_POLICY" in flag_ids
