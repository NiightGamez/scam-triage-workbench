"""Pre-loaded sample phishing and benign triage reports for Demo Mode."""

from __future__ import annotations

from typing import Dict, List, Optional
from triage.models import (
    CTDiscovery,
    DNSRecordItem,
    DNSRecords,
    IPEnrichment,
    MXRecordItem,
    RDAPInfo,
    RiskAssessment,
    RiskFlag,
    RiskSeverity,
    RiskTier,
    TargetMetadata,
    TargetType,
    TriageReport,
)

SAMPLE_1_BANK_PHISH = TriageReport(
    target=TargetMetadata(
        raw_target="hxxps://chase-secure-verify[.]top/auth/login",
        normalized_target="https://chase-secure-verify.top/auth/login",
        defanged_target="hxxps://chase-secure-verify[.]top/auth/login",
        target_type=TargetType.URL,
        scheme="https",
        host="chase-secure-verify.top",
        defanged_host="chase-secure-verify[.]top",
        domain="chase-secure-verify.top",
        subdomain=None,
        suffix="top",
        path="/auth/login",
    ),
    timestamp="2026-11-16T19:30:00Z",
    dns=DNSRecords(
        a_records=[
            DNSRecordItem(value="185.220.101.5", ttl=30),
            DNSRecordItem(value="185.220.101.6", ttl=30),
        ],
        aaaa_records=[],
        mx_records=[],
        ns_records=["ns1.bulletproof-dns.is", "ns2.bulletproof-dns.is"],
        txt_records=[],
        spf_record=None,
        dmarc_record=None,
        min_ttl=30,
        resolved_ips=["185.220.101.5", "185.220.101.6"],
    ),
    rdap=RDAPInfo(
        queried=True,
        registrar="NameSilo, LLC",
        creation_date="2026-11-13T10:15:22Z",
        expiration_date="2027-11-13T10:15:22Z",
        updated_date="2026-11-13T11:00:10Z",
        age_days=3,
        days_until_expiration=362,
        status=["clientTransferProhibited", "addPeriod"],
    ),
    ct_logs=CTDiscovery(
        queried=True,
        subdomain_count=3,
        subdomains=[
            "m.chase-secure-verify.top",
            "online.chase-secure-verify.top",
            "portal.chase-secure-verify.top",
        ],
    ),
    ip_enrichments=[
        IPEnrichment(
            ip="185.220.101.5",
            defanged_ip="185[.]220[.]101[.]5",
            asn="AS20473",
            as_name="CHOOPA - The Constant Company, LLC",
            bgp_prefix="185.220.100.0/22",
            country_code="US",
            registry="RIPE",
            allocated_date="2018-04-12",
        ),
        IPEnrichment(
            ip="185.220.101.6",
            defanged_ip="185[.]220[.]101[.]6",
            asn="AS20473",
            as_name="CHOOPA - The Constant Company, LLC",
            bgp_prefix="185.220.100.0/22",
            country_code="US",
            registry="RIPE",
            allocated_date="2018-04-12",
        ),
    ],
    risk_assessment=RiskAssessment(
        score=85,
        tier=RiskTier.CRITICAL,
        flags=[
            RiskFlag(
                id="DOMAIN_NEW_REGISTRATION",
                name="Newly Registered Domain (<30 days)",
                severity=RiskSeverity.HIGH,
                score_impact=25,
                description="Domain was registered only 3 day(s) ago (high phishing correlation).",
                evidence="Age: 3 days (Created: 2026-11-13T10:15:22Z)",
            ),
            RiskFlag(
                id="SUSPICIOUS_KEYWORDS",
                name="Suspicious Phishing/Credential Keywords Detected",
                severity=RiskSeverity.HIGH,
                score_impact=20,
                description="Target infrastructure or discovered subdomains contain high-risk scam or credential-harvesting keywords.",
                evidence="Matched keywords: auth, chase, login, portal, secure, verify",
            ),
            RiskFlag(
                id="FAST_FLUX_INDICATOR",
                name="Potential Fast-Flux DNS Configuration",
                severity=RiskSeverity.MEDIUM,
                score_impact=15,
                description="DNS A records exhibit an unusually low TTL (30s) with multiple IPs.",
                evidence="Min TTL: 30s, A records: 2",
            ),
            RiskFlag(
                id="SPF_MISSING",
                name="Missing SPF Authentication Record",
                severity=RiskSeverity.MEDIUM,
                score_impact=15,
                description="Domain has no published SPF (Sender Policy Framework) TXT record, allowing unauthorized email spoofing.",
                evidence="No v=spf1 TXT record found",
            ),
            RiskFlag(
                id="DMARC_MISSING",
                name="Missing DMARC Policy Record",
                severity=RiskSeverity.MEDIUM,
                score_impact=15,
                description="Domain lacks a _dmarc TXT record. Receivers cannot verify email authenticity or handle spoofing.",
                evidence="No _dmarc TXT record found",
            ),
            RiskFlag(
                id="SUSPICIOUS_TLD",
                name="High-Abuse Top-Level Domain",
                severity=RiskSeverity.LOW,
                score_impact=10,
                description="Top-level domain .top has high prevalence in phishing and abuse campaigns.",
                evidence="TLD: .top",
            ),
        ],
    ),
)


SAMPLE_2_CRYPTO_DRAINER = TriageReport(
    target=TargetMetadata(
        raw_target="hxxps://claim-metamask-airdrop-rewards[.]xyz/connect-wallet",
        normalized_target="https://claim-metamask-airdrop-rewards.xyz/connect-wallet",
        defanged_target="hxxps://claim-metamask-airdrop-rewards[.]xyz/connect-wallet",
        target_type=TargetType.URL,
        scheme="https",
        host="claim-metamask-airdrop-rewards.xyz",
        defanged_host="claim-metamask-airdrop-rewards[.]xyz",
        domain="claim-metamask-airdrop-rewards.xyz",
        subdomain=None,
        suffix="xyz",
        path="/connect-wallet",
    ),
    timestamp="2026-11-16T18:45:00Z",
    dns=DNSRecords(
        a_records=[
            DNSRecordItem(value="104.21.45.101", ttl=300),
            DNSRecordItem(value="172.67.180.20", ttl=300),
        ],
        aaaa_records=[
            DNSRecordItem(value="2606:4700:3033::6815:2d65", ttl=300),
        ],
        mx_records=[],
        ns_records=["dora.ns.cloudflare.com", "todd.ns.cloudflare.com"],
        txt_records=["v=spf1 include:_spf.mx.cloudflare.net ~all"],
        spf_record="v=spf1 include:_spf.mx.cloudflare.net ~all",
        dmarc_record="v=DMARC1; p=none;",
        min_ttl=300,
        resolved_ips=["104.21.45.101", "172.67.180.20"],
    ),
    rdap=RDAPInfo(
        queried=True,
        registrar="Hostinger, UAB",
        creation_date="2026-11-04T14:20:00Z",
        expiration_date="2027-11-04T14:20:00Z",
        updated_date="2026-11-04T15:00:00Z",
        age_days=12,
        days_until_expiration=353,
        status=["clientTransferProhibited"],
    ),
    ct_logs=CTDiscovery(
        queried=True,
        subdomain_count=64,
        subdomains=[
            "airdrop.claim-metamask-airdrop-rewards.xyz",
            "app.claim-metamask-airdrop-rewards.xyz",
            "auth.claim-metamask-airdrop-rewards.xyz",
            "connect.claim-metamask-airdrop-rewards.xyz",
            "dapp.claim-metamask-airdrop-rewards.xyz",
            "drop.claim-metamask-airdrop-rewards.xyz",
            "eth.claim-metamask-airdrop-rewards.xyz",
            "sync.claim-metamask-airdrop-rewards.xyz",
            "wallet.claim-metamask-airdrop-rewards.xyz",
            "web3.claim-metamask-airdrop-rewards.xyz",
        ],
    ),
    ip_enrichments=[
        IPEnrichment(
            ip="104.21.45.101",
            defanged_ip="104[.]21[.]45[.]101",
            asn="AS13335",
            as_name="CLOUDFLARENET - Cloudflare, Inc.",
            bgp_prefix="104.21.32.0/20",
            country_code="US",
            registry="ARIN",
            allocated_date="2014-03-28",
        ),
    ],
    risk_assessment=RiskAssessment(
        score=75,
        tier=RiskTier.CRITICAL,
        flags=[
            RiskFlag(
                id="DOMAIN_NEW_REGISTRATION",
                name="Newly Registered Domain (<30 days)",
                severity=RiskSeverity.HIGH,
                score_impact=25,
                description="Domain was registered only 12 day(s) ago (high phishing correlation).",
                evidence="Age: 12 days (Created: 2026-11-04T14:20:00Z)",
            ),
            RiskFlag(
                id="SUSPICIOUS_KEYWORDS",
                name="Suspicious Phishing/Credential Keywords Detected",
                severity=RiskSeverity.HIGH,
                score_impact=20,
                description="Target infrastructure or discovered subdomains contain high-risk scam or credential-harvesting keywords.",
                evidence="Matched keywords: auth, metamask, wallet",
            ),
            RiskFlag(
                id="HIGH_SUBDOMAIN_VOLUME_YOUNG_DOMAIN",
                name="High Subdomain Volume on Recent Domain",
                severity=RiskSeverity.MEDIUM,
                score_impact=10,
                description="Domain has generated 64 subdomains within 12 days of registration.",
                evidence="Subdomains: 64, Age: 12 days",
            ),
            RiskFlag(
                id="SUSPICIOUS_TLD",
                name="High-Abuse Top-Level Domain",
                severity=RiskSeverity.LOW,
                score_impact=10,
                description="Top-level domain .xyz has high prevalence in phishing and abuse campaigns.",
                evidence="TLD: .xyz",
            ),
            RiskFlag(
                id="DMARC_PERMISSIVE_POLICY",
                name="Permissive DMARC Policy (p=none)",
                severity=RiskSeverity.LOW,
                score_impact=5,
                description="DMARC policy is set to 'p=none' (monitoring only; spoofed emails will not be rejected or quarantined).",
                evidence="v=DMARC1; p=none;",
            ),
        ],
    ),
)


SAMPLE_3_BENIGN = TriageReport(
    target=TargetMetadata(
        raw_target="example.com",
        normalized_target="example.com",
        defanged_target="example[.]com",
        target_type=TargetType.DOMAIN,
        scheme=None,
        host="example.com",
        defanged_host="example[.]com",
        domain="example.com",
        subdomain=None,
        suffix="com",
    ),
    timestamp="2026-11-16T17:00:00Z",
    dns=DNSRecords(
        a_records=[
            DNSRecordItem(value="104.20.23.154", ttl=300),
            DNSRecordItem(value="172.66.147.243", ttl=300),
        ],
        aaaa_records=[
            DNSRecordItem(value="2606:4700:10::6814:179a", ttl=300),
            DNSRecordItem(value="2606:4700:10::ac42:93f3", ttl=300),
        ],
        mx_records=[
            MXRecordItem(host=". (Null MX - RFC 7505)", preference=0, ttl=300),
        ],
        ns_records=["hera.ns.cloudflare.com", "elliott.ns.cloudflare.com"],
        txt_records=["v=spf1 -all"],
        spf_record="v=spf1 -all",
        dmarc_record="v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s",
        min_ttl=300,
        resolved_ips=["104.20.23.154", "172.66.147.243"],
    ),
    rdap=RDAPInfo(
        queried=True,
        registrar="RESERVED-Internet Assigned Numbers Authority",
        creation_date="1995-08-14T04:00:00Z",
        expiration_date="2027-08-13T04:00:00Z",
        updated_date="2026-08-14T08:01:43Z",
        age_days=11417,
        days_until_expiration=269,
        status=["clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"],
    ),
    ct_logs=CTDiscovery(
        queried=True,
        subdomain_count=6,
        subdomains=[
            "dev.example.com",
            "emudhra-lab.example.com",
            "m.example.com",
            "products.example.com",
            "support.example.com",
            "www.example.com",
        ],
    ),
    ip_enrichments=[
        IPEnrichment(
            ip="104.20.23.154",
            defanged_ip="104[.]20[.]23[.]154",
            asn="AS13335",
            as_name="CLOUDFLARENET - Cloudflare, Inc., US",
            bgp_prefix="104.20.16.0/20",
            country_code="US",
            registry="ARIN",
        ),
    ],
    risk_assessment=RiskAssessment(
        score=20,
        tier=RiskTier.LOW,
        flags=[
            RiskFlag(
                id="SUSPICIOUS_KEYWORDS",
                name="Suspicious Phishing/Credential Keywords Detected",
                severity=RiskSeverity.HIGH,
                score_impact=20,
                description="Target infrastructure or discovered subdomains contain high-risk scam or credential-harvesting keywords.",
                evidence="Matched keywords: support",
            ),
        ],
    ),
)


SAMPLES_DICT: Dict[str, TriageReport] = {
    "bank_phish": SAMPLE_1_BANK_PHISH,
    "crypto_drainer": SAMPLE_2_CRYPTO_DRAINER,
    "benign_baseline": SAMPLE_3_BENIGN,
}

SAMPLE_METADATA = [
    {
        "id": "bank_phish",
        "title": "Case 1: Bank Credential Harvest (Chase Spoof)",
        "subtitle": "Newly registered .top domain with fast-flux DNS and missing email auth.",
        "target": "hxxps://chase-secure-verify[.]top/auth/login",
        "risk_score": 85,
        "risk_tier": "CRITICAL",
        "badge_color": "rose",
    },
    {
        "id": "crypto_drainer",
        "title": "Case 2: Crypto Wallet Drainer (MetaMask Airdrop Kit)",
        "subtitle": "Wildcard CT subdomain churn on .xyz TLD with permissive DMARC.",
        "target": "hxxps://claim-metamask-airdrop-rewards[.]xyz/connect-wallet",
        "risk_score": 75,
        "risk_tier": "CRITICAL",
        "badge_color": "rose",
    },
    {
        "id": "benign_baseline",
        "title": "Case 3: Benign Reference Domain (example.com)",
        "subtitle": "Long-standing historical stability, RFC 7505 Null MX, and strict DMARC reject.",
        "target": "example[.]com",
        "risk_score": 20,
        "risk_tier": "LOW",
        "badge_color": "emerald",
    },
]


def get_sample_summaries() -> List[dict]:
    """Return summary list of all available sample cases."""
    return SAMPLE_METADATA


def get_sample_report(sample_id: str) -> Optional[TriageReport]:
    """Retrieve complete pre-populated TriageReport for a given sample ID."""
    return SAMPLES_DICT.get(sample_id)
