"""Automated heuristic risk flags and scoring engine."""

from __future__ import annotations

import re
from typing import List, Optional, Set

from triage.models import (
    CTDiscovery,
    DNSRecords,
    IPEnrichment,
    RDAPInfo,
    RiskAssessment,
    RiskFlag,
    RiskSeverity,
    RiskTier,
    TargetMetadata,
    TargetType,
)

SUSPICIOUS_KEYWORDS = {
    "login", "log-in", "signin", "sign-in", "verify", "verification",
    "secure", "security", "account", "banking", "wallet", "update",
    "support", "auth", "authenticate", "recover", "recovery", "billing",
    "invoice", "appleid", "paypal", "metamask", "coinbase", "binance",
    "chase", "wellsfargo", "bankofamerica", "netflix", "microsoft",
    "office365", "portal", "password", "credential",
}

SUSPICIOUS_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "icu", "buzz",
    "cfd", "sbs", "rest", "work", "loan", "click", "link", "country",
    "surf", "casa", "bar", "lat", "cam",
}

STANDARD_PORTS = {80, 443}


class HeuristicEngine:
    """Evaluates passive infrastructure artifacts and generates risk flags."""

    def evaluate(
        self,
        target: TargetMetadata,
        dns: DNSRecords,
        rdap: Optional[RDAPInfo] = None,
        ct_logs: Optional[CTDiscovery] = None,
        ip_enrichments: Optional[List[IPEnrichment]] = None,
    ) -> RiskAssessment:
        flags: List[RiskFlag] = []

        # 1. Target Type: Raw IP Target
        if target.target_type == TargetType.IP:
            flags.append(
                RiskFlag(
                    id="RAW_IP_TARGET",
                    name="Direct IP Address Target",
                    severity=RiskSeverity.MEDIUM,
                    score_impact=15,
                    description="Target is referenced by raw IP address rather than a domain name.",
                    evidence=f"Target: {target.defanged_host}",
                )
            )

        # 2. Non-standard Port
        if target.port and target.port not in STANDARD_PORTS:
            flags.append(
                RiskFlag(
                    id="SUSPICIOUS_PORT",
                    name="Non-Standard Web Port",
                    severity=RiskSeverity.LOW,
                    score_impact=5,
                    description=f"Target URL specifies non-standard web port {target.port}.",
                    evidence=f"Port: {target.port}",
                )
            )

        # 3. Suspicious / High-Abuse TLD
        if target.suffix and target.suffix.lower() in SUSPICIOUS_TLDS:
            flags.append(
                RiskFlag(
                    id="SUSPICIOUS_TLD",
                    name="High-Abuse Top-Level Domain",
                    severity=RiskSeverity.LOW,
                    score_impact=10,
                    description=f"Top-level domain .{target.suffix} has high prevalence in phishing and abuse campaigns.",
                    evidence=f"TLD: .{target.suffix}",
                )
            )

        # 4. Domain Age & Registration Heuristics
        if rdap and rdap.age_days is not None:
            if rdap.age_days < 30:
                flags.append(
                    RiskFlag(
                        id="DOMAIN_NEW_REGISTRATION",
                        name="Newly Registered Domain (<30 days)",
                        severity=RiskSeverity.HIGH,
                        score_impact=25,
                        description=f"Domain was registered only {rdap.age_days} day(s) ago (high phishing correlation).",
                        evidence=f"Age: {rdap.age_days} days (Created: {rdap.creation_date})",
                    )
                )
            elif rdap.age_days < 90:
                flags.append(
                    RiskFlag(
                        id="DOMAIN_RECENT_REGISTRATION",
                        name="Recently Registered Domain (<90 days)",
                        severity=RiskSeverity.MEDIUM,
                        score_impact=15,
                        description=f"Domain was registered recently ({rdap.age_days} days ago).",
                        evidence=f"Age: {rdap.age_days} days (Created: {rdap.creation_date})",
                    )
                )

        if rdap and rdap.days_until_expiration is not None:
            if 0 <= rdap.days_until_expiration <= 30:
                flags.append(
                    RiskFlag(
                        id="DOMAIN_EXPIRING_SOON",
                        name="Domain Expiring Soon (<=30 days)",
                        severity=RiskSeverity.LOW,
                        score_impact=5,
                        description=f"Domain expires in {rdap.days_until_expiration} day(s). Short-lived domains are often abandoned after campaigns.",
                        evidence=f"Expires: {rdap.expiration_date} ({rdap.days_until_expiration} days left)",
                    )
                )

        # 5. DNS Resolution Status & Fast-Flux
        if not dns.a_records and not dns.aaaa_records and target.target_type != TargetType.IP:
            flags.append(
                RiskFlag(
                    id="NO_RESOLVING_IPS",
                    name="No Resolving IP Records",
                    severity=RiskSeverity.LOW,
                    score_impact=5,
                    description="Domain currently does not resolve to any active IPv4/IPv6 addresses (may be parked, sinkholed, or unconfigured).",
                    evidence="0 A/AAAA records returned",
                )
            )

        if dns.min_ttl is not None and dns.min_ttl < 60 and len(dns.a_records) > 1:
            flags.append(
                RiskFlag(
                    id="FAST_FLUX_INDICATOR",
                    name="Potential Fast-Flux DNS Configuration",
                    severity=RiskSeverity.MEDIUM,
                    score_impact=15,
                    description=f"DNS A records exhibit an unusually low TTL ({dns.min_ttl}s) with multiple IPs.",
                    evidence=f"Min TTL: {dns.min_ttl}s, A records: {len(dns.a_records)}",
                )
            )

        # 6. Email Authentication (SPF / DMARC)
        if target.target_type != TargetType.IP:
            # SPF Record Check
            if not dns.spf_record:
                flags.append(
                    RiskFlag(
                        id="SPF_MISSING",
                        name="Missing SPF Authentication Record",
                        severity=RiskSeverity.MEDIUM,
                        score_impact=15,
                        description="Domain has no published SPF (Sender Policy Framework) TXT record, allowing unauthorized email spoofing.",
                        evidence="No v=spf1 TXT record found",
                    )
                )
            else:
                # Check for permissive SPF mechanisms (+all or ?all)
                clean_spf = dns.spf_record.strip().lower()
                if "+all" in clean_spf:
                    flags.append(
                        RiskFlag(
                            id="SPF_PERMISSIVE_ALL",
                            name="Overly Permissive SPF (+all)",
                            severity=RiskSeverity.HIGH,
                            score_impact=15,
                            description="SPF record permits ANY host to send email on behalf of the domain (+all).",
                            evidence=dns.spf_record,
                        )
                    )
                elif "?all" in clean_spf:
                    flags.append(
                        RiskFlag(
                            id="SPF_NEUTRAL_ALL",
                            name="Neutral SPF Policy (?all)",
                            severity=RiskSeverity.LOW,
                            score_impact=5,
                            description="SPF record specifies neutral (?all) rather than a hard or soft fail (~all / -all).",
                            evidence=dns.spf_record,
                        )
                    )

            # DMARC Record Check
            if not dns.dmarc_record:
                flags.append(
                    RiskFlag(
                        id="DMARC_MISSING",
                        name="Missing DMARC Policy Record",
                        severity=RiskSeverity.MEDIUM,
                        score_impact=15,
                        description="Domain lacks a _dmarc TXT record. Receivers cannot verify email authenticity or handle spoofing.",
                        evidence="No _dmarc TXT record found",
                    )
                )
            else:
                # Check for p=none policy
                clean_dmarc = dns.dmarc_record.lower()
                if re.search(r"p\s*=\s*none(\s*;|$)", clean_dmarc):
                    flags.append(
                        RiskFlag(
                            id="DMARC_PERMISSIVE_POLICY",
                            name="Permissive DMARC Policy (p=none)",
                            severity=RiskSeverity.LOW,
                            score_impact=5,
                            description="DMARC policy is set to 'p=none' (monitoring only; spoofed emails will not be rejected or quarantined).",
                            evidence=dns.dmarc_record,
                        )
                    )

        # 7. Suspicious Keywords in Host, Subdomain, Path, or CT Subdomains
        matched_keywords: Set[str] = set()
        text_to_search = f"{target.host} {target.path or ''} {target.query or ''}".lower()

        # Check in URL/host
        for kw in SUSPICIOUS_KEYWORDS:
            if kw in text_to_search:
                matched_keywords.add(kw)

        # Check in CT subdomains
        if ct_logs and ct_logs.subdomains:
            for sub in ct_logs.subdomains:
                for kw in SUSPICIOUS_KEYWORDS:
                    if kw in sub.lower():
                        matched_keywords.add(kw)

        if matched_keywords:
            sorted_kws = sorted(list(matched_keywords))
            flags.append(
                RiskFlag(
                    id="SUSPICIOUS_KEYWORDS",
                    name="Suspicious Phishing/Credential Keywords Detected",
                    severity=RiskSeverity.HIGH,
                    score_impact=20,
                    description="Target infrastructure or discovered subdomains contain high-risk scam or credential-harvesting keywords.",
                    evidence=f"Matched keywords: {', '.join(sorted_kws[:10])}",
                )
            )

        # 8. High Subdomain Volume in Young Domain
        if ct_logs and ct_logs.subdomain_count > 50 and rdap and rdap.age_days is not None and rdap.age_days < 180:
            flags.append(
                RiskFlag(
                    id="HIGH_SUBDOMAIN_VOLUME_YOUNG_DOMAIN",
                    name="High Subdomain Volume on Recent Domain",
                    severity=RiskSeverity.MEDIUM,
                    score_impact=10,
                    description=f"Domain has generated {ct_logs.subdomain_count} subdomains within {rdap.age_days} days of registration.",
                    evidence=f"Subdomains: {ct_logs.subdomain_count}, Age: {rdap.age_days} days",
                )
            )

        # Calculate composite score (capped at 100)
        total_score = min(100, sum(f.score_impact for f in flags))

        # Assign risk tier
        if total_score >= 75:
            tier = RiskTier.CRITICAL
        elif total_score >= 50:
            tier = RiskTier.HIGH
        elif total_score >= 25:
            tier = RiskTier.MEDIUM
        else:
            tier = RiskTier.LOW

        return RiskAssessment(
            score=total_score,
            tier=tier,
            flags=flags,
        )
