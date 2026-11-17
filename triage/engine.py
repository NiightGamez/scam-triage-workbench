"""Triage Engine coordinating the passive OSINT enrichment pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from triage.asn import ASNEnricher
from triage.ct_logs import CTEnricher
from triage.defang import is_ip_address, parse_target
from triage.dns_enricher import DNSEnricher
from triage.heuristics import HeuristicEngine
from triage.models import TargetType, TriageReport
from triage.network import SafeHttpClient, SSRFProtectionError, is_private_or_reserved_ip
from triage.rdap import RDAPEnricher


class TriageEngine:
    """Coordinates 100% passive infrastructure triage against suspicious targets."""

    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        timeout: float = 5.0,
    ):
        self.timeout = min(timeout, 5.0)
        self.client = SafeHttpClient(timeout=self.timeout)
        self.dns_enricher = DNSEnricher(nameservers=nameservers, timeout=self.timeout)
        self.rdap_enricher = RDAPEnricher(client=self.client)
        self.ct_enricher = CTEnricher(client=self.client)
        self.asn_enricher = ASNEnricher(resolver=self.dns_enricher.resolver, client=self.client)
        self.heuristic_engine = HeuristicEngine()

    def triage(self, raw_target: str) -> TriageReport:
        """Execute the end-to-end passive triage pipeline."""
        timestamp = datetime.now(timezone.utc).isoformat()

        # Step 1: URL Deconstruction & Defanging
        target_info = parse_target(raw_target)

        # Step 2: Immediate SSRF Target Guardrail Check
        # Disallow private, loopback, link-local, cloud metadata, or reserved targets
        clean_host = target_info.host.lower()
        if clean_host in ("localhost", "metadata.google.internal", "instance-data"):
            raise SSRFProtectionError(
                f"Target '{target_info.defanged_host}' is rejected by SSRF guardrail: loopback/metadata host"
            )

        if is_ip_address(clean_host):
            is_blocked, reason = is_private_or_reserved_ip(clean_host)
            if is_blocked:
                raise SSRFProtectionError(
                    f"Target '{target_info.defanged_host}' is rejected by SSRF guardrail: {reason}"
                )

        # Step 3: Configure SSRF guard target isolation
        self.client.set_target(host=target_info.host)

        # Step 3: Passive DNS Resolution
        if target_info.target_type == TargetType.IP:
            # If target is already an IP address, we don't need A resolution for host
            dns_records = self.dns_enricher.resolve(target_info.host, target_info.domain)
            # Add the target IP itself to resolved_ips if not present
            if target_info.host not in dns_records.resolved_ips:
                dns_records.resolved_ips.append(target_info.host)
        else:
            dns_records = self.dns_enricher.resolve(target_info.host, target_info.domain)

        # Step 4: Register all resolved IPs into target blocklist
        self.client.set_target(host=target_info.host, ips=dns_records.resolved_ips)

        # Step 5: Domain Registration Lookup via RDAP (rdap.org)
        rdap_info = None
        if target_info.target_type != TargetType.IP:
            rdap_info = self.rdap_enricher.lookup_domain(target_info.domain)

        # Step 6: Certificate Transparency Subdomain Enumeration (crt.sh)
        ct_info = None
        if target_info.target_type != TargetType.IP:
            ct_info = self.ct_enricher.discover_subdomains(target_info.domain)

        # Step 7: Public ASN & Hosting Provider Lookup
        ips_to_lookup = list(dns_records.resolved_ips)
        if target_info.target_type == TargetType.IP and target_info.host not in ips_to_lookup:
            ips_to_lookup.append(target_info.host)

        ip_enrichments = self.asn_enricher.lookup_ips(ips_to_lookup)

        # Step 8: Automated Heuristic Risk Assessment
        risk_assessment = self.heuristic_engine.evaluate(
            target=target_info,
            dns=dns_records,
            rdap=rdap_info,
            ct_logs=ct_info,
            ip_enrichments=ip_enrichments,
        )

        return TriageReport(
            target=target_info,
            timestamp=timestamp,
            dns=dns_records,
            rdap=rdap_info,
            ct_logs=ct_info,
            ip_enrichments=ip_enrichments,
            risk_assessment=risk_assessment,
        )
