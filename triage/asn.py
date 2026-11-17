"""Public ASN and hosting provider enrichment for resolved IP addresses."""

from __future__ import annotations

import ipaddress
from typing import List, Optional

import dns.exception
import dns.rdatatype
import dns.resolver

from triage.defang import defang_string
from triage.models import IPEnrichment
from triage.network import SafeHttpClient


class ASNEnricher:
    """Enriches IP addresses with ASN, BGP prefix, organization, and country."""

    def __init__(
        self,
        resolver: Optional[dns.resolver.Resolver] = None,
        client: Optional[SafeHttpClient] = None,
    ):
        self.resolver = resolver or dns.resolver.Resolver()
        self.resolver.lifetime = 5.0
        self.resolver.timeout = 5.0
        self.client = client or SafeHttpClient()

    def lookup_ip(self, ip_str: str) -> IPEnrichment:
        """Lookup ASN, AS Name, Prefix, and Country for a single IP address."""
        defanged_ip = defang_string(ip_str)

        try:
            ip_obj = ipaddress.ip_address(ip_str.strip("[]"))
        except ValueError as e:
            return IPEnrichment(
                ip=ip_str,
                defanged_ip=defanged_ip,
                error=f"Invalid IP address: {e}",
            )

        if ip_obj.is_private or ip_obj.is_loopback:
            return IPEnrichment(
                ip=ip_str,
                defanged_ip=defanged_ip,
                error="IP is private or loopback (no public ASN)",
            )

        # 1. Team Cymru DNS TXT Lookup
        cymru_res = self._lookup_cymru(ip_obj)
        if cymru_res and cymru_res.asn:
            return cymru_res

        # 2. RDAP IP Fallback
        rdap_res = self._lookup_rdap_ip(ip_str)
        if rdap_res:
            return rdap_res

        return IPEnrichment(
            ip=ip_str,
            defanged_ip=defanged_ip,
            error=cymru_res.error if cymru_res else "No ASN data found",
        )

    def lookup_ips(self, ips: List[str]) -> List[IPEnrichment]:
        """Lookup enrichment for multiple IP addresses (deduplicated)."""
        seen = set()
        results = []
        for ip in ips:
            clean = ip.strip()
            if clean not in seen:
                seen.add(clean)
                results.append(self.lookup_ip(clean))
        return results

    def _lookup_cymru(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Optional[IPEnrichment]:
        """Perform Team Cymru DNS TXT lookup."""
        defanged_ip = defang_string(str(ip_obj))

        if ip_obj.version == 4:
            # Reverse octets e.g. 8.8.8.8 -> 8.8.8.8.origin.asn.cymru.com
            octets = str(ip_obj).split(".")
            reversed_ip = ".".join(reversed(octets))
            query_name = f"{reversed_ip}.origin.asn.cymru.com"
        else:
            # IPv6: reverse 32 nibbles
            hex_str = ip_obj.exploded.replace(":", "")
            reversed_nibbles = ".".join(reversed(hex_str))
            query_name = f"{reversed_nibbles}.origin6.asn.cymru.com"

        asn: Optional[str] = None
        bgp_prefix: Optional[str] = None
        country_code: Optional[str] = None
        registry: Optional[str] = None
        allocated_date: Optional[str] = None
        as_name: Optional[str] = None

        try:
            answers = self.resolver.resolve(query_name, dns.rdatatype.TXT)
            for rdata in answers:
                txt_val = "".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
                # Format: "15169 | 8.8.8.0/24 | US | arin | 2014-03-14"
                parts = [p.strip() for p in txt_val.split("|")]
                if len(parts) >= 5:
                    asn_raw = parts[0]
                    # Handle multiple ASNs if separated by space
                    first_asn = asn_raw.split()[0] if asn_raw else None
                    asn = f"AS{first_asn}" if first_asn and not first_asn.startswith("AS") else first_asn
                    bgp_prefix = parts[1]
                    country_code = parts[2].upper()
                    registry = parts[3].upper()
                    allocated_date = parts[4]
                    break
        except Exception as e:
            return IPEnrichment(ip=str(ip_obj), defanged_ip=defanged_ip, error=f"Cymru DNS query failed: {e}")

        # Lookup AS Name description: AS<asn>.asn.cymru.com
        if asn:
            raw_num = asn.replace("AS", "")
            as_query = f"AS{raw_num}.asn.cymru.com"
            try:
                as_answers = self.resolver.resolve(as_query, dns.rdatatype.TXT)
                for rdata in as_answers:
                    txt_val = "".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
                    # Format: "15169 | US | arin | 2000-03-30 | GOOGLE, US"
                    parts = [p.strip() for p in txt_val.split("|")]
                    if len(parts) >= 5:
                        as_name = parts[4]
                        break
            except Exception:
                pass

        return IPEnrichment(
            ip=str(ip_obj),
            defanged_ip=defanged_ip,
            asn=asn,
            as_name=as_name,
            bgp_prefix=bgp_prefix,
            country_code=country_code,
            registry=registry,
            allocated_date=allocated_date,
        )

    def _lookup_rdap_ip(self, ip_str: str) -> Optional[IPEnrichment]:
        """Fallback to rdap.org/ip/<ip> via SafeHttpClient."""
        defanged_ip = defang_string(ip_str)
        url = f"https://rdap.org/ip/{ip_str}"

        try:
            resp = self.client.get_with_validated_redirects(
                url,
                headers={"Accept": "application/rdap+json, application/json"},
                timeout=5.0,
                max_redirects=2,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()

            as_name = data.get("name")
            country = data.get("country")
            # Extract CIDRs
            cidr = None
            cidrs = data.get("cidr0_cidrs", [])
            if cidrs and isinstance(cidrs, list):
                first_cidr = cidrs[0]
                if isinstance(first_cidr, dict):
                    cidr = f"{first_cidr.get('v4prefix', '')}/{first_cidr.get('length', '')}"

            return IPEnrichment(
                ip=ip_str,
                defanged_ip=defanged_ip,
                as_name=as_name,
                bgp_prefix=cidr,
                country_code=country,
            )
        except Exception:
            return None
