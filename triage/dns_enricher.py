"""DNS Resolution & SPF/DMARC enrichment using dnspython."""

from __future__ import annotations

import re
from typing import List, Optional

import dns.exception
import dns.rdatatype
import dns.resolver

from triage.models import DNSRecordItem, DNSRecords, MXRecordItem

DEFAULT_DNS_TIMEOUT = 5.0
PUBLIC_RESOLVERS = ["9.9.9.9", "1.1.1.1", "8.8.8.8"]


class DNSEnricher:
    """Performs passive DNS lookups for domains and hosts."""

    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        timeout: float = DEFAULT_DNS_TIMEOUT,
    ):
        self.resolver = dns.resolver.Resolver()
        effective_timeout = min(timeout, DEFAULT_DNS_TIMEOUT)
        self.resolver.lifetime = effective_timeout
        self.resolver.timeout = effective_timeout

        if nameservers:
            self.resolver.nameservers = nameservers

    def resolve(self, host: str, domain: str) -> DNSRecords:
        """Resolve A, AAAA, MX, NS, TXT, SPF, and DMARC records."""
        a_records: List[DNSRecordItem] = []
        aaaa_records: List[DNSRecordItem] = []
        mx_records: List[MXRecordItem] = []
        ns_records: List[str] = []
        txt_records: List[str] = []
        resolved_ips: List[str] = []
        ttls: List[int] = []
        error: Optional[str] = None

        # 1. A Records (IPv4)
        try:
            answers = self.resolver.resolve(host, dns.rdatatype.A)
            for rdata in answers:
                ip_str = rdata.to_text().strip()
                ttl = answers.ttl
                ttls.append(ttl)
                a_records.append(DNSRecordItem(value=ip_str, ttl=ttl))
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except dns.exception.Timeout:
            error = "DNS resolution timed out"
        except Exception as e:
            error = f"DNS A record query error: {e}"

        # 2. AAAA Records (IPv6)
        try:
            answers = self.resolver.resolve(host, dns.rdatatype.AAAA)
            for rdata in answers:
                ip_str = rdata.to_text().strip()
                ttl = answers.ttl
                ttls.append(ttl)
                aaaa_records.append(DNSRecordItem(value=ip_str, ttl=ttl))
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
            pass

        # 3. MX Records (query root domain)
        try:
            answers = self.resolver.resolve(domain, dns.rdatatype.MX)
            for rdata in answers:
                target_mx = rdata.exchange.to_text().rstrip(".")
                if not target_mx:
                    target_mx = ". (Null MX - RFC 7505)"
                pref = rdata.preference
                mx_records.append(MXRecordItem(host=target_mx, preference=pref, ttl=answers.ttl))
            # Sort by preference
            mx_records.sort(key=lambda m: m.preference)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
            pass

        # 4. NS Records (query root domain)
        try:
            answers = self.resolver.resolve(domain, dns.rdatatype.NS)
            for rdata in answers:
                ns_records.append(rdata.target.to_text().rstrip("."))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
            pass

        # 5. TXT Records & SPF (query root domain)
        spf_record: Optional[str] = None
        try:
            answers = self.resolver.resolve(domain, dns.rdatatype.TXT)
            for rdata in answers:
                # Combine multipart TXT chunks
                txt_val = "".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
                txt_records.append(txt_val)
                if re.match(r"^v=spf1(\s|$)", txt_val, re.IGNORECASE):
                    spf_record = txt_val
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
            pass

        # 6. DMARC Records (query _dmarc.<domain>)
        dmarc_record: Optional[str] = None
        dmarc_query_host = f"_dmarc.{domain}"
        try:
            answers = self.resolver.resolve(dmarc_query_host, dns.rdatatype.TXT)
            for rdata in answers:
                txt_val = "".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
                if re.match(r"^v=DMARC1(\s*;|$)", txt_val, re.IGNORECASE):
                    dmarc_record = txt_val
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
            pass

        min_ttl = min(ttls) if ttls else None

        return DNSRecords(
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            ns_records=ns_records,
            txt_records=txt_records,
            spf_record=spf_record,
            dmarc_record=dmarc_record,
            min_ttl=min_ttl,
            resolved_ips=resolved_ips,
            error=error,
        )
