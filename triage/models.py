"""Data models for Scam & Phishing Infrastructure Triage Workbench."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TargetType(str, Enum):
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP = "IP"


class RiskSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TargetMetadata(BaseModel):
    raw_target: str = Field(description="Raw input target as provided by user")
    normalized_target: str = Field(description="Normalized target for safe processing")
    defanged_target: str = Field(description="Defanged target for safe display")
    target_type: TargetType = Field(description="Classified target type: URL, DOMAIN, or IP")
    scheme: Optional[str] = Field(default=None, description="URL scheme (http, https, etc.)")
    host: str = Field(description="Target host (domain or IP)")
    defanged_host: str = Field(description="Defanged target host")
    domain: str = Field(description="Registrable domain (e.g. example.com)")
    subdomain: Optional[str] = Field(default=None, description="Subdomain prefix if any")
    suffix: Optional[str] = Field(default=None, description="Public suffix (e.g. com, co.uk)")
    port: Optional[int] = Field(default=None, description="Port number if specified")
    path: Optional[str] = Field(default=None, description="Path portion of URL")
    query: Optional[str] = Field(default=None, description="Query string portion of URL")


class DNSRecordItem(BaseModel):
    value: str
    ttl: Optional[int] = None


class MXRecordItem(BaseModel):
    host: str
    preference: int
    ttl: Optional[int] = None


class DNSRecords(BaseModel):
    a_records: List[DNSRecordItem] = Field(default_factory=list)
    aaaa_records: List[DNSRecordItem] = Field(default_factory=list)
    mx_records: List[MXRecordItem] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    spf_record: Optional[str] = None
    dmarc_record: Optional[str] = None
    min_ttl: Optional[int] = None
    resolved_ips: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class RDAPInfo(BaseModel):
    queried: bool = False
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    age_days: Optional[int] = None
    days_until_expiration: Optional[int] = None
    status: List[str] = Field(default_factory=list)
    raw_entities: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class CTDiscovery(BaseModel):
    queried: bool = False
    subdomain_count: int = 0
    subdomains: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class IPEnrichment(BaseModel):
    ip: str
    defanged_ip: str
    asn: Optional[str] = None
    as_name: Optional[str] = None
    bgp_prefix: Optional[str] = None
    country_code: Optional[str] = None
    registry: Optional[str] = None
    allocated_date: Optional[str] = None
    error: Optional[str] = None


class RiskFlag(BaseModel):
    id: str
    name: str
    severity: RiskSeverity
    score_impact: int
    description: str
    evidence: Optional[str] = None


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100, description="Normalized risk score from 0 to 100")
    tier: RiskTier
    flags: List[RiskFlag] = Field(default_factory=list)


class TriageReport(BaseModel):
    target: TargetMetadata
    timestamp: str
    dns: DNSRecords
    rdap: Optional[RDAPInfo] = None
    ct_logs: Optional[CTDiscovery] = None
    ip_enrichments: List[IPEnrichment] = Field(default_factory=list)
    risk_assessment: RiskAssessment
