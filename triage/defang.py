"""URL deconstruction, defanging, and refanging utilities."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import tldextract

from triage.models import TargetMetadata, TargetType

# Configure offline-only TLDExtract to never make outbound HTTP calls for PSL updates
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)


def defang_string(val: str) -> str:
    """Defang a URL, domain, or IP address for safe display."""
    if not val:
        return val

    # Check if raw IPv6
    try:
        ip = ipaddress.ip_address(val.strip("[]"))
        if ip.version == 6:
            return re.sub(r"(?<!\[):(?!\])", "[:]", str(ip))
    except ValueError:
        pass

    # Replace schemes
    s = re.sub(r"^https://", "hxxps://", val, flags=re.IGNORECASE)
    s = re.sub(r"^http://", "hxxp://", s, flags=re.IGNORECASE)

    # Replace dots in domains / IPs / paths
    # Defang dots not already defanged
    s = re.sub(r"(?<!\[)\.(?!\])", "[.]", s)
    return s


def refang_string(val: str) -> str:
    """Refang a previously defanged URL, domain, or IP for analysis."""
    if not val:
        return val

    s = val.strip()
    # Replace defanged schemes
    s = re.sub(r"^hxxps://", "https://", s, flags=re.IGNORECASE)
    s = re.sub(r"^hxxp://", "http://", s, flags=re.IGNORECASE)

    # Replace brackets around dots and colons
    s = s.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".").replace("[dot]", ".")
    s = s.replace("[:]", ":")
    return s


def is_ip_address(val: str) -> bool:
    """Check if value is a valid IPv4 or IPv6 address."""
    clean = val.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def parse_target(raw_input: str) -> TargetMetadata:
    """Deconstruct and defang any suspicious URL, domain, or IP input.
    
    100% passive: no network operations performed.
    """
    raw_target = raw_input.strip()
    refanged = refang_string(raw_target)

    # Check if a scheme exists
    has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", refanged))
    if not has_scheme:
        # Prepend dummy scheme so urlparse can extract host & path properly
        parsed = urlparse("//" + refanged)
        scheme = None
    else:
        parsed = urlparse(refanged)
        scheme = parsed.scheme.lower() if parsed.scheme else None

    # Determine host and port
    host_raw = parsed.hostname or ""
    # Strip brackets if IPv6
    host = host_raw.strip("[]")
    port = parsed.port
    path = parsed.path if parsed.path else None
    query = parsed.query if parsed.query else None

    # In case urlparse didn't set host (e.g. simple string with no slashes)
    if not host:
        host = refanged.split("/")[0].split(":")[0]

    # Classify TargetType
    if is_ip_address(host):
        target_type = TargetType.IP if not has_scheme and not path and not query else TargetType.URL
        domain = host
        subdomain = None
        suffix = None
    else:
        # Extract domain components using offline PSL
        ext = _EXTRACTOR(host)
        if ext.domain and ext.suffix:
            domain = f"{ext.domain}.{ext.suffix}"
            subdomain = ext.subdomain if ext.subdomain else None
            suffix = ext.suffix
        else:
            domain = host
            subdomain = None
            suffix = None

        if has_scheme or (path and path != "/") or query:
            target_type = TargetType.URL
        else:
            target_type = TargetType.DOMAIN

    # Build normalized representation
    if target_type == TargetType.URL:
        norm_scheme = scheme or "http"
        port_part = f":{port}" if port and port not in (80, 443) else ""
        path_part = path or "/"
        query_part = f"?{query}" if query else ""
        normalized_target = f"{norm_scheme}://{host}{port_part}{path_part}{query_part}"
    elif target_type == TargetType.IP:
        normalized_target = host
    else:
        normalized_target = host

    defanged_target = defang_string(normalized_target)
    defanged_host = defang_string(host)

    return TargetMetadata(
        raw_target=raw_target,
        normalized_target=normalized_target,
        defanged_target=defanged_target,
        target_type=target_type,
        scheme=scheme,
        host=host,
        defanged_host=defanged_host,
        domain=domain,
        subdomain=subdomain,
        suffix=suffix,
        port=port,
        path=path,
        query=query,
    )
