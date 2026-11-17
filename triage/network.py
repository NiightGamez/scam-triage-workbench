"""Security & SSRF Guardrails for outbound HTTP requests."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests

# RFC 6598 Carrier Grade NAT: 100.64.0.0/10
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
# Documentation networks
_DOC_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking
    ipaddress.ip_network("2001:db8::/32"),
]
# Well-known cloud metadata endpoints
_METADATA_IPS = {"169.254.169.254", "169.254.170.2"}
_METADATA_HOSTS = {"metadata.google.internal", "instance-data"}

DEFAULT_TIMEOUT_SECONDS = 5.0
DEFAULT_USER_AGENT = "ScamTriageWorkbench/1.0 (Passive OSINT Security Research)"


class SSRFProtectionError(RuntimeError):
    """Raised when an outbound network call violates SSRF guardrails."""
    pass


class DirectTargetAccessForbiddenError(RuntimeError):
    """Raised when an attempt is made to send HTTP requests directly to the target."""
    pass


class NetworkTimeoutError(RuntimeError):
    """Raised when an outbound network call exceeds the strict timeout."""
    pass


def is_private_or_reserved_ip(ip_str: str) -> Tuple[bool, str]:
    """Validate whether an IP address belongs to private, loopback, or reserved space.
    
    Returns (is_blocked, reason).
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip("[]"))
    except ValueError as e:
        return True, f"Invalid IP address syntax: {e}"

    if str(ip) in _METADATA_IPS:
        return True, f"Cloud metadata IP address blocked: {ip}"

    if ip.is_loopback:
        return True, f"Loopback address blocked: {ip} (RFC 1122 / RFC 3513)"

    if ip.is_private:
        return True, f"Private IP address blocked: {ip} (RFC 1918 / RFC 4193)"

    if ip.is_link_local:
        return True, f"Link-local address blocked: {ip} (RFC 3927 / RFC 4291)"

    if ip.is_reserved:
        return True, f"Reserved IP address blocked: {ip} (RFC 5735 / RFC 6890)"

    if ip.is_multicast:
        return True, f"Multicast IP address blocked: {ip}"

    if ip.is_unspecified:
        return True, f"Unspecified IP address blocked: {ip} (0.0.0.0 or ::)"

    if ip.version == 4 and ip in _CGNAT_NET:
        return True, f"Carrier-Grade NAT address blocked: {ip} (RFC 6598)"

    for doc_net in _DOC_NETS:
        if ip in doc_net:
            return True, f"Documentation/Benchmark address blocked: {ip}"

    return False, "Public IP"


def resolve_and_validate_host(hostname: str) -> List[str]:
    """Resolve a hostname to IP addresses and verify none are private or reserved."""
    clean_host = hostname.strip("[]").lower()

    if clean_host in _METADATA_HOSTS:
        raise SSRFProtectionError(f"Cloud metadata hostname blocked: {clean_host}")

    # If already an IP address, validate directly
    try:
        ipaddress.ip_address(clean_host)
        is_blocked, reason = is_private_or_reserved_ip(clean_host)
        if is_blocked:
            raise SSRFProtectionError(f"Direct IP blocked: {reason}")
        return [clean_host]
    except ValueError:
        pass

    # Resolve hostname via getaddrinfo
    try:
        addr_info = socket.getaddrinfo(clean_host, None)
    except socket.gaierror as e:
        raise SSRFProtectionError(f"DNS resolution failed for host {clean_host}: {e}")

    resolved_ips: List[str] = []
    for item in addr_info:
        sockaddr = item[4]
        ip = sockaddr[0]
        if ip not in resolved_ips:
            resolved_ips.append(ip)

    if not resolved_ips:
        raise SSRFProtectionError(f"No IP addresses resolved for {clean_host}")

    for ip in resolved_ips:
        is_blocked, reason = is_private_or_reserved_ip(ip)
        if is_blocked:
            raise SSRFProtectionError(
                f"SSRF violation: Host '{clean_host}' resolved to blocked IP '{ip}': {reason}"
            )

    return resolved_ips


class SafeHttpClient:
    """HTTP Client enforcing strict SSRF guardrails, timeouts, and redirect controls."""

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        target_host: Optional[str] = None,
        target_ips: Optional[Set[str]] = None,
    ):
        self.timeout = min(timeout, DEFAULT_TIMEOUT_SECONDS)
        self.target_host = target_host.lower() if target_host else None
        self.target_ips: Set[str] = set(target_ips) if target_ips else set()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    def set_target(self, host: str, ips: Optional[List[str]] = None) -> None:
        """Register the target being investigated to prevent any direct HTTP requests."""
        if host:
            self.target_host = host.strip("[]").lower()
        if ips:
            for ip in ips:
                self.target_ips.add(ip.strip("[]").lower())

    def validate_request_destination(self, url: str) -> Tuple[str, List[str]]:
        """Validate URL scheme and host against SSRF and direct-target isolation rules."""
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            raise SSRFProtectionError(f"Unsupported URI scheme: '{parsed.scheme}'. Only HTTP(S) allowed.")

        host = (parsed.hostname or "").strip("[]").lower()
        if not host:
            raise SSRFProtectionError(f"Invalid URL without hostname: '{url}'")

        # 1. Target Direct Access Check (Rule 2.1)
        if self.target_host and (host == self.target_host or host.endswith("." + self.target_host)):
            raise DirectTargetAccessForbiddenError(
                f"CRITICAL: Direct HTTP request to target domain/host '{host}' is strictly forbidden! "
                "The Scam Triage Workbench operates 100% passively via trusted public APIs."
            )

        # 2. SSRF Host Resolution & Private IP Validation (Rule 2.2)
        resolved_ips = resolve_and_validate_host(host)

        # 3. Target IP Check
        for ip in resolved_ips:
            if ip in self.target_ips:
                raise DirectTargetAccessForbiddenError(
                    f"CRITICAL: Request host '{host}' resolved to target IP '{ip}'! Direct target queries are forbidden."
                )

        return host, resolved_ips

    def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> requests.Response:
        """Execute a safe GET request. Strictly disables automatic redirects (Rule 2.3)."""
        self.validate_request_destination(url)
        effective_timeout = min(timeout or self.timeout, DEFAULT_TIMEOUT_SECONDS)

        try:
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=effective_timeout,
                allow_redirects=False,  # Enforce strict disabled redirects
            )
            return response
        except requests.exceptions.Timeout as e:
            raise NetworkTimeoutError(f"HTTP request timed out after {effective_timeout}s: {e}")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"HTTP request error: {e}")

    def get_with_validated_redirects(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        max_redirects: int = 2,
    ) -> requests.Response:
        """Execute a GET request with explicit SSRF validation on every redirect hop.
        
        Used specifically for bootstrap APIs like rdap.org that issue 302/307 redirects to
        authoritative registry servers.
        """
        current_url = url
        current_params = params
        effective_timeout = min(timeout or self.timeout, DEFAULT_TIMEOUT_SECONDS)
        hops = 0

        while hops <= max_redirects:
            self.validate_request_destination(current_url)
            try:
                response = self.session.get(
                    current_url,
                    params=current_params,
                    headers=headers,
                    timeout=effective_timeout,
                    allow_redirects=False,
                )
            except requests.exceptions.Timeout as e:
                raise NetworkTimeoutError(f"HTTP request timed out after {effective_timeout}s: {e}")
            except requests.exceptions.RequestException as e:
                raise RuntimeError(f"HTTP request error: {e}")

            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    return response
                # Resolve relative redirects
                next_url = urljoin(current_url, location)
                hops += 1
                if hops > max_redirects:
                    raise SSRFProtectionError(f"Exceeded maximum allowed redirects ({max_redirects})")
                current_url = next_url
                current_params = None  # Params are now in query string of redirect URL
                continue

            return response

        return response
