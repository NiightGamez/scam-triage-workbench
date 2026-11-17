"""Certificate Transparency (CT) subdomain discovery via crt.sh JSON API."""

from __future__ import annotations

from typing import List, Optional, Set
import urllib.parse

from triage.models import CTDiscovery
from triage.network import SafeHttpClient


class CTEnricher:
    """Discovers subdomains logged in Certificate Transparency via crt.sh."""

    def __init__(self, client: Optional[SafeHttpClient] = None):
        self.client = client or SafeHttpClient()

    def discover_subdomains(self, domain: str) -> CTDiscovery:
        """Query crt.sh for logged certificates matching %.<domain>."""
        if not domain:
            return CTDiscovery(error="No domain provided for CT discovery")

        clean_domain = domain.strip().lower()
        # Query crt.sh with wildcard parameter
        query_val = f"%.{clean_domain}"
        encoded_query = urllib.parse.quote(query_val)
        url = f"https://crt.sh/?q={encoded_query}&output=json"

        try:
            response = self.client.get(
                url,
                headers={"Accept": "application/json"},
                timeout=5.0,
            )
        except Exception as e:
            return CTDiscovery(queried=True, error=f"crt.sh request failed: {e}")

        if response.status_code != 200:
            return CTDiscovery(
                queried=True,
                error=f"crt.sh returned HTTP {response.status_code}",
            )

        try:
            data = response.json()
        except Exception as e:
            return CTDiscovery(
                queried=True,
                error=f"Failed to decode crt.sh JSON response: {e}",
            )

        if not isinstance(data, list):
            return CTDiscovery(queried=True, subdomain_count=0, subdomains=[])

        discovered: Set[str] = set()

        for cert_entry in data:
            if not isinstance(cert_entry, dict):
                continue

            for key in ("name_value", "common_name"):
                val = cert_entry.get(key)
                if not val or not isinstance(val, str):
                    continue

                # Names can be newline-separated SAN lists
                lines = val.split("\n")
                for line in lines:
                    sub = line.strip().lower()
                    # Strip leading wildcards (*.example.com -> example.com)
                    if sub.startswith("*."):
                        sub = sub[2:]

                    # Ensure the name belongs to the domain and is not just the root domain itself
                    if (sub == clean_domain or sub.endswith(f".{clean_domain}")) and sub != clean_domain:
                        discovered.add(sub)

        sorted_subdomains = sorted(list(discovered))
        return CTDiscovery(
            queried=True,
            subdomain_count=len(sorted_subdomains),
            subdomains=sorted_subdomains,
        )
