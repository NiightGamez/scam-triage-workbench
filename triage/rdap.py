"""Domain and IP registration lookup via public RDAP (rdap.org)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import re

from triage.models import RDAPInfo
from triage.network import SafeHttpClient


class RDAPEnricher:
    """Performs passive RDAP registration lookups via rdap.org."""

    def __init__(self, client: Optional[SafeHttpClient] = None):
        self.client = client or SafeHttpClient()

    def lookup_domain(self, domain: str) -> RDAPInfo:
        """Query rdap.org/domain/<domain> and parse registration metadata."""
        if not domain:
            return RDAPInfo(error="No domain specified for RDAP lookup")

        clean_domain = domain.strip().lower()
        url = f"https://rdap.org/domain/{clean_domain}"

        try:
            # rdap.org redirects to authoritative server with 302/307; follow safely
            response = self.client.get_with_validated_redirects(
                url,
                headers={"Accept": "application/rdap+json, application/json"},
                timeout=5.0,
                max_redirects=2,
            )
        except Exception as e:
            return RDAPInfo(queried=True, error=f"RDAP query failed: {e}")

        if response.status_code == 404:
            return RDAPInfo(queried=True, error="Domain not found in RDAP (NXDOMAIN / unregistered)")

        if response.status_code != 200:
            return RDAPInfo(
                queried=True,
                error=f"RDAP service returned HTTP {response.status_code}",
            )

        try:
            data = response.json()
        except Exception as e:
            return RDAPInfo(queried=True, error=f"Failed to parse RDAP JSON response: {e}")

        return self._parse_rdap_response(data)

    def _parse_rdap_response(self, data: Dict[str, Any]) -> RDAPInfo:
        """Extract registration dates, registrar, and statuses from RDAP data."""
        creation_date: Optional[str] = None
        expiration_date: Optional[str] = None
        updated_date: Optional[str] = None
        registrar: Optional[str] = None
        statuses: List[str] = []
        raw_entities: List[str] = []

        # Parse events (dates)
        events = data.get("events", [])
        for event in events:
            action = event.get("eventAction", "").lower()
            date_str = event.get("eventDate")
            if not date_str:
                continue

            if action in ("registration", "created"):
                creation_date = date_str
            elif action in ("expiration", "expired"):
                expiration_date = date_str
            elif action in ("last changed", "last update", "updated"):
                updated_date = date_str

        # Parse registrar from entities
        entities = data.get("entities", [])
        for entity in entities:
            roles = [r.lower() for r in entity.get("roles", [])]
            handle = entity.get("handle")
            vcard = entity.get("vcardArray", [])

            fn = None
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for entry in vcard[1]:
                    if len(entry) > 3 and entry[0] == "fn":
                        fn = entry[3]
                        break

            name = fn or handle
            if name:
                raw_entities.append(f"{name} ({', '.join(roles)})")
                if "registrar" in roles and not registrar:
                    registrar = name

        # Parse domain statuses
        if "status" in data and isinstance(data["status"], list):
            statuses = data["status"]

        # Calculate age and days until expiration
        age_days: Optional[int] = None
        days_until_expiration: Optional[int] = None
        now = datetime.now(timezone.utc)

        if creation_date:
            try:
                c_dt = self._parse_iso_date(creation_date)
                if c_dt:
                    age_days = max(0, (now - c_dt).days)
            except Exception:
                pass

        if expiration_date:
            try:
                e_dt = self._parse_iso_date(expiration_date)
                if e_dt:
                    days_until_expiration = (e_dt - now).days
            except Exception:
                pass

        return RDAPInfo(
            queried=True,
            registrar=registrar,
            creation_date=creation_date,
            expiration_date=expiration_date,
            updated_date=updated_date,
            age_days=age_days,
            days_until_expiration=days_until_expiration,
            status=statuses,
            raw_entities=raw_entities,
        )

    def _parse_iso_date(self, date_str: str) -> Optional[datetime]:
        """Parse various ISO-8601 date string formats into UTC datetime."""
        # Replace trailing Z with +00:00 for fromisoformat compatibility
        clean_str = date_str.strip()
        if clean_str.endswith("Z"):
            clean_str = clean_str[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            # Fallback simple YYYY-MM-DD
            m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", clean_str)
            if m:
                y, mon, d = map(int, m.groups())
                return datetime(y, mon, d, tzinfo=timezone.utc)
            return None
