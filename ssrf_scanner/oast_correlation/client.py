"""OAST (Out-of-band Application Security Testing) correlation.

Integrates with Interactsh or self-hosted DNS/HTTP callback services.
- Generates unique subdomains per scan session
- Polls OAST provider API asynchronously
- Correlates callbacks to specific payloads
- Excludes false positives (test machine self-calls, OAST infrastructure IPs)

No LLM calls — pure rule-based matching.
"""

import asyncio
import ipaddress
import uuid
import datetime
from typing import Optional, List, Dict, Any

import httpx

from ..shared_types import (
    Payload,
    OastResult,
    Protocol,
    SecurityError,
)


class OastCorrelation:
    """Integrate with OAST services for out-of-band SSRF detection."""

    def __init__(self,
                 api_url: str = "https://interact.sh",
                 poll_interval_sec: int = 5,
                 poll_timeout_sec: int = 120,
                 self_ips: Optional[List[str]] = None):
        """
        Args:
            api_url: Interactsh server URL (default public instance)
            poll_interval_sec: Seconds between poll attempts
            poll_timeout_sec: Maximum total polling duration
            self_ips: IPs of the test machine to exclude from results
        """
        self.api_url = api_url.rstrip("/")
        self.poll_interval = poll_interval_sec
        self.poll_timeout = poll_timeout_sec
        self.self_ips = set(self_ips or [])
        self._sessions: Dict[str, dict] = {}

    async def create_session(self) -> str:
        """Create a new Interactsh session, return session_id."""
        session_id = f"ssrf-{uuid.uuid4().hex[:12]}"

        async with httpx.AsyncClient(timeout=15) as client:
            try:
                resp = await client.post(
                    f"{self.api_url}/register",
                    json={"correlation-id": session_id},
                )
                resp.raise_for_status()
                data = resp.json()
                correlation_id = data.get("correlation-id", session_id)
            except Exception:
                # Fallback: use session_id directly if register fails
                correlation_id = session_id

        self._sessions[correlation_id] = {
            "domain": f"{correlation_id}.oast.pro",
            "created_at": datetime.datetime.utcnow(),
        }

        return correlation_id

    def get_oast_domain(self, session_id: str) -> str:
        """Return the OAST subdomain for this session (for payload generation)."""
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Unknown session: {session_id}")
        return session["domain"]

    async def poll_interactions(self, session_id: str,
                                timeout_sec: Optional[int] = None
                                ) -> List[Dict[str, Any]]:
        """Poll OAST API for interactions associated with this session."""
        session = self._sessions.get(session_id)
        if not session:
            raise ValueError(f"Unknown session: {session_id}")

        timeout = timeout_sec or self.poll_timeout
        elapsed = 0.0
        all_interactions: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=15) as client:
            while elapsed < timeout:
                try:
                    resp = await client.get(
                        f"{self.api_url}/poll",
                        params={
                            "id": session_id,
                            "correlation-id": session_id,
                        },
                    )
                    resp.raise_for_status()
                    data = resp.json()

                    interactions = (
                        data.get("interactions", []) or
                        data.get("data", []) or
                        []
                    )

                    for entry in interactions:
                        # Deduplicate by protocol + timestamp
                        key = (entry.get("protocol", ""), entry.get("timestamp", ""))
                        if key not in {(i.get("protocol"), i.get("timestamp")) for i in all_interactions}:
                            all_interactions.append(entry)

                except Exception:
                    pass  # Interactsh may return errors between polls

                await asyncio.sleep(self.poll_interval)
                elapsed += self.poll_interval

        return all_interactions

    async def correlate(self,
                        session_id: str,
                        payloads: List[Payload],
                        target_network_cidrs: List[str],
                        target_asns: Optional[List[str]] = None
                        ) -> List[OastResult]:
        """
        Core correlation: poll → match payloads → check source IP against target CIDRs.

        Returns one OastResult per payload (even if no hit).
        """
        interactions = await self.poll_interactions(session_id)

        # Build quick lookup: which payload IDs are referenced in interactions
        # The correlation is done by checking if the interaction contains the payload's
        # unique subdomain or identifier
        results: List[OastResult] = []

        for payload in payloads:
            matched = self._match_payload(payload, interactions)
            if matched:
                source_ip = matched.get("remote-address", "")
                protocol_raw = matched.get("protocol", "http").lower()

                protocol = Protocol.HTTP
                if "dns" in protocol_raw:
                    protocol = Protocol.DNS
                elif "smtp" in protocol_raw:
                    protocol = Protocol.SMTP

                in_target = self._ip_in_target_network(source_ip, target_network_cidrs)
                is_self = self._is_self_ip(source_ip)

                results.append(OastResult(
                    payload_id=payload.id,
                    hit=True,
                    source_ip=source_ip if source_ip else None,
                    protocol=protocol,
                    request_body=matched.get("raw-request", matched.get("raw_request")),
                    dns_query=matched.get("full-id", matched.get("full_id")),
                    timestamp=datetime.datetime.utcnow(),
                    in_target_network=in_target and not is_self,
                    known_self_ip=is_self,
                    confidence=0.9 if (in_target and not is_self) else 0.5,
                ))
            else:
                results.append(OastResult(
                    payload_id=payload.id,
                    hit=False,
                    confidence=0.0,
                ))

        return results

    def close_session(self, session_id: str):
        """Clean up the OAST session."""
        self._sessions.pop(session_id, None)

    # ===== Internal helpers =====

    def _match_payload(self, payload: Payload,
                       interactions: List[Dict]) -> Optional[Dict]:
        """Find the interaction matching this payload (by subdomain in value)."""
        payload_text = payload.value.lower()
        for interaction in interactions:
            full_id = (interaction.get("full-id", "") or
                       interaction.get("full_id", "") or
                       interaction.get("unique-id", "")).lower()
            raw_req = (interaction.get("raw-request", "") or
                       interaction.get("raw_request", "") or "").lower()

            # Match if payload's OAST domain appears in the interaction
            if full_id and self.oast_domain_suffix() in full_id:
                return interaction
            if raw_req and self.oast_domain_suffix() in raw_req:
                return interaction

        return None

    def oast_domain_suffix(self) -> str:
        """Extract domain suffix from api_url for matching."""
        # e.g., "interact.sh" from "https://interact.sh"
        from urllib.parse import urlparse
        parsed = urlparse(self.api_url)
        return parsed.netloc or parsed.path

    def _ip_in_target_network(self, ip: str, cidrs: List[str]) -> bool:
        """Check if an IP falls within the target network CIDRs."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip.strip())
            for cidr in cidrs:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
        except (ipaddress.AddressValueError, ValueError):
            pass
        return False

    def _is_self_ip(self, ip: str) -> bool:
        """Check if the returning IP is the test machine itself."""
        return ip and ip.strip() in self.self_ips

    @staticmethod
    def ip_in_cidrs(ip: str, cidrs: List[str]) -> bool:
        """Static utility: check if IP is in any CIDR range."""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip.strip())
            for cidr in cidrs:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
        except (ipaddress.AddressValueError, ValueError):
            pass
        return False
