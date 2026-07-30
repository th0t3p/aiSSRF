"""collaborator_client — Burp Collaborator operations via McpSseClient.

Wraps the shared MCP client (``burp_mcp_client.McpSseClient``) for the
specific Collaborator workflow:

  1. create_client()         — obtain a Collaborator client ID
  2. generate_payload()      — get a unique subdomain for this client
  3. poll()                  — fetch interactions (client_ip / protocol /
                               timestamp)
  4. verify_interaction()    — check whether callback client_ip falls
                               inside the target's known CIDR ranges
                               (excludes "my own testing machine"
                               false positives)

Does NOT re-implement SSE / JSON-RPC — delegates entirely to
McpSseClient.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from burp_mcp_client import McpSseClient

from aiSSRF.config import (
    AiSsrfConfig,
    CollaboratorPayload,
    Interaction,
    VerificationResult,
    Payload,
)

logger = logging.getLogger(__name__)


class CollaboratorClient:
    """High-level Collaborator operations backed by McpSseClient."""

    def __init__(self, config: AiSsrfConfig) -> None:
        """
        Args:
            config: Validated AiSsrfConfig.  ``target_cidrs`` is used by
                    ``verify_interaction()`` for false-positive exclusion.
        """
        self._config = config
        self._mcp: Optional[McpSseClient] = None
        # Lazy-discovered HTTP-send tool name (cached after first lookup)
        self._http_send_tool: Optional[str] = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Initialise the underlying McpSseClient.

        Connects to ``config.burp_mcp_url`` with ``sse_path="/"`` and
        optional ``Authorization: Bearer <token>`` header (BurpMCP-Ultra).
        """
        headers: Optional[dict[str, str]] = None
        if self._config.burp_mcp_auth_token:
            headers = {"Authorization": f"Bearer {self._config.burp_mcp_auth_token}"}

        self._mcp = McpSseClient(
            base_url=self._config.burp_mcp_url,
            sse_path="/",
            headers=headers,
        )
        await self._mcp.connect()
        logger.info("CollaboratorClient connected to %s", self._config.burp_mcp_url)

    async def disconnect(self) -> None:
        """Tear down the MCP SSE connection."""
        if self._mcp is not None:
            await self._mcp.disconnect()
            self._mcp = None
            self._http_send_tool = None
            logger.info("CollaboratorClient disconnected")

    # ------------------------------------------------------------------
    # Collaborator operations
    # ------------------------------------------------------------------

    async def create_client(self) -> str:
        """Create a new Burp Collaborator client.

        Returns the *client_id* string.

        The real BurpMCP-Ultra tool ``collaborator_create_client()``
        returns ``{"client_id": str, "server": str, "created_at": str}``.
        On error (e.g. Community Edition without Collaborator), the
        response is ``{"error": "message"}`` — we surface that as a
        RuntimeError.
        """
        assert self._mcp is not None, "Not connected — call connect() first"
        result = await self._mcp.call_tool("collaborator_create_client", {})
        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(
                f"collaborator_create_client failed: {result['error']}"
            )
        return result["client_id"]

    async def generate_payload(self, client_id: str) -> CollaboratorPayload:
        """Generate a unique Collaborator subdomain for the given client.

        The real BurpMCP-Ultra tool ``collaborator_generate_payload(client_id)``
        returns ``{"client_id": str, "payload": str, "interaction_url": str}``.
        """
        assert self._mcp is not None, "Not connected — call connect() first"
        result = await self._mcp.call_tool(
            "collaborator_generate_payload", {"client_id": client_id}
        )
        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(
                f"collaborator_generate_payload failed: {result['error']}"
            )
        return CollaboratorPayload(
            collaborator_domain=result["payload"],
            payload_client_id=client_id,
        )

    async def poll(
        self,
        client_id: str,
        *,
        payload_id: Optional[str] = None,
        interaction_type: Optional[str] = None,
    ) -> list[Interaction]:
        """Poll for interactions on this client.

        Uses ``collaborator_poll(client_id, type?, payload_id?)`` — the
        real BurpMCP-Ultra tool.  *payload_id* filters server-side to
        only that payload's interactions.

        Returns a (possibly empty) list of Interaction records parsed
        from the ``interactions`` array, with ``client_ip`` mapped
        correctly from the real field name.
        """
        assert self._mcp is not None, "Not connected — call connect() first"
        arguments: dict = {"client_id": client_id}
        if payload_id is not None:
            arguments["payload_id"] = payload_id
        if interaction_type is not None:
            arguments["type"] = interaction_type

        result = await self._mcp.call_tool("collaborator_poll", arguments)
        if isinstance(result, dict) and "error" in result:
            raise RuntimeError(f"collaborator_poll failed: {result['error']}")

        interactions_raw: list[dict] = result.get("interactions", [])
        parsed: list[Interaction] = []
        for raw in interactions_raw:
            try:
                ts = raw.get("timestamp") or raw.get("created_at", "")
                parsed.append(
                    Interaction(
                        protocol=raw.get("type", raw.get("protocol", "")),
                        client_ip=raw.get("client_ip", raw.get("source_ip", "")),
                        timestamp=datetime.fromisoformat(
                            ts.replace("Z", "+00:00")
                        ),
                        raw_request=raw.get("raw_request"),
                    )
                )
            except (ValueError, TypeError) as exc:
                logger.debug("Skipping malformed interaction: %s — %s", raw, exc)
        return parsed

    # ------------------------------------------------------------------
    # Verification helpers
    # ------------------------------------------------------------------

    async def verify_interaction(
        self,
        interaction: Interaction,
        target_cidrs: list[str],
    ) -> bool:
        """Return True if ``interaction.client_ip`` falls inside any of the
        *target_cidrs*, meaning the callback came from the target's
        infrastructure rather than the tester's own machine.

        Uses the stdlib ``ipaddress`` module for CIDR membership checks.
        Returns False for unparseable IPs rather than raising.
        """
        if not target_cidrs:
            return False
        import ipaddress

        try:
            client_addr = ipaddress.ip_address(interaction.client_ip)
        except ValueError:
            logger.debug(
                "Unparseable client_ip %r — cannot verify CIDR membership",
                interaction.client_ip,
            )
            return False

        for cidr_str in target_cidrs:
            try:
                network = ipaddress.ip_network(cidr_str, strict=False)
                if client_addr in network:
                    return True
            except ValueError:
                logger.debug("Skipping unparseable CIDR: %r", cidr_str)
                continue
        return False

    async def verify_payload(
        self,
        client_id: str,
        payload: Payload,
        target_cidrs: list[str],
    ) -> VerificationResult:
        """Poll interactions for a specific payload, verify against CIDRs.

        If ``payload.collaborator_domain`` is None (internal-IP-encoding
        payload, not OAST-verifiable), returns ``hit=False`` immediately
        with no polling attempt.

        Otherwise polls with the payload's domain as the ``payload_id``
        filter, retrying per the configured poll interval/timeout. Builds
        a VerificationResult with confidence scoring:

        - 1.0 if any interaction IP matches target_cidrs
        - 0.3 if hits exist but none match target_cidrs (or no CIDRs
          configured)
        - 0.0 if no hits at all
        """
        if payload.collaborator_domain is None:
            return VerificationResult(
                payload_id=payload.id,
                candidate_id=payload.candidate_id,
                hit=False,
                confidence=0.0,
            )

        assert self._mcp is not None, "Not connected — call connect() first"

        deadline = time.monotonic() + self._config.collaborator_poll_timeout_sec
        interval = self._config.collaborator_poll_interval_sec
        all_interactions: list[Interaction] = []

        while True:
            interactions = await self.poll(
                client_id, payload_id=payload.collaborator_domain
            )
            all_interactions.extend(interactions)

            if interactions:
                break  # got hits, stop polling

            if time.monotonic() >= deadline:
                break  # timed out

            logger.debug(
                "No interactions yet for %s, retrying in %.1fs…",
                payload.collaborator_domain,
                interval,
            )
            await asyncio.sleep(interval)

        hit = len(all_interactions) > 0
        in_target_infra = False
        if hit:
            for interaction in all_interactions:
                if await self.verify_interaction(interaction, target_cidrs):
                    in_target_infra = True
                    break

        false_positive = hit and not in_target_infra

        if in_target_infra:
            confidence = 1.0
        elif hit:
            confidence = 0.3
        else:
            confidence = 0.0

        return VerificationResult(
            payload_id=payload.id,
            candidate_id=payload.candidate_id,
            hit=hit,
            interactions=all_interactions,
            in_target_infra=in_target_infra,
            false_positive=false_positive,
            confidence=confidence,
        )

    # ------------------------------------------------------------------
    # HTTP request sending (via Burp)
    # ------------------------------------------------------------------

    async def send_request(
        self,
        candidate_id: str,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Optional[str] = None,
    ) -> dict:
        """Send an HTTP request through Burp's MCP HTTP-send tool.

        Discovers the correct tool name at runtime via ``list_tools()``,
        caching it for subsequent calls.  This avoids hardcoding a guessed
        tool name that could drift across BurpMCP-Ultra versions.

        Typical BurpMCP-Ultra tool names include:
          - ``send_http_request``
          - ``send_request``
          - ``make_request``
          - ``http_send``
        """
        assert self._mcp is not None, "Not connected — call connect() first"

        # --- Lazy tool discovery -------------------------------------------
        if self._http_send_tool is None:
            tools = await self._mcp.list_tools()
            candidates = [t for t in tools if isinstance(t, dict)]
            match: Optional[str] = None
            discovery_path: str = "none"

            # 1) Exact match for the confirmed BurpMCP-Ultra tool name.
            #    This avoids accidentally selecting "http_send_request_chain"
            #    or "http_send_requests_parallel" which also satisfy the
            #    substring fuzzy match below.
            confirmed_name = "http_send_request"
            for tool in candidates:
                if tool.get("name") == confirmed_name:
                    match = confirmed_name
                    discovery_path = "exact"
                    break

            # 2) Fuzzy fallback: tool name containing "send", "request",
            #    AND "http" (any case).  Only used when the exact match
            #    above finds nothing (e.g. a future version renames the tool).
            if match is None:
                patterns = ["send", "request", "http"]
                for tool in candidates:
                    name = tool.get("name", "")
                    name_lower = name.lower()
                    if all(p in name_lower for p in patterns):
                        match = name
                        discovery_path = "fuzzy-all-three"
                        break

            # 3) Broader fuzzy fallback: any tool with "send" or "request".
            if match is None:
                for tool in candidates:
                    name = tool.get("name", "")
                    if "send" in name.lower() or "request" in name.lower():
                        match = name
                        discovery_path = "fuzzy-send-or-request"
                        break

            if match is None:
                available = [t.get("name", "?") for t in candidates]
                raise RuntimeError(
                    "Could not discover an HTTP-send tool on the Burp MCP server. "
                    f"Available tools: {available}"
                )
            self._http_send_tool = match
            logger.info(
                "Discovered HTTP-send tool %r (path=%s)",
                self._http_send_tool,
                discovery_path,
            )

        # --- Build arguments -----------------------------------------------
        arguments: dict = {
            "url": url,
            "method": method,
            "headers": headers,
        }
        if body is not None:
            arguments["body"] = body

        return await self._mcp.call_tool(self._http_send_tool, arguments)
