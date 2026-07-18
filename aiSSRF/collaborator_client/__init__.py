"""collaborator_client — Burp Collaborator operations via McpSseClient.

Wraps the shared MCP client (``burp_mcp_client.McpSseClient``) for the
specific Collaborator workflow:

  1. create_client()         — obtain a Collaborator client ID
  2. generate_payload()      — get a unique subdomain for this client
  3. poll()                  — fetch interactions (source_ip /
                               protocol / timestamp)
  4. verify_interaction()    — check whether callback source_ip falls
                               inside the target's known CIDR ranges
                               (excludes "my own testing machine"
                               false positives)

Does NOT re-implement SSE / JSON-RPC — delegates entirely to
McpSseClient.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from burp_mcp_client import McpSseClient

from aiSSRF.config import (
    AiSsrfConfig,
    CollaboratorPayload,
    Interaction,
    VerificationResult,
    Payload,
)


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

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """
        Initialise the underlying McpSseClient.

        Connects to ``config.burp_mcp_url``, optionally passing
        ``config.burp_mcp_auth_token``.
        """
        raise NotImplementedError("stub — McpSseClient(url, auth_token=...)")

    async def disconnect(self) -> None:
        """Tear down the MCP SSE connection."""
        raise NotImplementedError("stub")

    # ------------------------------------------------------------------
    # Collaborator operations
    # ------------------------------------------------------------------

    async def create_client(self) -> str:
        """
        Create a new Burp Collaborator client.

        Returns the *client_id* string.
        """
        raise NotImplementedError("stub — calls MCP tool 'collaborator.create_client'")

    async def generate_payload(self, client_id: str) -> CollaboratorPayload:
        """
        Generate a unique Collaborator subdomain for the given client.

        Returns a CollaboratorPayload with the domain and client_id.
        """
        raise NotImplementedError("stub — calls MCP tool 'collaborator.generate_payload'")

    async def poll(self, client_id: str) -> list[Interaction]:
        """
        Poll for all pending interactions on this client.

        Returns a (possibly empty) list of Interaction records.
        """
        raise NotImplementedError("stub — calls MCP tool 'collaborator.poll'")

    # ------------------------------------------------------------------
    # Verification helpers
    # ------------------------------------------------------------------

    async def verify_interaction(
        self,
        interaction: Interaction,
        target_cidrs: list[str],
    ) -> bool:
        """
        Return True if ``interaction.source_ip`` falls inside any of the
        *target_cidrs*, meaning the callback came from the target's
        infrastructure rather than the tester's own machine.

        TODO: future enhancement — also check ASN via external lookup
              (currently CIDR-only).
        """
        raise NotImplementedError("stub — ipaddress module + CIDR matching")

    async def verify_payload(
        self,
        client_id: str,
        payload: Payload,
        target_cidrs: list[str],
    ) -> VerificationResult:
        """
        Poll interactions, filter by payload's Collaborator domain,
        verify source IPs against target CIDRs, and return a structured
        VerificationResult (hit / in_target_infra / false_positive /
        confidence).
        """
        raise NotImplementedError("stub — orchestrates poll + verify_interaction")

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
        """
        Send an HTTP request through Burp's MCP http-send tool.

        Returns the raw response dict from Burp.
        """
        raise NotImplementedError("stub — calls MCP tool 'http.send' or equivalent")
