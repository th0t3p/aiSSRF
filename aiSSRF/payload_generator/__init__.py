"""payload_generator — Deterministic SSRF payload generation.

Zero LLM calls.  For each candidate endpoint, produces a list of payload
variants tagged with BypassTechnique labels for report traceability.

Generates:
  a) IP encoding variants — decimal, hex, octal, short-form, IPv6,
     IPv4-mapped-IPv6
  b) URL parser confusion — userinfo injection, scheme omission,
     fragment tricks, case / trailing-dot
  c) Protocol variants — gopher / dict / file (NOTE: flagged as a TODO
     heuristic — only include these when the candidate's context suggests
     the target might follow arbitrary URL schemes)
"""

from __future__ import annotations

from aiSSRF.config import CandidateEndpoint, Payload, BypassTechnique


class PayloadGenerator:
    """Deterministic payload factory — one candidate → many payloads."""

    def __init__(self, collaborator_domain: str) -> None:
        """
        Args:
            collaborator_domain: The unique Burp Collaborator subdomain
                                 (e.g. ``abc123.oastify.com``) that will
                                 be embedded in OAST payloads.
        """
        self._collaborator_domain = collaborator_domain

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, candidate: CandidateEndpoint) -> list[Payload]:
        """
        Return all applicable payloads for a single candidate.

        Groups returned:
          - OAST callbacks  (use collaborator_domain)
          - Internal probes (127.0.0.1, 169.254.169.254, …)
          - Protocol tricks (gopher / dict / file — TODO: heuristic gate)
        """
        raise NotImplementedError("stub")

    def generate_for_technique(
        self, candidate: CandidateEndpoint, technique: BypassTechnique
    ) -> Optional[Payload]:
        """
        Generate exactly one payload for the requested technique, or None
        if the technique is not applicable to this candidate.
        """
        raise NotImplementedError("stub")

    # ------------------------------------------------------------------
    # Static helpers (to be implemented)
    # ------------------------------------------------------------------

    @staticmethod
    def ip_to_decimal(ip: str) -> str:
        """IPv4 → decimal integer (e.g. 169.254.169.254 → 2852039166)."""
        raise NotImplementedError("stub")

    @staticmethod
    def ip_to_hex(ip: str) -> str:
        """IPv4 → hex (e.g. 169.254.169.254 → 0xA9FEA9FE)."""
        raise NotImplementedError("stub")

    @staticmethod
    def ip_to_octal(ip: str) -> str:
        """IPv4 → zero-padded octal per octet."""
        raise NotImplementedError("stub")

    @staticmethod
    def ip_to_short_form(ip: str) -> str:
        """Collapse zero octets (e.g. 10.0.0.1 → 10.1)."""
        raise NotImplementedError("stub")

    @staticmethod
    def ip_to_ipv4_mapped_ipv6(ip: str) -> str:
        """IPv4 → ::ffff:a.b.c.d format."""
        raise NotImplementedError("stub")
