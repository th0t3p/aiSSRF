"""Tests for payload_generator — deterministic SSRF payload generation."""

from __future__ import annotations

import pytest

from aiSSRF.config import CandidateEndpoint, Payload, BypassTechnique
from aiSSRF.payload_generator import PayloadGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_candidate(**overrides) -> CandidateEndpoint:
    """Build a CandidateEndpoint with sensible defaults for testing."""
    defaults = {
        "id": "test-c1",
        "method": "GET",
        "url": "https://example.com/api?redirect=http://evil.com/path?x=1",
        "param_name": "redirect",
        "param_location": "query",
        "param_value": "http://evil.com/path?x=1",
        "host": "example.com",
    }
    defaults.update(overrides)
    return CandidateEndpoint(**defaults)


# ---------------------------------------------------------------------------
# Static IP-encoding helpers — known values
# ---------------------------------------------------------------------------

class TestIpToDecimal:
    def test_known_value_169_254_169_254(self):
        assert PayloadGenerator.ip_to_decimal("169.254.169.254") == "2852039166"

    def test_known_value_127_0_0_1(self):
        assert PayloadGenerator.ip_to_decimal("127.0.0.1") == "2130706433"

    def test_known_value_0_0_0_0(self):
        assert PayloadGenerator.ip_to_decimal("0.0.0.0") == "0"


class TestIpToHex:
    def test_known_value_169_254_169_254(self):
        assert PayloadGenerator.ip_to_hex("169.254.169.254") == "0xA9FEA9FE"

    def test_known_value_127_0_0_1(self):
        assert PayloadGenerator.ip_to_hex("127.0.0.1") == "0x7F000001"

    def test_known_value_0_0_0_0(self):
        assert PayloadGenerator.ip_to_hex("0.0.0.0") == "0x00000000"


class TestIpToOctal:
    def test_known_value_169_254_169_254(self):
        assert PayloadGenerator.ip_to_octal("169.254.169.254") == "0251.0376.0251.0376"

    def test_known_value_127_0_0_1(self):
        assert PayloadGenerator.ip_to_octal("127.0.0.1") == "0177.00.00.01"

    def test_known_value_0_0_0_0(self):
        assert PayloadGenerator.ip_to_octal("0.0.0.0") == "00.00.00.00"


class TestIpToShortForm:
    def test_collapses_middle_zero_octets(self):
        """127.0.0.1 → 127.1 (middle two octets are zero)."""
        assert PayloadGenerator.ip_to_short_form("127.0.0.1") == "127.1"

    def test_collapses_all_zeros(self):
        """0.0.0.0 → 0.0."""
        assert PayloadGenerator.ip_to_short_form("0.0.0.0") == "0.0"

    def test_collapses_10_0_0_1(self):
        assert PayloadGenerator.ip_to_short_form("10.0.0.1") == "10.1"

    def test_no_collapse_when_middle_nonzero(self):
        """169.254.169.254 has no zero middle octets → full form."""
        assert PayloadGenerator.ip_to_short_form("169.254.169.254") == "169.254.169.254"

    def test_no_collapse_192_168_1_1(self):
        """192.168.1.1 → no collapse (second octet non-zero)."""
        assert PayloadGenerator.ip_to_short_form("192.168.1.1") == "192.168.1.1"


class TestIpToIpv4MappedIpv6:
    def test_known_value_169_254_169_254(self):
        assert (
            PayloadGenerator.ip_to_ipv4_mapped_ipv6("169.254.169.254")
            == "::ffff:169.254.169.254"
        )

    def test_known_value_127_0_0_1(self):
        assert (
            PayloadGenerator.ip_to_ipv4_mapped_ipv6("127.0.0.1")
            == "::ffff:127.0.0.1"
        )

    def test_known_value_0_0_0_0(self):
        assert (
            PayloadGenerator.ip_to_ipv4_mapped_ipv6("0.0.0.0")
            == "::ffff:0.0.0.0"
        )


# ---------------------------------------------------------------------------
# Static IP-encoding helpers — ValueError on invalid input
# ---------------------------------------------------------------------------

class TestStaticHelpersValueError:
    """Each static helper must raise ValueError (not a raw ipaddress exception)
    for non-IPv4 input."""

    @pytest.mark.parametrize("func", [
        PayloadGenerator.ip_to_decimal,
        PayloadGenerator.ip_to_hex,
        PayloadGenerator.ip_to_octal,
        PayloadGenerator.ip_to_short_form,
        PayloadGenerator.ip_to_ipv4_mapped_ipv6,
    ])
    @pytest.mark.parametrize("bad_input", [
        "not-an-ip",
        "2001:db8::1",
        "999.999.999.999",
        "",
    ])
    def test_raises_valueerror(self, func, bad_input):
        with pytest.raises(ValueError):
            func(bad_input)


# ---------------------------------------------------------------------------
# generate() — structure and correctness
# ---------------------------------------------------------------------------

class TestGenerate:
    def test_all_payloads_have_correct_candidate_id(self):
        """Every generated payload must link back to its candidate.id."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate(id="abc-42")
        payloads = gen.generate(candidate)
        assert len(payloads) > 0
        for p in payloads:
            assert p.candidate_id == "abc-42"

    def test_produces_oast_payloads(self):
        """Category A: Collaborator domain payloads exist."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate()
        payloads = gen.generate(candidate)

        # At least the direct substitution + a few confusion variants
        oast = [p for p in payloads if "collab.example.com" in p.value]
        assert len(oast) >= 3  # direct, userinfo, scheme-omit, fragment, case-dot

        # Verify specific technique tags appear
        techniques = set()
        for p in oast:
            for t in p.bypass_techniques:
                techniques.add(t)
        assert BypassTechnique.URL_USERINFO_INJECTION in techniques
        assert BypassTechnique.URL_SCHEME_OMIT in techniques
        assert BypassTechnique.URL_FRAGMENT_CONFUSION in techniques
        assert BypassTechnique.URL_CASE_DOT_CONFUSION in techniques

    def test_produces_internal_ip_payloads(self):
        """Category B: IP encoding payloads for internal targets."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate()
        payloads = gen.generate(candidate)

        # At least one decimal/hex/octal/short/ipv6 per internal IP (3 ips × ≥5 each)
        ip_payloads = [
            p for p in payloads
            if any(
                t in p.bypass_techniques
                for t in (
                    BypassTechnique.IP_DECIMAL,
                    BypassTechnique.IP_HEX,
                    BypassTechnique.IP_OCTAL,
                    BypassTechnique.IP_SHORT,
                    BypassTechnique.IPV4_MAPPED_IPV6,
                    BypassTechnique.IPV6_FULL,
                )
            )
        ]
        # 3 IPs × 6 encoding types = 18 payloads
        assert len(ip_payloads) == 18

        # Spot-check: there should be a decimal-encoded 127.0.0.1 payload
        decimal_127 = [
            p for p in payloads
            if BypassTechnique.IP_DECIMAL in p.bypass_techniques
            and "2130706433" in p.value
        ]
        assert len(decimal_127) == 1

    def test_no_protocol_payloads_for_generic_query_param(self):
        """A generic 'redirect' query param does NOT trigger protocol tricks."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate(param_name="redirect", param_location="query")
        payloads = gen.generate(candidate)

        protocol_techniques = {
            BypassTechnique.PROTOCOL_GOPHER,
            BypassTechnique.PROTOCOL_DICT,
            BypassTechnique.PROTOCOL_FILE,
        }
        for p in payloads:
            assert not any(t in protocol_techniques for t in p.bypass_techniques), (
                f"Payload {p.id} has protocol technique but should not"
            )

    def test_protocol_payloads_for_webhook_param(self):
        """A 'webhook_url' param (contains 'webhook') DOES trigger protocol tricks."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate(
            param_name="webhook_url", param_location="query",
            param_value="https://target.com/callback",
        )
        payloads = gen.generate(candidate)

        protocol_techniques = {
            BypassTechnique.PROTOCOL_GOPHER,
            BypassTechnique.PROTOCOL_DICT,
            BypassTechnique.PROTOCOL_FILE,
        }
        protocol_payloads = [
            p for p in payloads
            if any(t in protocol_techniques for t in p.bypass_techniques)
        ]
        assert len(protocol_payloads) == 3

    def test_protocol_payloads_for_body_param(self):
        """A body param always triggers protocol tricks regardless of name."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate(
            param_name="target", param_location="body",
            param_value="https://target.com/callback",
        )
        payloads = gen.generate(candidate)

        protocol_techniques = {
            BypassTechnique.PROTOCOL_GOPHER,
            BypassTechnique.PROTOCOL_DICT,
            BypassTechnique.PROTOCOL_FILE,
        }
        protocol_payloads = [
            p for p in payloads
            if any(t in protocol_techniques for t in p.bypass_techniques)
        ]
        assert len(protocol_payloads) == 3

    def test_url_query_param_excluded_from_protocols(self):
        """'url' query param alone is too generic → no protocol payloads."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate(
            param_name="url", param_location="query",
            param_value="https://original.com/x",
        )
        payloads = gen.generate(candidate)

        protocol_techniques = {
            BypassTechnique.PROTOCOL_GOPHER,
            BypassTechnique.PROTOCOL_DICT,
            BypassTechnique.PROTOCOL_FILE,
        }
        for p in payloads:
            assert not any(t in protocol_techniques for t in p.bypass_techniques), (
                f"Payload {p.id} has protocol technique but 'url' query param "
                f"should be excluded"
            )

    def test_payload_ids_are_unique(self):
        """No two payloads from a single generate() call should share an ID."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate()
        payloads = gen.generate(candidate)
        ids = [p.id for p in payloads]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {ids}"

    def test_payload_values_vary(self):
        """Generated payloads should not all have the same value."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate()
        payloads = gen.generate(candidate)
        values = {p.value for p in payloads}
        assert len(values) > 1, "All payload values are identical"

    def test_ipv6_full_form_for_127_0_0_1(self):
        """127.0.0.1 should produce a ::1 IPv6 full form payload."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate(param_value="http://127.0.0.1/path")
        payloads = gen.generate(candidate)

        ipv6_127 = [
            p for p in payloads
            if BypassTechnique.IPV6_FULL in p.bypass_techniques
            and "[::1]" in p.value
        ]
        assert len(ipv6_127) == 1

    def test_ipv6_literals_are_bracketed(self):
        """Regression: any payload value containing '::' must have that
        IPv6 literal wrapped in square brackets per RFC 3986 §3.2.2.
        Covers both IPV4_MAPPED_IPV6 and IPV6_FULL techniques."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate()
        payloads = gen.generate(candidate)

        ipv6_payloads = [p for p in payloads if "::" in p.value]
        assert len(ipv6_payloads) > 0, (
            "Expected at least one payload containing '::' (IPv6 literal)"
        )
        for p in ipv6_payloads:
            # Match any IPv6-ish segment containing :: that is NOT inside
            # brackets — this is the bug pattern we're guarding against.
            import re
            bare_ipv6 = re.findall(r'(?<!\[)[\w]*::[\w:.]*(?!\])', p.value)
            assert bare_ipv6 == [], (
                f"Payload {p.id} has bare IPv6 literal outside brackets: "
                f"{p.value!r}"
            )

    def test_each_payload_has_description(self):
        """Every payload should carry a non-empty description."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate()
        payloads = gen.generate(candidate)
        for p in payloads:
            assert p.description, f"Payload {p.id} has empty description"


# ---------------------------------------------------------------------------
# generate_for_technique()
# ---------------------------------------------------------------------------

class TestGenerateForTechnique:
    def test_returns_payload_for_applicable_technique(self):
        """Requesting IP_DECIMAL for any candidate returns exactly one payload."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate()
        p = gen.generate_for_technique(candidate, BypassTechnique.IP_DECIMAL)
        assert p is not None
        assert isinstance(p, Payload)
        assert BypassTechnique.IP_DECIMAL in p.bypass_techniques
        assert p.candidate_id == candidate.id

    def test_returns_none_for_gated_out_technique(self):
        """PROTOCOL_GOPHER for a generic query param → None."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate(
            param_name="redirect", param_location="query",
        )
        p = gen.generate_for_technique(candidate, BypassTechnique.PROTOCOL_GOPHER)
        assert p is None

    def test_returns_payload_for_protocol_when_gate_passes(self):
        """PROTOCOL_GOPHER for webhook param → a real Payload."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate(
            param_name="webhook_url", param_location="query",
            param_value="https://target.com/callback",
        )
        p = gen.generate_for_technique(candidate, BypassTechnique.PROTOCOL_GOPHER)
        assert p is not None
        assert BypassTechnique.PROTOCOL_GOPHER in p.bypass_techniques

    def test_returns_none_for_irrelevant_technique(self):
        """Requesting a valid enum value that happens not to be generated
        for ANY candidate still returns None (e.g., if we filtered
        everything).  But in practice every technique is generated for at
        least one internal IP, so this just verifies the dispatch works."""
        gen = PayloadGenerator("collab.example.com")
        candidate = _make_candidate()
        # All technique values should find at least one match for a normal candidate
        for technique in BypassTechnique:
            if technique in (
                BypassTechnique.PROTOCOL_GOPHER,
                BypassTechnique.PROTOCOL_DICT,
                BypassTechnique.PROTOCOL_FILE,
            ):
                continue  # gated out for redirect
            p = gen.generate_for_technique(candidate, technique)
            assert p is not None, (
                f"Technique {technique.value} should produce a payload "
                f"for a normal candidate"
            )
            assert technique in p.bypass_techniques
