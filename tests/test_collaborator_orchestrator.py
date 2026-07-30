"""Tests for CollaboratorClient and the merged orchestrator pipeline."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aiSSRF.config import (
    AiSsrfConfig,
    BypassTechnique,
    CandidateEndpoint,
    Interaction,
    Payload,
    VerificationResult,
    ReportEntry,
)
from aiSSRF.collaborator_client import CollaboratorClient
from aiSSRF.orchestrator import Orchestrator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> AiSsrfConfig:
    defaults = {
        "authorized_scope": ["*.example.com"],
        "burp_mcp_url": "http://127.0.0.1:9876",
        "target_cidrs": ["10.0.0.0/8"],
        "collaborator_poll_interval_sec": 0.1,
        "collaborator_poll_timeout_sec": 2.0,
    }
    defaults.update(overrides)
    return AiSsrfConfig(**defaults)


def _make_candidate(**overrides) -> CandidateEndpoint:
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


# ── Realistic BurpMCP-Ultra tool responses ──────────────────────────────────

def _create_client_response(client_id="abc123"):
    return {"client_id": client_id, "server": "polling.oastify.com", "created_at": "2026-07-30T00:00:00Z"}


def _generate_payload_response(client_id="abc123", domain="abcdef.oastify.com"):
    return {
        "client_id": client_id,
        "payload": domain,
        "interaction_url": f"https://{domain}/interact",
    }


def _poll_response(interactions=None):
    return {
        "client_id": "abc123",
        "interaction_count": len(interactions or []),
        "interactions": interactions or [],
    }


def _poll_error_response(message="Community Edition does not support Collaborator"):
    return {"error": message}


def _dns_interaction(client_ip="10.0.0.5", ts="2026-07-30T12:00:00Z"):
    return {
        "type": "dns",
        "id": "int-001",
        "client_ip": client_ip,
        "client_port": 54321,
        "timestamp": ts,
        "dns_details": {"query_type": "A", "query_name": "abcdef.oastify.com"},
    }


def _http_interaction(client_ip="10.0.0.5", ts="2026-07-30T12:00:01Z"):
    return {
        "type": "http",
        "id": "int-002",
        "client_ip": client_ip,
        "client_port": 54322,
        "timestamp": ts,
        "http_details": {
            "protocol": "HTTP/1.1",
            "request_method": "GET",
            "request_url": "/interact",
            "response_status": 200,
        },
    }


# ── Mocked McpSseClient factory ────────────────────────────────────────────

def _mock_mcp(create_result=None, generate_result=None, poll_results=None):
    """Build a mock McpSseClient whose ``call_tool`` returns shaped data.

    *poll_results* can be a single dict or a list of dicts (for retry
    scenarios: first call returns empty, second returns hits).

    *generate_result* is used as a template: each
    ``collaborator_generate_payload`` call increments a counter appended
    to the domain so that every OAST technique gets a unique domain.
    If a dict is passed, the ``"payload"`` key is mutated per call.
    """
    mcp = AsyncMock()
    _gen_counter = 0

    async def _call_tool(tool_name, arguments=None):
        nonlocal _gen_counter
        if tool_name == "collaborator_create_client":
            return create_result or _create_client_response()
        elif tool_name == "collaborator_generate_payload":
            base = dict(generate_result or _generate_payload_response())
            _gen_counter += 1
            base["payload"] = f"abcdef{_gen_counter:03d}.oastify.com"
            return base
        elif tool_name == "collaborator_poll":
            if isinstance(poll_results, list):
                return poll_results.pop(0) if poll_results else _poll_response([])
            return poll_results if poll_results is not None else _poll_response([])
        elif tool_name == "send_http_request":
            return {"status_code": 200, "body": "OK"}
        return {}

    mcp.call_tool = MagicMock(side_effect=_call_tool)
    mcp.connect = AsyncMock()
    mcp.disconnect = AsyncMock()
    mcp.list_tools = AsyncMock(return_value=[
        {"name": "collaborator_create_client"},
        {"name": "collaborator_generate_payload"},
        {"name": "collaborator_poll"},
        {"name": "send_http_request"},
    ])
    return mcp


# ═══════════════════════════════════════════════════════════════════════════
# CollaboratorClient tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCreateClient:
    @pytest.mark.asyncio
    async def test_returns_client_id(self):
        client = CollaboratorClient(_make_config())
        client._mcp = _mock_mcp()

        cid = await client.create_client()
        assert cid == "abc123"

    @pytest.mark.asyncio
    async def test_raises_on_error_shape(self):
        client = CollaboratorClient(_make_config())
        client._mcp = _mock_mcp(
            create_result={"error": "Community Edition does not support Collaborator"}
        )
        with pytest.raises(RuntimeError, match="Community Edition"):
            await client.create_client()


class TestGeneratePayload:
    @pytest.mark.asyncio
    async def test_returns_collaborator_payload(self):
        client = CollaboratorClient(_make_config())
        client._mcp = _mock_mcp()

        cp = await client.generate_payload("abc123")
        assert cp.collaborator_domain.startswith("abcdef")
        assert cp.collaborator_domain.endswith(".oastify.com")
        assert cp.payload_client_id == "abc123"

    @pytest.mark.asyncio
    async def test_raises_on_error_shape(self):
        client = CollaboratorClient(_make_config())
        client._mcp = _mock_mcp(
            generate_result={"error": "rate limited"}
        )
        with pytest.raises(RuntimeError, match="rate limited"):
            await client.generate_payload("abc123")


class TestPoll:
    @pytest.mark.asyncio
    async def test_parses_client_ip_not_source_ip(self):
        """Confirm the real BurpMCP-Ultra field ``client_ip`` is parsed,
        not the old/incorrect ``source_ip``."""
        client = CollaboratorClient(_make_config())
        client._mcp = _mock_mcp(
            poll_results=_poll_response([
                _dns_interaction(client_ip="10.0.0.5"),
            ])
        )
        interactions = await client.poll("abc123")
        assert len(interactions) == 1
        assert interactions[0].client_ip == "10.0.0.5"
        # Also confirm the protocol field maps from 'type'
        assert interactions[0].protocol == "dns"

    @pytest.mark.asyncio
    async def test_parses_multiple_interaction_types(self):
        client = CollaboratorClient(_make_config())
        client._mcp = _mock_mcp(
            poll_results=_poll_response([
                _dns_interaction(client_ip="10.0.0.5"),
                _http_interaction(client_ip="10.0.0.6"),
            ])
        )
        interactions = await client.poll("abc123")
        assert len(interactions) == 2
        assert interactions[0].protocol == "dns"
        assert interactions[1].protocol == "http"
        assert interactions[0].client_ip == "10.0.0.5"
        assert interactions[1].client_ip == "10.0.0.6"

    @pytest.mark.asyncio
    async def test_empty_interactions(self):
        client = CollaboratorClient(_make_config())
        client._mcp = _mock_mcp()
        interactions = await client.poll("abc123")
        assert interactions == []

    @pytest.mark.asyncio
    async def test_passes_payload_id_filter(self):
        """Verify payload_id is forwarded to the MCP tool arguments."""
        client = CollaboratorClient(_make_config())
        mcp = _mock_mcp()
        client._mcp = mcp

        await client.poll("abc123", payload_id="payload123.oastify.com")

        # Extract the call arguments
        call_args = mcp.call_tool.call_args_list
        poll_call = [c for c in call_args if c.args[0] == "collaborator_poll"]
        assert len(poll_call) == 1
        args = poll_call[0].args[1]
        assert args["payload_id"] == "payload123.oastify.com"

    @pytest.mark.asyncio
    async def test_raises_on_error_shape(self):
        client = CollaboratorClient(_make_config())
        client._mcp = _mock_mcp(
            poll_results=_poll_error_response("no collaborator for you")
        )
        with pytest.raises(RuntimeError, match="no collaborator for you"):
            await client.poll("abc123")


class TestVerifyInteraction:
    @pytest.mark.asyncio
    async def test_ip_in_cidr_returns_true(self):
        client = CollaboratorClient(_make_config())
        interaction = Interaction(
            protocol="dns",
            client_ip="10.0.0.5",
            timestamp=datetime.now(timezone.utc),
        )
        result = await client.verify_interaction(interaction, ["10.0.0.0/8"])
        assert result is True

    @pytest.mark.asyncio
    async def test_ip_not_in_cidr_returns_false(self):
        client = CollaboratorClient(_make_config())
        interaction = Interaction(
            protocol="dns",
            client_ip="192.168.1.1",
            timestamp=datetime.now(timezone.utc),
        )
        result = await client.verify_interaction(interaction, ["10.0.0.0/8"])
        assert result is False

    @pytest.mark.asyncio
    async def test_unparseable_ip_returns_false(self):
        client = CollaboratorClient(_make_config())
        interaction = Interaction(
            protocol="dns",
            client_ip="not-an-ip",
            timestamp=datetime.now(timezone.utc),
        )
        result = await client.verify_interaction(interaction, ["10.0.0.0/8"])
        assert result is False

    @pytest.mark.asyncio
    async def test_empty_cidrs_returns_false(self):
        client = CollaboratorClient(_make_config())
        interaction = Interaction(
            protocol="dns",
            client_ip="10.0.0.5",
            timestamp=datetime.now(timezone.utc),
        )
        result = await client.verify_interaction(interaction, [])
        assert result is False

    @pytest.mark.asyncio
    async def test_ipv6_in_cidr(self):
        client = CollaboratorClient(_make_config())
        interaction = Interaction(
            protocol="dns",
            client_ip="::1",
            timestamp=datetime.now(timezone.utc),
        )
        # ::1 is in the loopback /128
        result = await client.verify_interaction(interaction, ["::1/128"])
        assert result is True

    @pytest.mark.asyncio
    async def test_skips_unparseable_cidr_and_continues(self):
        client = CollaboratorClient(_make_config())
        interaction = Interaction(
            protocol="dns",
            client_ip="10.0.0.5",
            timestamp=datetime.now(timezone.utc),
        )
        # First CIDR is garbage, second matches
        result = await client.verify_interaction(
            interaction, ["not-a-cidr", "10.0.0.0/8"]
        )
        assert result is True


class TestVerifyPayload:
    @pytest.mark.asyncio
    async def test_in_target_infra_hit(self):
        """Interaction from target infrastructure → confidence=1.0."""
        client = CollaboratorClient(_make_config(target_cidrs=["10.0.0.0/8"]))
        client._mcp = _mock_mcp(
            poll_results=_poll_response([_dns_interaction(client_ip="10.0.0.5")])
        )
        payload = Payload(
            id="p1", candidate_id="c1", value="http://abcdef.oastify.com/x",
            collaborator_domain="abcdef.oastify.com",
        )
        result = await client.verify_payload("abc123", payload, ["10.0.0.0/8"])
        assert result.hit is True
        assert result.in_target_infra is True
        assert result.false_positive is False
        assert result.confidence == 1.0
        assert len(result.interactions) == 1

    @pytest.mark.asyncio
    async def test_hit_not_in_target_infra(self):
        """Interaction exists but from non-target IP → false_positive."""
        client = CollaboratorClient(_make_config(target_cidrs=["10.0.0.0/8"]))
        client._mcp = _mock_mcp(
            poll_results=_poll_response([_dns_interaction(client_ip="203.0.113.1")])
        )
        payload = Payload(
            id="p2", candidate_id="c2", value="http://abcdef.oastify.com/x",
            collaborator_domain="abcdef.oastify.com",
        )
        result = await client.verify_payload("abc123", payload, ["10.0.0.0/8"])
        assert result.hit is True
        assert result.in_target_infra is False
        assert result.false_positive is True
        assert result.confidence == 0.3

    @pytest.mark.asyncio
    async def test_no_hit(self):
        """No interactions → hit=False, confidence=0.0."""
        client = CollaboratorClient(_make_config(
            target_cidrs=["10.0.0.0/8"],
            collaborator_poll_timeout_sec=0.5,
            collaborator_poll_interval_sec=0.1,
        ))
        client._mcp = _mock_mcp(poll_results=_poll_response([]))
        payload = Payload(
            id="p3", candidate_id="c3", value="http://abcdef.oastify.com/x",
            collaborator_domain="abcdef.oastify.com",
        )
        result = await client.verify_payload("abc123", payload, ["10.0.0.0/8"])
        assert result.hit is False
        assert result.confidence == 0.0

    @pytest.mark.asyncio
    async def test_internal_ip_payload_skips_polling(self):
        """Internal-IP payload (collaborator_domain=None) → no poll, hit=False."""
        client = CollaboratorClient(_make_config())
        mcp = _mock_mcp()
        client._mcp = mcp

        payload = Payload(
            id="p4", candidate_id="c4", value="http://2130706433/path",
            bypass_techniques=[BypassTechnique.IP_DECIMAL],
        )
        # collaborator_domain defaults to None

        result = await client.verify_payload("abc123", payload, ["10.0.0.0/8"])
        assert result.hit is False
        assert result.confidence == 0.0

        # Verify NO poll call was made
        poll_calls = [
            c for c in mcp.call_tool.call_args_list
            if c.args[0] == "collaborator_poll"
        ]
        assert len(poll_calls) == 0, "Internal-IP payload should not trigger polling"

    @pytest.mark.asyncio
    async def test_retries_on_empty_poll_then_gets_hits(self):
        """First poll returns empty, second returns an interaction → retry succeeds."""
        client = CollaboratorClient(_make_config(
            target_cidrs=["10.0.0.0/8"],
            collaborator_poll_interval_sec=0.05,
            collaborator_poll_timeout_sec=5.0,
        ))
        # Use a list that mutates: first returns empty, then returns hit
        poll_results_list = [
            _poll_response([]),
            _poll_response([_dns_interaction(client_ip="10.0.0.5")]),
        ]

        client._mcp = _mock_mcp(poll_results=poll_results_list)

        payload = Payload(
            id="p5", candidate_id="c5", value="http://abcdef.oastify.com/x",
            collaborator_domain="abcdef.oastify.com",
        )
        result = await client.verify_payload("abc123", payload, ["10.0.0.0/8"])
        assert result.hit is True
        assert result.in_target_infra is True
        assert result.confidence == 1.0


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator tests
# ═══════════════════════════════════════════════════════════════════════════

class TestBuildRequest:
    """Static _build_request helper."""

    def test_query_param_substitution(self):
        c = _make_candidate(
            url="https://example.com/api?redirect=http://evil.com/path",
            param_name="redirect", param_location="query",
            param_value="http://evil.com/path",
        )
        method, url, headers, body = Orchestrator._build_request(
            c, "http://collab.com/cb"
        )
        assert "redirect=http%3A%2F%2Fcollab.com%2Fcb" in url or "redirect=http://collab.com/cb" in url

    def test_body_json_substitution(self):
        c = _make_candidate(
            url="https://example.com/api",
            method="POST",
            param_name="webhook", param_location="body",
            param_value="https://evil.com/hook",
            request_body='{"webhook": "https://evil.com/hook", "x": 1}',
        )
        method, url, headers, body = Orchestrator._build_request(
            c, "http://collab.com/cb"
        )
        data = json.loads(body)
        assert data["webhook"] == "http://collab.com/cb"
        assert data["x"] == 1

    def test_body_form_encoded_substitution(self):
        c = _make_candidate(
            url="https://example.com/api",
            method="POST",
            param_name="next", param_location="body",
            param_value="https://evil.com/next",
            request_body="next=https%3A%2F%2Fevil.com%2Fnext&foo=bar",
        )
        method, url, headers, body = Orchestrator._build_request(
            c, "http://collab.com/cb"
        )
        assert "next=http%3A%2F%2Fcollab.com%2Fcb" in body or "next=http://collab.com/cb" in body
        assert "foo=bar" in body

    def test_header_substitution(self):
        c = _make_candidate(
            param_name="X-Callback", param_location="header",
            param_value="http://evil.com/cb",
            request_headers={"X-Callback": "http://evil.com/cb"},
        )
        method, url, headers, body = Orchestrator._build_request(
            c, "http://collab.com/cb"
        )
        assert headers["X-Callback"] == "http://collab.com/cb"

    def test_path_substitution(self):
        c = _make_candidate(
            url="https://example.com/users/http://evil.com",
            param_name="target", param_location="path",
            param_value="http://evil.com",
        )
        method, url, headers, body = Orchestrator._build_request(
            c, "http://collab.com"
        )
        assert url.endswith("/http://collab.com") or "/http://collab.com" in url


class TestMergedPipeline:
    """Integration-style tests for _run_payload_and_verification.

    Mocks McpSseClient and CandidateFetcher so no real I/O is attempted.
    """

    def _mock_orchestrator(self, **config_overrides):
        config = _make_config(**config_overrides)
        orch = Orchestrator(config)

        # Override _run_discovery to return a fixed candidate
        async def mock_discovery():
            return [_make_candidate(param_name="webhook_url")]
        orch._run_discovery = mock_discovery

        # LLM judgment is still a stub; mock it to pass through
        async def mock_judge(entries):
            return entries
        orch._run_llm_judgment = mock_judge

        return orch

    @pytest.mark.asyncio
    async def test_produces_entries_for_oast_and_ip_techniques(self):
        """The merged pipeline should produce one ReportEntry per technique."""
        orch = self._mock_orchestrator()

        # Patch CollaboratorClient at the point of construction
        with patch.object(
            Orchestrator, "_ensure_collab_connected", new_callable=AsyncMock
        ) as mock_connect, patch.object(
            Orchestrator, "_ensure_collab_disconnected", new_callable=AsyncMock
        ) as mock_disconnect:

            # Build the collab client with all mocks
            collab = CollaboratorClient(orch._config)
            collab._mcp = _mock_mcp(
                create_result=_create_client_response("cid-1"),
                generate_result=_generate_payload_response("cid-1", "abcdef.oastify.com"),
                poll_results=_poll_response([_dns_interaction(client_ip="10.0.0.5")]),
            )
            orch._collab = collab
            orch._ensure_collab_connected = AsyncMock()

            entries = await orch._run_payload_and_verification(
                [_make_candidate(param_name="webhook_url")]
            )

        assert len(entries) > 0, "Expected at least one ReportEntry"

        # Every entry must link back to the candidate
        for e in entries:
            assert e.candidate.id == "test-c1"
            assert e.payload.candidate_id == "test-c1"

        # Should have OAST entries with collaborator_domain set
        oast_entries = [
            e for e in entries
            if e.payload.collaborator_domain is not None
        ]
        ip_entries = [
            e for e in entries
            if e.payload.collaborator_domain is None
        ]

        assert len(oast_entries) > 0, "Expected OAST entries with collaborator_domain"
        assert len(ip_entries) > 0, "Expected internal-IP entries without collaborator_domain"

        # Each OAST entry should have a distinct domain
        oast_domains = {e.payload.collaborator_domain for e in oast_entries}
        assert len(oast_domains) == len(oast_entries), (
            f"Expected {len(oast_entries)} distinct domains, got {len(oast_domains)}: "
            f"{oast_domains}"
        )

        # IP entries should have hit=False
        for e in ip_entries:
            assert e.verification.hit is False
            assert e.verification.confidence == 0.0

    @pytest.mark.asyncio
    async def test_oast_entry_has_correct_technique_tagging(self):
        """Each OAST ReportEntry's payload should carry its respective technique."""
        orch = self._mock_orchestrator()

        collab = CollaboratorClient(orch._config)
        collab._mcp = _mock_mcp(
            create_result=_create_client_response("cid-1"),
            generate_result=_generate_payload_response("cid-1", "abcdef.oastify.com"),
            poll_results=_poll_response([]),
        )
        orch._collab = collab
        orch._ensure_collab_connected = AsyncMock()

        entries = await orch._run_payload_and_verification(
            [_make_candidate(param_name="webhook_url")]
        )

        oast_entries = [e for e in entries if e.payload.collaborator_domain is not None]
        techniques_seen = set()
        for e in oast_entries:
            for t in e.payload.bypass_techniques:
                techniques_seen.add(t)

        # Should include URL confusion and protocol techniques
        assert BypassTechnique.URL_USERINFO_INJECTION in techniques_seen
        assert BypassTechnique.URL_SCHEME_OMIT in techniques_seen
        # webhook_url should trigger protocol tricks
        assert BypassTechnique.PROTOCOL_GOPHER in techniques_seen

    @pytest.mark.asyncio
    async def test_generic_query_param_gets_no_protocol_entries(self):
        """A generic 'redirect' query param should NOT get protocol entries."""
        orch = self._mock_orchestrator()

        collab = CollaboratorClient(orch._config)
        collab._mcp = _mock_mcp(
            create_result=_create_client_response("cid-1"),
            generate_result=_generate_payload_response("cid-1", "abcdef.oastify.com"),
            poll_results=_poll_response([]),
        )
        orch._collab = collab
        orch._ensure_collab_connected = AsyncMock()

        entries = await orch._run_payload_and_verification(
            [_make_candidate(param_name="redirect", param_location="query")]
        )

        oast_entries = [e for e in entries if e.payload.collaborator_domain is not None]
        techniques_seen = set()
        for e in oast_entries:
            for t in e.payload.bypass_techniques:
                techniques_seen.add(t)

        # URL confusion techniques should be present
        assert BypassTechnique.URL_USERINFO_INJECTION in techniques_seen
        # Protocol tricks should NOT be present for generic redirect
        assert BypassTechnique.PROTOCOL_GOPHER not in techniques_seen
        assert BypassTechnique.PROTOCOL_DICT not in techniques_seen
        assert BypassTechnique.PROTOCOL_FILE not in techniques_seen

    @pytest.mark.asyncio
    async def test_ip_entries_have_all_six_ip_techniques(self):
        """Internal-IP category should produce all 6 encoding techniques × 3 IPs = 18 entries."""
        orch = self._mock_orchestrator()

        collab = CollaboratorClient(orch._config)
        collab._mcp = _mock_mcp(
            create_result=_create_client_response("cid-1"),
            generate_result=_generate_payload_response("cid-1", "abcdef.oastify.com"),
            poll_results=_poll_response([]),
        )
        orch._collab = collab
        orch._ensure_collab_connected = AsyncMock()

        entries = await orch._run_payload_and_verification(
            [_make_candidate(param_name="redirect", param_location="query")]
        )

        ip_entries = [e for e in entries if e.payload.collaborator_domain is None]
        ip_techniques_seen = set()
        for e in ip_entries:
            for t in e.payload.bypass_techniques:
                ip_techniques_seen.add(t)

        expected = {
            BypassTechnique.IP_DECIMAL,
            BypassTechnique.IP_HEX,
            BypassTechnique.IP_OCTAL,
            BypassTechnique.IP_SHORT,
            BypassTechnique.IPV6_FULL,
            BypassTechnique.IPV4_MAPPED_IPV6,
        }
        assert ip_techniques_seen == expected, (
            f"Expected all 6 IP techniques, got {ip_techniques_seen}"
        )
        # One entry per technique = 6
        assert len(ip_entries) == 6


# ═══════════════════════════════════════════════════════════════════════════
# Config regression: Interaction uses client_ip, not source_ip
# ═══════════════════════════════════════════════════════════════════════════

class TestInteractionModel:
    def test_client_ip_field_exists(self):
        i = Interaction(
            protocol="dns",
            client_ip="1.2.3.4",
            timestamp=datetime.now(timezone.utc),
        )
        assert i.client_ip == "1.2.3.4"

    def test_source_ip_field_removed(self):
        """The old source_ip field must not exist."""
        with pytest.raises(Exception):
            Interaction(
                protocol="dns",
                source_ip="1.2.3.4",
                timestamp=datetime.now(timezone.utc),
            )


class TestPayloadModel:
    def test_collaborator_domain_defaults_to_none(self):
        p = Payload(id="p1", candidate_id="c1", value="http://x.com")
        assert p.collaborator_domain is None

    def test_collaborator_domain_settable(self):
        p = Payload(
            id="p1", candidate_id="c1", value="http://x.com",
            collaborator_domain="abc.oastify.com",
        )
        assert p.collaborator_domain == "abc.oastify.com"
