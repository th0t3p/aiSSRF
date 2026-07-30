"""Tests for LlmJudgment and the _run_llm_judgment orchestrator wiring."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from aiSSRF.config import (
    AiSsrfConfig,
    BypassTechnique,
    CandidateEndpoint,
    Interaction,
    Payload,
    VerificationResult,
    LlmVerdict,
    ReportEntry,
)
from aiSSRF.llm_judgment import LlmJudgment
from aiSSRF.orchestrator import Orchestrator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> AiSsrfConfig:
    defaults = {
        "authorized_scope": ["*.example.com"],
        "llm_provider": "anthropic",
        "llm_model": "claude-sonnet-4-20250514",
        "llm_api_key": "test-key",
        "llm_max_tokens": 256,
        "llm_temperature": 0.0,
    }
    defaults.update(overrides)
    return AiSsrfConfig(**defaults)


def _make_candidate(**overrides) -> CandidateEndpoint:
    defaults = {
        "id": "test-c1",
        "method": "GET",
        "url": "https://example.com/api?redirect=http://evil.com",
        "param_name": "redirect",
        "param_location": "query",
        "param_value": "http://evil.com",
        "host": "example.com",
    }
    defaults.update(overrides)
    return CandidateEndpoint(**defaults)


def _make_payload(**overrides):
    defaults = {
        "id": "p1",
        "candidate_id": "test-c1",
        "value": "http://abcdef.oastify.com/path",
        "bypass_techniques": [BypassTechnique.URL_USERINFO_INJECTION],
        "description": "Userinfo injection payload",
        "collaborator_domain": "abcdef.oastify.com",
    }
    defaults.update(overrides)
    return Payload(**defaults)


def _make_verification(**overrides) -> VerificationResult:
    defaults = {
        "payload_id": "p1",
        "candidate_id": "test-c1",
        "hit": True,
        "interactions": [
            Interaction(
                protocol="dns",
                client_ip="10.0.0.5",
                timestamp=datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc),
                dns_details={"query_type": "A", "query_name": "abcdef.oastify.com"},
            ),
        ],
        "in_target_infra": True,
        "false_positive": False,
        "confidence": 1.0,
    }
    defaults.update(overrides)
    return VerificationResult(**defaults)


# ── Mock httpx response helper ─────────────────────────────────────────────

def _mock_httpx_response(json_body: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = json.dumps(json_body)
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    else:
        resp.raise_for_status = MagicMock()
    return resp


# ═══════════════════════════════════════════════════════════════════════════
# _build_request_body — provider shapes
# ═══════════════════════════════════════════════════════════════════════════

class TestBuildRequestBody:
    def test_anthropic_shape(self):
        config = _make_config(llm_provider="anthropic")
        judge = LlmJudgment(config)
        req = judge._build_request_body("system", "user")

        assert req["provider"] == "anthropic"
        assert req["url"] == "https://api.anthropic.com/v1/messages"
        assert req["headers"]["x-api-key"] == "test-key"
        assert req["headers"]["anthropic-version"] == "2023-06-01"
        assert req["body"]["system"] == "system"
        assert req["body"]["messages"] == [{"role": "user", "content": "user"}]
        assert req["body"]["model"] == "claude-sonnet-4-20250514"
        assert req["body"]["max_tokens"] == 256

    def test_anthropic_omits_temperature_when_zero(self):
        config = _make_config(llm_provider="anthropic", llm_temperature=0.0)
        judge = LlmJudgment(config)
        req = judge._build_request_body("sys", "usr")
        assert "temperature" not in req["body"]

    def test_anthropic_includes_temperature_when_set(self):
        config = _make_config(llm_provider="anthropic", llm_temperature=0.5)
        judge = LlmJudgment(config)
        req = judge._build_request_body("sys", "usr")
        assert req["body"]["temperature"] == 0.5

    def test_openai_shape(self):
        config = _make_config(llm_provider="openai")
        judge = LlmJudgment(config)
        req = judge._build_request_body("system", "user")

        assert req["provider"] == "openai"
        assert req["url"] == "https://api.openai.com/v1/chat/completions"
        assert req["headers"]["Authorization"] == "Bearer test-key"
        msgs = req["body"]["messages"]
        assert msgs[0] == {"role": "system", "content": "system"}
        assert msgs[1] == {"role": "user", "content": "user"}
        assert req["body"]["model"] == "claude-sonnet-4-20250514"

    def test_deepseek_shape(self):
        config = _make_config(llm_provider="deepseek")
        judge = LlmJudgment(config)
        req = judge._build_request_body("s", "u")

        assert req["provider"] == "deepseek"
        assert req["url"] == "https://api.deepseek.com/v1/chat/completions"

    def test_custom_base_url(self):
        config = _make_config(
            llm_provider="openai",
            llm_base_url="https://custom-proxy.example.com/v1",
        )
        judge = LlmJudgment(config)
        req = judge._build_request_body("s", "u")
        assert req["url"] == "https://custom-proxy.example.com/v1/chat/completions"


# ═══════════════════════════════════════════════════════════════════════════
# _parse_response
# ═══════════════════════════════════════════════════════════════════════════

class TestParseResponse:
    def _judge(self, **kw):
        return LlmJudgment(_make_config(**kw))

    def test_anthropic_text_extraction(self):
        result = self._judge()._parse_response(
            {
                "content": [
                    {"text": '{"verdict":"confirmed","severity":"high",'
                     '"reasoning":"r","chainable_to":[],'
                     '"suggested_next_step":"report"}'}
                ],
                "_provider": "anthropic",
            },
            candidate_id="c1", payload_id="p1", model_used="claude-3",
        )
        assert result.verdict.value == "confirmed"
        assert result.severity.value == "high"
        assert result.candidate_id == "c1"
        assert result.payload_id == "p1"
        assert result.model_used == "claude-3"

    def test_openai_text_extraction(self):
        result = self._judge()._parse_response(
            {
                "choices": [
                    {"message": {
                        "content": '{"verdict":"inconclusive","severity":"medium",'
                                   '"reasoning":"x","chainable_to":[],'
                                   '"suggested_next_step":""}'
                    }}
                ],
                "_provider": "openai",
            },
            candidate_id="c2", payload_id="p2", model_used="gpt-4",
        )
        assert result.verdict.value == "inconclusive"
        assert result.severity.value == "medium"

    def test_strips_markdown_json_fence(self):
        result = self._judge()._parse_response(
            {
                "content": [
                    {"text": '```json\n{"verdict":"false_positive",'
                             '"severity":"low","reasoning":"f",'
                             '"chainable_to":[],'
                             '"suggested_next_step":""}\n```'}
                ],
                "_provider": "anthropic",
            },
            candidate_id="c3", payload_id="p3", model_used="c",
        )
        assert result.verdict.value == "false_positive"

    def test_strips_bare_markdown_fence(self):
        result = self._judge()._parse_response(
            {
                "content": [
                    {"text": '```\n{"verdict":"confirmed","severity":"info",'
                             '"reasoning":"ok","chainable_to":[],'
                             '"suggested_next_step":""}\n```'}
                ],
                "_provider": "anthropic",
            },
            candidate_id="c4", payload_id="p4", model_used="c",
        )
        assert result.verdict.value == "confirmed"

    def test_raises_on_non_json_text(self):
        judge = self._judge()
        with pytest.raises(RuntimeError, match="not json"):
            judge._parse_response(
                {"content": [{"text": "not json at all"}], "_provider": "anthropic"},
                candidate_id="x", payload_id="y", model_used="z",
            )

    def test_raises_on_empty_content(self):
        judge = self._judge()
        with pytest.raises(RuntimeError, match="no text content"):
            judge._parse_response(
                {"content": [], "_provider": "anthropic"},
                candidate_id="x", payload_id="y", model_used="z",
            )

    def test_caller_ids_override_llm_ids(self):
        """IDs come from the caller, not whatever the LLM happened to emit."""
        result = self._judge()._parse_response(
            {
                "content": [
                    {"text": '{"verdict":"confirmed","severity":"high",'
                             '"reasoning":"r","chainable_to":[],'
                             '"suggested_next_step":"s"}'}
                ],
                "_provider": "anthropic",
            },
            candidate_id="CALLER-C1",
            payload_id="CALLER-P1",
            model_used="CALLER-MODEL",
        )
        assert result.candidate_id == "CALLER-C1"
        assert result.payload_id == "CALLER-P1"
        assert result.model_used == "CALLER-MODEL"

    def test_regression_fully_fenced_parses(self):
        """Exact reproduction from bug report: fully-wrapped response with
        both ````json` and closing ```` ``` ```` must parse correctly."""
        text = (
            '```json\n'
            '{"verdict":"confirmed","severity":"high",'
            '"reasoning":"callback from target infrastructure",'
            '"chainable_to":["credential_leak"],'
            '"suggested_next_step":"escalate to manual review"}'
            '\n```'
        )
        result = self._judge()._parse_response(
            {"content": [{"text": text}], "_provider": "anthropic"},
            candidate_id="c-repro", payload_id="p-repro", model_used="m",
        )
        assert result.verdict.value == "confirmed"
        assert result.severity.value == "high"
        assert result.reasoning == "callback from target infrastructure"
        assert result.chainable_to == ["credential_leak"]

    def test_regression_leading_fence_only_still_parses(self):
        """Leading-only fence (no trailing ```` ``` ```` — some models
        truncate) must still parse correctly after the combined-regex fix."""
        text = (
            '```json\n'
            '{"verdict":"false_positive","severity":"low",'
            '"reasoning":"likely sandbox callback",'
            '"chainable_to":[],'
            '"suggested_next_step":"document as false positive"}'
        )
        result = self._judge()._parse_response(
            {"content": [{"text": text}], "_provider": "anthropic"},
            candidate_id="c-lead", payload_id="p-lead", model_used="m",
        )
        assert result.verdict.value == "false_positive"
        assert result.severity.value == "low"


# ═══════════════════════════════════════════════════════════════════════════
# judge() integration — mocks httpx
# ═══════════════════════════════════════════════════════════════════════════

class TestJudgeIntegration:
    @pytest.mark.asyncio
    async def test_judge_calls_correct_anthropic_endpoint(self):
        config = _make_config(llm_provider="anthropic")
        judge = LlmJudgment(config)

        mock_resp = _mock_httpx_response({
            "content": [
                {"text": '{"verdict":"confirmed","severity":"high",'
                         '"reasoning":"test reasoning",'
                         '"chainable_to":["credential_leak"],'
                         '"suggested_next_step":"escalate to manual review"}'}
            ]
        })
        judge._client = AsyncMock()
        judge._client.post.return_value = mock_resp

        candidate = _make_candidate()
        payload = _make_payload()
        verification = _make_verification()

        verdict = await judge.judge(candidate, payload, verification)

        # Verify the POST URL
        call_args = judge._client.post.call_args
        assert "/v1/messages" in call_args[0][0]

        assert verdict.verdict.value == "confirmed"
        assert verdict.severity.value == "high"
        assert verdict.candidate_id == candidate.id
        assert verdict.payload_id == payload.id

    @pytest.mark.asyncio
    async def test_judge_calls_correct_openai_endpoint(self):
        config = _make_config(llm_provider="openai")
        judge = LlmJudgment(config)

        mock_resp = _mock_httpx_response({
            "choices": [
                {"message": {
                    "content": '{"verdict":"inconclusive","severity":"medium",'
                               '"reasoning":"ambiguous","chainable_to":[],'
                               '"suggested_next_step":"correlate with logs"}'
                }}
            ]
        })
        judge._client = AsyncMock()
        judge._client.post.return_value = mock_resp

        verdict = await judge.judge(
            _make_candidate(), _make_payload(), _make_verification()
        )

        call_args = judge._client.post.call_args
        assert "/chat/completions" in call_args[0][0]
        assert verdict.verdict.value == "inconclusive"

    @pytest.mark.asyncio
    async def test_judge_raises_on_http_error(self):
        config = _make_config()
        judge = LlmJudgment(config)

        mock_resp = _mock_httpx_response({}, status_code=500)
        judge._client = AsyncMock()
        judge._client.post.return_value = mock_resp

        with pytest.raises(RuntimeError, match="HTTP 500"):
            await judge.judge(
                _make_candidate(), _make_payload(), _make_verification()
            )

    @pytest.mark.asyncio
    async def test_judge_raises_on_malformed_response(self):
        config = _make_config()
        judge = LlmJudgment(config)

        mock_resp = _mock_httpx_response({
            "content": [{"text": "this is not valid JSON"}]
        })
        judge._client = AsyncMock()
        judge._client.post.return_value = mock_resp

        with pytest.raises(RuntimeError, match="Failed to parse"):
            await judge.judge(
                _make_candidate(), _make_payload(), _make_verification()
            )


# ═══════════════════════════════════════════════════════════════════════════
# _build_user_prompt — evidence rendering
# ═══════════════════════════════════════════════════════════════════════════

class TestBuildUserPrompt:
    def test_includes_candidate_fields(self):
        judge = LlmJudgment(_make_config())
        prompt = judge._build_user_prompt(
            _make_candidate(id="abc", method="POST", host="target.com"),
            _make_payload(),
            _make_verification(),
        )
        assert "abc" in prompt
        assert "POST" in prompt
        assert "target.com" in prompt

    def test_includes_payload_fields(self):
        judge = LlmJudgment(_make_config())
        payload = _make_payload(
            value="http://collab.com/x",
            bypass_techniques=[BypassTechnique.IP_DECIMAL, BypassTechnique.IP_HEX],
        )
        prompt = judge._build_user_prompt(
            _make_candidate(), payload, _make_verification(),
        )
        assert "http://collab.com/x" in prompt
        assert "ip_decimal" in prompt
        assert "ip_hex" in prompt

    def test_includes_verification_and_interactions(self):
        judge = LlmJudgment(_make_config())
        verification = _make_verification(
            hit=True, in_target_infra=True, confidence=1.0,
        )
        prompt = judge._build_user_prompt(
            _make_candidate(), _make_payload(), verification,
        )
        assert "Hit:" in prompt
        assert "In Target Infra" in prompt
        assert "1.00" in prompt
        assert "10.0.0.5" in prompt
        assert "dns" in prompt
        assert "dns_details" not in prompt.lower() or "query_type" in prompt

    def test_renders_interaction_details(self):
        judge = LlmJudgment(_make_config())
        verification = _make_verification(
            interactions=[
                Interaction(
                    protocol="http",
                    client_ip="10.0.0.5",
                    timestamp=datetime(2026, 7, 30, 12, 0, tzinfo=timezone.utc),
                    http_details={
                        "protocol": "HTTP/1.1",
                        "request_method": "GET",
                        "request_url": "/interact",
                        "response_status": 200,
                    },
                )
            ]
        )
        prompt = judge._build_user_prompt(
            _make_candidate(), _make_payload(), verification,
        )
        assert "HTTP/1.1" in prompt
        assert "/interact" in prompt


# ═══════════════════════════════════════════════════════════════════════════
# Orchestrator._run_llm_judgment
# ═══════════════════════════════════════════════════════════════════════════

class TestOrchestratorLlmJudgment:
    @pytest.mark.asyncio
    async def test_skips_entries_with_hit_false(self):
        """Entries with hit=False must keep verdict=None — they should NOT
        trigger an LLM call at all."""
        config = _make_config()
        orch = Orchestrator(config)

        entry_no_hit = ReportEntry(
            candidate=_make_candidate(),
            payload=_make_payload(),
            verification=_make_verification(hit=False, confidence=0.0),
        )

        # Mock judge() to track calls
        mock_judge = AsyncMock()
        orch._llm = MagicMock()
        orch._llm.judge = mock_judge

        entries = await orch._run_llm_judgment([entry_no_hit])

        assert len(entries) == 1
        assert entries[0].verdict is None, (
            "hit=False entry should keep verdict=None"
        )
        mock_judge.assert_not_called()

    @pytest.mark.asyncio
    async def test_calls_judge_for_hit_true_entries(self):
        """Entries with hit=True must trigger judge() and receive a verdict."""
        config = _make_config()
        orch = Orchestrator(config)

        entry_hit = ReportEntry(
            candidate=_make_candidate(),
            payload=_make_payload(),
            verification=_make_verification(hit=True),
        )

        mock_verdict = LlmVerdict(
            candidate_id="test-c1",
            payload_id="p1",
            verdict="confirmed",
            severity="high",
            reasoning="test",
            chainable_to=[],
            suggested_next_step="report",
            model_used="test-model",
        )

        orch._llm = MagicMock()
        orch._llm.judge = AsyncMock(return_value=mock_verdict)

        entries = await orch._run_llm_judgment([entry_hit])

        assert len(entries) == 1
        assert entries[0].verdict is not None
        assert entries[0].verdict.verdict.value == "confirmed"
        orch._llm.judge.assert_called_once()

    @pytest.mark.asyncio
    async def test_mixed_hit_and_no_hit_entries(self):
        """Some hit, some not — only hit entries get judged."""
        config = _make_config()
        orch = Orchestrator(config)

        entry_hit = ReportEntry(
            candidate=_make_candidate(id="hit-candidate"),
            payload=_make_payload(id="hit-payload"),
            verification=_make_verification(hit=True),
        )
        entry_no_hit = ReportEntry(
            candidate=_make_candidate(id="nohit-candidate"),
            payload=_make_payload(id="nohit-payload"),
            verification=_make_verification(hit=False, confidence=0.0),
        )

        mock_verdict = LlmVerdict(
            candidate_id="hit-candidate",
            payload_id="hit-payload",
            verdict="confirmed",
            severity="high",
            reasoning="",
            chainable_to=[],
            suggested_next_step="",
            model_used="test",
        )

        orch._llm = MagicMock()
        orch._llm.judge = AsyncMock(return_value=mock_verdict)

        entries = await orch._run_llm_judgment([entry_hit, entry_no_hit])

        assert len(entries) == 2
        assert entries[0].verdict is not None  # hit=True
        assert entries[1].verdict is None       # hit=False
        orch._llm.judge.assert_called_once()    # only one call
