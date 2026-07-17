"""LLM-based judgment for SSRF findings.

The ONLY module that calls an LLM. Uses httpx to speak to OpenAI/Anthropic/DeepSeek
APIs directly — zero SDK dependencies.

LLM tasks are strictly limited to:
  a) Judging whether the structured evidence chain constitutes a real SSRF
     (as opposed to client-side behavior).
  b) Assessing severity and whether the finding is chainable to credential
     leakage or RCE.

The LLM is NEVER asked to "figure out how to verify" — all verification is
done upstream by the deterministic modules.
"""

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Literal

import httpx

from ..shared_types import (
    CandidateEndpoint,
    OastResult,
    ResponseDiffResult,
    LlmVerdict,
    Severity,
)


@dataclass
class LlmConfig:
    """LLM connection configuration — provider-agnostic."""
    provider: Literal["openai", "anthropic", "deepseek"] = "openai"
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""
    base_url: str = ""
    max_tokens: int = 1024
    temperature: float = 0.0
    extra_headers: Dict[str, str] = field(default_factory=dict)


# Default base URLs per provider
_DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
}

# Strict system prompt: defines exactly what the LLM may and may not do
_SYSTEM_PROMPT = """You are a security triage expert evaluating SSRF (Server-Side Request Forgery) findings.

Your ONLY task is to judge the structured evidence provided below. You must:

1. Determine whether the evidence constitutes a genuine server-side request forgery
   (the server initiated a request to an external/internal resource it should not have
   accessed) — as opposed to client-side behavior, a false positive from the scanner,
   or an intentional/non-exploitable outbound request.

2. If confirmed, assign a severity:
   - "info" — interesting but not exploitable
   - "low" — internal network scanning possible, no sensitive data reachable
   - "medium" — internal services reachable, limited data exposure
   - "high" — cloud metadata access, internal API access, sensitive data exposure
   - "critical" — credential leakage, RCE potential, cloud account takeover path

3. Identify whether this finding can be chained to:
   - credential_leak (cloud IAM credentials extracted)
   - rce (remote code execution via internal service exploitation)
   - internal_scan (internal network mapping)
   - data_exfiltration (ability to leak arbitrary data via the SSRF)

Rules:
- ONLY use the evidence provided. Do NOT suggest additional tests.
- Do NOT make assumptions beyond what the evidence supports.
- If the evidence is inconclusive, say so and assign "info" severity.
- Output ONLY valid JSON matching the required format. No markdown, no commentary."""

_USER_PROMPT_TEMPLATE = """## SSRF Evidence Report

### Candidate Endpoint
- URL: {endpoint}
- Method: {method}
- Parameter: {param_name} (in {param_location})
- Original value: {original_value}
- Source: {source}
- Heuristics triggered: {heuristics}

### OAST Correlation Result
{{
  "hit": {oast_hit},
  "source_ip": "{oast_source_ip}",
  "protocol": "{oast_protocol}",
  "in_target_network": {oast_in_target},
  "known_self_ip": {oast_self_ip},
  "confidence": {oast_confidence}
}}

### Response Differential Analysis Result
{{
  "reachable": {diff_reachable},
  "confidence": {diff_confidence},
  "p_value": {diff_p_value},
  "metrics_diff": {diff_metrics}
}}

### Target Tech Stack
{tech_stack}

---

Output a JSON object with these fields:
```json
{{
  "verdict": true/false,
  "severity": "info" | "low" | "medium" | "high" | "critical",
  "reasoning": "Brief explanation of your judgment (2-4 sentences)",
  "chainable_to": ["credential_leak", "rce", "internal_scan", "data_exfiltration"],
  "suggested_next_step": "What the bug bounty hunter should do next"
}}
```"""


class LlmJudgment:
    """Call LLM for semantic judgment of SSRF evidence."""

    def __init__(self, config: LlmConfig):
        self.config = config
        self._base_url = config.base_url or _DEFAULT_BASE_URLS.get(
            config.provider, "https://api.openai.com/v1"
        )

    async def judge(self,
                    candidate: CandidateEndpoint,
                    oast_result: Optional[OastResult],
                    diff_result: Optional[ResponseDiffResult],
                    tech_stack: str = "") -> LlmVerdict:
        """
        Core method: send structured evidence to LLM and return verdict.

        Args:
            candidate: The candidate endpoint from discovery
            oast_result: OAST correlation result (may be None)
            diff_result: Response diff analysis result (may be None)
            tech_stack: Optional target tech stack context (e.g., "AWS Lambda, Python 3.11")
        """
        user_prompt = self._build_user_prompt(candidate, oast_result, diff_result, tech_stack)
        payload = self._build_payload(user_prompt)

        try:
            raw_response = await self._call_llm(payload)
            verdict = self._parse_response(raw_response)
            verdict.model_used = self.config.model
            return verdict
        except Exception as e:
            return LlmVerdict(
                verdict=False,
                severity=Severity.INFO,
                reasoning=f"LLM judgment failed: {e}",
                model_used=self.config.model,
            )

    # ===== Prompt building =====

    def _build_user_prompt(self,
                           candidate: CandidateEndpoint,
                           oast: Optional[OastResult],
                           diff: Optional[ResponseDiffResult],
                           tech_stack: str) -> str:
        """Build the user prompt from structured evidence."""
        oast_hit = oast.hit if oast else False
        oast_source_ip = oast.source_ip if oast else "N/A"
        oast_protocol = oast.protocol.value if (oast and oast.protocol) else "N/A"
        oast_in_target = oast.in_target_network if oast else False
        oast_self_ip = oast.known_self_ip if oast else False
        oast_confidence = oast.confidence if oast else 0.0

        diff_reachable = diff.reachable if diff else False
        diff_confidence = diff.confidence if diff else 0.0
        diff_p_value = diff.p_value if (diff and diff.p_value) else "N/A"
        diff_metrics = json.dumps(diff.metrics_diff) if diff else "{}"

        return _USER_PROMPT_TEMPLATE.format(
            endpoint=candidate.endpoint,
            method=candidate.method.value,
            param_name=candidate.param_name,
            param_location=candidate.param_location,
            original_value=candidate.original_value,
            source=candidate.candidate_source.value,
            heuristics=", ".join(candidate.heuristics_triggered) or "none",
            oast_hit=json.dumps(oast_hit),
            oast_source_ip=oast_source_ip,
            oast_protocol=oast_protocol,
            oast_in_target=json.dumps(oast_in_target),
            oast_self_ip=json.dumps(oast_self_ip),
            oast_confidence=oast_confidence,
            diff_reachable=json.dumps(diff_reachable),
            diff_confidence=diff_confidence,
            diff_p_value=diff_p_value,
            diff_metrics=diff_metrics,
            tech_stack=tech_stack or "Unknown",
        )

    def _build_payload(self, user_prompt: str) -> Dict[str, Any]:
        """Build the HTTP payload for the chat completions endpoint."""
        return {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }

    # ===== LLM HTTP call =====

    async def _call_llm(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to the LLM API, adapt headers per provider."""
        headers = self._build_headers()
        endpoint = f"{self._base_url.rstrip('/')}/chat/completions"

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(endpoint, json=payload, headers=headers)
            resp.raise_for_status()
            return resp.json()

    def _build_headers(self) -> Dict[str, str]:
        """Build authentication headers based on provider type."""
        api_key = self.config.api_key or os.environ.get("LLM_API_KEY", "")
        headers = {"Content-Type": "application/json"}

        if self.config.provider == "anthropic":
            # Anthropic uses x-api-key header
            headers["x-api-key"] = api_key
            headers["anthropic-version"] = "2023-06-01"
        else:
            # OpenAI / DeepSeek / compatible use Bearer
            headers["Authorization"] = f"Bearer {api_key}"

        # Merge any extra headers from config
        headers.update(self.config.extra_headers)
        return headers

    # ===== Response parsing =====

    def _parse_response(self, raw: Dict[str, Any]) -> LlmVerdict:
        """Parse the LLM's JSON response into a LlmVerdict."""
        # Extract content from chat completion response
        choices = raw.get("choices", [])
        if not choices:
            raise ValueError("No choices in LLM response")

        content = choices[0].get("message", {}).get("content", "")
        if not content:
            raise ValueError("Empty content in LLM response")

        # Try to extract JSON from content (may be wrapped in markdown code block)
        parsed = self._extract_json(content)

        severity_str = parsed.get("severity", "info").lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.INFO

        return LlmVerdict(
            verdict=bool(parsed.get("verdict", False)),
            severity=severity,
            reasoning=str(parsed.get("reasoning", "")),
            chainable_to=list(parsed.get("chainable_to", []) or []),
            suggested_next_step=str(parsed.get("suggested_next_step", "")),
            model_used=self.config.model,
        )

    @staticmethod
    def _extract_json(text: str) -> Dict[str, Any]:
        """Extract JSON object from text that may contain markdown fences."""
        # Remove markdown code fences
        text = text.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            # Remove first line (```json or ```) and last line (```)
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines)

        # Find first { and matching }
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start:end + 1]

        return json.loads(text)

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Rough token count estimate — ~4 chars per token for English text."""
        return len(text) // 4
