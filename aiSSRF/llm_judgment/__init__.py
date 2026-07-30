"""llm_judgment — LLM call for structured SSRF verdict on verified evidence.

The ONLY module permitted to call an LLM.

Constraints enforced by design:
  - Input is ALWAYS structured evidence (CandidateEndpoint + Payload +
    VerificationResult), never raw traffic or unverified payloads.
  - The LLM is NEVER asked "how should I verify this?" — that decision
    is made upstream by the deterministic modules.
  - Output is a structured LlmVerdict (verdict / severity / reasoning /
    chainable_to / suggested_next_step).

Supports two distinct API shapes:
  - Anthropic (Messages API):  POST /v1/messages  with x-api-key header
  - OpenAI / DeepSeek:         POST /v1/chat/completions with
                               Authorization: Bearer header — these
                               genuinely share the same wire format.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

import httpx

from aiSSRF.config import (
    AiSsrfConfig,
    CandidateEndpoint,
    Payload,
    VerificationResult,
    LlmVerdict,
)

logger = logging.getLogger(__name__)

# Single regex that strips both leading and trailing markdown code fences
# in one pass.  Anchored at ^ (start) for the opening fence and $ (end)
# for the closing fence so only outer wrapping is affected.
_MD_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


class LlmJudgment:
    """Call the LLM for a structured verdict on verified evidence."""

    def __init__(self, config: AiSsrfConfig) -> None:
        self._config = config
        self._client: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def judge(
        self,
        candidate: CandidateEndpoint,
        payload: Payload,
        verification: VerificationResult,
    ) -> LlmVerdict:
        """Produce a structured verdict from already-verified evidence.

        Args:
            candidate:     The original candidate endpoint.
            payload:       The payload that triggered the interactions
                           (carries ``bypass_techniques`` for severity
                           context).
            verification:  The result of Collaborator polling + CIDR checks.
        """
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(candidate, payload, verification)

        request_body = self._build_request_body(system_prompt, user_prompt)
        raw_response = await self._call_llm(request_body)

        return self._parse_response(
            raw_response,
            candidate_id=candidate.id,
            payload_id=payload.id,
            model_used=self._config.llm_model,
        )

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

    def _build_system_prompt(self) -> str:
        """Construct the system prompt that restricts the LLM to judging
        already-verified evidence."""
        return (
            "You are an AI security analyst assisting authorized bug bounty "
            "research.  The user will present evidence from automated OAST "
            "(out-of-band) callback testing for SSRF (Server-Side Request "
            "Forgery) candidates.  This testing has been conducted under an "
            "explicit authorized scope — you are NOT being asked to suggest "
            "or evaluate unauthorized actions.\n"
            "\n"
            "Your job is to JUDGE ONLY the evidence given.  Do NOT:\n"
            "  - Suggest new SSRF payloads or bypass techniques.\n"
            "  - Propose new verification or exploitation methods.\n"
            "  - Speculate about attack chains not directly supported by "
            "the evidence.\n"
            "\n"
            "suggested_next_step should describe reporting/remediation-adjacent "
            "next steps (e.g. \"escalate to manual review\", \"check if the "
            "confirmed SSRF host has neighboring in-scope assets\", \"document "
            "in the final report with the interaction timestamps\"), NOT new "
            "attack techniques.\n"
            "\n"
            "Respond with ONLY a single JSON object — no markdown fences, no "
            "prose before or after — matching exactly this shape:\n"
            '{"verdict": "confirmed"|"inconclusive"|"false_positive",\n'
            ' "severity": "info"|"low"|"medium"|"high"|"critical",\n'
            ' "reasoning": str,\n'
            ' "chainable_to": [str, ...],\n'
            ' "suggested_next_step": str}\n'
            "\n"
            "Severity guidance:\n"
            "  - critical: confirmed SSRF to a highly-sensitive internal "
            "endpoint (e.g. cloud metadata 169.254.169.254) with potential "
            "for credential leakage or RCE chaining.\n"
            "  - high: confirmed SSRF to internal infrastructure with clear "
            "callbacks from the target's IP space.\n"
            "  - medium: confirmed callbacks but from unknown or ambiguous "
            "infrastructure (not clearly target-owned).\n"
            "  - low: interactions seen but likely false-positive (callbacks "
            "from tester's own infrastructure or unrelated third parties).\n"
            "  - info: no interactions or insufficient data to judge.\n"
        )

    def _build_user_prompt(
        self,
        candidate: CandidateEndpoint,
        payload: Payload,
        verification: VerificationResult,
    ) -> str:
        """Render the structured evidence as a readable text block."""
        lines: list[str] = []

        # Candidate context
        lines.append("=== CANDIDATE ENDPOINT ===")
        lines.append(f"ID:              {candidate.id}")
        lines.append(f"Method:          {candidate.method}")
        lines.append(f"URL:             {candidate.url}")
        lines.append(f"Host:            {candidate.host}")
        lines.append(f"Parameter:       {candidate.param_name}")
        lines.append(f"Param Location:  {candidate.param_location}")
        lines.append(f"Original Value:  {candidate.param_value}")

        # Payload context
        lines.append("\n=== PAYLOAD ===")
        lines.append(f"Payload ID:      {payload.id}")
        lines.append(f"Payload Value:   {payload.value}")
        techniques = [t.value for t in payload.bypass_techniques]
        lines.append(f"Bypass Techniques: {', '.join(techniques) if techniques else 'none'}")
        lines.append(f"Description:     {payload.description}")

        # Verification results
        lines.append("\n=== VERIFICATION RESULTS ===")
        lines.append(f"Hit:             {verification.hit}")
        lines.append(f"In Target Infra: {verification.in_target_infra}")
        lines.append(f"False Positive:  {verification.false_positive}")
        lines.append(f"Confidence:      {verification.confidence:.2f}")

        # Interactions
        lines.append(f"\n=== INTERACTIONS ({len(verification.interactions)}) ===")
        for i, interaction in enumerate(verification.interactions, 1):
            lines.append(f"\n  Interaction #{i}:")
            lines.append(f"    Type:      {interaction.protocol}")
            lines.append(f"    Client IP: {interaction.client_ip}")
            lines.append(f"    Timestamp: {interaction.timestamp.isoformat()}")
            if interaction.dns_details:
                lines.append(f"    DNS Details: {json.dumps(interaction.dns_details)}")
            if interaction.http_details:
                lines.append(f"    HTTP Details: {json.dumps(interaction.http_details)}")
            if interaction.smtp_details:
                lines.append(f"    SMTP Details: {json.dumps(interaction.smtp_details)}")
            if interaction.raw_request:
                lines.append(f"    Raw Request: {interaction.raw_request[:500]}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # LLM call
    # ------------------------------------------------------------------

    def _build_request_body(
        self, system_prompt: str, user_prompt: str
    ) -> dict:
        """Build the provider-specific HTTP request body.

        Returns a dict with keys: url, headers, json_body — plus a
        'provider' key used by _call_llm to choose the response parser.
        """
        provider = self._config.llm_provider.lower()

        if provider == "anthropic":
            url = (
                self._config.llm_base_url.rstrip("/")
                if self._config.llm_base_url
                else "https://api.anthropic.com"
            ) + "/v1/messages"

            headers = {
                "x-api-key": self._config.llm_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }

            body: dict = {
                "model": self._config.llm_model,
                "max_tokens": self._config.llm_max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
            }
            if self._config.llm_temperature:
                body["temperature"] = self._config.llm_temperature

            return {"provider": "anthropic", "url": url, "headers": headers, "body": body}

        else:
            # openai / deepseek — share the same chat/completions shape
            if self._config.llm_base_url:
                base = self._config.llm_base_url.rstrip("/")
            elif provider == "deepseek":
                base = "https://api.deepseek.com/v1"
            else:
                base = "https://api.openai.com/v1"

            url = f"{base}/chat/completions"

            headers = {
                "Authorization": f"Bearer {self._config.llm_api_key}",
                "content-type": "application/json",
            }

            body = {
                "model": self._config.llm_model,
                "max_tokens": self._config.llm_max_tokens,
                "temperature": self._config.llm_temperature,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            }

            return {"provider": provider, "url": url, "headers": headers, "body": body}

    async def _call_llm(self, request: dict) -> dict:
        """POST to the provider-specific endpoint and return the HTTP
        response JSON dict."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=60.0)

        url = request["url"]
        headers = request["headers"]
        body = request["body"]

        logger.info("Calling LLM (%s): %s", request["provider"], url)
        resp = await self._client.post(url, json=body, headers=headers)

        if resp.status_code >= 400:
            raise RuntimeError(
                f"LLM API returned HTTP {resp.status_code}: {resp.text[:500]}"
            )

        return {**resp.json(), "_provider": request["provider"]}

    # ------------------------------------------------------------------
    # Response parsing
    # ------------------------------------------------------------------

    def _parse_response(
        self,
        raw: dict,
        *,
        candidate_id: str,
        payload_id: str,
        model_used: str,
    ) -> LlmVerdict:
        """Extract the JSON verdict from a provider-specific LLM response.

        Strips markdown fences if present, then JSON-decodes and validates
        against LlmVerdict.  Merges in caller-provided IDs (not trusted
        from the LLM).
        """
        provider = raw.pop("_provider", "unknown")

        # Extract the text field per provider shape
        if provider == "anthropic":
            content = raw.get("content", [])
            if isinstance(content, list) and content:
                text = content[0].get("text", "")
            else:
                text = ""
        else:
            # openai / deepseek
            choices = raw.get("choices", [])
            if isinstance(choices, list) and choices:
                text = choices[0].get("message", {}).get("content", "")
            else:
                text = ""

        if not text:
            raise RuntimeError(
                f"LLM response contained no text content. Raw: {json.dumps(raw)[:500]}"
            )

        # Strip markdown code fences (leading + trailing in one pass).
        # strip() first so the ^/$ anchors match even with surrounding
        # whitespace/newlines.
        cleaned = _MD_FENCE_RE.sub("", text.strip()).strip()

        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Failed to parse LLM verdict as JSON. "
                f"Raw text: {text[:500]!r}"
            ) from exc

        try:
            return LlmVerdict(
                candidate_id=candidate_id,
                payload_id=payload_id,
                model_used=model_used,
                verdict=parsed.get("verdict", "inconclusive"),
                severity=parsed.get("severity", "info"),
                reasoning=parsed.get("reasoning", ""),
                chainable_to=parsed.get("chainable_to", []),
                suggested_next_step=parsed.get("suggested_next_step", ""),
            )
        except Exception as exc:
            raise RuntimeError(
                f"LLM verdict validation failed. Parsed JSON: {json.dumps(parsed)[:500]!r}"
            ) from exc
