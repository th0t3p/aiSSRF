"""llm_judgment — Claude API call for structured SSRF verdict.

The ONLY module permitted to call an LLM.

Constraints enforced by design:
  - Input is ALWAYS structured evidence (CandidateEndpoint context +
    VerificationResult), never raw traffic or unverified payloads.
  - The LLM is NEVER asked "how should I verify this?" — that decision
    is made upstream by the deterministic modules.
  - Output is a structured LlmVerdict (verdict / severity / reasoning /
    chainable_to / suggested_next_step).

Uses httpx to speak the OpenAI-compatible chat/completions endpoint,
so Claude, GPT, and DeepSeek are all supported via the same wire format.
"""

from __future__ import annotations

from typing import Optional

import httpx

from aiSSRF.config import (
    AiSsrfConfig,
    CandidateEndpoint,
    VerificationResult,
    LlmVerdict,
)


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
        verification: VerificationResult,
    ) -> LlmVerdict:
        """
        Produce a structured verdict from already-verified evidence.

        Args:
            candidate:   The original candidate endpoint.
            verification: The result of Collaborator polling + CIDR checks.

        Returns:
            LlmVerdict with verdict, severity, reasoning, and optional
            chaining / next-step hints.
        """
        raise NotImplementedError("stub — builds prompt, calls _call_llm, parses response")

    # ------------------------------------------------------------------
    # Internal stubs
    # ------------------------------------------------------------------

    def _build_system_prompt(self) -> str:
        """
        Construct the system prompt that restricts the LLM to judging
        already-verified evidence.  Must explicitly forbid the model from
        suggesting new verification methods.
        """
        raise NotImplementedError("stub")

    def _build_user_prompt(
        self,
        candidate: CandidateEndpoint,
        verification: VerificationResult,
    ) -> str:
        """Render the structured evidence into a user message."""
        raise NotImplementedError("stub")

    async def _call_llm(self, payload: dict) -> dict:
        """
        POST to the chat/completions endpoint.

        Adapts headers per provider:
          - openai / deepseek:  ``Authorization: Bearer <key>``
          - anthropic:         ``x-api-key: <key>``
                               ``anthropic-version: 2023-06-01``
        """
        raise NotImplementedError("stub — httpx call")

    def _parse_response(self, raw: dict) -> LlmVerdict:
        """
        Extract the JSON verdict from the LLM response and validate it
        against the LlmVerdict schema.
        """
        raise NotImplementedError("stub")
