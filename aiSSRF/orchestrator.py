"""orchestrator — Top-level pipeline that wires together all modules.

Pipeline
--------

  candidate_fetcher.fetch()
         │
         ▼
  payload_generator.generate()  × N candidates
         │
         ▼
  [send every payload through Burp via McpSseClient]
         │
         ▼
  collaborator_client.create_client()
  collaborator_client.generate_payload()
         │
         ▼
  collaborator_client.poll()   ← wait window (configurable)
         │
         ▼
  collaborator_client.verify_payload()  → VerificationResult
         │
         ▼
  llm_judgment.judge()         → LlmVerdict  (only if we have hits)
         │
         ▼
  ScanReport
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional

from aiSSRF.config import (
    AiSsrfConfig,
    CandidateEndpoint,
    Payload,
    VerificationResult,
    LlmVerdict,
    ReportEntry,
    ScanReport,
    Verdict,
    Severity,
)
from aiSSRF.candidate_fetcher import CandidateFetcher
from aiSSRF.payload_generator import PayloadGenerator
from aiSSRF.collaborator_client import CollaboratorClient
from aiSSRF.llm_judgment import LlmJudgment


class Orchestrator:
    """Wires the full pipeline and produces a ScanReport."""

    def __init__(self, config: AiSsrfConfig) -> None:
        self._config = config

        # Lazy-init sub-modules
        self._fetcher: Optional[CandidateFetcher] = None
        self._generator: Optional[PayloadGenerator] = None
        self._collab: Optional[CollaboratorClient] = None
        self._llm: Optional[LlmJudgment] = None

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def run(self) -> ScanReport:
        """
        Execute the full pipeline.

        Raises
        ------
        RuntimeError
            If ``authorized_scope`` is empty (fail-closed) — the tool
            refuses to proceed in this case.
        """
        if not self._config.authorized_scope:
            raise RuntimeError(
                "authorized_scope is empty — refusing to run (fail-closed). "
                "Add target domains to authorized_scope in your config."
            )

        report = ScanReport(
            config_summary=self._config.model_dump(
                exclude={"ai_scraper_api_key", "llm_api_key"}
            ),
            started_at=datetime.now(timezone.utc),
        )

        # --- Stage 1: discover candidates ---------------------------------
        candidates = await self._run_discovery()
        report.total_candidates = len(candidates)
        if not candidates:
            report.finished_at = datetime.now(timezone.utc)
            return report

        # --- Stage 2: generate payloads -----------------------------------
        payload_map = self._run_payload_generation(candidates)

        # --- Stage 3: OAST verification -----------------------------------
        entries = await self._run_oast_verification(candidates, payload_map)

        # --- Stage 4: LLM judgment (only for candidates with hits) ---------
        entries = await self._run_llm_judgment(entries)

        report.entries = entries
        report.confirmed = sum(1 for e in entries if e.is_confirmed)
        report.inconclusive = sum(
            1 for e in entries
            if e.verdict and e.verdict.verdict == Verdict.INCONCLUSIVE
        )
        report.false_positives = sum(
            1 for e in entries
            if e.verdict and e.verdict.verdict == Verdict.FALSE_POSITIVE
        )
        report.finished_at = datetime.now(timezone.utc)
        return report

    # ------------------------------------------------------------------
    # Stage implementations (stubs)
    # ------------------------------------------------------------------

    async def _run_discovery(self) -> list[CandidateEndpoint]:
        """Fetch candidates from aiScraper."""
        if self._fetcher is None:
            self._fetcher = CandidateFetcher(self._config)
        raise NotImplementedError("stub — calls self._fetcher.fetch()")

    def _run_payload_generation(
        self, candidates: list[CandidateEndpoint]
    ) -> dict[str, list[Payload]]:
        """
        Generate payloads for every candidate.

        Returns a dict keyed by candidate.id → list of Payloads.
        """
        raise NotImplementedError(
            "stub — creates PayloadGenerator, calls .generate() per candidate"
        )

    async def _run_oast_verification(
        self,
        candidates: list[CandidateEndpoint],
        payload_map: dict[str, list[Payload]],
    ) -> list[ReportEntry]:
        """
        For each candidate:
          1. Create a Collaborator client
          2. Generate a unique subdomain
          3. For each payload, send the modified request through Burp
          4. Poll Collaborator for interactions (wait window)
          5. verify_payload() → VerificationResult
          6. Assemble a ReportEntry

        Returns a list of ReportEntry (one per candidate).
        """
        raise NotImplementedError(
            "stub — orchestrates CollaboratorClient lifecycle + Burp send + poll"
        )

    async def _run_llm_judgment(
        self, entries: list[ReportEntry]
    ) -> list[ReportEntry]:
        """
        For each entry where verification had at least one interaction
        that passed the CIDR filter, call LlmJudgment.judge() and attach
        the verdict to the entry.

        Candidates with zero hits are left as-are (no LLM call).
        """
        raise NotImplementedError(
            "stub — skips entries w/o hits, calls LlmJudgment.judge() for the rest"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _ensure_collab_connected(self) -> None:
        """Lazy-init + connect the CollaboratorClient."""
        if self._collab is None:
            self._collab = CollaboratorClient(self._config)
            await self._collab.connect()

    async def _ensure_collab_disconnected(self) -> None:
        """Tear down the MCP connection."""
        if self._collab is not None:
            await self._collab.disconnect()
            self._collab = None
