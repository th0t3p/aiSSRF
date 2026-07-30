"""orchestrator — Top-level pipeline that wires together all modules.

Pipeline
--------

  candidate_fetcher.fetch()
         │
         ▼
  ┌── payload_generator + OAST verification (merged) ──┐
  │  For each candidate:                                │
  │    • Create Collaborator client                     │
  │    • Per OAST technique: fresh domain → generate    │
  │      payload → send via Burp → poll & verify        │
  │    • Per internal-IP technique: generate payload    │
  │      → send via Burp → mark as not OAST-verifiable  │
  └──────────────────────────────────────────────────────┘
         │
         ▼
  llm_judgment.judge()         → LlmVerdict  (only if we have hits)
         │
         ▼
  ScanReport
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from aiSSRF.config import (
    AiSsrfConfig,
    BypassTechnique,
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

logger = logging.getLogger(__name__)

# Techniques that encode a fixed internal IP — not OAST-verifiable.
_IP_TECHNIQUES = frozenset({
    BypassTechnique.IP_DECIMAL,
    BypassTechnique.IP_HEX,
    BypassTechnique.IP_OCTAL,
    BypassTechnique.IP_SHORT,
    BypassTechnique.IPV6_FULL,
    BypassTechnique.IPV4_MAPPED_IPV6,
})

# Everything else is OAST (Collaborator) or protocol-trick (gate via heuristic).
_OAST_TECHNIQUES = tuple(t for t in BypassTechnique if t not in _IP_TECHNIQUES)


class Orchestrator:
    """Wires the full pipeline and produces a ScanReport."""

    def __init__(self, config: AiSsrfConfig) -> None:
        self._config = config

        # Lazy-init sub-modules
        self._fetcher: Optional[CandidateFetcher] = None
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

        # --- Stages 2+3 (merged): generate payloads + OAST verification ---
        entries = await self._run_payload_and_verification(candidates)

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
    # Stage 1: discovery
    # ------------------------------------------------------------------

    async def _run_discovery(self) -> list[CandidateEndpoint]:
        """Fetch candidates from aiScraper."""
        if self._fetcher is None:
            self._fetcher = CandidateFetcher(self._config)
        return await self._fetcher.fetch()

    # ------------------------------------------------------------------
    # Stages 2+3 merged: payload generation + OAST verification
    # ------------------------------------------------------------------

    async def _run_payload_and_verification(
        self, candidates: list[CandidateEndpoint]
    ) -> list[ReportEntry]:
        """Generate payloads and verify OAST callbacks in one pass.

        For each candidate:
          - Create a Collaborator client
          - For each OAST technique: get a fresh domain, generate the
            payload with that domain's generator, send it through Burp,
            then poll + verify.
          - For each internal-IP technique: generate the payload, send
            through Burp, record as not-verifiable (hit=False).
        """
        entries: list[ReportEntry] = []
        await self._ensure_collab_connected()
        try:
            for candidate in candidates:
                client_id = await self._collab.create_client()

                # --- OAST + protocol-trick techniques -------------------
                for technique in _OAST_TECHNIQUES:
                    # Fresh domain per technique for precise correlation
                    collab_payload = await self._collab.generate_payload(client_id)
                    generator = PayloadGenerator(
                        collaborator_domain=collab_payload.collaborator_domain
                    )
                    payload = generator.generate_for_technique(candidate, technique)
                    if payload is None:
                        continue  # heuristic gate rejected this technique
                    payload.collaborator_domain = collab_payload.collaborator_domain

                    # Construct and send the modified request
                    method, url, headers, body = self._build_request(
                        candidate, payload.value
                    )
                    await self._collab.send_request(
                        candidate.id, method, url, headers, body,
                    )

                    # Poll and verify
                    verification = await self._collab.verify_payload(
                        client_id, payload, self._config.target_cidrs,
                    )
                    entries.append(
                        ReportEntry(
                            candidate=candidate,
                            payload=payload,
                            verification=verification,
                        )
                    )

                # --- Internal-IP-encoding techniques ---------------------
                # Not OAST-verifiable — no Collaborator domain.
                ip_generator = PayloadGenerator(collaborator_domain="unused.invalid")
                for technique in sorted(_IP_TECHNIQUES, key=lambda t: t.value):
                    payload = ip_generator.generate_for_technique(candidate, technique)
                    if payload is None:
                        continue
                    # payload.collaborator_domain stays None

                    method, url, headers, body = self._build_request(
                        candidate, payload.value,
                    )
                    await self._collab.send_request(
                        candidate.id, method, url, headers, body,
                    )
                    verification = VerificationResult(
                        payload_id=payload.id,
                        candidate_id=candidate.id,
                        hit=False,
                        confidence=0.0,
                    )
                    entries.append(
                        ReportEntry(
                            candidate=candidate,
                            payload=payload,
                            verification=verification,
                        )
                    )
        finally:
            await self._ensure_collab_disconnected()
        return entries

    # ------------------------------------------------------------------
    # Stage 4: LLM judgment (stub)
    # ------------------------------------------------------------------

    async def _run_llm_judgment(
        self, entries: list[ReportEntry]
    ) -> list[ReportEntry]:
        """For each entry with verified interactions, call the LLM."""
        raise NotImplementedError(
            "stub — skips entries w/o hits, calls LlmJudgment.judge() for the rest"
        )

    # ------------------------------------------------------------------
    # Request construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_request(
        candidate: CandidateEndpoint,
        new_value: str,
    ) -> tuple[str, str, dict[str, str], Optional[str]]:
        """Build a (method, url, headers, body) tuple with *new_value*
        substituted at ``candidate.param_location``.

        Handles:
          - ``query``: replace the param in the URL's query string
          - ``body``:   replace inside JSON or form-encoded body
          - ``header``: replace the header value
          - ``path``:   replace the param segment in the URL path
        """
        method = candidate.method
        headers = dict(candidate.request_headers)
        body = candidate.request_body
        url = candidate.url
        location = candidate.param_location
        param_name = candidate.param_name

        if location == "query":
            url = Orchestrator._replace_query_param(url, param_name, new_value)

        elif location == "body":
            body = Orchestrator._replace_body_param(body, param_name, new_value)

        elif location == "header":
            headers[param_name] = new_value

        elif location == "path":
            url = Orchestrator._replace_path_segment(url, param_name, new_value)

        return method, url, headers, body

    @staticmethod
    def _replace_query_param(url: str, param_name: str, new_value: str) -> str:
        """Replace a single query parameter in *url* with *new_value*."""
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs[param_name] = [new_value]
        new_query = urlencode(qs, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    @staticmethod
    def _replace_body_param(
        body: Optional[str], param_name: str, new_value: str,
    ) -> Optional[str]:
        """Replace *param_name*'s value in the request body.

        Tries JSON first, then form-encoded.  If neither parses, returns
        the body unchanged (best-effort).
        """
        if body is None:
            return None

        # JSON body
        try:
            data = json.loads(body)
            if isinstance(data, dict) and param_name in data:
                data[param_name] = new_value
                return json.dumps(data)
        except (json.JSONDecodeError, TypeError):
            pass

        # form-urlencoded body
        try:
            parsed = parse_qs(body, keep_blank_values=True)
            if param_name in parsed:
                parsed[param_name] = [new_value]
                return urlencode(parsed, doseq=True)
        except Exception:
            pass

        return body

    @staticmethod
    def _replace_path_segment(url: str, param_name: str, new_value: str) -> str:
        """Replace a path segment placeholder like ``{param}`` or the
        segment that matches *param_name* with *new_value*.

        Heuristic: look for ``{param_name}`` in the path; if not found,
        replace the last path segment (best-effort).
        """
        parsed = urlparse(url)
        path = parsed.path or "/"

        # Replace explicit template: /users/{id} → /users/new_value
        template = f"{{{param_name}}}"
        if template in path:
            path = path.replace(template, new_value)
        else:
            # Best-effort: replace the last segment if it looks like the
            # original param value
            segments = path.rstrip("/").split("/")
            if segments:
                segments[-1] = new_value
                path = "/".join(segments)
                if parsed.path.endswith("/"):
                    path += "/"

        return urlunparse((
            parsed.scheme, parsed.netloc, path,
            parsed.params, parsed.query, parsed.fragment,
        ))

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
