"""Main orchestrator for SSRF scanning pipeline.

Coordinates the 6 sub-modules in dependency order, managing:
  - Stage execution order (enforced DAG)
  - Concurrency control and rate limiting
  - SSE real-time progress push (via callback)
  - Resume-from-stage checkpointing
  - Final report generation

Pipeline stages:
  1. candidate_discovery  → List[CandidateEndpoint]
  2. payload_generation   → List[Payload]
  3. oast_correlation     → List[OastResult]       (for OAST payloads)
  4. response_diff_analysis → List[ResponseDiffResult] (for internal probes)
  5. cloud_credential_chain → List[CloudCredentialInfo] (if metadata hit)
  6. llm_judgment          → List[LlmVerdict]
"""

import asyncio
import json
import time
import uuid
from typing import Optional, List, Dict, Any, Callable, Awaitable

from ..shared_types import (
    CandidateEndpoint,
    CandidateSource,
    Payload,
    OastResult,
    ResponseDiffResult,
    LlmVerdict,
    CloudCredentialInfo,
    Finding,
    ScanConfig,
    ScanStage,
    SSRFType,
    Severity,
    SecurityError,
)
from ..candidate_discovery import CandidateDiscovery
from ..payload_generator import PayloadGenerator
from ..oast_correlation import OastCorrelation
from ..response_diff_analyzer import ResponseDiffAnalyzer
from ..llm_judgment import LlmJudgment, LlmConfig
from ..cloud_credential_chain import CloudCredentialChain


# Pipeline stage order
_STAGES = [
    "candidate_discovery",
    "payload_generation",
    "oast_correlation",
    "response_diff_analysis",
    "cloud_credential_chain",
    "llm_judgment",
]


class SSRFScanner:
    """Orchestrate the full SSRF detection pipeline."""

    def __init__(self,
                 config: ScanConfig,
                 sse_callback: Optional[Callable[[str, Dict], Awaitable[None]]] = None):
        """
        Args:
            config: Full scan configuration
            sse_callback: Async callback for SSE progress pushes.
                          Signature: async def callback(stage_name: str, data: dict)
        """
        self.config = config
        self._sse = sse_callback

        # State tracking
        self._stages: Dict[str, ScanStage] = {
            name: ScanStage(stage_name=name) for name in _STAGES
        }
        self._candidates: List[CandidateEndpoint] = []
        self._payloads: List[Payload] = []
        self._oast_results: Dict[str, OastResult] = {}
        self._diff_results: Dict[str, ResponseDiffResult] = {}
        self._cloud_infos: Dict[str, CloudCredentialInfo] = {}
        self._verdicts: Dict[str, LlmVerdict] = {}
        self._findings: List[Finding] = []

        # Module instances (lazy init)
        self._discovery = CandidateDiscovery()
        self._oast: Optional[OastCorrelation] = None
        self._diff_analyzer: Optional[ResponseDiffAnalyzer] = None
        self._llm: Optional[LlmJudgment] = None
        self._cloud_chain = CloudCredentialChain()

    @property
    def stages(self) -> List[str]:
        return list(_STAGES)

    # ===== Main entry point =====

    async def run(self) -> List[Finding]:
        """Run the complete scan pipeline. Returns list of findings."""
        start_idx = 0
        if self.config.resume_from_stage:
            try:
                start_idx = _STAGES.index(self.config.resume_from_stage)
            except ValueError:
                pass

        for stage_name in _STAGES[start_idx:]:
            stage = await self.run_stage(stage_name)
            if stage.status == "failed":
                await self._emit_progress(stage_name, 1.0,
                                          f"Stage {stage_name} failed: {stage.error}",
                                          status="failed")
                break

        return self._findings

    async def run_stage(self, stage_name: str) -> ScanStage:
        """Execute a single pipeline stage."""
        stage = self._stages[stage_name]
        stage.status = "running"
        await self._emit_progress(stage_name, 0.0, f"Starting {stage_name}",
                                  status="running")

        try:
            if stage_name == "candidate_discovery":
                await self._do_discovery(stage)
            elif stage_name == "payload_generation":
                await self._do_payload_gen(stage)
            elif stage_name == "oast_correlation":
                await self._do_oast(stage)
            elif stage_name == "response_diff_analysis":
                await self._do_diff_analysis(stage)
            elif stage_name == "cloud_credential_chain":
                await self._do_cloud_chain(stage)
            elif stage_name == "llm_judgment":
                await self._do_llm_judgment(stage)

            stage.status = "completed"
            await self._emit_progress(stage_name, 1.0,
                                      f"Completed {stage_name}",
                                      status="completed")

        except SecurityError as e:
            stage.status = "skipped"
            stage.error = str(e)
            await self._emit_progress(stage_name, 1.0,
                                      f"Skipped {stage_name}: {e}",
                                      status="skipped")
        except Exception as e:
            stage.status = "failed"
            stage.error = str(e)
            await self._emit_progress(stage_name, 1.0,
                                      f"Failed {stage_name}: {e}",
                                      status="failed")

        return stage

    # ===== Stage implementations =====

    async def _do_discovery(self, stage: ScanStage):
        """Stage 1: Discover candidate endpoints."""
        if self.config.input_source == CandidateSource.BURP_JSON:
            self._candidates = self._discovery.from_burp_json(self.config.input_file)
        elif self.config.input_source == CandidateSource.OPENAPI_SPEC:
            self._candidates = self._discovery.from_openapi_spec(self.config.input_file)
        else:
            raise ValueError(f"Unsupported input source: {self.config.input_source}")

        stage.items_total = len(self._candidates)
        stage.items_processed = len(self._candidates)
        await self._emit_progress("candidate_discovery", 1.0,
                                  f"Discovered {len(self._candidates)} candidates")

    async def _do_payload_gen(self, stage: ScanStage):
        """Stage 2: Generate payloads for all candidates."""
        if not self._oast:
            self._oast = OastCorrelation(
                api_url=self.config.oast_api_url,
                poll_interval_sec=self.config.oast_poll_interval_sec,
                poll_timeout_sec=self.config.oast_poll_timeout_sec,
            )

        oast_domain = self.config.oast_api_url
        generator = PayloadGenerator(
            oast_domain=oast_domain,
            target_network_cidrs=self.config.target_network_cidrs,
        )

        all_payloads: List[Payload] = []
        for i, candidate in enumerate(self._candidates):
            payloads = generator.generate(candidate)
            all_payloads.extend(payloads)

            if i % 10 == 0:
                await self._emit_progress(
                    "payload_generation",
                    (i + 1) / max(len(self._candidates), 1),
                    f"Generated payloads for {i + 1}/{len(self._candidates)} candidates",
                )

        self._payloads = all_payloads
        stage.items_total = len(self._payloads)
        stage.items_processed = len(self._payloads)
        await self._emit_progress("payload_generation", 1.0,
                                  f"Generated {len(self._payloads)} payloads")

    async def _do_oast(self, stage: ScanStage):
        """Stage 3: Run OAST correlation for OAST payloads."""
        if not self.config.authorized:
            raise SecurityError("OAST correlation requires authorized=True")

        if not self._oast:
            self._oast = OastCorrelation(
                api_url=self.config.oast_api_url,
                poll_interval_sec=self.config.oast_poll_interval_sec,
                poll_timeout_sec=self.config.oast_poll_timeout_sec,
            )

        session_id = await self._oast.create_session()

        # Only test OAST payloads (those targeting the OAST domain)
        oast_payloads = [p for p in self._payloads
                         if self.config.oast_api_url.replace("https://", "").replace("http://", "")
                         in p.value]

        stage.items_total = len(oast_payloads)

        # Start polling in background
        results = await self._oast.correlate(
            session_id=session_id,
            payloads=oast_payloads,
            target_network_cidrs=self.config.target_network_cidrs,
            target_asns=self.config.target_asns,
        )

        for r in results:
            self._oast_results[r.payload_id] = r

        stage.items_processed = len(results)
        self._oast.close_session(session_id)

        hits = sum(1 for r in results if r.hit and r.in_target_network)
        await self._emit_progress("oast_correlation", 1.0,
                                  f"OAST: {hits}/{len(results)} payloads hit")

    async def _do_diff_analysis(self, stage: ScanStage):
        """Stage 4: Response differential analysis for internal probes."""
        if not self.config.authorized:
            raise SecurityError("Response diff analysis requires authorized=True")

        if not self._diff_analyzer:
            self._diff_analyzer = ResponseDiffAnalyzer()

        # Find internal probe payloads (not OAST, not protocol-only)
        internal_payloads = [p for p in self._payloads
                             if "127.0.0.1" in p.value or "localhost" in p.value
                             or "169.254" in p.value or "10." in p.value
                             or "172." in p.value or "192.168" in p.value]

        stage.items_total = len(internal_payloads)

        # Group by candidate
        by_candidate: Dict[str, List[Payload]] = {}
        for p in internal_payloads:
            by_candidate.setdefault(p.candidate_id, []).append(p)

        sem = asyncio.Semaphore(self.config.concurrency)

        async def _analyze_one(candidate: CandidateEndpoint, payloads: List[Payload]):
            async with sem:
                for payload in payloads:
                    try:
                        probes = await self._diff_analyzer.collect_test_samples(
                            candidate, [payload.value], authorized=True
                        )
                        baseline = await self._diff_analyzer.collect_baseline(
                            candidate,
                            candidate.request_context.url,  # original URL as baseline
                            authorized=True,
                        )
                        for url, test_probes in probes.items():
                            result = self._diff_analyzer.analyze(baseline, test_probes)
                            result.payload_id = payload.id
                            self._diff_results[payload.id] = result
                    except Exception:
                        continue

        tasks = []
        for candidate_id, plist in by_candidate.items():
            candidate = next((c for c in self._candidates if c.id == candidate_id), None)
            if candidate:
                tasks.append(_analyze_one(candidate, plist))

        if tasks:
            await asyncio.gather(*tasks)

        stage.items_processed = len(self._diff_results)
        reachable = sum(1 for r in self._diff_results.values() if r.reachable)
        await self._emit_progress("response_diff_analysis", 1.0,
                                  f"Diff analysis: {reachable} likely reachable")

    async def _do_cloud_chain(self, stage: ScanStage):
        """Stage 5: Check for cloud metadata hits."""
        # Check OAST results for metadata responses
        metadata_hits = 0
        for result in self._oast_results.values():
            if not result.hit or not result.request_body:
                continue

            # Check if any metadata endpoint was hit
            for metadata_url in self.config.cloud_metadata_endpoints:
                cloud_type = CloudCredentialChain.is_cloud_metadata_endpoint(metadata_url)
                if not cloud_type:
                    continue

                info = self._cloud_chain.parse_metadata_response(
                    result.request_body, metadata_url
                )
                if info and info.credentials_raw:
                    if self.config.authorized:
                        info = await self._cloud_chain.build_permission_graph(
                            info.credentials_raw, cloud_type, authorized=True
                        )
                    self._cloud_infos[result.payload_id] = info
                    metadata_hits += 1

        stage.items_processed = metadata_hits
        await self._emit_progress("cloud_credential_chain", 1.0,
                                  f"Cloud metadata: {metadata_hits} hits")

    async def _do_llm_judgment(self, stage: ScanStage):
        """Stage 6: LLM judgment on all gathered evidence."""
        if not self._llm:
            llm_config = LlmConfig(
                provider=self.config.llm_provider,
                model=self.config.llm_model,
                api_key=self.config.llm_api_key,
                base_url=self.config.llm_base_url,
                max_tokens=self.config.llm_max_tokens,
                temperature=self.config.llm_temperature,
                extra_headers=self.config.llm_extra_headers,
            )
            self._llm = LlmJudgment(llm_config)

        # Build evidence bundles: one per payload that had some hit
        judged = 0
        for payload in self._payloads:
            oast = self._oast_results.get(payload.id)
            diff = self._diff_results.get(payload.id)
            cloud_info = self._cloud_infos.get(payload.id)

            # Skip payloads with no signals at all
            if not oast or (not oast.hit and not diff):
                continue

            candidate = next((c for c in self._candidates
                              if c.id == payload.candidate_id), None)
            if not candidate:
                continue

            verdict = await self._llm.judge(
                candidate=candidate,
                oast_result=oast,
                diff_result=diff,
                tech_stack="",  # can be extended with target info
            )
            self._verdicts[payload.id] = verdict

            # Assemble finding
            self._findings.append(self._assemble_finding(
                candidate=candidate,
                payload=payload,
                oast_result=oast,
                diff_result=diff,
                cloud_info=cloud_info,
                verdict=verdict,
            ))
            judged += 1

        stage.items_total = judged
        stage.items_processed = judged
        confirmed = sum(1 for v in self._verdicts.values() if v.verdict)
        await self._emit_progress("llm_judgment", 1.0,
                                  f"LLM: {confirmed}/{judged} confirmed SSRF")

    # ===== Helpers =====

    def _assemble_finding(self,
                          candidate: CandidateEndpoint,
                          payload: Payload,
                          oast_result: Optional[OastResult],
                          diff_result: Optional[ResponseDiffResult],
                          cloud_info: Optional[CloudCredentialInfo],
                          verdict: LlmVerdict) -> Finding:
        """Assemble all evidence into a Finding."""
        # Determine SSRF type
        if cloud_info and cloud_info.credentials_raw:
            ssrf_type = SSRFType.CREDENTIAL_LEAKED
        elif cloud_info:
            ssrf_type = SSRFType.CLOUD_METADATA
        elif oast_result and oast_result.hit and oast_result.in_target_network:
            ssrf_type = SSRFType.INTERNAL
        elif oast_result and oast_result.hit:
            ssrf_type = SSRFType.BASIC
        elif diff_result and diff_result.reachable:
            ssrf_type = SSRFType.SEMI_BLIND
        else:
            ssrf_type = SSRFType.BLIND

        # Build evidence chain
        evidence_chain = []
        evidence_chain.append(
            f"Discovered candidate: {candidate.param_name} in {candidate.endpoint} "
            f"(triggers: {candidate.heuristics_triggered})"
        )
        evidence_chain.append(
            f"Payload: {payload.value} (techniques: {[t.value for t in payload.bypass_techniques]})"
        )
        if oast_result and oast_result.hit:
            evidence_chain.append(
                f"OAST hit: from {oast_result.source_ip}, "
                f"in_target={oast_result.in_target_network}, conf={oast_result.confidence}"
            )
        if diff_result:
            evidence_chain.append(f"Diff analysis: {diff_result.evidence_summary}")
        if cloud_info:
            evidence_chain.append(f"Cloud creds: {cloud_info.credential_type}")
        evidence_chain.append(f"LLM verdict: {verdict.verdict}, severity={verdict.severity.value}")
        evidence_chain.append(f"LLM reasoning: {verdict.reasoning}")

        return Finding(
            finding_id=f"SSRF-{uuid.uuid4().hex[:8]}",
            candidate=candidate,
            payload=payload,
            oast_result=oast_result,
            diff_result=diff_result,
            llm_verdict=verdict,
            cloud_info=cloud_info,
            ssrf_type=ssrf_type,
            severity=verdict.severity,
            evidence_chain=evidence_chain,
            raw_logs={
                "payload_value": payload.value,
                "bypass_techniques": [t.value for t in payload.bypass_techniques],
            },
        )

    async def _emit_progress(self, stage: str, progress: float,
                             message: str, status: str = "running"):
        """Emit progress via SSE callback if configured."""
        if self._sse:
            try:
                await self._sse(stage, {
                    "stage": stage,
                    "progress": progress,
                    "message": message,
                    "status": status,
                    "timestamp": time.time(),
                })
            except Exception:
                pass  # Don't let SSE failures break the scan

    # ===== Report generation =====

    def generate_report(self) -> str:
        """Generate a JSON report of all findings."""
        report = {
            "target_id": self.config.target_id,
            "total_findings": len(self._findings),
            "findings": [],
            "stages": {name: s.status for name, s in self._stages.items()},
        }

        for f in self._findings:
            report["findings"].append({
                "finding_id": f.finding_id,
                "ssrf_type": f.ssrf_type.value,
                "severity": f.severity.value,
                "endpoint": f.candidate.endpoint,
                "param_name": f.candidate.param_name,
                "payload": f.payload.value,
                "bypass_techniques": [t.value for t in f.payload.bypass_techniques],
                "oast_hit": f.oast_result.hit if f.oast_result else None,
                "diff_reachable": f.diff_result.reachable if f.diff_result else None,
                "llm_verdict": f.llm_verdict.verdict if f.llm_verdict else None,
                "llm_reasoning": f.llm_verdict.reasoning if f.llm_verdict else "",
                "evidence_chain": f.evidence_chain,
            })

        return json.dumps(report, indent=2, ensure_ascii=False)

    def export_findings(self, format: str = "json") -> str:
        """Export findings in the specified format."""
        if format == "json":
            return self.generate_report()

        if format == "markdown":
            lines = [
                f"# SSRF Scan Report — {self.config.target_id}",
                f"",
                f"**Total findings:** {len(self._findings)}",
                f"",
            ]
            for f in self._findings:
                lines.append(f"## {f.finding_id} — {f.severity.value.upper()}")
                lines.append(f"- **Type:** {f.ssrf_type.value}")
                lines.append(f"- **Endpoint:** `{f.candidate.endpoint}`")
                lines.append(f"- **Parameter:** `{f.candidate.param_name}`")
                lines.append(f"- **Payload:** `{f.payload.value}`")
                lines.append(f"- **OAST hit:** {f.oast_result.hit if f.oast_result else 'N/A'}")
                lines.append(f"- **LLM reasoning:** {f.llm_verdict.reasoning if f.llm_verdict else 'N/A'}")
                lines.append("")
                lines.append("### Evidence Chain")
                for step in f.evidence_chain:
                    lines.append(f"- {step}")
                lines.append("")
            return "\n".join(lines)

        raise ValueError(f"Unsupported export format: {format}")
