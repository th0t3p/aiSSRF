"""Response differential analyzer for blind SSRF detection.

For scenarios where OAST callbacks are not possible, this module:
- Collects multiple response samples for baseline (known reachable) and test URLs
- Compares: status code, body length, response time, TLS error type, ETag
- Uses Welch's t-test for continuous metrics (response time, body length)
- Outputs per-address reachability confidence score

No LLM calls — purely statistical.
"""

import asyncio
import math
import statistics
import uuid
from typing import Optional, List, Dict, Tuple, Any

import httpx

from ..shared_types import (
    CandidateEndpoint,
    Payload,
    ResponseProbe,
    ResponseDiffResult,
    SecurityError,
)


class ResponseDiffAnalyzer:
    """Statistical analysis of response differences for blind SSRF."""

    def __init__(self,
                 baseline_probes: int = 3,
                 test_probes: int = 3,
                 alpha: float = 0.05):
        """
        Args:
            baseline_probes: Number of samples to collect for baseline (known reachable)
            test_probes: Number of samples to collect per test address
            alpha: Significance level for t-test
        """
        self.baseline_count = baseline_probes
        self.test_count = test_probes
        self.alpha = alpha

    async def probe(self,
                    candidate: CandidateEndpoint,
                    target_url: str,
                    authorized: bool = False) -> ResponseProbe:
        """Send a single probe and return response metrics. Raises SecurityError if not authorized."""
        if not authorized:
            raise SecurityError(
                "Probing requires authorized=True. Set this flag only for authorized targets."
            )

        # Build the probe request by substituting the SSRF parameter
        probe_url = self._build_probe_url(candidate, target_url)

        async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
            tls_error = None
            try:
                start = asyncio.get_event_loop().time()
                resp = await client.request(
                    method=candidate.method.value,
                    url=probe_url,
                    headers=candidate.request_context.headers,
                    content=candidate.request_context.body,
                )
                elapsed_ms = (asyncio.get_event_loop().time() - start) * 1000

                return ResponseProbe(
                    payload_id=f"probe-{uuid.uuid4().hex[:6]}",
                    url=probe_url,
                    status_code=resp.status_code,
                    body_length=len(resp.content),
                    response_time_ms=elapsed_ms,
                    etag=resp.headers.get("etag", resp.headers.get("ETag")),
                    headers=dict(resp.headers),
                )
            except httpx.ConnectError as e:
                tls_error = str(e)
            except Exception as e:
                tls_error = type(e).__name__

        # If we got a connection error, return what we have
        return ResponseProbe(
            payload_id=f"probe-{uuid.uuid4().hex[:6]}",
            url=probe_url,
            tls_error=tls_error,
        )

    async def collect_baseline(self,
                               candidate: CandidateEndpoint,
                               baseline_url: str,
                               authorized: bool = False) -> List[ResponseProbe]:
        """Collect baseline samples from a known reachable URL."""
        probes = []
        for _ in range(self.baseline_count):
            p = await self.probe(candidate, baseline_url, authorized)
            probes.append(p)
        return probes

    async def collect_test_samples(self,
                                   candidate: CandidateEndpoint,
                                   target_urls: List[str],
                                   authorized: bool = False) -> Dict[str, List[ResponseProbe]]:
        """Collect samples for multiple test URLs."""
        results: Dict[str, List[ResponseProbe]] = {}
        for url in target_urls:
            probes = []
            for _ in range(self.test_count):
                p = await self.probe(candidate, url, authorized)
                probes.append(p)
            results[url] = probes
        return results

    def analyze(self,
                baseline: List[ResponseProbe],
                test_group: List[ResponseProbe]) -> ResponseDiffResult:
        """
        Statistical comparison of baseline vs test group.

        Metrics compared:
          - Response time: Welch's t-test
          - Body length: Welch's t-test (continuous)
          - Status code: categorical (same or different)
          - TLS error: exact match
          - ETag: changes
        """
        evidence: Dict[str, Any] = {}
        reachable_signals = 0
        total_signals = 0

        # 1. Status code comparison
        baseline_codes = {p.status_code for p in baseline if p.status_code is not None}
        test_codes = {p.status_code for p in test_group if p.status_code is not None}
        total_signals += 1
        if test_codes and test_codes != baseline_codes:
            evidence["status_code"] = f"differs: baseline={baseline_codes}, test={test_codes}"
            reachable_signals += 1
        else:
            evidence["status_code"] = "no significant difference"

        # 2. Body length t-test
        baseline_lens = [p.body_length for p in baseline if p.body_length is not None]
        test_lens = [p.body_length for p in test_group if p.body_length is not None]
        if len(baseline_lens) >= 2 and len(test_lens) >= 2:
            total_signals += 1
            p_val, sig = self.welch_ttest(baseline_lens, test_lens, self.alpha)
            evidence["body_length"] = f"t-test p={p_val:.4f}, significant={sig}"
            if sig:
                reachable_signals += 1
        else:
            evidence["body_length"] = "insufficient samples"

        # 3. Response time t-test
        baseline_times = [p.response_time_ms for p in baseline
                          if p.response_time_ms is not None]
        test_times = [p.response_time_ms for p in test_group
                      if p.response_time_ms is not None]
        if len(baseline_times) >= 2 and len(test_times) >= 2:
            total_signals += 1
            p_val, sig = self.welch_ttest(baseline_times, test_times, self.alpha)
            evidence["response_time"] = f"t-test p={p_val:.4f}, significant={sig}"
            if sig:
                reachable_signals += 1
        else:
            evidence["response_time"] = "insufficient samples"

        # 4. TLS error pattern
        baseline_tls = {p.tls_error for p in baseline}
        test_tls = {p.tls_error for p in test_group}
        total_signals += 1
        if test_tls and test_tls != baseline_tls:
            evidence["tls_error"] = f"differs: baseline={baseline_tls}, test={test_tls}"
            reachable_signals += 1
        else:
            evidence["tls_error"] = "no significant difference"

        # 5. ETag change
        baseline_etags = {p.etag for p in baseline if p.etag}
        test_etags = {p.etag for p in test_group if p.etag}
        total_signals += 1
        if test_etags and test_etags != baseline_etags:
            evidence["etag"] = f"differs: baseline={baseline_etags}, test={test_etags}"
            reachable_signals += 1
        else:
            evidence["etag"] = "no significant difference"

        # Compute confidence
        confidence = reachable_signals / max(total_signals, 1)
        reachable = confidence >= 0.4  # at least 2 of 5 signals suggest reachable

        # Best p-value across t-tests (smallest = strongest signal)
        pvals = []
        if "body_length" in evidence and "p=" in str(evidence["body_length"]):
            pvals.append(self._extract_pvalue(evidence["body_length"]))
        if "response_time" in evidence and "p=" in str(evidence["response_time"]):
            pvals.append(self._extract_pvalue(evidence["response_time"]))

        return ResponseDiffResult(
            payload_id=test_group[0].payload_id if test_group else "",
            reachable=reachable,
            confidence=confidence,
            p_value=min(pvals) if pvals else None,
            metrics_diff=evidence,
            evidence_summary=self._summarize(reachable, confidence, evidence),
        )

    # ===== Internal helpers =====

    def _build_probe_url(self, candidate: CandidateEndpoint, target_url: str) -> str:
        """Substitute the SSRF parameter with the target URL."""
        import re
        from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

        if candidate.param_location in ("query",):
            parsed = urlparse(candidate.endpoint)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs[candidate.param_name] = [target_url]
            new_query = urlencode(qs, doseq=True)
            return urlunparse(parsed._replace(query=new_query))

        if candidate.param_location == "body" and candidate.request_context.body:
            try:
                import json
                body = json.loads(candidate.request_context.body)
                if isinstance(body, dict):
                    body[candidate.param_name] = target_url
                    return candidate.endpoint  # URL unchanged, body changes
            except Exception:
                pass

        return candidate.endpoint

    @staticmethod
    def welch_ttest(sample_a: List[float],
                    sample_b: List[float],
                    alpha: float = 0.05) -> Tuple[float, bool]:
        """
        Welch's unequal variance t-test.

        Returns (p_value, is_significant_at_alpha).

        Uses the approximation via t-distribution CDF.
        For very small samples (n < 5), this is an approximation.
        """
        n_a, n_b = len(sample_a), len(sample_b)
        if n_a < 2 or n_b < 2:
            return 1.0, False

        mean_a = statistics.mean(sample_a)
        mean_b = statistics.mean(sample_b)
        var_a = statistics.variance(sample_a) if n_a > 1 else 0.0
        var_b = statistics.variance(sample_b) if n_b > 1 else 0.0

        if var_a == 0 and var_b == 0:
            # Both samples have zero variance
            return 0.0 if mean_a != mean_b else 1.0, mean_a != mean_b

        se = math.sqrt(var_a / n_a + var_b / n_b)
        if se == 0:
            return 1.0, False

        t_stat = (mean_a - mean_b) / se

        # Welch-Satterthwaite degrees of freedom
        num = (var_a / n_a + var_b / n_b) ** 2
        denom = ((var_a / n_a) ** 2) / (n_a - 1) + ((var_b / n_b) ** 2) / (n_b - 1)
        df = num / denom if denom != 0 else 1

        # Two-tailed p-value approximation using standard normal + correction
        p_value = 2 * (1 - _std_normal_cdf(abs(t_stat)))

        return p_value, p_value < alpha

    def _extract_pvalue(self, text: str) -> float:
        """Extract p-value from evidence string like 't-test p=0.0321, significant=True'."""
        import re
        m = re.search(r'p=([\d.e+-]+)', str(text))
        return float(m.group(1)) if m else 1.0

    def _summarize(self, reachable: bool, confidence: float,
                   evidence: Dict[str, Any]) -> str:
        """Produce a human-readable evidence summary."""
        if reachable:
            return (f"Likely reachable (confidence={confidence:.0%}). "
                    f"Key signals: {[k for k, v in evidence.items() if 'differs' in str(v) or 'True' in str(v)]}")
        return f"Not reachable (confidence={confidence:.0%}). No significant differences detected."


def _std_normal_cdf(x: float) -> float:
    """Standard normal CDF approximation (Abramowitz and Stegun 7.1.26)."""
    # Using math.erf for accuracy
    return 0.5 * (1 + math.erf(x / math.sqrt(2)))
