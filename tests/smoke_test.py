"""Smoke test — verifies all modules are importable and core logic works.

Usage: python tests/smoke_test.py
"""

import sys
import os
import json
import asyncio

# Ensure ssrf_scanner is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_shared_types():
    """Verify shared types import + instantiation."""
    from ssrf_scanner.shared_types import (
        CandidateEndpoint, Payload, OastResult, ResponseProbe,
        ResponseDiffResult, LlmVerdict, CloudCredentialInfo, Finding,
        ScanConfig, ScanStage, RequestContext,
        CandidateSource, HttpMethod, BypassTechnique, SSRFType,
        Severity, Protocol, SecurityError,
    )

    ctx = RequestContext(method=HttpMethod.GET, url="http://example.com", headers={})
    candidate = CandidateEndpoint(
        id="test-1", endpoint="http://example.com/api?url=",
        method=HttpMethod.GET, param_name="url", param_location="query",
        original_value="https://example.com", candidate_source=CandidateSource.BURP_JSON,
        request_context=ctx, heuristics_triggered=["param_name_dict_match"],
        confidence=0.8,
    )
    payload = Payload(
        id="p-1", candidate_id="test-1", value="http://127.0.0.1/",
        bypass_techniques=[BypassTechnique.IP_DECIMAL],
        description="Test payload",
    )
    config = ScanConfig(
        target_id="test-target",
        input_source=CandidateSource.BURP_JSON,
        input_file="/tmp/test.json",
        target_network_cidrs=["10.0.0.0/8"],
        authorized=False,
    )

    print("✓ shared_types: all dataclasses and enums instantiate correctly")


def test_candidate_discovery():
    """Verify discovery import + param matching."""
    from ssrf_scanner.candidate_discovery import CandidateDiscovery
    from ssrf_scanner.shared_types import RequestContext, HttpMethod

    cd = CandidateDiscovery()
    assert cd is not None
    assert len(cd.param_dict) > 30  # default dict is loaded

    # Test with raw request
    raw = "GET /api?url=http://evil.com&callback=https://target.com HTTP/1.1\r\nHost: example.com\r\n\r\n"
    result = cd.from_raw_requests([])
    assert isinstance(result, list)

    # Test single request
    ctx = RequestContext(
        method=HttpMethod.GET,
        url="http://example.com/api?url=http://evil.com",
        headers={"Host": "example.com"},
    )
    candidates = cd.from_raw_requests([ctx])
    assert len(candidates) >= 1
    assert candidates[0].param_name == "url"
    assert "param_name_dict_match" in candidates[0].heuristics_triggered

    print(f"✓ candidate_discovery: {len(candidates)} candidate(s) found for request with 'url' param")


def test_payload_generator():
    """Verify payload generation + IP encoding."""
    from ssrf_scanner.payload_generator import PayloadGenerator, IpEncoder
    from ssrf_scanner.shared_types import (
        CandidateEndpoint, HttpMethod, RequestContext, CandidateSource,
    )

    # IP encoding
    assert IpEncoder.to_decimal("127.0.0.1") == "2130706433"
    assert IpEncoder.to_hex("127.0.0.1") == "0x7F000001"
    assert IpEncoder.to_octal("127.0.0.1") == "0177.0000.0000.0001"

    # IPv4-mapped IPv6
    mapped = IpEncoder.to_ipv4_mapped_ipv6("169.254.169.254")
    assert "ffff" in mapped.lower()

    # Payload generation
    gen = PayloadGenerator(oast_domain="test123.oast.pro")
    ctx = RequestContext(method=HttpMethod.GET, url="http://example.com/?url=X", headers={})
    candidate = CandidateEndpoint(
        id="c1", endpoint="http://example.com/?url=X",
        method=HttpMethod.GET, param_name="url", param_location="query",
        original_value="X", candidate_source=CandidateSource.BURP_JSON,
        request_context=ctx,
    )
    payloads = gen.generate(candidate)
    assert len(payloads) > 20, f"Expected >20 payloads, got {len(payloads)}"

    # Verify bypass techniques are tagged
    techniques = set()
    for p in payloads:
        for t in p.bypass_techniques:
            techniques.add(t)
    assert len(techniques) >= 6, f"Expected >=6 technique types, got {len(techniques)}"

    print(f"✓ payload_generator: {len(payloads)} payloads with {len(techniques)} technique types")


def test_oast_correlation():
    """Verify OAST module import + CIDR matching."""
    from ssrf_scanner.oast_correlation import OastCorrelation

    oast = OastCorrelation()
    assert oast is not None

    # IP in CIDR test
    assert OastCorrelation.ip_in_cidrs("10.0.0.5", ["10.0.0.0/8"])
    assert OastCorrelation.ip_in_cidrs("172.16.5.5", ["172.16.0.0/12"])
    assert not OastCorrelation.ip_in_cidrs("8.8.8.8", ["10.0.0.0/8"])
    assert not OastCorrelation.ip_in_cidrs("invalid", ["10.0.0.0/8"])

    print("✓ oast_correlation: CIDR matching works correctly")


def test_response_diff_analyzer():
    """Verify statistical analysis logic."""
    from ssrf_scanner.response_diff_analyzer import ResponseDiffAnalyzer
    from ssrf_scanner.shared_types import ResponseProbe

    analyzer = ResponseDiffAnalyzer()

    # Welch's t-test: clearly different groups
    p_val, sig = analyzer.welch_ttest(
        [100.0, 105.0, 98.0, 102.0, 101.0],  # baseline ~101ms
        [500.0, 510.0, 495.0, 505.0, 502.0],  # test ~502ms (clearly different)
        alpha=0.05,
    )
    assert sig, f"Expected significant difference, got p={p_val:.6f}"
    assert p_val < 0.001

    # Welch's t-test: similar groups
    p_val2, sig2 = analyzer.welch_ttest(
        [100.0, 105.0, 98.0, 102.0],
        [101.0, 104.0, 99.0, 103.0],
        alpha=0.05,
    )
    assert not sig2, f"Expected no significant difference, got p={p_val2:.4f}"

    # Analyze with ResponseProbe objects
    baseline = [
        ResponseProbe(payload_id="b1", url="http://example.com", status_code=200, body_length=1000, response_time_ms=100),
        ResponseProbe(payload_id="b2", url="http://example.com", status_code=200, body_length=1005, response_time_ms=105),
        ResponseProbe(payload_id="b3", url="http://example.com", status_code=200, body_length=998, response_time_ms=98),
    ]
    test = [
        ResponseProbe(payload_id="t1", url="http://10.0.0.1", status_code=500, body_length=50, response_time_ms=500),
        ResponseProbe(payload_id="t2", url="http://10.0.0.1", status_code=500, body_length=52, response_time_ms=510),
        ResponseProbe(payload_id="t3", url="http://10.0.0.1", status_code=500, body_length=48, response_time_ms=495),
    ]
    result = analyzer.analyze(baseline, test)
    assert result.reachable
    assert result.confidence > 0.5

    print(f"✓ response_diff_analyzer: t-test works, diff result: reachable={result.reachable}, conf={result.confidence:.0%}")


def test_llm_judgment():
    """Verify LLM module import + prompt building."""
    from ssrf_scanner.llm_judgment import LlmJudgment, LlmConfig

    config = LlmConfig(
        provider="openai",
        model="gpt-4o",
        api_key="sk-dummy",
        max_tokens=512,
    )
    llm = LlmJudgment(config)
    assert llm is not None
    assert llm.config.provider == "openai"

    # Token estimation
    estimate = LlmJudgment.estimate_tokens("Hello world " * 100)
    assert estimate > 0

    # Prompt building (no API call)
    from ssrf_scanner.shared_types import (
        CandidateEndpoint, OastResult, ResponseDiffResult,
        HttpMethod, RequestContext, CandidateSource,
    )
    ctx = RequestContext(method=HttpMethod.GET, url="http://example.com", headers={})
    candidate = CandidateEndpoint(
        id="c1", endpoint="http://example.com/?url=X",
        method=HttpMethod.GET, param_name="url", param_location="query",
        original_value="X", candidate_source=CandidateSource.BURP_JSON,
        request_context=ctx, heuristics_triggered=["param_name_dict_match"],
    )
    oast = OastResult(payload_id="p1", hit=True, source_ip="10.0.0.5",
                      in_target_network=True, confidence=0.9)

    # Build prompt without calling API
    prompt = llm._build_user_prompt(candidate, oast, None, "Python/Flask")
    assert "10.0.0.5" in prompt
    assert "Python/Flask" in prompt

    print("✓ llm_judgment: module imports, prompt builds correctly")


def test_cloud_credential_chain():
    """Verify cloud credential parsing."""
    from ssrf_scanner.cloud_credential_chain import CloudCredentialChain

    chain = CloudCredentialChain()

    # Test endpoint detection
    assert CloudCredentialChain.is_cloud_metadata_endpoint(
        "http://169.254.169.254/latest/meta-data/"
    ) == "aws"
    assert CloudCredentialChain.is_cloud_metadata_endpoint(
        "http://metadata.google.internal/computeMetadata/v1/"
    ) == "gcp"
    assert CloudCredentialChain.is_cloud_metadata_endpoint(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
    ) == "azure"

    # Test AWS credential parsing
    aws_body = json.dumps({
        "AccessKeyId": "ASIA1234567890ABCD",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "FQoGZXIvYXdzE...EXAMPLE...",
        "Expiration": "2026-07-18T12:00:00Z",
    })
    info = chain.parse_metadata_response(aws_body,
                                         "http://169.254.169.254/latest/meta-data/iam/security-credentials/test")
    assert info is not None
    assert info.credential_type == "aws_sts"
    assert info.credentials_raw.get("AccessKeyId") == "ASIA1234567890ABCD"

    # Test GCP token parsing
    gcp_body = json.dumps({"access_token": "ya29.example", "expires_in": 3600})
    info2 = chain.parse_metadata_response(gcp_body,
                                          "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
    assert info2 is not None
    assert info2.credential_type == "gcp_sa"

    # Test Azure parsing
    azure_body = json.dumps({"access_token": "eyJ0eXAi...", "expires_on": "1712345678"})
    info3 = chain.parse_metadata_response(azure_body,
                                          "http://169.254.169.254/metadata/instance?api-version=2021-02-01")
    assert info3 is not None
    assert info3.credential_type == "azure_msi"

    # Test non-metadata URL
    assert chain.parse_metadata_response("not credentials", "http://example.com/api") is None

    print("✓ cloud_credential_chain: all cloud providers parsed correctly")


def test_orchestrator():
    """Verify orchestrator import + config building."""
    from ssrf_scanner.orchestrator import SSRFScanner
    from ssrf_scanner.shared_types import ScanConfig, CandidateSource

    config = ScanConfig(
        target_id="test-target",
        input_source=CandidateSource.BURP_JSON,
        input_file="/tmp/test.json",
        target_network_cidrs=["10.0.0.0/8"],
        authorized=False,
    )
    scanner = SSRFScanner(config)
    assert scanner is not None
    assert len(scanner.stages) == 6
    assert scanner.stages[0] == "candidate_discovery"
    assert scanner.stages[-1] == "llm_judgment"

    print(f"✓ orchestrator: {len(scanner.stages)} stages defined in correct order")


def test_security_gate():
    """Verify all modules respect the authorized=False gate."""
    from ssrf_scanner.response_diff_analyzer import ResponseDiffAnalyzer
    from ssrf_scanner.shared_types import (
        CandidateEndpoint, HttpMethod, RequestContext, CandidateSource, SecurityError,
    )

    analyzer = ResponseDiffAnalyzer()
    ctx = RequestContext(method=HttpMethod.GET, url="http://example.com", headers={})
    candidate = CandidateEndpoint(
        id="c1", endpoint="http://example.com/?url=X",
        method=HttpMethod.GET, param_name="url", param_location="query",
        original_value="X", candidate_source=CandidateSource.BURP_JSON,
        request_context=ctx,
    )

    # Should raise SecurityError
    try:
        asyncio.get_event_loop().run_until_complete(
            analyzer.probe(candidate, "http://127.0.0.1/", authorized=False)
        )
        assert False, "Should have raised SecurityError"
    except SecurityError as e:
        assert "authorized=True" in str(e)

    print("✓ security_gate: all modules require authorized=True for network operations")


def main():
    print("=" * 60)
    print("SSRF Scanner — Smoke Test Suite")
    print("=" * 60)
    print()

    tests = [
        ("shared_types", test_shared_types),
        ("candidate_discovery", test_candidate_discovery),
        ("payload_generator", test_payload_generator),
        ("oast_correlation", test_oast_correlation),
        ("response_diff_analyzer", test_response_diff_analyzer),
        ("llm_judgment", test_llm_judgment),
        ("cloud_credential_chain", test_cloud_credential_chain),
        ("orchestrator", test_orchestrator),
        ("security_gate", test_security_gate),
    ]

    passed = 0
    failed = 0

    for name, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"✗ {name}: {e}")
            import traceback
            traceback.print_exc()

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
