"""Rule-based candidate endpoint discovery.

Pure rule matching — no LLM calls. Detects SSRF-vulnerable parameters from:
- Burp Suite JSON exports
- OpenAPI 3.x specs
- Raw request objects

Detection logic:
  1. Parameter name dictionary match (case-insensitive, underscore/hyphen variants)
  2. Response body heuristics (Content-Type mismatch + third-party absolute URLs in body)
  3. Parameter value pattern (value itself looks like a URL)
"""

import json
import re
import uuid
from pathlib import Path
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse, parse_qs

from ..shared_types import (
    CandidateEndpoint,
    CandidateSource,
    HttpMethod,
    RequestContext,
)

# ===== Default parameter name dictionary =====
_DEFAULT_PARAM_DICT = [
    "url", "uri", "link", "href", "src", "source",
    "webhook", "callback", "callback_url", "redirect", "redirect_uri",
    "forward", "proxy", "endpoint", "path", "file", "document",
    "avatar", "image", "img", "photo", "import", "upload",
    "download", "fetch", "load", "retrieve", "remote", "resource",
    "target", "dest", "destination", "continue", "return", "return_url",
    "next", "goto", "domain", "host",
    "xml", "feed", "rss", "data_url",
]

# URL-like pattern in parameter values
_URL_PATTERN = re.compile(
    r'^https?://[^\s<>"{}|\\^`\[\]]+$',
    re.IGNORECASE,
)

# Absolute URLs of third-party domains in response body
_ABSOLUTE_URL_PATTERN = re.compile(
    r'https?://[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+\.[a-zA-Z]{2,}[^\s<>"\'\[\]{}|\\^`]*',
    re.IGNORECASE,
)


class CandidateDiscovery:
    """Discover SSRF candidate parameters from traffic / API specs."""

    def __init__(self, param_dictionary: Optional[List[str]] = None):
        """
        Args:
            param_dictionary: Custom parameter name dictionary.
                              Merges with defaults if provided (doesn't replace).
        """
        base = list(_DEFAULT_PARAM_DICT)
        if param_dictionary:
            base.extend(p.lower() for p in param_dictionary)
        self.param_dict = list(dict.fromkeys(base))  # de-duplicate, preserve order

    # ---- Public entry points ----

    def from_burp_json(self, file_path: str) -> List[CandidateEndpoint]:
        """Parse Burp Suite JSON export and discover candidate endpoints."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        requests = self._parse_burp_items(data)
        return self._analyze_requests(requests, CandidateSource.BURP_JSON)

    def from_openapi_spec(self, spec_path: str) -> List[CandidateEndpoint]:
        """Parse OpenAPI 3.x spec and discover candidate endpoints."""
        with open(spec_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        requests = self._parse_openapi_items(data)
        return self._analyze_requests(requests, CandidateSource.OPENAPI_SPEC)

    def from_raw_requests(self, requests: List[RequestContext]) -> List[CandidateEndpoint]:
        """Analyze a list of pre-built RequestContext objects."""
        return self._analyze_requests(requests, CandidateSource.RAW_REQUESTS)

    # ---- Burp JSON parsing ----

    def _parse_burp_items(self, data: dict) -> List[RequestContext]:
        """Extract RequestContext list from Burp Suite JSON export."""
        results = []
        items = data.get("items", []) or data.get("history", []) or data.get("requests", [])

        for item in items:
            try:
                # Common Burp export formats
                req = item.get("request", item)
                resp = item.get("response", {})

                # Parse request line
                req_text = req.get("raw", req.get("request", ""))
                if isinstance(req_text, bytes):
                    req_text = req_text.decode("utf-8", errors="replace")

                ctx = self._parse_raw_http(req_text)
                if ctx:
                    results.append(ctx)
            except Exception:
                continue

        return results

    # ---- OpenAPI parsing ----

    def _parse_openapi_items(self, data: dict) -> List[RequestContext]:
        """Extract RequestContext list from OpenAPI 3.x spec."""
        results = []
        servers = data.get("servers", [{"url": ""}])
        base_url = servers[0].get("url", "").rstrip("/") if servers else ""

        for path, methods in (data.get("paths", {}) or {}).items():
            for method_name in ("get", "post", "put", "patch", "delete", "head"):
                operation = methods.get(method_name)
                if not operation:
                    continue

                params = (operation.get("parameters") or []) + (
                    (operation.get("requestBody", {})
                     .get("content", {})
                     .get("application/json", {})
                     .get("schema", {})
                     .get("properties", {}) or {})
                )

                for p in params:
                    p_name = p.get("name", "") if isinstance(p, dict) else p
                    p_in = p.get("in", "query") if isinstance(p, dict) else "query"

                    ctx = RequestContext(
                        method=HttpMethod(method_name.upper()),
                        url=f"{base_url}{path}?{p_name}=PLACEHOLDER" if p_in == "query" else f"{base_url}{path}",
                        headers={"Content-Type": "application/json"},
                        body=json.dumps({p_name: "PLACEHOLDER"}) if p_in == "body" else None,
                    )
                    results.append(ctx)

        return results

    # ---- Raw HTTP parsing ----

    def _parse_raw_http(self, raw: str) -> Optional[RequestContext]:
        """Parse a raw HTTP request string into RequestContext."""
        if not raw.strip():
            return None

        lines = raw.splitlines()
        if not lines:
            return None

        request_line = lines[0]
        parts = request_line.split(" ")
        if len(parts) < 2:
            return None

        method_str, url_str = parts[0], parts[1]
        try:
            method = HttpMethod(method_str.upper())
        except ValueError:
            return None

        headers: Dict[str, str] = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == "":
                body_start = i + 1
                break
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip()] = value.strip()

        body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else None

        # Construct full URL if relative
        if not url_str.startswith("http"):
            host = headers.get("Host", "")
            protocol = "https" if ":443" in host else "http"
            url_str = f"{protocol}://{host}{url_str}"

        return RequestContext(method=method, url=url_str, headers=headers, body=body)

    # ---- Rule engine core ----

    def _analyze_requests(self, requests: List[RequestContext],
                          source: CandidateSource) -> List[CandidateEndpoint]:
        """Run all detection rules against a list of requests."""
        candidates: List[CandidateEndpoint] = []
        seen = set()

        for req in requests:
            params = self._extract_all_params(req)

            for param_name, param_value, location in params:
                heuristics: List[str] = []
                confidence = 0.0

                # Rule 1: Parameter name dictionary match
                if self._param_name_hit(param_name):
                    heuristics.append("param_name_dict_match")
                    confidence = max(confidence, 0.6)

                # Rule 2: Parameter value is a URL
                if isinstance(param_value, str) and _URL_PATTERN.search(param_value):
                    heuristics.append("param_value_is_url")
                    confidence = max(confidence, 0.8)

                # Rule 3: Response body heuristics (if we have response context)
                # Note: Burp items may include response; OpenAPI won't
                if heuristics:
                    candidate = CandidateEndpoint(
                        id=str(uuid.uuid4())[:8],
                        endpoint=req.url,
                        method=req.method,
                        param_name=param_name,
                        param_location=location,
                        original_value=str(param_value),
                        candidate_source=source,
                        request_context=req,
                        heuristics_triggered=heuristics,
                        confidence=confidence,
                    )

                    dedup_key = f"{req.method.value}:{req.url}:{param_name}:{location}"
                    if dedup_key not in seen:
                        seen.add(dedup_key)
                        candidates.append(candidate)

        return candidates

    # ---- Helpers ----

    def _extract_all_params(self, req: RequestContext) -> List[tuple]:
        """Extract (name, value, location) tuples from a request."""
        params: List[tuple] = []

        # Query params
        parsed = urlparse(req.url)
        for k, v_list in parse_qs(parsed.query).items():
            params.append((k, v_list[0] if v_list else "", "query"))

        # Body params (JSON or form-encoded)
        if req.body:
            # JSON
            try:
                body_json = json.loads(req.body)
                if isinstance(body_json, dict):
                    for k, v in body_json.items():
                        params.append((k, v, "body"))
            except (json.JSONDecodeError, TypeError):
                # Form-encoded
                for k, v_list in parse_qs(req.body).items():
                    params.append((k, v_list[0] if v_list else "", "body"))

        # Path params: segments that look like placeholders or IDs
        path_segments = parsed.path.strip("/").split("/")
        for seg in path_segments:
            # Skip common static segments
            if seg in ("api", "v1", "v2", "v3", "v4", "rest", "graphql"):
                continue
            # Segments that look like values rather than static path parts
            if re.search(r'^\d+$|^[a-f0-9-]{20,}$|^\{', seg):
                params.append((seg, seg, "path"))

        # Header params with URL-like values
        for k, v in req.headers.items():
            if isinstance(v, str) and _URL_PATTERN.search(v):
                params.append((k, v, "header"))

        return params

    def _param_name_hit(self, name: str) -> bool:
        """Check if a parameter name matches the dictionary (normalized)."""
        normalized = name.lower().replace("-", "_").strip()
        for entry in self.param_dict:
            if normalized == entry or normalized in entry or entry in normalized:
                return True
        return False
