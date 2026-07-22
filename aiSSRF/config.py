"""Configuration and shared Pydantic models for aiSSRF.

Every model lives here so that each sub-module can import from a single
source of truth without circular dependencies.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Optional, Annotated
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_validator,
    AnyUrl,
)


# =========================================================================
# Enums
# =========================================================================

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BypassTechnique(str, Enum):
    """Tag applied to every generated payload for report traceability."""
    IP_DECIMAL = "ip_decimal"
    IP_HEX = "ip_hex"
    IP_OCTAL = "ip_octal"
    IP_SHORT = "ip_short"
    IPV6_FULL = "ipv6_full"
    IPV4_MAPPED_IPV6 = "ipv4_mapped_ipv6"
    URL_USERINFO_INJECTION = "url_userinfo_injection"
    URL_SCHEME_OMIT = "url_scheme_omit"
    URL_FRAGMENT_CONFUSION = "url_fragment_confusion"
    URL_CASE_DOT_CONFUSION = "url_case_dot_confusion"
    PROTOCOL_GOPHER = "protocol_gopher"
    PROTOCOL_DICT = "protocol_dict"
    PROTOCOL_FILE = "protocol_file"


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    INCONCLUSIVE = "inconclusive"
    FALSE_POSITIVE = "false_positive"


# =========================================================================
# Scope helpers
# =========================================================================

def _glob_to_regex(pattern: str) -> str:
    """Convert a scope glob like ``*.example.com`` to a regex fragment."""
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*", r"[^.]*")       # single-label wildcard
    escaped = escaped.replace(r"\?", r".")            # single-char wildcard
    return f"^{escaped}$"


def _in_scope(host: str, scope: list[str]) -> bool:
    """Return True if *host* matches any glob in *scope*."""
    if not scope:
        return False
    for pattern in scope:
        if re.match(_glob_to_regex(pattern), host, re.IGNORECASE):
            return True
    return False


# =========================================================================
# Config
# =========================================================================

class AiSsrfConfig(BaseModel):
    """Top-level configuration.

    All network-side-effect fields are gated behind ``authorized_scope``:
    if the list is empty the orchestrator refuses to run **any** stage
    that would touch the target (fail-closed).
    """

    # -- aiScraper --------------------------------------------------------
    ai_scraper_api_url: str = Field(
        default="http://localhost:8000",
        description="Base URL of the aiScraper REST API.",
    )
    ai_scraper_api_key: str = Field(
        default="",
        description="API key for aiScraper (sent as X-API-Key header).",
    )
    ai_scraper_page_size: int = Field(
        default=200,
        description="Number of records per page when fetching traffic from aiScraper.",
    )

    # -- Burp MCP ---------------------------------------------------------
    burp_mcp_url: str = Field(
        default="http://127.0.0.1:9876",
        description="Burp MCP SSE endpoint (McpSseClient).",
    )
    burp_mcp_auth_token: Optional[str] = Field(
        default=None,
        description="Optional auth token for BurpMCP-Ultra.",
    )

    # -- Authorization (fail-closed) --------------------------------------
    authorized_scope: list[str] = Field(
        default_factory=list,
        description=(
            "Glob patterns for domains the tool is allowed to test. "
            "Empty = nothing runs. Example: ['example.com', '*.target.org']"
        ),
    )

    # -- Collaborator -----------------------------------------------------
    collaborator_poll_interval_sec: float = Field(
        default=5.0,
        description="Seconds between Collaborator poll attempts.",
    )
    collaborator_poll_timeout_sec: float = Field(
        default=120.0,
        description="Maximum total polling duration.",
    )

    # -- Infrastructure filtering -----------------------------------------
    target_cidrs: list[str] = Field(
        default_factory=list,
        description=(
            "CIDR ranges of the target's known infrastructure. "
            "Used to exclude callbacks coming from the tester's own machine."
        ),
    )

    # -- LLM --------------------------------------------------------------
    llm_provider: str = Field(
        default="anthropic",
        description="LLM provider: anthropic | openai | deepseek",
    )
    llm_model: str = Field(
        default="claude-sonnet-4-20250514",
        description="Model name passed to the chat/completions endpoint.",
    )
    llm_api_key: str = Field(
        default="",
        description="API key for the LLM provider.",
    )
    llm_base_url: str = Field(
        default="",
        description="Custom base URL (falls back to the provider default).",
    )
    llm_max_tokens: int = Field(default=1024)
    llm_temperature: float = Field(default=0.0)

    @field_validator("authorized_scope")
    @classmethod
    def _scope_not_empty_for_prod(cls, v: list[str]) -> list[str]:
        """Explicit reminder: empty scope = no operations allowed."""
        if not v:
            # We don't raise — orchestrator checks at runtime and skips stages.
            pass
        return v


# =========================================================================
# Domain models
# =========================================================================

class CandidateEndpoint(BaseModel):
    """A single SSRF candidate pulled from aiScraper."""

    id: str = Field(description="Unique ID assigned by aiScraper.")
    method: str = Field(description="HTTP method (GET, POST, …).")
    url: str = Field(description="Full request URL including query string.")
    param_name: str = Field(description="Name of the URL-like parameter.")
    param_location: str = Field(
        description="Where the param sits: query | body | header | path",
    )
    param_value: str = Field(description="Original parameter value observed in traffic.")
    host: str = Field(description="Host portion of the URL (for scope checking).")

    # Raw context for reconstruction
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: Optional[str] = Field(default=None)

    @field_validator("host")
    @classmethod
    def _lower_host(cls, v: str) -> str:
        return v.lower()


class Payload(BaseModel):
    """A single SSRF probe payload."""

    id: str = Field(description="Unique payload ID.")
    candidate_id: str = Field(description="FK → CandidateEndpoint.id")
    value: str = Field(description="The actual string substituted into the param.")
    bypass_techniques: list[BypassTechnique] = Field(
        default_factory=list,
        description="Which bypass techniques this payload exercises.",
    )
    description: str = Field(default="")


class CollaboratorPayload(BaseModel):
    """Result from Burp Collaborator: create + generate."""

    collaborator_domain: str = Field(
        description="The unique Collaborator subdomain (e.g. abc123.oastify.com)."
    )
    payload_client_id: str = Field(
        description="Collaborator client ID returned by create_client()."
    )


class Interaction(BaseModel):
    """A single Collaborator interaction record."""

    protocol: str = Field(description="dns | http | smtp")
    source_ip: str = Field(description="IP that made the callback.")
    timestamp: datetime = Field(description="When the interaction was received.")
    raw_request: Optional[str] = Field(default=None)


class VerificationResult(BaseModel):
    """Per-payload verification outcome from Collaborator polling."""

    payload_id: str
    candidate_id: str
    hit: bool = Field(default=False)
    interactions: list[Interaction] = Field(default_factory=list)
    in_target_infra: bool = Field(
        default=False,
        description="True if any interaction's source_ip falls inside target_cidrs.",
    )
    false_positive: bool = Field(
        default=False,
        description="True when the callback came from the tester's own IP space.",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="0.0–1.0 confidence that this is a genuine server-side callback.",
    )


class LlmVerdict(BaseModel):
    """Structured judgment produced by the LLM."""

    candidate_id: str
    payload_id: str
    verdict: Verdict
    severity: Severity = Severity.INFO
    reasoning: str = Field(
        default="",
        description="Brief explanation from the LLM (preserved for audit).",
    )
    chainable_to: list[str] = Field(
        default_factory=list,
        description="Potential next exploitation paths (credential_leak, rce, …).",
    )
    suggested_next_step: str = Field(default="")
    model_used: str = Field(default="")


class ReportEntry(BaseModel):
    """One row in the final report — the entire evidence trail."""

    candidate: CandidateEndpoint
    payload: Payload
    verification: VerificationResult
    verdict: Optional[LlmVerdict] = None

    @property
    def is_confirmed(self) -> bool:
        return self.verdict is not None and self.verdict.verdict == Verdict.CONFIRMED


class ScanReport(BaseModel):
    """Top-level scan report."""

    config_summary: dict = Field(default_factory=dict)
    entries: list[ReportEntry] = Field(default_factory=list)
    total_candidates: int = 0
    confirmed: int = 0
    inconclusive: int = 0
    false_positives: int = 0
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
