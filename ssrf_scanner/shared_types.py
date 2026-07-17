"""Shared dataclasses and enums for all SSRF scanner modules."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any
import datetime


# ===== Enums =====

class CandidateSource(str, Enum):
    BURP_JSON = "burp_json"
    OPENAPI_SPEC = "openapi_spec"
    RAW_REQUESTS = "raw_requests"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"


class BypassTechnique(str, Enum):
    """Payload bypass technique tag — maps each payload to the evasion it exercises."""
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
    DNS_REBINDING = "dns_rebinding"
    REDIRECT_CHAIN = "redirect_chain"


class SSRFType(str, Enum):
    BASIC = "basic"
    BLIND = "blind"
    SEMI_BLIND = "semi_blind"
    INTERNAL = "internal"
    CLOUD_METADATA = "cloud_metadata"
    CREDENTIAL_LEAKED = "credential_leaked"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Protocol(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SMTP = "smtp"


# ===== Data classes =====

@dataclass
class RequestContext:
    method: HttpMethod
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    http_version: str = "HTTP/1.1"


@dataclass
class CandidateEndpoint:
    id: str
    endpoint: str
    method: HttpMethod
    param_name: str
    param_location: str                     # query | body | header | path
    original_value: str
    candidate_source: CandidateSource
    request_context: RequestContext
    heuristics_triggered: List[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class Payload:
    id: str
    candidate_id: str
    value: str
    bypass_techniques: List[BypassTechnique] = field(default_factory=list)
    description: str = ""
    target_protocol: Protocol = Protocol.HTTP


@dataclass
class OastResult:
    payload_id: str
    hit: bool = False
    source_ip: Optional[str] = None
    protocol: Optional[Protocol] = None
    request_body: Optional[str] = None
    dns_query: Optional[str] = None
    timestamp: Optional[datetime.datetime] = None
    in_target_network: bool = False
    known_self_ip: bool = False
    confidence: float = 0.0


@dataclass
class ResponseProbe:
    payload_id: str
    url: str
    status_code: Optional[int] = None
    body_length: Optional[int] = None
    response_time_ms: Optional[float] = None
    tls_error: Optional[str] = None
    etag: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class ResponseDiffResult:
    payload_id: str
    reachable: bool = False
    confidence: float = 0.0
    p_value: Optional[float] = None
    metrics_diff: Dict[str, Any] = field(default_factory=dict)
    evidence_summary: str = ""


@dataclass
class LlmVerdict:
    verdict: bool = False
    severity: Severity = Severity.INFO
    reasoning: str = ""
    chainable_to: List[str] = field(default_factory=list)
    suggested_next_step: str = ""
    model_used: str = ""


@dataclass
class CloudCredentialInfo:
    metadata_url: str = ""
    credential_type: str = ""
    credentials_raw: Dict[str, Any] = field(default_factory=dict)
    permissions: List[str] = field(default_factory=list)
    accessible_resources: List[str] = field(default_factory=list)
    permission_graph: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    finding_id: str
    candidate: CandidateEndpoint
    payload: Payload
    oast_result: Optional[OastResult] = None
    diff_result: Optional[ResponseDiffResult] = None
    llm_verdict: Optional[LlmVerdict] = None
    cloud_info: Optional[CloudCredentialInfo] = None
    ssrf_type: SSRFType = SSRFType.BASIC
    severity: Severity = Severity.INFO
    evidence_chain: List[str] = field(default_factory=list)
    raw_logs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanConfig:
    target_id: str
    input_source: CandidateSource
    input_file: str
    target_network_cidrs: List[str] = field(default_factory=list)
    target_asns: List[str] = field(default_factory=list)
    oast_provider: str = "interactsh"
    oast_api_url: str = "https://interact.sh"
    oast_poll_interval_sec: int = 5
    oast_poll_timeout_sec: int = 120
    llm_provider: str = "openai"
    llm_model: str = "claude-sonnet-4-20250514"
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_max_tokens: int = 1024
    llm_temperature: float = 0.0
    llm_extra_headers: Dict[str, str] = field(default_factory=dict)
    authorized: bool = False
    concurrency: int = 5
    resume_from_stage: Optional[str] = None
    cloud_metadata_endpoints: List[str] = field(default_factory=lambda: [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    ])


@dataclass
class ScanStage:
    stage_name: str
    status: str = "pending"                  # pending | running | completed | failed | skipped
    items_processed: int = 0
    items_total: int = 0
    error: Optional[str] = None


# ===== Exceptions =====

class SecurityError(Exception):
    """Raised when an operation requiring explicit authorization is attempted without it."""
    pass
