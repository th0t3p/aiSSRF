# aiSSRF — Automated SSRF Candidate Verification

Consumes traffic data from **aiScraper** (REST API) and uses **Burp Suite
Collaborator** (via Burp MCP) for out-of-band SSRF verification.  A
structured LLM judgment step evaluates already-verified evidence — the LLM
never decides *how* to test, only produces a verdict from collected proof.

## ⚠️ Safety Warning

This tool **actively sends HTTP requests to the target** through Burp Suite.

It will **refuse to run** unless `authorized_scope` is explicitly configured
with the domains you are authorized to test.  An empty `authorized_scope`
means nothing executes — this is **fail-closed** by design, matching the
behaviour of aiScraper.

## Architecture

```
aiScraper REST API
       │
       ▼
[candidate_fetcher] ──► pulls url_like params, filters by authorized_scope
       │
       ▼
┌── payload_generator + OAST verification (merged per candidate) ──┐
│  • Per OAST technique: fresh Collaborator domain → generate       │
│    payload → send through Burp → poll & verify callback           │
│  • Per internal-IP technique: generate payload → send through     │
│    Burp → mark as not-OAST-verifiable                            │
└──────────────────────────────────────────────────────────────────┘
       │
       ▼
[llm_judgment] ───────► Anthropic / OpenAI / DeepSeek: judges verified
                         evidence (never decides *how* to verify — only
                         produces a verdict from already-collected proof)
       │
       ▼
[orchestrator] ───────► structured JSON report per candidate
```

## Quick Start

```bash
# 1. Copy the example env file and fill in real values
cp .env.example .env
# $EDITOR .env   ← set AISSRF_AUTHORIZED_SCOPE, API keys, etc.

# 2. Run — two equivalent ways:
python -m aiSSRF
# or, after `pip install -e .`:
aissrf

# optional: write report to file with verbose logging
aissrf --output report.json -v

# override scope for a single run without editing .env:
aissrf --scope '*.example.com' --scope other.com
```

## Configuration

All settings live in a `.env` file (copy `.env.example` to get started).
Every field has a sensible default — only set what you need to override.

| Variable | Default | Description |
|---|---|---|
| `AISSRF_AI_SCRAPER_API_URL` | `http://localhost:8000` | aiScraper REST API base URL |
| `AISSRF_AI_SCRAPER_API_KEY` | — | API key (sent as `X-API-Key` header) |
| `AISSRF_BURP_MCP_URL` | `http://127.0.0.1:9876` | Burp MCP SSE endpoint |
| `AISSRF_BURP_MCP_AUTH_TOKEN` | — | Optional Bearer token for BurpMCP-Ultra |
| `AISSRF_AUTHORIZED_SCOPE` | `[]` | Domains allowed to test (JSON array, fail-closed) |
| `AISSRF_TARGET_CIDRS` | `[]` | Target infrastructure CIDRs for callback filtering |
| `AISSRF_COLLABORATOR_POLL_INTERVAL_SEC` | `5.0` | Seconds between poll attempts |
| `AISSRF_COLLABORATOR_POLL_TIMEOUT_SEC` | `120.0` | Maximum total polling duration |
| `AISSRF_LLM_PROVIDER` | `anthropic` | LLM provider: `anthropic`, `openai`, or `deepseek` |
| `AISSRF_LLM_MODEL` | `claude-sonnet-4-20250514` | Model name (may be stale — set to current) |
| `AISSRF_LLM_API_KEY` | — | API key for the LLM provider |
| `AISSRF_LLM_BASE_URL` | — | Custom base URL (falls back to provider default) |
| `AISSRF_LLM_MAX_TOKENS` | `1024` | Max tokens for LLM response |
| `AISSRF_LLM_TEMPERATURE` | `0.0` | Temperature (0.0 = deterministic) |

List fields (`AISSRF_AUTHORIZED_SCOPE`, `AISSRF_TARGET_CIDRS`) use JSON-array
syntax:

```bash
AISSRF_AUTHORIZED_SCOPE=["example.com", "*.target.org"]
AISSRF_TARGET_CIDRS=["10.0.0.0/8", "172.16.0.0/12"]
```

Explicit kwargs to `AiSsrfConfig()` override both `.env` and environment
variables — useful for programmatic or test use.

## How It Works

### Candidate Discovery

Pulls traffic records from aiScraper's `GET /api/v1/traffic` endpoint,
filtering for parameters tagged `url_like`.  Only candidates whose host
matches `authorized_scope` are kept.

### Payload Generation (deterministic — no LLM)

Three categories of payloads, all generated without any LLM calls:

| Category | What it tests | Techniques |
|---|---|---|
| **OAST callbacks** | Proves out-of-band interaction | Direct collaborator substitution, userinfo injection, scheme omission, fragment confusion, case/dot confusion |
| **Internal IP encoding** | Bypasses IP allowlists | Decimal, hex, octal, short-form, IPv4-mapped IPv6, full IPv6 — targeting 127.0.0.1, 169.254.169.254, 0.0.0.0 |
| **Protocol tricks** | Probes alternate scheme handlers | `gopher://`, `dict://`, `file:///etc/hostname` — heuristic-gated: only generated for params named `webhook`/`callback`/`fetch`/`import`/`proxy` or `param_location == "body"` |

Every payload is tagged with a `BypassTechnique` enum for report
traceability.

### OAST Verification

Per OAST technique, a fresh unique Collaborator domain is generated so each
technique can be polled independently.  Callbacks are verified against
`target_cidrs` to distinguish genuine infrastructure hits from tester/VPS
noise.  Internal-IP payloads skip polling entirely (not OAST-verifiable).

### LLM Judgment

Supports **Anthropic** (native Messages API), **OpenAI**, and **DeepSeek**
(the latter two share the chat/completions wire format).  The LLM receives
structured evidence — candidate endpoint, payload with bypass techniques,
and verification results with full interaction details — and returns a
structured verdict: `confirmed` / `inconclusive` / `false_positive` with
severity, reasoning, and suggested remediation-adjacent next steps.  The LLM
is explicitly forbidden from suggesting new attack techniques.

## Dependencies

- `httpx>=0.27.0` — async HTTP (aiScraper API + LLM APIs)
- `pydantic>=2.0` — data models throughout
- `pydantic-settings>=2.0` — `.env` file and environment variable loading
- `burp-mcp-client` — MCP SSE client for Burp communication (git dependency)

Development: `pytest>=8.0`, `pytest-asyncio>=0.23`

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```
