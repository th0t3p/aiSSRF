# aiSSRF — Automated SSRF Candidate Verification

Consumes traffic data from **aiScraper** (REST API) and uses **Burp Suite
Collaborator** (via Burp MCP) for out-of-band SSRF verification.

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
[payload_generator] ──► deterministic IP/URL/protocol payloads (no LLM)
       │
       ▼
[McpSseClient] ───────► sends HTTP requests through Burp
       │
       ▼
[collaborator_client] ─► polls Burp Collaborator for callbacks
       │                    filters out self-callbacks via CIDR matching
       ▼
[llm_judgment] ───────► Claude API: judges verified evidence (never decides
                         *how* to verify — only produces a verdict from
                         already-collected structured proof)
       │
       ▼
[orchestrator] ───────► structured report per candidate
```

## Quick Start

```python
import asyncio
from aiSSRF.config import AiSsrfConfig
from aiSSRF.orchestrator import Orchestrator

config = AiSsrfConfig(
    ai_scraper_api_url="http://localhost:8000",
    ai_scraper_api_key="sk-...",
    burp_mcp_url="http://127.0.0.1:9876",
    authorized_scope=["example.com", "*.target.org"],
)
orch = Orchestrator(config)
report = asyncio.run(orch.run())
print(report.model_dump_json(indent=2))
```

## Dependencies

- `httpx` — async HTTP for aiScraper API + Claude API
- `pydantic>=2.0` — data models throughout
- `burp-mcp-client` — MCP SSE client for Burp communication
