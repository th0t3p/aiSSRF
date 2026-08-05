"""Local-file candidate fetcher — read SSRF candidates from an aiBrowser
traffic capture directory (``index.jsonl`` + ``bodies/``).

Unlike the aiScraper-API fetcher, aiBrowser records have no ``host`` field
and no ``tags.param_categories`` enrichment.  This module:

1. Derives ``host`` from the record's ``url``.
2. Locally classifies URL-like parameters via a name + value heuristic.
3. Resolves request bodies via the content-addressed ``bodies/`` directory
   and extracts JSON/form-encoded params from them.
4. Produces the same ``CandidateEndpoint`` objects the rest of the pipeline
   already consumes.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

from aiSSRF.config import AiSsrfConfig, CandidateEndpoint, _in_scope

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# URL-like classification heuristic
# ---------------------------------------------------------------------------

# Param names that strongly suggest a URL-like value.
_URL_LIKE_PARAM_NAMES: set[str] = {
    "url",
    "redirect",
    "callback",
    "webhook",
    "next",
    "target",
    "return",
    "goto",
    "link",
    "uri",
    "href",
    "src",
    "dest",
    "destination",
    "forward",
    "proxy",
    "path",
    "continue",
    "return_to",
    "redirect_uri",
    "redirect_url",
    "oauth_callback",
    "return_url",
    "success_url",
    "cancel_url",
    "error_url",
    "notify_url",
    "ping_url",
    "webhook_url",
    "endpoint",
    "origin",
    "fallback_url",
    "image_url",
    "avatar_url",
    "icon_url",
    "asset_url",
    "file_url",
    "resource_url",
}

# Substring match patterns — if a param name *contains* any of these, it's
# considered URL-like.
_URL_LIKE_NAME_SUBSTRINGS: tuple[str, ...] = (
    "_url", "url_",
    "_uri", "uri_",
    "_link", "link_",
    "_callback",
    "_redirect",
    "_webhook",
    "_endpoint",
)


def _is_url_like_param_name(name: str) -> bool:
    """Return True if *name* looks like a URL-carrying parameter."""
    lowered = name.lower()
    if lowered in _URL_LIKE_PARAM_NAMES:
        return True
    for sub in _URL_LIKE_NAME_SUBSTRINGS:
        if sub in lowered:
            return True
    return False


# Regex to detect URL-like values: absolute URLs, scheme-relative, bare domains, IPs.
_URL_LIKE_VALUE_RE = re.compile(
    r"^(?:"
    r"https?://|"           # http:// or https:// (absolute URL)
    r"//|"                   # scheme-relative URL
    r"[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}(?:[/?#]|$)|"  # bare domain with TLD
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"  # bare IPv4
    r")",
    re.IGNORECASE,
)


def _is_url_like_param_value(value: str) -> bool:
    """Return True if *value* looks like a URL (absolute, scheme-relative,
    bare domain, or bare IPv4)."""
    stripped = value.strip()
    if not stripped:
        return False
    return bool(_URL_LIKE_VALUE_RE.search(stripped))


def _param_is_url_like(name: str, value: str) -> bool:
    """Combined heuristic: a param is URL-like if its name OR value suggests it."""
    return _is_url_like_param_name(name) or _is_url_like_param_value(value)


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------


class LocalFileCandidateFetcher:
    """Fetches candidate endpoints from a local aiBrowser traffic capture directory.

    Mirrors the public interface of ``CandidateFetcher`` (async ``fetch()``
    returning ``list[CandidateEndpoint]``) so it's a drop-in alternative.
    """

    def __init__(self, config: AiSsrfConfig) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch(self) -> list[CandidateEndpoint]:
        """Read candidates from the local aiBrowser traffic directory.

        Returns an empty list when ``authorized_scope`` is empty (fail-closed).
        """
        if not self._config.authorized_scope:
            return []

        records = self._parse_index()
        return self._filter_by_scope(records)

    # ------------------------------------------------------------------
    # Index parsing
    # ------------------------------------------------------------------

    def _parse_index(self) -> list[dict]:
        """Read and parse every JSON line in ``index.jsonl``.

        Malformed lines and unreadable files are logged and skipped — never
        crash the whole fetch.
        """
        traffic_dir = Path(self._config.local_traffic_dir)
        index_path = traffic_dir / "index.jsonl"

        if not index_path.is_file():
            logger.warning(
                "index.jsonl not found at %s — returning 0 candidates",
                index_path,
            )
            return []

        records: list[dict] = []
        try:
            with open(index_path, "r", encoding="utf-8") as fh:
                for line_no, line in enumerate(fh, start=1):
                    stripped = line.strip()
                    if not stripped:
                        continue  # blank line
                    try:
                        record = json.loads(stripped)
                        if not isinstance(record, dict):
                            logger.debug(
                                "Skipping non-dict line %d in %s: %s",
                                line_no, index_path, type(record).__name__,
                            )
                            continue
                        records.append(record)
                    except json.JSONDecodeError as exc:
                        logger.debug(
                            "Skipping malformed JSON at %s line %d: %s",
                            index_path, line_no, exc,
                        )
                        continue
        except OSError as exc:
            logger.error("Failed to read %s: %s", index_path, exc)
            return []

        logger.debug("Parsed %d records from %s", len(records), index_path)
        return records

    # ------------------------------------------------------------------
    # Candidate extraction
    # ------------------------------------------------------------------

    def _record_to_candidates(self, raw: dict) -> list[CandidateEndpoint]:
        """Produce one ``CandidateEndpoint`` per URL-like param in a record.

        A single record can carry multiple URL-like parameters across both
        query_params and a parsed request body.
        """
        request_id = raw.get("request_id", "unknown")

        # Defensive extraction
        try:
            url = str(raw.get("url", ""))
            method = str(raw.get("method", "GET"))
            request_headers: dict[str, str] = raw.get("request_headers") or {}
            query_params: dict = raw.get("query_params") or {}
        except (TypeError, ValueError, AttributeError) as exc:
            logger.debug(
                "Skipping malformed record (request_id=%s): %s",
                request_id, exc,
            )
            return []

        # Derive host from url (aiBrowser records have no host field)
        host = self._host_from_url(url)

        # Resolve the request body from the content-addressed bodies/ dir
        request_body: Optional[str] = self._resolve_body(raw)

        candidates: list[CandidateEndpoint] = []

        # --- Query params ---
        for param_name, param_values in query_params.items():
            param_value = ""
            if isinstance(param_values, list) and param_values:
                param_value = str(param_values[0])
            elif isinstance(param_values, str):
                param_value = param_values
            else:
                param_value = str(param_values)

            if not _param_is_url_like(param_name, param_value):
                continue

            try:
                candidates.append(
                    CandidateEndpoint(
                        id=f"{request_id}:{param_name}",
                        method=method,
                        url=url,
                        param_name=str(param_name),
                        param_location="query",
                        param_value=param_value,
                        host=host,
                        request_headers=request_headers,
                        request_body=request_body,
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                logger.debug(
                    "Skipping candidate (request_id=%s, param=%s): %s",
                    request_id, param_name, exc,
                )

        # --- Body params ---
        if request_body and query_params:
            # Skip body params whose name already appeared in query_params
            query_param_names = set(query_params.keys())
        else:
            query_param_names = set()

        body_params = self._parse_body_params(request_body)
        for param_name, param_value in body_params.items():
            if param_name in query_param_names:
                continue  # prefer query_params (same logic as existing fetcher)
            if not _param_is_url_like(param_name, param_value):
                continue
            try:
                candidates.append(
                    CandidateEndpoint(
                        id=f"{request_id}:{param_name}",
                        method=method,
                        url=url,
                        param_name=str(param_name),
                        param_location="body",
                        param_value=param_value,
                        host=host,
                        request_headers=request_headers,
                        request_body=request_body,
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                logger.debug(
                    "Skipping candidate (request_id=%s, param=%s): %s",
                    request_id, param_name, exc,
                )

        return candidates

    # ------------------------------------------------------------------
    # Body resolution
    # ------------------------------------------------------------------

    def _resolve_body(self, record: dict) -> Optional[str]:
        """Read the request body from ``bodies/<sha>.bin`` if present.

        Returns the decoded text or ``None`` if the body is unavailable,
        missing, or unreadable.
        """
        body_ref = record.get("request_body_ref")
        if not body_ref or not isinstance(body_ref, str):
            return None

        traffic_dir = Path(self._config.local_traffic_dir)
        # body_ref is relative like "bodies/<sha>.bin" — resolve against traffic_dir
        body_path = traffic_dir / body_ref

        try:
            raw = body_path.read_bytes()
        except (OSError, IOError) as exc:
            logger.debug(
                "Failed to read body file %s (request_id=%s): %s",
                body_path, record.get("request_id", "unknown"), exc,
            )
            return None

        # Try common text encodings; skip non-text bodies
        for encoding in ("utf-8", "latin-1"):
            try:
                text = raw.decode(encoding)
                # Heuristic: if the body is mostly non-printable, treat as binary
                if len(text) > 0 and _is_likely_binary(text):
                    logger.debug(
                        "Body file %s appears to be binary — skipping",
                        body_path,
                    )
                    return None
                return text
            except UnicodeDecodeError:
                continue

        logger.debug(
            "Body file %s could not be decoded as text — skipping",
            body_path,
        )
        return None

    @staticmethod
    def _parse_body_params(body: Optional[str]) -> dict[str, str]:
        """Extract a flat ``{param_name: value}`` dict from a body string.

        Tries JSON first, then form-urlencoded. Returns ``{}`` for
        unparseable or missing bodies.
        """
        if not body:
            return {}

        result: dict[str, str] = {}

        # JSON body
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for key, val in data.items():
                    if val is None:
                        result[str(key)] = ""
                    elif isinstance(val, (str, int, float, bool)):
                        result[str(key)] = str(val)
                    else:
                        result[str(key)] = json.dumps(val)
            return result
        except (json.JSONDecodeError, TypeError):
            pass

        # form-urlencoded body
        try:
            parsed = parse_qs(body, keep_blank_values=True)
            for key, values in parsed.items():
                result[str(key)] = values[0] if values else ""
            return result
        except Exception:
            pass

        return {}

    # ------------------------------------------------------------------
    # Host extraction
    # ------------------------------------------------------------------

    @staticmethod
    def _host_from_url(url: str) -> str:
        """Extract the hostname from a URL string.

        Returns empty string for unparseable URLs.
        """
        if not url:
            return ""
        try:
            parsed = urlparse(url)
            return parsed.hostname or ""
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # Scope filtering
    # ------------------------------------------------------------------

    def _filter_by_scope(
        self, raw_items: list[dict]
    ) -> list[CandidateEndpoint]:
        """Parse every record, classify params, drop out-of-scope hosts.

        Logs a one-line summary: ``N records fetched, M candidates parsed, K kept``.
        """
        kept: list[CandidateEndpoint] = []
        total_candidates = 0
        for raw in raw_items:
            candidates = self._record_to_candidates(raw)
            total_candidates += len(candidates)
            for candidate in candidates:
                if _in_scope(candidate.host, self._config.authorized_scope):
                    kept.append(candidate)

        logger.info(
            "%d records fetched, %d candidates parsed, %d kept",
            len(raw_items),
            total_candidates,
            len(kept),
        )
        return kept


# ---------------------------------------------------------------------------
# Binary detection helper
# ---------------------------------------------------------------------------

def _is_likely_binary(text: str, sample_len: int = 512) -> bool:
    """Heuristic: if more than 30% of the first *sample_len* chars are
    non-printable, treat as binary."""
    if not text:
        return True
    sample = text[:sample_len]
    if not sample:
        return True
    non_printable = sum(
        1 for ch in sample if ord(ch) < 32 and ch not in ("\n", "\r", "\t")
    )
    return non_printable / len(sample) > 0.3
