"""candidate_fetcher — Pull SSRF candidates from aiScraper's REST API.

Talks to ``GET /api/v1/traffic?param_categories=url_like``, applies
the same fail-closed authorized_scope filtering that aiScraper itself
uses: even if aiScraper returns a candidate, we silently drop it if
its host does not match authorized_scope.
"""

from __future__ import annotations

import logging
from typing import Optional

import httpx

from aiSSRF.config import AiSsrfConfig, CandidateEndpoint, _in_scope

logger = logging.getLogger(__name__)


class CandidateFetcher:
    """Fetches candidate endpoints from aiScraper and filters by scope."""

    def __init__(self, config: AiSsrfConfig) -> None:
        """
        Args:
            config: Validated AiSsrfConfig.  If ``authorized_scope`` is empty,
                    ``fetch()`` will return an empty list (fail-closed).
        """
        self._config = config
        self._client: Optional[httpx.AsyncClient] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch(self) -> list[CandidateEndpoint]:
        """
        Pull candidates from aiScraper and return only those whose host
        matches ``authorized_scope``.

        Returns an empty list when ``authorized_scope`` is empty.
        """
        if not self._config.authorized_scope:
            return []

        raw = await self._fetch_from_api()
        return self._filter_by_scope(raw)

    # ------------------------------------------------------------------
    # Implementation
    # ------------------------------------------------------------------

    async def _fetch_from_api(self) -> list[dict]:
        """Fetch all traffic records from aiScraper with offset/limit pagination.

        ``GET {ai_scraper_api_url}/api/v1/traffic?param_categories=url_like``

        Headers: ``X-API-Key: {ai_scraper_api_key}``

        Paginates via limit/offset until ``len(all_records) >= total``,
        guarding against a full-page response that still leaves records
        behind (aiScraper caps limit at 1000).
        """
        url = f"{self._config.ai_scraper_api_url.rstrip('/')}/api/v1/traffic"
        limit = self._config.ai_scraper_page_size
        headers = {"X-API-Key": self._config.ai_scraper_api_key}
        all_records: list[dict] = []
        offset = 0

        async with httpx.AsyncClient() as client:
            while True:
                try:
                    response = await client.get(
                        url,
                        params={"param_categories": "url_like", "limit": limit, "offset": offset},
                        headers=headers,
                    )
                    response.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    status = exc.response.status_code
                    if status == 401:
                        logger.error(
                            "aiScraper returned 401 — check ai_scraper_api_key (sent as X-API-Key). "
                            "URL: %s",
                            url,
                        )
                    else:
                        logger.error(
                            "aiScraper HTTP %d from %s: %s",
                            status,
                            url,
                            exc.response.text[:500],
                        )
                    raise
                except httpx.RequestError as exc:
                    logger.error(
                        "aiScraper connection failure at %s: %s",
                        url,
                        exc,
                    )
                    raise

                body = response.json()
                total: int = body.get("total", 0)
                page_records: list[dict] = body.get("records", [])
                all_records.extend(page_records)

                # Stop when we have everything or the page came back empty
                if len(all_records) >= total or len(page_records) == 0:
                    break

                offset += limit

        logger.debug("Fetched %d total records from aiScraper", len(all_records))
        return all_records

    def _parse_candidate(self, raw: dict) -> list[CandidateEndpoint]:
        """Produce one CandidateEndpoint per url-like param in a TrafficRecord.

        A single TrafficRecord can carry multiple url-like parameters
        (e.g. ``callback_url`` in query and ``webhook`` in body), so we
        iterate ``tags["param_categories"]`` and emit one candidate for
        every entry whose value is exactly ``"url_like"``.

        Param location is inferred from the source:
        * ``query_params`` → ``param_location="query"``
        * parsed from ``body``  → ``param_location="body"``

        Known limitation: when a param name appears in **both** query_params
        and a parseable body, we prefer query_params.  Without extra context
        from aiScraper's enrichment step we cannot resolve the true origin.
        """
        request_id = raw.get("request_id", "unknown")

        # Defensive extraction — tolerate missing/malformed fields
        try:
            host = str(raw.get("host", ""))
            url = str(raw.get("url", ""))
            method = str(raw.get("method", "GET"))
            request_headers: dict[str, str] = raw.get("headers") or {}
            request_body: Optional[str] = raw.get("body")
            query_params: dict = raw.get("query_params") or {}
            tags: dict = raw.get("tags") or {}
            param_categories: dict = tags.get("param_categories") or {}
        except (TypeError, ValueError, AttributeError) as exc:
            logger.debug(
                "Skipping malformed record (request_id=%s): %s",
                request_id,
                exc,
            )
            return []

        candidates: list[CandidateEndpoint] = []

        for param_name, category in param_categories.items():
            if category != "url_like":
                continue

            # Determine location and value
            param_location: str
            param_value: str

            in_query = param_name in query_params
            in_body = request_body is not None

            if in_query:
                # Known limitation: if the same param name also exists in
                # the body we cannot tell which one aiScraper's enrichment
                # step matched — we prefer query_params.
                param_location = "query"
                qv = query_params[param_name]
                param_value = str(qv[0]) if qv else ""
            elif in_body:
                param_location = "body"
                param_value = self._extract_param_from_body(
                    request_body, param_name  # type: ignore[arg-type]
                )
            else:
                # Param listed in tags but value not found in query or body
                logger.debug(
                    "Param %r tagged url_like in record %s but value not "
                    "found in query_params or body — skipping",
                    param_name,
                    request_id,
                )
                continue

            try:
                candidates.append(
                    CandidateEndpoint(
                        id=f"{request_id}:{param_name}",
                        method=method,
                        url=url,
                        param_name=str(param_name),
                        param_location=param_location,
                        param_value=param_value,
                        host=host,
                        request_headers=request_headers,
                        request_body=request_body,
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                logger.debug(
                    "Skipping candidate (request_id=%s, param=%s): %s",
                    request_id,
                    param_name,
                    exc,
                )

        return candidates

    @staticmethod
    def _extract_param_from_body(body: str, param_name: str) -> str:
        """Try to extract *param_name*'s value from a raw body string.

        Attempts JSON then form-urlencoded parsing.  Returns ``""`` if
        the param cannot be located.
        """
        # JSON body
        try:
            import json

            data = json.loads(body)
            if isinstance(data, dict) and param_name in data:
                value = data[param_name]
                return str(value) if value is not None else ""
        except (json.JSONDecodeError, TypeError):
            pass

        # form-urlencoded body
        try:
            from urllib.parse import parse_qs

            parsed = parse_qs(body)
            if param_name in parsed:
                values = parsed[param_name]
                return values[0] if values else ""
        except Exception:
            pass

        return ""

    def _filter_by_scope(self, raw_items: list[dict]) -> list[CandidateEndpoint]:
        """Parse every item (one record → N candidates), drop out-of-scope.

        Logs a one-line summary: ``N records fetched, M candidates parsed, K kept``.
        """
        kept: list[CandidateEndpoint] = []
        total_candidates = 0
        for raw in raw_items:
            candidates = self._parse_candidate(raw)
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
