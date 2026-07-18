"""candidate_fetcher — Pull SSRF candidates from aiScraper's REST API.

Talks to ``GET /api/v1/traffic?param_category=url_like``, applies
the same fail-closed authorized_scope filtering that aiScraper itself
uses: even if aiScraper returns a candidate, we silently drop it if
its host does not match authorized_scope.
"""

from __future__ import annotations

from typing import Optional
import httpx
from aiSSRF.config import AiSsrfConfig, CandidateEndpoint, _in_scope


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
    # Stubs (to be implemented)
    # ------------------------------------------------------------------

    async def _fetch_from_api(self) -> list[dict]:
        """
        GET {ai_scraper_api_url}/api/v1/traffic?param_category=url_like

        Headers: Authorization: Bearer {ai_scraper_api_key}

        Returns the raw JSON list from aiScraper.
        """
        raise NotImplementedError("stub — will call aiScraper REST API via httpx")

    def _parse_candidate(self, raw: dict) -> Optional[CandidateEndpoint]:
        """
        Parse a single aiScraper traffic item into a CandidateEndpoint.
        Returns None if the item is malformed or missing required fields.
        """
        raise NotImplementedError("stub — will map aiScraper JSON → CandidateEndpoint")

    def _filter_by_scope(self, raw_items: list[dict]) -> list[CandidateEndpoint]:
        """
        Parse every item, drop those whose host is not in authorized_scope.
        """
        raise NotImplementedError("stub — loops over raw items, calls _parse_candidate + _in_scope")
