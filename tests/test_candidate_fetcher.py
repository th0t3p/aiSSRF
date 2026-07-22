"""Tests for candidate_fetcher — mock aiScraper's real TrafficRecord shape."""

from __future__ import annotations

import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlencode

import httpx
import pytest

from aiSSRF.config import AiSsrfConfig, CandidateEndpoint
from aiSSRF.candidate_fetcher import CandidateFetcher


# ---------------------------------------------------------------------------
# Helpers — build aiScraper-shaped data
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> AiSsrfConfig:
    defaults = {
        "ai_scraper_api_url": "http://scraper:8000",
        "ai_scraper_api_key": "test-key",
        "authorized_scope": ["*.example.com"],
        "ai_scraper_page_size": 10,
    }
    defaults.update(overrides)
    return AiSsrfConfig(**defaults)


def _make_record(
    request_id: str = "abc-123",
    *,
    host: str = "example.com",
    url: str | None = None,
    **overrides,
) -> dict:
    """Build a TrafficRecord dict matching aiScraper's real response shape.

    Fields match ``ai_scraper/normalizer/models.py:TrafficRecord``::

        request_id, method, url, host, path, query_params, headers,
        body, response_status, response_headers, response_body,
        timestamp, source_tool, tags
    """
    record: dict = {
        "request_id": request_id,
        "method": "GET",
        "url": url or f"https://{host}/api/v1/users?redirect=http://evil.com",
        "host": host,
        "path": "/api/v1/users",
        "query_params": {"redirect": ["http://evil.com"]},
        "headers": {"User-Agent": "test"},
        "body": None,
        "response_status": 200,
        "response_headers": None,
        "response_body": None,
        "timestamp": "2026-07-22T00:00:00Z",
        "source_tool": "test",
        "tags": {"param_categories": {"redirect": "url_like"}},
    }
    record.update(overrides)
    return record


def _make_records_response(
    records: list[dict], total: int | None = None
) -> dict:
    """Wrap records in aiScraper's TrafficQueryResult envelope.

    ``{"total": int, "records": [TrafficRecord, ...]}``
    """
    return {"total": total if total is not None else len(records), "records": records}


def _make_mock_response(
    json_body: dict,
    status_code: int = 200,
) -> MagicMock:
    """Create a mock httpx.Response with the given JSON body and status."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = json.dumps(json_body)
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    else:
        resp.raise_for_status = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# _parse_candidate — sync, testable directly
# ---------------------------------------------------------------------------

class TestParseCandidate:
    """Tests for the tag-based multi-param parser."""

    def test_single_url_like_query_param(self):
        """One url-like query param → one CandidateEndpoint."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = _make_record("r1", host="example.com")
        result = fetcher._parse_candidate(raw)

        assert len(result) == 1
        c = result[0]
        assert isinstance(c, CandidateEndpoint)
        assert c.id == "r1:redirect"
        assert c.host == "example.com"
        assert c.method == "GET"
        assert c.param_name == "redirect"
        assert c.param_location == "query"
        assert c.param_value == "http://evil.com"
        assert c.request_headers == {"User-Agent": "test"}
        assert c.request_body is None

    def test_two_url_like_query_params_produces_two_candidates(self):
        """A record with two url-like params → two CandidateEndpoints."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = _make_record(
            "r2",
            host="example.com",
            query_params={
                "callback_url": ["https://collab.com/cb"],
                "redirect": ["http://evil.com"],
            },
            tags={
                "param_categories": {
                    "callback_url": "url_like",
                    "redirect": "url_like",
                }
            },
        )
        result = fetcher._parse_candidate(raw)

        assert len(result) == 2
        ids = {c.id for c in result}
        assert ids == {"r2:callback_url", "r2:redirect"}

        by_param = {c.param_name: c for c in result}
        assert by_param["callback_url"].param_value == "https://collab.com/cb"
        assert by_param["callback_url"].param_location == "query"
        assert by_param["redirect"].param_value == "http://evil.com"
        assert by_param["redirect"].param_location == "query"

    def test_url_like_param_in_json_body(self):
        """url-like param found in JSON body → location='body'."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        body_json = json.dumps({"webhook": "https://evil.com/hook", "other": 42})
        raw = _make_record(
            "r3",
            host="example.com",
            query_params={},
            body=body_json,
            tags={"param_categories": {"webhook": "url_like"}},
        )
        result = fetcher._parse_candidate(raw)

        assert len(result) == 1
        c = result[0]
        assert c.param_name == "webhook"
        assert c.param_location == "body"
        assert c.param_value == "https://evil.com/hook"

    def test_url_like_param_in_form_urlencoded_body(self):
        """url-like param found in form-urlencoded body → location='body'."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        body_form = urlencode({"next": "https://attacker.com/next"})
        raw = _make_record(
            "r4",
            host="example.com",
            query_params={},
            body=body_form,
            tags={"param_categories": {"next": "url_like"}},
        )
        result = fetcher._parse_candidate(raw)

        assert len(result) == 1
        c = result[0]
        assert c.param_name == "next"
        assert c.param_location == "body"
        assert c.param_value == "https://attacker.com/next"

    def test_non_url_like_param_is_skipped(self):
        """A param tagged 'identifier_like' is ignored, only 'url_like' kept."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = _make_record(
            "r5",
            host="example.com",
            tags={
                "param_categories": {
                    "redirect": "url_like",
                    "user_id": "identifier_like",
                }
            },
        )
        result = fetcher._parse_candidate(raw)

        assert len(result) == 1
        assert result[0].param_name == "redirect"

    def test_param_tagged_but_not_found_in_query_or_body_is_skipped(self, caplog):
        """Param tagged url_like but missing from query_params/body → skipped + log."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = _make_record(
            "r6",
            host="example.com",
            query_params={},
            body=None,
            tags={"param_categories": {"orphan_param": "url_like"}},
        )
        with caplog.at_level(logging.DEBUG):
            result = fetcher._parse_candidate(raw)

        assert result == []
        debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
        assert any("orphan_param" in m for m in debug_msgs)
        assert any("r6" in m for m in debug_msgs)
        assert any("skipping" in m.lower() for m in debug_msgs)

    def test_param_in_both_query_and_body_prefers_query(self):
        """Known limitation: param in both query and body → prefers query."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = _make_record(
            "r7",
            host="example.com",
            query_params={"url": ["https://query-val.com"]},
            body=json.dumps({"url": "https://body-val.com"}),
            tags={"param_categories": {"url": "url_like"}},
        )
        result = fetcher._parse_candidate(raw)

        assert len(result) == 1
        c = result[0]
        assert c.param_location == "query"
        assert c.param_value == "https://query-val.com"

    def test_json_body_param_with_null_value_returns_empty_string(self):
        """JSON body param with null → value=''."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = _make_record(
            "r8",
            host="example.com",
            query_params={},
            body=json.dumps({"webhook": None}),
            tags={"param_categories": {"webhook": "url_like"}},
        )
        result = fetcher._parse_candidate(raw)

        assert len(result) == 1
        assert result[0].param_value == ""

    def test_unparseable_body_with_tagged_param_returns_empty_value(self):
        """Body is plain text that can't be parsed → value=''."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = _make_record(
            "r9",
            host="example.com",
            query_params={},
            body="just some random text",
            tags={"param_categories": {"target": "url_like"}},
        )
        result = fetcher._parse_candidate(raw)

        assert len(result) == 1
        c = result[0]
        assert c.param_location == "body"
        assert c.param_value == ""

    def test_missing_tags_field_produces_empty_list(self):
        """Record without a 'tags' key → no candidates parsed."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = _make_record("r10", host="example.com")
        del raw["tags"]
        result = fetcher._parse_candidate(raw)

        assert result == []

    def test_missing_param_categories_key_produces_empty_list(self):
        """Record with 'tags' but no 'param_categories' → empty."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = _make_record("r11", host="example.com", tags={})
        result = fetcher._parse_candidate(raw)

        assert result == []

    def test_missing_host_url_defaults(self):
        """Missing host/url → defaults to empty string, still parses."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = {
            "request_id": "r12",
            "method": "POST",
            "query_params": {"cb": ["https://x.com"]},
            "headers": {},
            "body": None,
            "tags": {"param_categories": {"cb": "url_like"}},
        }
        result = fetcher._parse_candidate(raw)

        assert len(result) == 1
        c = result[0]
        assert c.host == ""
        assert c.url == ""
        assert c.method == "POST"

    def test_malformed_tags_not_dict_returns_empty(self, caplog):
        """tags is a list instead of dict → defensive, returns []."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        raw = _make_record("r13", host="example.com", tags=["not", "a", "dict"])
        with caplog.at_level(logging.DEBUG):
            result = fetcher._parse_candidate(raw)

        assert result == []
        # The except block catches TypeError from .get() on a list
        debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
        assert any("r13" in m for m in debug_msgs)


# ---------------------------------------------------------------------------
# _filter_by_scope — sync, testable without HTTP mocking
# ---------------------------------------------------------------------------

class TestFilterByScope:
    def test_all_in_scope(self):
        """All parsed candidates match authorized_scope wildcard → all kept."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = CandidateFetcher(config)

        raw = [
            _make_record("1", host="sub.example.com"),
            _make_record("2", host="api.example.com"),
        ]
        result = fetcher._filter_by_scope(raw)
        assert len(result) == 2
        assert {c.id for c in result} == {"1:redirect", "2:redirect"}

    def test_exact_scope_matching(self):
        """Exact domain scope only matches the exact host, not subdomains."""
        config = _make_config(authorized_scope=["example.com"])
        fetcher = CandidateFetcher(config)

        raw = [
            _make_record("1", host="example.com"),
            _make_record("2", host="sub.example.com"),
        ]
        result = fetcher._filter_by_scope(raw)
        assert len(result) == 1
        assert {c.id for c in result} == {"1:redirect"}

    def test_partial_out_of_scope(self):
        """Only candidates from in-scope hosts are kept."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = CandidateFetcher(config)

        raw = [
            _make_record("1", host="sub.example.com"),
            _make_record("2", host="evil.com"),
            _make_record("3", host="api.example.com"),
            _make_record("4", host="attacker.net"),
        ]
        result = fetcher._filter_by_scope(raw)
        assert len(result) == 2
        assert {c.id for c in result} == {"1:redirect", "3:redirect"}

    def test_multi_param_record_mixed_scope(self):
        """A single record with 2 url-like params → both candidates checked independently."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = CandidateFetcher(config)

        raw = [
            _make_record(
                "5",
                host="sub.example.com",
                query_params={
                    "callback_url": ["https://evil.com/cb"],
                    "redirect": ["http://safe.com"],
                },
                tags={
                    "param_categories": {
                        "callback_url": "url_like",
                        "redirect": "url_like",
                    }
                },
            ),
        ]
        result = fetcher._filter_by_scope(raw)
        assert len(result) == 2
        assert {c.id for c in result} == {"5:callback_url", "5:redirect"}

    def test_glob_scope_matching(self):
        """Wildcard scope patterns match subdomains."""
        config = _make_config(authorized_scope=["*.target.org"])
        fetcher = CandidateFetcher(config)

        raw = [
            _make_record("1", host="app.target.org"),
            _make_record("2", host="target.org"),
            _make_record("3", host="other.org"),
        ]
        result = fetcher._filter_by_scope(raw)
        # "target.org" doesn't match "*.target.org" — only subdomains match
        assert len(result) == 1
        assert {c.id for c in result} == {"1:redirect"}

    def test_malformed_records_are_skipped(self, caplog):
        """A malformed record produces zero candidates; batch continues."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = CandidateFetcher(config)

        raw = [
            _make_record("1", host="sub.example.com"),
            {"garbage": True},
            _make_record("2", host="evil.com"),
            _make_record("3", host="api.example.com"),
        ]
        with caplog.at_level(logging.DEBUG):
            result = fetcher._filter_by_scope(raw)

        assert len(result) == 2
        assert {c.id for c in result} == {"1:redirect", "3:redirect"}

    def test_record_with_no_url_like_params(self):
        """Record with tags but no url_like entries → zero candidates from it."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = CandidateFetcher(config)

        raw = [
            _make_record(
                "1",
                host="sub.example.com",
                tags={"param_categories": {"user_id": "identifier_like"}},
            ),
            _make_record("2", host="api.example.com"),
        ]
        result = fetcher._filter_by_scope(raw)
        # Only record 2 has a url_like param
        assert len(result) == 1
        assert {c.id for c in result} == {"2:redirect"}

    def test_summary_log_counts_records_and_candidates(self, caplog):
        """Log shows records fetched, candidates parsed, candidates kept."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = CandidateFetcher(config)

        raw = [
            _make_record("1", host="sub.example.com"),
            _make_record("2", host="evil.com"),
            _make_record("3", host="api.example.com"),
        ]
        with caplog.at_level(logging.INFO):
            fetcher._filter_by_scope(raw)

        info_msgs = [r.message for r in caplog.records if r.levelno == logging.INFO]
        assert len(info_msgs) == 1
        assert "3 records fetched" in info_msgs[0]
        assert "3 candidates parsed" in info_msgs[0]
        assert "2 kept" in info_msgs[0]


# ---------------------------------------------------------------------------
# _fetch_from_api — async, requires HTTP mocking
# ---------------------------------------------------------------------------

class TestFetchFromApi:
    @pytest.mark.asyncio
    async def test_single_page_with_total(self):
        """One page; total equals len(records) → single call, returns records."""
        config = _make_config(ai_scraper_page_size=10)
        fetcher = CandidateFetcher(config)

        records = [_make_record(str(i)) for i in range(3)]
        mock_resp = _make_mock_response(_make_records_response(records, total=3))

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch("aiSSRF.candidate_fetcher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            result = await fetcher._fetch_from_api()

        assert len(result) == 3
        assert result == records

        mock_client.get.assert_called_once()
        call_kwargs = mock_client.get.call_args.kwargs
        assert call_kwargs["params"]["param_categories"] == "url_like"
        assert call_kwargs["params"]["limit"] == 10
        assert call_kwargs["params"]["offset"] == 0
        assert call_kwargs["headers"]["X-API-Key"] == "test-key"

    @pytest.mark.asyncio
    async def test_pagination_via_total(self):
        """Paginates until len(all_records) >= total across two pages."""
        config = _make_config(ai_scraper_page_size=5)
        fetcher = CandidateFetcher(config)

        # total=12 across three pages of 5, 5, 2
        page1 = [_make_record(str(i)) for i in range(5)]
        page2 = [_make_record(str(i)) for i in range(5, 10)]
        page3 = [_make_record(str(i)) for i in range(10, 12)]

        mock_resp1 = _make_mock_response(_make_records_response(page1, total=12))
        mock_resp2 = _make_mock_response(_make_records_response(page2, total=12))
        mock_resp3 = _make_mock_response(_make_records_response(page3, total=12))

        mock_client = AsyncMock()
        mock_client.get.side_effect = [mock_resp1, mock_resp2, mock_resp3]

        with patch("aiSSRF.candidate_fetcher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            result = await fetcher._fetch_from_api()

        assert len(result) == 12
        assert mock_client.get.call_count == 3

        calls = mock_client.get.call_args_list
        assert calls[0].kwargs["params"]["offset"] == 0
        assert calls[1].kwargs["params"]["offset"] == 5
        assert calls[2].kwargs["params"]["offset"] == 10

    @pytest.mark.asyncio
    async def test_pagination_stops_on_empty_page(self):
        """Empty page triggers stop even if total not yet reached."""
        config = _make_config(ai_scraper_page_size=3)
        fetcher = CandidateFetcher(config)

        page1 = [_make_record(str(i)) for i in range(3)]
        page2: list[dict] = []

        mock_resp1 = _make_mock_response(_make_records_response(page1, total=100))
        mock_resp2 = _make_mock_response(_make_records_response(page2, total=100))

        mock_client = AsyncMock()
        mock_client.get.side_effect = [mock_resp1, mock_resp2]

        with patch("aiSSRF.candidate_fetcher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            result = await fetcher._fetch_from_api()

        assert len(result) == 3
        assert mock_client.get.call_count == 2

    @pytest.mark.asyncio
    async def test_401_logs_specifically_and_raises(self, caplog):
        """401 produces distinct log mentioning X-API-Key, then re-raises."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        mock_resp = _make_mock_response({"detail": "Unauthorized"}, status_code=401)

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch("aiSSRF.candidate_fetcher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            with pytest.raises(httpx.HTTPStatusError):
                await fetcher._fetch_from_api()

        errors = [r.message for r in caplog.records if r.levelno == logging.ERROR]
        assert any("401" in m for m in errors)
        assert any("X-API-Key" in m for m in errors)

    @pytest.mark.asyncio
    async def test_connection_error_logs_and_raises(self, caplog):
        """Connection error → 'connection failure' log, then re-raises."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")

        with patch("aiSSRF.candidate_fetcher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            with pytest.raises(httpx.ConnectError):
                await fetcher._fetch_from_api()

        errors = [r.message for r in caplog.records if r.levelno == logging.ERROR]
        assert any("connection failure" in m for m in errors)

    @pytest.mark.asyncio
    async def test_other_http_error(self, caplog):
        """Non-401 HTTP error (e.g. 500) logged with status code."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        mock_resp = _make_mock_response({"error": "boom"}, status_code=500)

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch("aiSSRF.candidate_fetcher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            with pytest.raises(httpx.HTTPStatusError):
                await fetcher._fetch_from_api()

        errors = [r.message for r in caplog.records if r.levelno == logging.ERROR]
        assert any("HTTP 500" in m for m in errors)

    @pytest.mark.asyncio
    async def test_uses_records_key_not_results(self):
        """Response with 'results' key instead of 'records' → empty result."""
        config = _make_config(ai_scraper_page_size=5)
        fetcher = CandidateFetcher(config)

        bad = _make_mock_response({"total": 1, "results": [_make_record("1")]})

        mock_client = AsyncMock()
        mock_client.get.return_value = bad

        with patch("aiSSRF.candidate_fetcher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            result = await fetcher._fetch_from_api()

        assert result == []

    @pytest.mark.asyncio
    async def test_missing_records_key_is_safe(self):
        """Response without 'records' key → empty list, no crash."""
        config = _make_config()
        fetcher = CandidateFetcher(config)

        mock_resp = _make_mock_response({"total": 42, "offset": 0})

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch("aiSSRF.candidate_fetcher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            result = await fetcher._fetch_from_api()

        assert result == []

    @pytest.mark.asyncio
    async def test_missing_total_defaults_to_zero_stops_after_first_page(self):
        """Response without 'total' → total=0 → first page returned, then stops."""
        config = _make_config(ai_scraper_page_size=3)
        fetcher = CandidateFetcher(config)

        records = [_make_record(str(i)) for i in range(2)]
        # No 'total' key
        mock_resp = _make_mock_response({"records": records})

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch("aiSSRF.candidate_fetcher.httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            result = await fetcher._fetch_from_api()

        assert len(result) == 2
        mock_client.get.assert_called_once()


# ---------------------------------------------------------------------------
# Integration: fetch() via mocked _fetch_from_api
# ---------------------------------------------------------------------------

class TestFetchIntegration:
    @pytest.mark.asyncio
    async def test_fetch_returns_only_in_scope_candidates(self):
        """fetch() calls _fetch_from_api → _filter_by_scope, returns in-scope."""
        config = _make_config(
            authorized_scope=["*.example.com"],
            ai_scraper_page_size=10,
        )
        fetcher = CandidateFetcher(config)

        raw = [
            _make_record("1", host="sub.example.com"),
            _make_record("2", host="evil.com"),
            _make_record("3", host="api.example.com"),
        ]

        with patch.object(
            fetcher, "_fetch_from_api", new_callable=AsyncMock
        ) as mock_fetch:
            mock_fetch.return_value = raw
            result = await fetcher.fetch()

        assert len(result) == 2
        assert {c.id for c in result} == {"1:redirect", "3:redirect"}

    @pytest.mark.asyncio
    async def test_fetch_empty_scope_returns_empty(self):
        """Empty authorized_scope → short-circuits to [], no API call."""
        config = _make_config(authorized_scope=[])
        fetcher = CandidateFetcher(config)

        with patch.object(
            fetcher, "_fetch_from_api", new_callable=AsyncMock
        ) as mock_fetch:
            result = await fetcher.fetch()

        assert result == []
        mock_fetch.assert_not_called()

    @pytest.mark.asyncio
    async def test_fetch_flattens_multi_param_records(self):
        """A record with 2 url-like params → fetch returns both (if in scope)."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = CandidateFetcher(config)

        raw = [
            _make_record(
                "multi",
                host="sub.example.com",
                query_params={
                    "cb": ["https://collab.com"],
                    "next": ["https://next.com"],
                },
                tags={
                    "param_categories": {
                        "cb": "url_like",
                        "next": "url_like",
                    }
                },
            ),
        ]

        with patch.object(
            fetcher, "_fetch_from_api", new_callable=AsyncMock
        ) as mock_fetch:
            mock_fetch.return_value = raw
            result = await fetcher.fetch()

        assert len(result) == 2
        assert {c.id for c in result} == {"multi:cb", "multi:next"}
