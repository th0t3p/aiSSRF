"""Tests for LocalFileCandidateFetcher — the aiBrowser index.jsonl candidate source."""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from urllib.parse import urlencode

import pytest

from aiSSRF.config import AiSsrfConfig, CandidateEndpoint
from aiSSRF.candidate_fetcher.local_file import (
    LocalFileCandidateFetcher,
    _is_url_like_param_name,
    _is_url_like_param_value,
    _param_is_url_like,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**overrides) -> AiSsrfConfig:
    defaults = {
        "candidate_source": "local_file",
        "local_traffic_dir": "/tmp/mock_traffic",
        "authorized_scope": ["*.example.com"],
    }
    defaults.update(overrides)
    return AiSsrfConfig(**defaults)


def _make_record(
    *,
    request_id: str = "abc123",
    method: str = "GET",
    url: str = "https://api.example.com/v1/users?redirect=https://evil.com",
    query_params: dict | None = None,
    request_headers: dict | None = None,
    request_body_ref: str | None = None,
    request_body_sha256: str | None = None,
    **overrides,
) -> dict:
    """Build a record matching aiBrowser's index.jsonl schema."""
    record: dict = {
        "schema_version": "1.0",
        "request_id": request_id,
        "captured_at": "2026-08-01T00:00:00Z",
        "method": method,
        "url": url,
        "query_params": query_params or {},
        "request_headers": request_headers or {},
        "request_body_ref": request_body_ref,
        "request_body_sha256": request_body_sha256,
        "response_status": 200,
        "response_headers": {},
        "response_body_ref": None,
        "response_body_sha256": None,
    }
    record.update(overrides)
    return record


def _write_index(tmp_path: Path, records: list[dict]) -> Path:
    """Write an index.jsonl into *tmp_path* and return its path."""
    traffic_dir = tmp_path / "traffic"
    traffic_dir.mkdir()
    bodies_dir = traffic_dir / "bodies"
    bodies_dir.mkdir()
    index_path = traffic_dir / "index.jsonl"
    with open(index_path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return traffic_dir


def _write_body(tmp_path: Path, traffic_dir: Path, content: str | bytes) -> tuple[str, str]:
    """Write a body file into bodies/<sha256>.bin and return (ref, sha256)."""
    body_bytes = content if isinstance(content, bytes) else content.encode("utf-8")
    sha = hashlib.sha256(body_bytes).hexdigest()
    ref = f"bodies/{sha}.bin"
    body_path = traffic_dir / ref
    body_path.write_bytes(body_bytes)
    return ref, sha


# ---------------------------------------------------------------------------
# URL-like heuristic unit tests
# ---------------------------------------------------------------------------


class TestUrlLikeHeuristic:
    def test_known_param_name_is_url_like(self):
        """Params like 'url', 'redirect', 'webhook' match by name."""
        assert _is_url_like_param_name("url") is True
        assert _is_url_like_param_name("redirect") is True
        assert _is_url_like_param_name("callback") is True
        assert _is_url_like_param_name("webhook") is True
        assert _is_url_like_param_name("next") is True
        assert _is_url_like_param_name("target") is True

    def test_substring_match_is_url_like(self):
        """Params containing '_url', '_redirect', etc. match."""
        assert _is_url_like_param_name("callback_url") is True
        assert _is_url_like_param_name("icon_url") is True
        assert _is_url_like_param_name("redirect_uri") is True

    def test_plain_id_param_is_not_url_like_by_name(self):
        """A plain 'id' or 'count' param is not url-like by name."""
        assert _is_url_like_param_name("id") is False
        assert _is_url_like_param_name("count") is False
        assert _is_url_like_param_name("name") is False

    def test_value_starting_with_http_is_url_like(self):
        """Values starting with http:// or https:// match."""
        assert _is_url_like_param_value("https://evil.com/hook") is True
        assert _is_url_like_param_value("http://target.net/path") is True

    def test_scheme_relative_value_is_url_like(self):
        """Scheme-relative URLs (//) match."""
        assert _is_url_like_param_value("//evil.com/path") is True

    def test_bare_domain_is_url_like(self):
        """Bare domains with a TLD match."""
        assert _is_url_like_param_value("evil.com/path") is True
        assert _is_url_like_param_value("sub.example.com") is True

    def test_bare_ipv4_is_url_like(self):
        """Bare IPv4 addresses match."""
        assert _is_url_like_param_value("192.168.1.1") is True
        assert _is_url_like_param_value("10.0.0.1/admin") is True

    def test_plain_numeric_value_is_not_url_like(self):
        """Plain numeric values like '42' don't match."""
        assert _is_url_like_param_value("42") is False

    def test_plain_text_value_is_not_url_like(self):
        """Plain text like 'hello' doesn't match."""
        assert _is_url_like_param_value("hello") is False

    def test_combined_heuristic_name_or_value(self):
        """A param named 'id' with a URL value is still url-like."""
        assert _param_is_url_like("id", "https://evil.com") is True
        # A param named 'url' with a non-URL value is still url-like by name
        assert _param_is_url_like("url", "foo") is True
        # Neither name nor value suggests URL-like
        assert _param_is_url_like("id", "42") is False


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


class TestConfigValidation:
    def test_candidate_source_defaults_to_api(self):
        """Default candidate_source is 'api'."""
        config = AiSsrfConfig(_env_file=None)
        assert config.candidate_source == "api"

    def test_candidate_source_invalid_value_raises(self):
        """Invalid candidate_source raises ValidationError."""
        with pytest.raises(ValueError, match="candidate_source"):
            AiSsrfConfig(
                _env_file=None,
                candidate_source="invalid",
            )

    def test_local_file_requires_traffic_dir(self):
        """candidate_source='local_file' with empty local_traffic_dir raises."""
        with pytest.raises(ValueError, match="local_traffic_dir"):
            AiSsrfConfig(
                _env_file=None,
                candidate_source="local_file",
                local_traffic_dir="",
            )

    def test_local_file_with_traffic_dir_ok(self):
        """candidate_source='local_file' with a traffic dir is valid."""
        config = AiSsrfConfig(
            _env_file=None,
            candidate_source="local_file",
            local_traffic_dir="/some/path",
        )
        assert config.local_traffic_dir == "/some/path"


# ---------------------------------------------------------------------------
# Fetch — fail-closed and missing-file behavior
# ---------------------------------------------------------------------------


class TestFetchFailClosed:
    @pytest.mark.asyncio
    async def test_empty_scope_returns_empty(self):
        """Empty authorized_scope → empty list, no file I/O."""
        config = _make_config(authorized_scope=[])
        fetcher = LocalFileCandidateFetcher(config)
        result = await fetcher.fetch()
        assert result == []

    @pytest.mark.asyncio
    async def test_missing_index_jsonl_returns_empty(self, tmp_path):
        """No index.jsonl → empty result, no crash."""
        traffic_dir = tmp_path / "empty"
        traffic_dir.mkdir()
        # No index.jsonl created
        config = _make_config(local_traffic_dir=str(traffic_dir))
        fetcher = LocalFileCandidateFetcher(config)
        result = await fetcher.fetch()
        assert result == []

    @pytest.mark.asyncio
    async def test_missing_traffic_dir_returns_empty(self):
        """Non-existent traffic dir → empty result, no crash."""
        config = _make_config(local_traffic_dir="/nonexistent/path/12345")
        fetcher = LocalFileCandidateFetcher(config)
        result = await fetcher.fetch()
        assert result == []


# ---------------------------------------------------------------------------
# Candidate extraction — query params
# ---------------------------------------------------------------------------


class TestQueryParamExtraction:
    def test_url_like_query_param_kept(self):
        """Query param named 'redirect' with a URL value is extracted."""
        config = _make_config()
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="r1",
            url="https://api.example.com/login?redirect=https://evil.com",
            query_params={"redirect": ["https://evil.com"]},
        )
        candidates = fetcher._record_to_candidates(raw)

        assert len(candidates) == 1
        c = candidates[0]
        assert isinstance(c, CandidateEndpoint)
        assert c.id == "r1:redirect"
        assert c.host == "api.example.com"
        assert c.param_name == "redirect"
        assert c.param_location == "query"
        assert c.param_value == "https://evil.com"

    def test_non_url_like_query_param_dropped(self):
        """Query param 'id' with value '42' is dropped (not url-like)."""
        config = _make_config()
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="r2",
            url="https://api.example.com/users?id=42",
            query_params={"id": ["42"]},
        )
        candidates = fetcher._record_to_candidates(raw)

        assert candidates == []

    def test_url_like_by_value_only(self):
        """A param named 'data' but with a URL value is kept."""
        config = _make_config()
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="r3",
            url="https://api.example.com/fetch?data=https://evil.com",
            query_params={"data": ["https://evil.com"]},
        )
        candidates = fetcher._record_to_candidates(raw)

        assert len(candidates) == 1
        assert candidates[0].param_name == "data"

    def test_mixed_url_like_and_non_url_like(self):
        """Only url-like params are kept; non-url-like are dropped."""
        config = _make_config()
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="r4",
            url="https://api.example.com/search?q=hello&redirect=https://evil.com&page=1&limit=10",
            query_params={
                "q": ["hello"],
                "redirect": ["https://evil.com"],
                "page": ["1"],
                "limit": ["10"],
            },
        )
        candidates = fetcher._record_to_candidates(raw)

        assert len(candidates) == 1
        assert candidates[0].param_name == "redirect"

    def test_host_derived_from_url(self):
        """host is extracted from the record's url field."""
        config = _make_config()
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="r5",
            url="https://sub.example.com/api?next=https://target.com",
            query_params={"next": ["https://target.com"]},
        )
        candidates = fetcher._record_to_candidates(raw)

        assert len(candidates) == 1
        assert candidates[0].host == "sub.example.com"


# ---------------------------------------------------------------------------
# Body param extraction
# ---------------------------------------------------------------------------


class TestBodyParamExtraction:
    def test_json_body_param_resolved_and_classified(self, tmp_path):
        """A JSON body with a webhook URL → param resolved and classified."""
        body_json = json.dumps({"webhook": "https://evil.com/hook", "user_id": 42})
        traffic_dir = _write_index(tmp_path, [])
        ref, sha = _write_body(tmp_path, traffic_dir, body_json)

        config = _make_config(local_traffic_dir=str(traffic_dir))
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="r_b1",
            method="POST",
            url="https://api.example.com/hooks",
            query_params={},
            request_body_ref=ref,
            request_body_sha256=sha,
        )
        candidates = fetcher._record_to_candidates(raw)

        assert len(candidates) >= 1
        body_candidates = [c for c in candidates if c.param_location == "body"]
        assert len(body_candidates) == 1  # only webhook is url-like
        c = body_candidates[0]
        assert c.param_name == "webhook"
        assert c.param_location == "body"
        assert c.param_value == "https://evil.com/hook"

    def test_form_urlencoded_body_param(self, tmp_path):
        """A form-urlencoded body with a 'next' param → resolved from bodies/."""
        body_form = urlencode({"next": "https://attacker.com/next", "csrf": "abc"})
        traffic_dir = _write_index(tmp_path, [])
        ref, sha = _write_body(tmp_path, traffic_dir, body_form)

        config = _make_config(local_traffic_dir=str(traffic_dir))
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="r_b2",
            method="POST",
            url="https://login.example.com/oauth",
            query_params={},
            request_body_ref=ref,
            request_body_sha256=sha,
        )
        candidates = fetcher._record_to_candidates(raw)

        body_candidates = [c for c in candidates if c.param_location == "body"]
        assert len(body_candidates) == 1
        c = body_candidates[0]
        assert c.param_name == "next"
        assert c.param_value == "https://attacker.com/next"

    def test_param_in_both_query_and_body_prefers_query(self, tmp_path):
        """Known limitation: param in both query and body → prefers query."""
        body_json = json.dumps({"url": "https://body-val.com"})
        traffic_dir = _write_index(tmp_path, [])
        ref, sha = _write_body(tmp_path, traffic_dir, body_json)

        config = _make_config(local_traffic_dir=str(traffic_dir))
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="r_b3",
            method="POST",
            url="https://api.example.com/action",
            query_params={"url": ["https://query-val.com"]},
            request_body_ref=ref,
            request_body_sha256=sha,
        )
        candidates = fetcher._record_to_candidates(raw)

        # Only the query version should appear
        query_candidates = [c for c in candidates if c.param_location == "query"]
        assert len(query_candidates) == 1
        assert query_candidates[0].param_value == "https://query-val.com"

    def test_missing_body_file_is_handled_gracefully(self, tmp_path):
        """A record referencing a non-existent body file → skipped, no crash."""
        traffic_dir = _write_index(tmp_path, [])
        # Don't create the body file

        config = _make_config(local_traffic_dir=str(traffic_dir))
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="r_b4",
            method="POST",
            url="https://api.example.com/hooks",
            query_params={},
            request_body_ref="bodies/deadbeef.bin",
            request_body_sha256="deadbeef",
        )
        candidates = fetcher._record_to_candidates(raw)

        # No body params extracted (body couldn't be read), only query params
        body_candidates = [c for c in candidates if c.param_location == "body"]
        assert len(body_candidates) == 0

    def test_binary_body_skipped(self, tmp_path):
        """A binary body is detected and skipped."""
        binary_body = bytes([0x00, 0x01, 0x02, 0xFF] * 100)
        traffic_dir = _write_index(tmp_path, [])
        ref, sha = _write_body(tmp_path, traffic_dir, binary_body)

        config = _make_config(local_traffic_dir=str(traffic_dir))
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="r_b5",
            method="POST",
            url="https://api.example.com/upload",
            query_params={},
            request_body_ref=ref,
            request_body_sha256=sha,
        )
        candidates = fetcher._record_to_candidates(raw)
        assert candidates == []


# ---------------------------------------------------------------------------
# Scope filtering
# ---------------------------------------------------------------------------


class TestScopeFiltering:
    def test_in_scope_host_kept(self):
        """A candidate from an in-scope host is kept."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = LocalFileCandidateFetcher(config)

        raw = [
            _make_record(
                request_id="s1",
                url="https://api.example.com/foo?redirect=https://evil.com",
                query_params={"redirect": ["https://evil.com"]},
            ),
        ]
        result = fetcher._filter_by_scope(raw)
        assert len(result) == 1

    def test_out_of_scope_host_dropped(self):
        """A candidate from an out-of-scope host is dropped even if param is url-like."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = LocalFileCandidateFetcher(config)

        raw = [
            _make_record(
                request_id="s2",
                url="https://evil.com/foo?redirect=https://attacker.net",
                query_params={"redirect": ["https://attacker.net"]},
            ),
        ]
        result = fetcher._filter_by_scope(raw)
        assert result == []

    def test_mixed_scope(self):
        """In-scope hosts are kept; out-of-scope are dropped."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = LocalFileCandidateFetcher(config)

        raw = [
            _make_record(
                request_id="s3",
                url="https://api.example.com/foo?next=https://x.com",
                query_params={"next": ["https://x.com"]},
            ),
            _make_record(
                request_id="s4",
                url="https://evil.com/bar?url=https://y.com",
                query_params={"url": ["https://y.com"]},
            ),
            _make_record(
                request_id="s5",
                url="https://sub.example.com/baz?cb=https://z.com",
                query_params={"cb": ["https://z.com"]},
            ),
        ]
        result = fetcher._filter_by_scope(raw)

        assert len(result) == 2
        ids = {c.id for c in result}
        assert ids == {"s3:next", "s5:cb"}

    def test_exact_scope_no_wildcard(self):
        """Exact scope 'example.com' only matches 'example.com', not subdomains."""
        config = _make_config(authorized_scope=["example.com"])
        fetcher = LocalFileCandidateFetcher(config)

        raw = [
            _make_record(
                request_id="s6",
                url="https://example.com/foo?redirect=https://x.com",
                query_params={"redirect": ["https://x.com"]},
            ),
            _make_record(
                request_id="s7",
                url="https://sub.example.com/bar?url=https://y.com",
                query_params={"url": ["https://y.com"]},
            ),
        ]
        result = fetcher._filter_by_scope(raw)
        assert len(result) == 1
        assert result[0].id == "s6:redirect"


# ---------------------------------------------------------------------------
# Defensive parsing / edge cases
# ---------------------------------------------------------------------------


class TestDefensiveParsing:
    def test_blank_lines_skipped(self, tmp_path):
        """Blank lines in index.jsonl are skipped without error."""
        traffic_dir = _write_index(tmp_path, [])
        index_path = traffic_dir / "index.jsonl"
        with open(index_path, "w") as fh:
            fh.write("\n")
            fh.write(json.dumps(_make_record(
                request_id="d1",
                url="https://api.example.com/foo?redirect=https://evil.com",
                query_params={"redirect": ["https://evil.com"]},
            )) + "\n")
            fh.write("\n")
            fh.write("   \n")  # whitespace-only line

        config = _make_config(local_traffic_dir=str(traffic_dir))
        fetcher = LocalFileCandidateFetcher(config)

        records = fetcher._parse_index()
        assert len(records) == 1

    def test_malformed_json_line_skipped(self, tmp_path, caplog):
        """A line with invalid JSON is logged and skipped."""
        traffic_dir = _write_index(tmp_path, [])
        index_path = traffic_dir / "index.jsonl"
        with open(index_path, "w") as fh:
            fh.write(json.dumps(_make_record(
                request_id="d2a",
                url="https://api.example.com/foo?redirect=https://x.com",
                query_params={"redirect": ["https://x.com"]},
            )) + "\n")
            fh.write("{bad json}\n")
            fh.write(json.dumps(_make_record(
                request_id="d2b",
                url="https://api.example.com/bar?next=https://y.com",
                query_params={"next": ["https://y.com"]},
            )) + "\n")

        config = _make_config(local_traffic_dir=str(traffic_dir))
        fetcher = LocalFileCandidateFetcher(config)

        with caplog.at_level(logging.DEBUG):
            records = fetcher._parse_index()

        assert len(records) == 2
        debug_msgs = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
        assert any("malformed" in m.lower() or "jsondecode" in m.lower() for m in debug_msgs)

    def test_non_dict_json_line_skipped(self, tmp_path, caplog):
        """A line that is valid JSON but not a dict is skipped."""
        traffic_dir = _write_index(tmp_path, [])
        index_path = traffic_dir / "index.jsonl"
        with open(index_path, "w") as fh:
            fh.write(json.dumps(_make_record(
                request_id="d3a",
                url="https://api.example.com/foo?redirect=https://x.com",
                query_params={"redirect": ["https://x.com"]},
            )) + "\n")
            fh.write("[1, 2, 3]\n")
            fh.write('"just a string"\n')

        config = _make_config(local_traffic_dir=str(traffic_dir))
        fetcher = LocalFileCandidateFetcher(config)

        records = fetcher._parse_index()
        assert len(records) == 1

    def test_malformed_record_fields_produce_empty_candidates(self, caplog):
        """A record with unexpected types in fields → defensive, returns []."""
        config = _make_config()
        fetcher = LocalFileCandidateFetcher(config)

        # url is a list instead of a string
        raw = {
            "request_id": "d4",
            "url": ["not", "a", "string"],
            "method": 123,
            "query_params": None,
            "request_headers": None,
        }
        with caplog.at_level(logging.DEBUG):
            candidates = fetcher._record_to_candidates(raw)

        assert candidates == []

    def test_empty_index_produces_empty_candidates(self, tmp_path):
        """An empty index.jsonl → zero candidates."""
        traffic_dir = _write_index(tmp_path, [])
        config = _make_config(local_traffic_dir=str(traffic_dir))
        fetcher = LocalFileCandidateFetcher(config)

        records = fetcher._parse_index()
        assert records == []

    def test_record_with_no_url_like_params_produces_no_candidates(self):
        """A record where no params are url-like → zero candidates."""
        config = _make_config()
        fetcher = LocalFileCandidateFetcher(config)

        raw = _make_record(
            request_id="d5",
            url="https://api.example.com/users?id=42&page=1",
            query_params={"id": ["42"], "page": ["1"]},
        )
        candidates = fetcher._record_to_candidates(raw)
        assert candidates == []


# ---------------------------------------------------------------------------
# Summary logging
# ---------------------------------------------------------------------------


class TestSummaryLogging:
    def test_summary_log_counts(self, caplog):
        """_filter_by_scope logs records/candidates/kept counts."""
        config = _make_config(authorized_scope=["*.example.com"])
        fetcher = LocalFileCandidateFetcher(config)

        raw = [
            _make_record(
                request_id="log1",
                url="https://api.example.com/foo?redirect=https://x.com",
                query_params={"redirect": ["https://x.com"]},
            ),
            _make_record(
                request_id="log2",
                url="https://evil.com/bar?url=https://y.com",
                query_params={"url": ["https://y.com"]},
            ),
            _make_record(
                request_id="log3",
                url="https://sub.example.com/baz?next=https://z.com",
                query_params={"next": ["https://z.com"]},
            ),
        ]
        with caplog.at_level(logging.INFO):
            fetcher._filter_by_scope(raw)

        info_msgs = [r.message for r in caplog.records if r.levelno == logging.INFO]
        assert len(info_msgs) >= 1
        # 3 records, 3 candidates parsed (each has 1 url-like param), 2 kept
        summary = info_msgs[0]
        assert "3 records fetched" in summary or "3 records" in summary.lower()
        assert "3 candidates parsed" in summary or "3 candidates" in summary.lower()
        assert "2 kept" in summary


# ---------------------------------------------------------------------------
# Fetch full integration (parse + filter)
# ---------------------------------------------------------------------------


class TestFetchIntegration:
    @pytest.mark.asyncio
    async def test_fetch_returns_in_scope_candidates(self, tmp_path):
        """End-to-end: write index.jsonl, fetch, verify results."""
        body_json = json.dumps({"webhook": "https://hook.evil.com/callback"})
        body_bytes = body_json.encode("utf-8")
        body_sha = hashlib.sha256(body_bytes).hexdigest()
        body_ref = f"bodies/{body_sha}.bin"

        traffic_dir = tmp_path / "traffic"
        traffic_dir.mkdir()
        (traffic_dir / "bodies").mkdir()
        (traffic_dir / body_ref).write_bytes(body_bytes)

        records = [
            _make_record(
                request_id="int1",
                url="https://api.example.com/v1/oauth?redirect=https://evil.com",
                query_params={"redirect": ["https://evil.com"]},
            ),
            _make_record(
                request_id="int2",
                url="https://evil.com/callback?url=https://attacker.com",
                query_params={"url": ["https://attacker.com"]},
            ),
            _make_record(
                request_id="int3",
                method="POST",
                url="https://sub.example.com/hooks",
                query_params={},
                request_body_ref=body_ref,
                request_body_sha256=body_sha,
            ),
        ]

        index_path = traffic_dir / "index.jsonl"
        with open(index_path, "w", encoding="utf-8") as fh:
            for rec in records:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

        config = _make_config(
            local_traffic_dir=str(traffic_dir),
            authorized_scope=["*.example.com"],
        )
        fetcher = LocalFileCandidateFetcher(config)
        result = await fetcher.fetch()

        # int1: in scope (api.example.com), query redirect → 1 candidate
        # int2: out of scope (evil.com) → dropped
        # int3: in scope (sub.example.com), body webhook → 1 candidate
        assert len(result) == 2
        ids = {c.id for c in result}
        assert "int1:redirect" in ids
        assert "int3:webhook" in ids
