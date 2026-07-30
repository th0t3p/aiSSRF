"""Tests for AiSsrfConfig BaseSettings — .env loading and defaults."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from aiSSRF.config import AiSsrfConfig


class TestAiSsrfConfigDefaults:
    def test_defaults_no_env(self):
        """Without any .env or env vars, all fields use their defaults."""
        # Ensure no env vars leak from the test runner's environment
        with patch.dict(os.environ, {}, clear=True):
            # Also pass empty env_file to avoid loading from disk
            config = AiSsrfConfig(_env_file=None)

        assert config.ai_scraper_api_url == "http://localhost:8000"
        assert config.ai_scraper_api_key == ""
        assert config.burp_mcp_url == "http://127.0.0.1:9876"
        assert config.authorized_scope == []
        assert config.target_cidrs == []
        assert config.llm_provider == "anthropic"
        assert config.llm_max_tokens == 1024
        assert config.llm_temperature == 0.0
        assert config.collaborator_poll_interval_sec == 5.0
        assert config.collaborator_poll_timeout_sec == 120.0

    def test_kwargs_override_defaults(self):
        """Explicit kwargs override defaults (and .env values)."""
        config = AiSsrfConfig(
            _env_file=None,
            ai_scraper_api_url="https://custom:9000",
            authorized_scope=["custom.example.com"],
            llm_temperature=0.7,
        )
        assert config.ai_scraper_api_url == "https://custom:9000"
        assert config.authorized_scope == ["custom.example.com"]
        assert config.llm_temperature == 0.7


class TestEnvLoading:
    def test_scalar_fields_from_env(self, tmp_path, monkeypatch):
        """Single-value fields are picked up from env vars."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            "AISSRF_AI_SCRAPER_API_URL=https://scraper:9000\n"
            "AISSRF_AI_SCRAPER_API_KEY=sk-test-env\n"
            "AISSRF_LLM_PROVIDER=openai\n"
            "AISSRF_LLM_TEMPERATURE=0.3\n"
        )

        # Clear real env vars so they don't leak
        monkeypatch.delenv("AISSRF_AI_SCRAPER_API_URL", raising=False)
        monkeypatch.delenv("AISSRF_AI_SCRAPER_API_KEY", raising=False)
        monkeypatch.delenv("AISSRF_LLM_PROVIDER", raising=False)
        monkeypatch.delenv("AISSRF_LLM_TEMPERATURE", raising=False)

        config = AiSsrfConfig(_env_file=str(env_file), _env_file_encoding="utf-8")

        assert config.ai_scraper_api_url == "https://scraper:9000"
        assert config.ai_scraper_api_key == "sk-test-env"
        assert config.llm_provider == "openai"
        assert config.llm_temperature == 0.3

    def test_list_fields_from_json_array_env(self, tmp_path, monkeypatch):
        """list[str] fields parse JSON-array strings from .env correctly."""
        env_file = tmp_path / ".env"
        env_file.write_text(
            'AISSRF_AUTHORIZED_SCOPE=["*.example.com", "*.target.org"]\n'
            'AISSRF_TARGET_CIDRS=["10.0.0.0/8", "172.16.0.0/12"]\n'
        )

        monkeypatch.delenv("AISSRF_AUTHORIZED_SCOPE", raising=False)
        monkeypatch.delenv("AISSRF_TARGET_CIDRS", raising=False)

        config = AiSsrfConfig(_env_file=str(env_file), _env_file_encoding="utf-8")

        assert config.authorized_scope == ["*.example.com", "*.target.org"]
        assert config.target_cidrs == ["10.0.0.0/8", "172.16.0.0/12"]

    def test_empty_list_env_var(self, tmp_path, monkeypatch):
        """An empty JSON array in .env should produce an empty list, not crash."""
        env_file = tmp_path / ".env"
        env_file.write_text("AISSRF_AUTHORIZED_SCOPE=[]\n")

        monkeypatch.delenv("AISSRF_AUTHORIZED_SCOPE", raising=False)

        config = AiSsrfConfig(_env_file=str(env_file), _env_file_encoding="utf-8")
        assert config.authorized_scope == []

    def test_real_env_vars_override_env_file(self, tmp_path, monkeypatch):
        """Process environment variables take precedence over .env file values."""
        env_file = tmp_path / ".env"
        env_file.write_text("AISSRF_LLM_TEMPERATURE=0.1\n")

        monkeypatch.setenv("AISSRF_LLM_TEMPERATURE", "0.9")

        config = AiSsrfConfig(_env_file=str(env_file), _env_file_encoding="utf-8")
        assert config.llm_temperature == 0.9

    def test_partial_env_file_respects_defaults(self, tmp_path, monkeypatch):
        """Unset fields in .env fall back to class defaults."""
        env_file = tmp_path / ".env"
        env_file.write_text("AISSRF_LLM_PROVIDER=deepseek\n")

        monkeypatch.delenv("AISSRF_LLM_PROVIDER", raising=False)

        config = AiSsrfConfig(_env_file=str(env_file), _env_file_encoding="utf-8")

        assert config.llm_provider == "deepseek"
        # Fields not in .env use defaults
        assert config.llm_temperature == 0.0
        assert config.ai_scraper_page_size == 200
        assert config.authorized_scope == []

    def test_extra_fields_in_env_are_ignored(self, tmp_path, monkeypatch):
        """Unknown env vars are silently ignored (extra='ignore')."""
        env_file = tmp_path / ".env"
        env_file.write_text("AISSRF_UNKNOWN_FIELD=should_be_ignored\n")

        monkeypatch.delenv("AISSRF_UNKNOWN_FIELD", raising=False)

        # Should not raise
        config = AiSsrfConfig(_env_file=str(env_file), _env_file_encoding="utf-8")
        assert config.ai_scraper_api_url == "http://localhost:8000"  # default
