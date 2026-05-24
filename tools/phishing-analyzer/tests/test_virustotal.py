"""
Unit tests for the VirusTotal client.

Network calls are mocked so the suite runs offline and never burns
real API quota.
"""

import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import virustotal  # noqa: E402


class TestClientConstruction:
    def test_no_key_means_disabled(self, monkeypatch):
        monkeypatch.delenv("VT_API_KEY", raising=False)
        client = virustotal.VirusTotalClient()
        assert client.enabled is False

    def test_env_var_is_picked_up(self, monkeypatch):
        monkeypatch.setenv("VT_API_KEY", "fake-key")
        client = virustotal.VirusTotalClient()
        assert client.enabled is True

    def test_explicit_key_overrides_env(self, monkeypatch):
        monkeypatch.setenv("VT_API_KEY", "from-env")
        client = virustotal.VirusTotalClient(api_key="explicit")
        assert client.api_key == "explicit"


class TestHashLookup:
    def test_empty_hash_returns_unknown(self):
        client = virustotal.VirusTotalClient(api_key="fake")
        result = client.lookup_file_hash("")
        assert result["unknown"] is True

    @patch("virustotal.requests.get")
    def test_known_malicious_hash_is_summarized(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 30, "suspicious": 2,
                            "harmless": 0, "undetected": 40,
                        },
                        "reputation": -50,
                    }
                }
            },
        )
        # Bypass the throttle for a fast test
        client = virustotal.VirusTotalClient(api_key="fake")
        client.MIN_INTERVAL_SECONDS = 0
        result = client.lookup_file_hash("a" * 64)
        assert result["unknown"] is False
        assert result["malicious"] == 30
        assert result["total_engines"] == 72

    @patch("virustotal.requests.get")
    def test_unknown_hash_returns_not_found(self, mock_get):
        mock_get.return_value = MagicMock(status_code=404)
        client = virustotal.VirusTotalClient(api_key="fake")
        client.MIN_INTERVAL_SECONDS = 0
        result = client.lookup_file_hash("b" * 64)
        assert result["unknown"] is True

    @patch("virustotal.requests.get")
    def test_rate_limit_raises(self, mock_get):
        mock_get.return_value = MagicMock(status_code=429, text="slow down")
        client = virustotal.VirusTotalClient(api_key="fake")
        client.MIN_INTERVAL_SECONDS = 0
        with pytest.raises(virustotal.VirusTotalError, match="Rate limit"):
            client.lookup_file_hash("c" * 64)


class TestURLLookup:
    @patch("virustotal.requests.get")
    def test_url_is_base64_encoded_in_path(self, mock_get):
        mock_get.return_value = MagicMock(status_code=404)
        client = virustotal.VirusTotalClient(api_key="fake")
        client.MIN_INTERVAL_SECONDS = 0
        client.lookup_url("https://example.com/test")
        # Inspect the URL we actually called
        called_url = mock_get.call_args[0][0]
        assert called_url.startswith("https://www.virustotal.com/api/v3/urls/")
        # No padding in URL IDs
        assert not called_url.endswith("=")