"""
VirusTotal API client (v3).

Wraps the two endpoints we need for email analysis:
  - GET /files/{sha256}        — check if an attachment hash is known-bad
  - GET /urls/{url_id}         — check if a URL has been flagged by AV vendors

The free tier is rate-limited (4 req/min). Callers should reuse a single
VirusTotalClient instance so the internal rate limiter actually helps.
"""

import base64
import os
import time
from typing import Optional

import requests


class VirusTotalError(Exception):
    """Raised when the VirusTotal API returns an unexpected response."""


class VirusTotalClient:
    """Minimal VT v3 client tuned for the free tier."""

    BASE_URL = "https://www.virustotal.com/api/v3"
    MIN_INTERVAL_SECONDS = 16  # ~4 req/min, leaves a safety margin

    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "").strip()
        self.timeout = timeout
        self._last_request_at = 0.0

    @property
    def enabled(self) -> bool:
        """True when an API key was provided (env var or constructor)."""
        return bool(self.api_key)

    def _throttle(self) -> None:
        """Sleep so we never exceed the free-tier rate limit."""
        elapsed = time.monotonic() - self._last_request_at
        wait = self.MIN_INTERVAL_SECONDS - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_request_at = time.monotonic()

    def _get(self, path: str) -> dict:
        """Issue a GET request with throttling and error handling."""
        if not self.enabled:
            raise VirusTotalError("No API key configured (set VT_API_KEY).")

        self._throttle()
        url = f"{self.BASE_URL}{path}"
        headers = {"x-apikey": self.api_key, "Accept": "application/json"}

        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.RequestException as exc:
            raise VirusTotalError(f"Network error: {exc}") from exc

        if response.status_code == 404:
            return {"not_found": True}
        if response.status_code == 429:
            raise VirusTotalError("Rate limit exceeded (HTTP 429).")
        if response.status_code != 200:
            raise VirusTotalError(
                f"Unexpected status {response.status_code}: {response.text[:200]}"
            )

        try:
            return response.json()
        except ValueError as exc:
            raise VirusTotalError("Response was not valid JSON") from exc

    # ---- public API ----

    def lookup_file_hash(self, sha256: str) -> dict:
        """Return a summary of detections for a file hash, or unknown=True."""
        if not sha256:
            return {"unknown": True, "reason": "empty hash"}

        data = self._get(f"/files/{sha256}")
        if data.get("not_found"):
            return {"unknown": True, "reason": "hash not seen by VirusTotal"}

        return self._summarize(data, kind="file")

    def lookup_url(self, url: str) -> dict:
        """Return a summary of detections for a URL, or unknown=True."""
        if not url:
            return {"unknown": True, "reason": "empty URL"}

        # VT URL IDs are unpadded URL-safe base64 of the raw URL
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode().rstrip("=")
        data = self._get(f"/urls/{url_id}")
        if data.get("not_found"):
            return {"unknown": True, "reason": "URL not seen by VirusTotal"}

        return self._summarize(data, kind="url")

    @staticmethod
    def _summarize(data: dict, kind: str) -> dict:
        """Pull just the bits we want to render in our report."""
        attributes = data.get("data", {}).get("attributes", {}) or {}
        stats = attributes.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

        return {
            "unknown": False,
            "kind": kind,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": malicious + suspicious + harmless + undetected,
            "reputation": attributes.get("reputation"),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }