"""
Unit tests for analyzer.py.

These tests don't hit the network. DNS queries and VirusTotal lookups
are kept out of scope here — they're integration concerns. We focus on
the logic that turns a parsed email into a verdict.
"""

import email
import email.policy
import sys
from pathlib import Path

import pytest

# Make the parent directory importable when running pytest from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import analyzer  # noqa: E402


# ---------- helpers ----------

def build_message(headers: dict, body: str = "Hello") -> email.message.EmailMessage:
    """Construct an EmailMessage in-memory so tests don't need files on disk."""
    msg = email.message.EmailMessage(policy=email.policy.default)
    for k, v in headers.items():
        msg[k] = v
    msg.set_content(body)
    return msg


# ---------- analyze_headers ----------

class TestAnalyzeHeaders:
    def test_clean_sender_has_no_mismatches(self):
        msg = build_message({
            "From": "alerts@example.com",
            "To": "user@example.com",
            "Subject": "Hi",
        })
        result = analyzer.analyze_headers(msg)
        assert result["from_address"] == "alerts@example.com"
        assert result["from_domain"] == "example.com"
        assert result["mismatches"] == []

    def test_reply_to_mismatch_is_flagged(self):
        msg = build_message({
            "From": "alerts@bank.com",
            "Reply-To": "attacker@evil.tk",
            "To": "user@example.com",
        })
        result = analyzer.analyze_headers(msg)
        assert len(result["mismatches"]) == 1
        assert "Reply-To" in result["mismatches"][0]

    def test_return_path_mismatch_is_flagged(self):
        msg = build_message({
            "From": "alerts@bank.com",
            "Return-Path": "bounce@strange-relay.tk",
        })
        result = analyzer.analyze_headers(msg)
        assert any("Return-Path" in m for m in result["mismatches"])

    def test_both_mismatches_reported(self):
        msg = build_message({
            "From": "alerts@bank.com",
            "Reply-To": "attacker@evil.tk",
            "Return-Path": "bounce@strange-relay.tk",
        })
        result = analyzer.analyze_headers(msg)
        assert len(result["mismatches"]) == 2


# ---------- extract_urls ----------

class TestExtractURLs:
    def test_plain_url_is_extracted(self):
        msg = build_message({"From": "a@b.com"}, body="See https://example.com/page")
        urls = analyzer.extract_urls(msg)
        assert len(urls) == 1
        assert urls[0]["url"] == "https://example.com/page"
        assert urls[0]["flags"] == []

    def test_raw_ip_url_is_flagged(self):
        msg = build_message({"From": "a@b.com"}, body="Login at http://203.0.113.5/login")
        urls = analyzer.extract_urls(msg)
        assert any("raw IP" in f for f in urls[0]["flags"])

    def test_suspicious_tld_is_flagged(self):
        msg = build_message({"From": "a@b.com"}, body="Click https://verify.tk/login")
        urls = analyzer.extract_urls(msg)
        assert any("suspicious TLD" in f for f in urls[0]["flags"])

    def test_excessive_subdomains_are_flagged(self):
        msg = build_message(
            {"From": "a@b.com"},
            body="Click https://a.b.c.d.e.example.com/x",
        )
        urls = analyzer.extract_urls(msg)
        assert any("excessive subdomains" in f for f in urls[0]["flags"])

    def test_no_urls_returns_empty_list(self):
        msg = build_message({"From": "a@b.com"}, body="No links here.")
        assert analyzer.extract_urls(msg) == []


# ---------- check_keywords ----------

class TestKeywords:
    def test_keyword_match_is_case_insensitive(self):
        msg = build_message(
            {"From": "a@b.com"},
            body="This is URGENT, please act now.",
        )
        hits = analyzer.check_keywords(msg)
        assert "urgent" in hits
        assert "act now" in hits

    def test_no_keywords_in_normal_body(self):
        msg = build_message(
            {"From": "a@b.com"},
            body="Here is your weekly report. Thanks.",
        )
        assert analyzer.check_keywords(msg) == []


# ---------- calculate_verdict ----------

class TestVerdict:
    def _empty_report(self):
        """Build a minimal report dict with zero indicators."""
        return {
            "headers": {"mismatches": []},
            "auth_dns": {"spf_present": True, "dmarc_present": True},
            "auth_header": {"raw": "", "spf_pass": False, "dkim_pass": False, "dmarc_pass": False},
            "urls": [],
            "attachments": [],
            "keywords": [],
            "virustotal": {"enabled": False, "results": []},
        }

    def test_clean_email_is_benign(self):
        verdict = analyzer.calculate_verdict(self._empty_report())
        assert verdict["verdict"] == "BENIGN"
        assert verdict["score"] == 0

    def test_single_mismatch_alone_is_suspicious(self):
        report = self._empty_report()
        report["headers"]["mismatches"] = ["Reply-To differs from From"]
        verdict = analyzer.calculate_verdict(report)
        # 3 points = SUSPICIOUS threshold not hit yet (needs 4); just under
        assert verdict["score"] == 3
        assert verdict["verdict"] == "BENIGN"

    def test_multiple_indicators_become_phishing(self):
        report = self._empty_report()
        report["headers"]["mismatches"] = [
            "Reply-To differs from From",
            "Return-Path differs from From",
        ]
        report["auth_dns"] = {"spf_present": False, "dmarc_present": False}
        report["keywords"] = ["urgent", "verify your account"]
        verdict = analyzer.calculate_verdict(report)
        # 6 (mismatches) + 2 + 2 + 2 (keywords) = 12 -> phishing
        assert verdict["score"] >= 8
        assert verdict["verdict"] == "LIKELY PHISHING"

    def test_dangerous_attachment_alone_is_suspicious(self):
        report = self._empty_report()
        report["attachments"] = [{
            "filename": "invoice.exe",
            "size_bytes": 1024,
            "sha256": "abc",
            "content_type": "application/octet-stream",
            "suspicious_extension": True,
        }]
        verdict = analyzer.calculate_verdict(report)
        assert verdict["score"] == 4
        assert verdict["verdict"] == "SUSPICIOUS"

    def test_virustotal_high_confidence_hit_pushes_to_phishing(self):
        report = self._empty_report()
        report["virustotal"] = {
            "enabled": True,
            "results": [{
                "target": "https://evil.example/x",
                "kind": "url",
                "malicious": 12,
                "suspicious": 1,
                "harmless": 0,
                "undetected": 50,
                "unknown": False,
            }],
        }
        verdict = analyzer.calculate_verdict(report)
        assert verdict["score"] >= 8
        assert verdict["verdict"] == "LIKELY PHISHING"


# ---------- parse_email ----------

class TestParseEmail:
    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            analyzer.parse_email(Path("does-not-exist.eml"))

    def test_real_sample_is_parseable(self, tmp_path):
        eml = tmp_path / "x.eml"
        eml.write_bytes(
            b"From: sender@example.com\r\n"
            b"To: dest@example.com\r\n"
            b"Subject: hi\r\n"
            b"\r\n"
            b"body\r\n"
        )
        msg = analyzer.parse_email(eml)
        assert msg["From"] == "sender@example.com"
        assert msg["Subject"] == "hi"