"""
Phishing Email Analyzer
-----------------------
Defensive security tool that analyzes .eml files for indicators of phishing.

Author: David-Marian Muntean
Repository: github.com/davidmunteanm-lab/soc-analyst-portfolio
"""

import argparse
import email
import email.policy
import hashlib
import json
import re
import sys
from email.utils import parseaddr
from pathlib import Path

import dns.resolver
import dns.exception


# ----- Configuration -----

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify your account", "click here immediately",
    "suspended", "confirm your identity", "unusual activity",
    "act now", "limited time", "wire transfer", "gift card",
    "password expired", "update payment", "account locked",
    "tax refund", "you have won", "claim your prize",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".zip", ".mov",
]

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif",
    ".js", ".vbs", ".ps1", ".jar", ".hta",
    ".docm", ".xlsm", ".pptm",
    ".iso", ".img",
}

URL_PATTERN = re.compile(r'https?://[^\s<>"\'\)]+', re.IGNORECASE)


# ----- Email Parsing -----

def parse_email(file_path: Path) -> email.message.EmailMessage:
    """Read an .eml file and return a parsed EmailMessage object."""
    if not file_path.exists():
        raise FileNotFoundError(f"Email file not found: {file_path}")
    if not file_path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")

    try:
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
    except Exception as exc:
        raise ValueError(f"Failed to parse email: {exc}") from exc

    return msg


# ----- Header Analysis -----

def analyze_headers(msg: email.message.EmailMessage) -> dict:
    """Extract sender info and detect From/Reply-To/Return-Path mismatches."""
    from_name, from_addr = parseaddr(msg.get("From", ""))
    _, reply_addr = parseaddr(msg.get("Reply-To", ""))
    _, return_addr = parseaddr(msg.get("Return-Path", ""))

    received_chain = msg.get_all("Received") or []
    from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

    mismatches = []
    if reply_addr and reply_addr.lower() != from_addr.lower():
        mismatches.append(f"Reply-To ({reply_addr}) differs from From ({from_addr})")
    if return_addr and return_addr.lower() != from_addr.lower():
        mismatches.append(f"Return-Path ({return_addr}) differs from From ({from_addr})")

    return {
        "from_name": from_name,
        "from_address": from_addr,
        "from_domain": from_domain,
        "reply_to": reply_addr,
        "return_path": return_addr,
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "received_hops": len(received_chain),
        "mismatches": mismatches,
    }


# ----- Authentication Checks -----

def check_auth(domain: str) -> dict:
    """Query DNS for SPF and DMARC records of the sender's domain."""
    result = {
        "domain": domain,
        "spf_record": None,
        "dmarc_record": None,
        "spf_present": False,
        "dmarc_present": False,
        "errors": [],
    }

    if not domain:
        result["errors"].append("No domain to check")
        return result

    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=spf1"):
                result["spf_record"] = txt
                result["spf_present"] = True
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.exception.DNSException as exc:
        result["errors"].append(f"SPF lookup failed: {exc}")

    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=DMARC1"):
                result["dmarc_record"] = txt
                result["dmarc_present"] = True
                break
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.exception.DNSException as exc:
        result["errors"].append(f"DMARC lookup failed: {exc}")

    return result


def parse_auth_results(msg: email.message.EmailMessage) -> dict:
    """Read what the receiving MTA actually verified."""
    auth_header = msg.get("Authentication-Results", "")
    lower = auth_header.lower()
    return {
        "raw": auth_header,
        "spf_pass": "spf=pass" in lower,
        "dkim_pass": "dkim=pass" in lower,
        "dmarc_pass": "dmarc=pass" in lower,
    }


# ----- URL Extraction -----

def extract_urls(msg: email.message.EmailMessage) -> list:
    """Pull URLs out of body parts and flag risky ones."""
    urls = set()

    for part in msg.walk():
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        try:
            body = part.get_content()
        except Exception:
            continue
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        urls.update(URL_PATTERN.findall(body))

    findings = []
    for url in urls:
        flags = []
        lower = url.lower()

        for tld in SUSPICIOUS_TLDS:
            if tld in lower:
                flags.append(f"suspicious TLD ({tld})")
                break

        if re.search(r"https?://\d+\.\d+\.\d+\.\d+", lower):
            flags.append("URL uses raw IP")

        authority = url.split("://", 1)[-1].split("/", 1)[0]
        if "@" in authority:
            flags.append("'@' in authority section (potential redirect)")

        if authority.count(".") >= 4:
            flags.append("excessive subdomains")

        findings.append({"url": url, "flags": flags})

    return findings


# ----- Attachment Inspection -----

def extract_attachments(msg: email.message.EmailMessage) -> list:
    """List every attachment with size + SHA-256 hash."""
    attachments = []

    for part in msg.walk():
        disposition = str(part.get("Content-Disposition", ""))
        if "attachment" not in disposition.lower() and not part.get_filename():
            continue

        filename = part.get_filename() or "(unnamed)"
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""

        ext = Path(filename).suffix.lower()
        attachments.append({
            "filename": filename,
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest() if payload else "",
            "content_type": part.get_content_type(),
            "suspicious_extension": ext in DANGEROUS_EXTENSIONS,
        })

    return attachments


# ----- Keyword & Body Analysis -----

def check_keywords(msg: email.message.EmailMessage) -> list:
    """Scan plaintext body for known social engineering phrases."""
    hits = []
    body_text = ""

    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            try:
                body_text += part.get_content()
            except Exception:
                continue

    lower = body_text.lower()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in lower:
            hits.append(kw)

    return hits


# ----- Verdict -----

def calculate_verdict(report: dict) -> dict:
    """Aggregate findings into a risk score and verdict."""
    score = 0
    reasons = []

    # Header mismatches — strong signal
    if report["headers"]["mismatches"]:
        score += 3 * len(report["headers"]["mismatches"])
        reasons.extend(report["headers"]["mismatches"])

    # Missing authentication infrastructure
    auth_dns = report["auth_dns"]
    if not auth_dns["spf_present"]:
        score += 2
        reasons.append("Sender domain has no SPF record")
    if not auth_dns["dmarc_present"]:
        score += 2
        reasons.append("Sender domain has no DMARC record")

    # Authentication failed at receiving MTA
    auth_hdr = report["auth_header"]
    if auth_hdr["raw"]:
        if not auth_hdr["spf_pass"]:
            score += 2
            reasons.append("Authentication-Results: SPF did not pass")
        if not auth_hdr["dkim_pass"]:
            score += 2
            reasons.append("Authentication-Results: DKIM did not pass")
        if not auth_hdr["dmarc_pass"]:
            score += 3
            reasons.append("Authentication-Results: DMARC did not pass")

    # Risky URLs
    for u in report["urls"]:
        if u["flags"]:
            score += 2
            reasons.append(f"Risky URL: {u['url']} ({', '.join(u['flags'])})")

    # Risky attachments
    for a in report["attachments"]:
        if a["suspicious_extension"]:
            score += 4
            reasons.append(f"Dangerous attachment: {a['filename']}")

    # Social engineering keywords
    if report["keywords"]:
        score += len(report["keywords"])
        reasons.append(f"Suspicious keywords: {', '.join(report['keywords'])}")

    if score >= 8:
        verdict = "LIKELY PHISHING"
    elif score >= 4:
        verdict = "SUSPICIOUS"
    else:
        verdict = "BENIGN"

    return {"score": score, "verdict": verdict, "reasons": reasons}


# ----- Reporting -----

def build_report(file_path: Path) -> dict:
    """Run every analyzer on the email and return a structured report."""
    msg = parse_email(file_path)
    headers = analyze_headers(msg)

    report = {
        "file": str(file_path),
        "headers": headers,
        "auth_dns": check_auth(headers["from_domain"]),
        "auth_header": parse_auth_results(msg),
        "urls": extract_urls(msg),
        "attachments": extract_attachments(msg),
        "keywords": check_keywords(msg),
    }
    report["verdict"] = calculate_verdict(report)
    return report


def print_report(report: dict) -> None:
    """Render the report in a SOC-analyst-friendly format."""
    h = report["headers"]
    v = report["verdict"]

    line = "=" * 70
    print(line)
    print(f"PHISHING ANALYSIS REPORT — {report['file']}")
    print(line)

    print("\n[+] Sender")
    print(f"    Name        : {h['from_name'] or '(none)'}")
    print(f"    Address     : {h['from_address'] or '(none)'}")
    print(f"    Domain      : {h['from_domain'] or '(none)'}")
    print(f"    Reply-To    : {h['reply_to'] or '(same as From)'}")
    print(f"    Return-Path : {h['return_path'] or '(same as From)'}")

    print("\n[+] Message")
    print(f"    Subject     : {h['subject']}")
    print(f"    Date        : {h['date']}")
    print(f"    Hops        : {h['received_hops']}")

    print("\n[+] Authentication (DNS)")
    a = report["auth_dns"]
    print(f"    SPF present   : {a['spf_present']}")
    print(f"    DMARC present : {a['dmarc_present']}")

    print("\n[+] Authentication (received headers)")
    ah = report["auth_header"]
    if ah["raw"]:
        print(f"    SPF   : {'PASS' if ah['spf_pass'] else 'FAIL/missing'}")
        print(f"    DKIM  : {'PASS' if ah['dkim_pass'] else 'FAIL/missing'}")
        print(f"    DMARC : {'PASS' if ah['dmarc_pass'] else 'FAIL/missing'}")
    else:
        print("    (no Authentication-Results header)")

    print(f"\n[+] URLs found: {len(report['urls'])}")
    for u in report["urls"]:
        marker = "!" if u["flags"] else "-"
        print(f"    [{marker}] {u['url']}")
        for f in u["flags"]:
            print(f"        -> {f}")

    print(f"\n[+] Attachments: {len(report['attachments'])}")
    for at in report["attachments"]:
        marker = "!" if at["suspicious_extension"] else "-"
        print(f"    [{marker}] {at['filename']} ({at['size_bytes']} bytes)")
        print(f"        sha256: {at['sha256']}")

    print(f"\n[+] Suspicious keywords: {len(report['keywords'])}")
    for kw in report["keywords"]:
        print(f"    - {kw}")

    print(f"\n{line}")
    print(f"VERDICT: {v['verdict']}   (risk score: {v['score']})")
    print(line)
    for r in v["reasons"]:
        print(f"  - {r}")
    if not v["reasons"]:
        print("  (no risk indicators detected)")
    print(line)


# ----- Entry Point -----

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze an .eml file for phishing indicators."
    )
    parser.add_argument("email_file", help="Path to the .eml file")
    parser.add_argument(
        "--json", action="store_true",
        help="Output as JSON instead of human-readable report"
    )
    args = parser.parse_args()

    try:
        report = build_report(Path(args.email_file))
    except (FileNotFoundError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print_report(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())