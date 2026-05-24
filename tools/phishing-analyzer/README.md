# Phishing Email Analyzer

A defensive security tool that inspects `.eml` files for phishing indicators and produces an analyst-friendly report. Built as part of my SOC analyst learning path to combine my backend background with hands-on security tooling.

## What it checks

- **Header anomalies** — mismatches between `From`, `Reply-To`, and `Return-Path` (a classic phishing tell).
- **Authentication (DNS)** — queries the sender domain for SPF and DMARC records.
- **Authentication (headers)** — parses the `Authentication-Results` header to see what the receiving mail server actually verified.
- **URL risk** — flags raw-IP URLs, abused free TLDs (`.tk`, `.ml`, `.ga`, `.gq`, `.cf`), `.zip`/`.mov` look-alikes, excessive subdomains, and `@` tricks in the authority section.
- **Attachment risk** — computes SHA-256 (ready to pivot into VirusTotal) and flags dangerous extensions like `.exe`, `.scr`, `.hta`, macro-enabled Office documents, etc.
- **Social engineering keywords** — scans the body for urgency / fear / scarcity language commonly used in phishing.

Findings are aggregated into a weighted risk score with a final verdict of `BENIGN`, `SUSPICIOUS`, or `LIKELY PHISHING`.

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Analyze an email
python analyzer.py sample-emails/phishing-paypal.eml

# Get the report as JSON (useful for piping into other tools)
python analyzer.py sample-emails/phishing-paypal.eml --json
```

## Example output

Running the analyzer against the included `phishing-paypal.eml` sample: