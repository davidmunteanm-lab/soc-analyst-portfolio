# Phishing Email Analyzer

A defensive security tool that inspects `.eml` files for phishing indicators and produces an analyst-friendly report. Built as part of my SOC analyst learning path to combine my backend background with hands-on security tooling.

## What it checks

- **Header anomalies** — mismatches between `From`, `Reply-To`, and `Return-Path` (a classic phishing tell).
- **Authentication (DNS)** — queries the sender domain for SPF and DMARC records.
- **Authentication (headers)** — parses the `Authentication-Results` header to see what the receiving mail server actually verified.
- **URL risk** — flags raw-IP URLs, abused free TLDs (`.tk`, `.ml`, `.ga`, `.gq`, `.cf`), `.zip`/`.mov` look-alikes, excessive subdomains, and `@` tricks in the authority section.
- **Attachment risk** — computes SHA-256 (ready to pivot into VirusTotal) and flags dangerous extensions like `.exe`, `.scr`, `.hta`, macro-enabled Office documents, etc.
- **Social engineering keywords** — scans the body for urgency / fear / scarcity language commonly used in phishing.
- **VirusTotal enrichment** *(optional)* — looks up every URL and every attachment hash against the VirusTotal v3 API and folds the detection counts into the verdict.

Findings are aggregated into a weighted risk score with a final verdict of `BENIGN`, `SUSPICIOUS`, or `LIKELY PHISHING`.

## Usage

```bash
# Install dependencies
pip install -r requirements.txt

# Analyze an email (no VirusTotal)
python analyzer.py sample-emails/phishing-paypal.eml --no-vt

# Enable VirusTotal lookups (requires API key)
export VT_API_KEY="your_key_here"          # Linux/macOS
$env:VT_API_KEY = "your_key_here"          # PowerShell
python analyzer.py sample-emails/phishing-paypal.eml

# JSON output (pipe into jq, splunk, anything)
python analyzer.py sample-emails/phishing-paypal.eml --json
```

The VirusTotal client throttles itself to stay within the free tier (4 requests/minute), so analyzing an email with multiple URLs may take ~15 seconds per lookup.

## Example output

Running the analyzer against the included `phishing-paypal.eml` sample: