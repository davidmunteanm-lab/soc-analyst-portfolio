# Writeup #01 — PayPal Impersonation Phishing Email

**Date:** May 2026
**Category:** Email forensics / phishing analysis
**Difficulty:** Entry-level
**Tools used:** `phishing-analyzer` (custom), manual header review, DNS lookups, VirusTotal

## Scenario

A simulated phishing email landed in a user's inbox, claiming to be from "PayPal Security" and warning that the account has been suspended due to "unusual activity." The user must "verify their identity immediately" or the account will be closed within 24 hours.

This is a textbook impersonation attack using urgency and fear to bypass careful judgement. The goal of this investigation is to confirm the verdict, list the indicators of compromise, and document what a Tier-1 SOC analyst would do with this email in a real environment.

> **Note:** the email used here is a self-authored sample built into the [phishing-analyzer](../../tools/phishing-analyzer/sample-emails/phishing-paypal.eml) repo. It uses [IANA-reserved IPs (RFC 5737)](https://www.rfc-editor.org/rfc/rfc5737) and made-up `.tk`/`.gq` domains so nothing references real infrastructure.

## Artefact

A single `.eml` file containing the message, its headers, and the body. No attachments were included in this sample, but the analyzer is designed to flag them when present.

## Methodology

I worked through the message in the order a SOC analyst usually does:

1. **Header review** — start with the metadata. The headers are the hardest thing for an attacker to fake convincingly.
2. **Sender authentication** — check SPF, DKIM, DMARC alignment.
3. **URL analysis** — every clickable link is a potential phishing destination.
4. **Body inspection** — look for the social-engineering language pattern.
5. **Reputation lookups** — anything that survives the first four steps gets checked against VirusTotal.
6. **Verdict** — aggregate everything into a recommendation.

I ran the email through `phishing-analyzer` to automate steps 1–5, then reviewed the output manually. Full tool output is in [analyzer-output.txt](analyzer-output.txt).

## Findings

### 1. Sender mismatch — strong indicator

| Header | Value |
| --- | --- |
| `From:` | `PayPal Security <security@paypa1-verify.tk>` |
| `Reply-To:` | `noreply@randommailbox123.gq` |
| `Return-Path:` | `bounce@spam-relay-server.tk` |

Three different domains across three headers that should normally align. A legitimate PayPal notification would come from a domain in PayPal's owned namespace (e.g. `service.paypal.com`), and `Return-Path` would resolve to PayPal's own mail infrastructure.

Even at a glance: the visible domain is `paypa1-verify.tk` — note the **`1` substituted for `l`** (typosquatting), and the `.tk` TLD (Tokelau, one of the most-abused free TLDs in phishing campaigns).

### 2. Sender authentication failed across the board

```
[+] Authentication (DNS)
    SPF present   : False
    DMARC present : False

[+] Authentication (received headers)
    SPF   : FAIL/missing
    DKIM  : FAIL/missing
    DMARC : FAIL/missing
```

The sender domain has neither SPF nor DMARC records in DNS, and the receiving MTA explicitly recorded SPF/DKIM/DMARC failures in the `Authentication-Results` header. Any one of those failing would be suspicious; all three failing on a message claiming to be PayPal is conclusive.

### 3. URLs — two clear red flags

**URL #1:** `http://198.51.100.42/paypal-verify/login.php`

- Plain HTTP (no TLS).
- Hostname is a raw IPv4 address — a real brand would never link customers to a numeric IP.
- IP is in the IANA-reserved TEST-NET-2 range, which would never appear in legitimate traffic.

**URL #2:** `https://paypa1.secure-login.verify.account.update.tk/index.html`

- Same `1`-for-`l` substitution as the sender domain (consistent attacker tradecraft).
- Five subdomain levels stacked to push the misleading word `paypa1` to the start of the URL — the kind of layout users skim past.
- `.tk` TLD again.

### 4. Body — social engineering pattern

The body of the message hits six known phishing keyword patterns: `urgent`, `click here immediately`, `suspended`, `confirm your identity`, `unusual activity`, `act now`. This is the classic urgency + fear + scarcity stack used to push the recipient past their judgement.

A real customer-service email from a major brand might use one of those phrases. Six in a six-sentence message is not normal.

### 5. Reputation lookups (VirusTotal)

In the run captured for this writeup, neither URL had VT detections — they're fabricated for the sample, so VT has never indexed them. In a real investigation, the tool would surface engine counts and reputation scores here; with this sample the other indicators are already conclusive.

## Verdict

`phishing-analyzer` returned a risk score of **27** and a verdict of **LIKELY PHISHING**. The score breakdown:

- 6 points — two From/Reply-To/Return-Path mismatches
- 4 points — missing SPF and DMARC on the sender domain
- 7 points — SPF, DKIM, and DMARC all failed in the receiving headers
- 4 points — two URLs with multiple risk flags
- 6 points — six social-engineering keywords in the body

Even with the VirusTotal step inconclusive, the email fails authentication, fails domain-reputation reasoning, and uses textbook social-engineering language. Confidence: high.

## Indicators of Compromise (IOCs)

| Type | Value |
| --- | --- |
| Sender domain | `paypa1-verify.tk` |
| Reply-To domain | `randommailbox123.gq` |
| Return-Path domain | `spam-relay-server.tk` |
| URL | `http://198.51.100.42/paypal-verify/login.php` |
| URL | `https://paypa1.secure-login.verify.account.update.tk/index.html` |
| IP literal | `198.51.100.42` (TEST-NET-2 — would never be legitimate) |
| Subject line | `URGENT: Your account has been suspended - Verify immediately` |

## Recommended response

If this email had been reported by a real user, the Tier-1 SOC actions would be:

1. **Containment** — pull the message from any other inboxes it reached (e.g. via Microsoft Defender for Office's Threat Explorer "Soft Delete" / "Hard Delete"), and block the sender domain at the mail gateway.
2. **Detection — block the indicators** — add the two URLs to the proxy/DNS sinkhole and the sender + Reply-To + Return-Path domains to the email gateway blocklist.
3. **Investigate impact** — search SIEM logs to see if any recipient clicked the link (proxy logs / DNS logs for the malicious hostnames in the last 7 days), and check whether anyone submitted credentials.
4. **Notify the user** — confirm reception of the report, advise them not to interact with the email, and credit-back the good behaviour (you want users to keep reporting).
5. **Hunt for repeats** — pivot on the attacker's pattern (free `.tk`/`.gq` TLDs, the `paypa1`-style typosquat, raw-IP URLs in HTML mails) to surface other emails from the same campaign.
6. **Document** — record the IOCs in the ticketing system, with the analyzer output attached.

## What I learned

- Header authentication (SPF/DKIM/DMARC) is the single most useful set of signals in email analysis. Even before anyone reads the body, three "fail" lines in `Authentication-Results` are almost always enough to verdict an email.
- Typosquats like `paypa1` vs `paypal` are still effective because users skim. Knowing to look for them is a skill worth practising — `phishing-analyzer` doesn't catch typosquats yet and that's a clear next feature to add.
- A short, structured tool runs much faster than manual header reading. The analyzer turned a five-minute manual review into a one-second decision while still leaving the reasoning visible.

## References

- [MITRE ATT&CK — T1566.002 Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/)
- [RFC 5737 — IPv4 address blocks reserved for documentation](https://www.rfc-editor.org/rfc/rfc5737)
- [Spamhaus — Top-abused TLDs](https://www.spamhaus.org/statistics/tlds/)