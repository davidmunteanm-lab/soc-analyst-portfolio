# SOC Analyst Portfolio

[![CI](https://github.com/davidmunteanm-lab/soc-analyst-portfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/davidmunteanm-lab/soc-analyst-portfolio/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Personal portfolio documenting my transition from backend development into Security Operations and defensive cybersecurity. This repo holds the tools I build, the investigations I write up, and the notes I take along the way.

I'm currently a TryHackMe SAL1-certified analyst with a backend development background (Salesforce / Apex / Java), preparing for the Microsoft SC-900 certification.

## What's in here

### `tools/`
Security tooling I've written from scratch. Each tool ships with its own README, sample input, and usage instructions.

- **[phishing-analyzer](tools/phishing-analyzer/)** — Static analyzer for `.eml` files. Inspects headers, SPF/DMARC, URLs, attachments (SHA-256), and social engineering keywords; outputs a weighted risk score and verdict.

### `writeups/`
Investigation reports from labs and simulated scenarios. Each writeup follows the same structure: scenario, artefacts examined, methodology, findings, IOCs, recommended response.

- **[01 — PayPal Impersonation Phishing](writeups/01-phishing-paypal-impersonation/writeup.md)** — Full investigation of a self-authored simulated phishing email; demonstrates header analysis, authentication checks, URL triage, and Tier-1 SOC response workflow.

### `notes/`
Topical notes I take while studying. Currently published:

- **[Splunk SPL cheatsheet](notes/splunk-spl-cheatsheet.md)** — SPL queries I keep reaching for during investigations.
- **[MITRE ATT&CK quick reference](notes/mitre-techniques-quick-reference.md)** — Common techniques mapped to log artefacts.

## Background

- **Backend Developer** at OSF Digital — 1.5 years building Salesforce backend logic (Apex triggers, batch jobs, Lightning Web Components).
- **TryHackMe SAL1** — Security Analyst Level 1, completed April 2026. Covered SOC fundamentals, Splunk, incident response, and the analyst workflow.
- **Microsoft SC-900** — In progress (Security, Compliance, and Identity Fundamentals).

The dev background turns out to be useful: when investigating an incident, knowing how the application layer actually works (HTTP, authentication flows, what an API call looks like) speeds up making sense of logs.

## Contact

- LinkedIn: [david-marian-muntean](https://www.linkedin.com/in/david-marian-muntean-a41313286/)
- Email: david.muntean.m@gmail.com

---

*This is a personal learning portfolio. Sample emails and indicators in this repo are fabricated or use IANA-reserved address ranges (RFC 5737) — nothing points at real infrastructure.*