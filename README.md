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
Investigation reports from labs I've worked through (Blue Team Labs Online, TryHackMe, CyberDefenders). Each writeup follows the same structure: scenario, artifacts examined, methodology, findings, IOCs, recommended response.

*Coming soon — first writeup in progress.*

### `notes/`
Topical notes I take while studying: MITRE ATT&CK techniques mapped to detections, useful Splunk SPL queries, log-source references.

*Coming soon.*

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