# BreachMirror

See your business the way an attacker sees it — using only publicly available data.

---

## Overview

BreachMirror is a lightweight security intelligence tool that analyzes a company’s external exposure using public data sources. It helps translate technical security signals into clear, executive-friendly insights.

Instead of raw security dashboards, BreachMirror produces a simple exposure score and a plain-language summary of key risks.

---

## What It Provides

When a user enters a domain, BreachMirror generates:

* Exposure Score (0–100): Overall external visibility and risk level
* Email Security Review: SPF, DMARC, and DKIM configuration status
* Public Attack Surface: Exposed subdomains and services
* Breach History Check: Whether employee data appears in known breaches
* Executive Summary: A short, plain-English risk explanation

---

## Problem It Solves

Most security tools are designed for technical teams. Executives often receive either too much technical detail or too little actionable insight.

BreachMirror bridges this gap by translating external security posture into clear business language that decision-makers can act on quickly.

---

## Example Output

Domain: example-company.com
Exposure Score: 72/100 (High)

Executive Summary:

The domain is currently exposed to multiple external risks. Email authentication is not fully enforced, which may allow impersonation attempts such as phishing or CEO fraud. Public records also reveal development-related subdomains that could help attackers map internal systems. Additionally, credentials linked to this domain have appeared in past breaches, increasing the risk of account compromise. Immediate attention is recommended for email security configuration and credential monitoring.

---

## Data Sources

BreachMirror uses only public and legally accessible data sources:

* DNS records (SPF, DKIM, DMARC via dnspython)
* Certificate Transparency logs (crt.sh)
* Have I Been Pwned API (breach history)
* AI summarization layer for executive reporting

---

## Tech Stack

* Python 3.11+
* Flask
* dnspython
* Public OSINT data sources
* Optional AI summarization API

---

## Project Structure

breachmirror/
├── app.py
├── scanner/
│   ├── dns_check.py
│   ├── subdomain_scan.py
│   ├── breach_check.py
│   └── score_engine.py
├── ai/
│   └── summarizer.py
├── templates/
├── static/
└── requirements.txt

---

## Quick Start

```bash
git clone https://github.com/Amtul-kafi/breachmirror.git
cd breachmirror
cp .env.example .env
pip install -r requirements.txt
python app.py
```

Then open:
[http://localhost:5000](http://localhost:5000)

---

## Deployment

BreachMirror can be deployed on platforms like Render or similar services.

Basic steps:

1. Push repository to GitHub
2. Create a new web service
3. Add required environment variables
4. Set start command: gunicorn app:app

---

## Comparison
