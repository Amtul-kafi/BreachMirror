"""
subdomain_scan.py
Enumerates subdomains via crt.sh (Certificate Transparency logs).
100% public data, no API key required, completely legal.
"""

import requests
import re


# Subdomains that suggest sensitive exposure if public
SENSITIVE_KEYWORDS = [
    "admin", "api", "vpn", "remote", "portal", "login",
    "dev", "staging", "test", "backup", "internal",
    "mail", "smtp", "ftp", "ssh", "jenkins", "jira",
    "confluence", "gitlab", "grafana", "kibana", "elastic"
]


def get_subdomains(domain: str) -> dict:
    results = {
        "total_found": 0,
        "subdomains": [],
        "sensitive": [],
        "risk": "low"
    }

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=15, headers={"User-Agent": "BreachMirror-Security-Scanner/1.0"})

        if response.status_code != 200:
            return results

        certs = response.json()

        # Extract unique subdomains
        seen = set()
        for cert in certs:
            name = cert.get("name_value", "")
            # Handle multi-line entries
            for sub in name.split("\n"):
                sub = sub.strip().lower().lstrip("*.")
                if sub and sub.endswith(domain) and sub not in seen:
                    seen.add(sub)

        subdomains = sorted(list(seen))[:50]  # Cap at 50 for MVP
        results["total_found"] = len(seen)
        results["subdomains"] = subdomains[:20]  # Show top 20 in UI

        # Flag sensitive ones
        sensitive = []
        for sub in subdomains:
            prefix = sub.replace(f".{domain}", "").replace(domain, "")
            for keyword in SENSITIVE_KEYWORDS:
                if keyword in prefix:
                    sensitive.append({
                        "subdomain": sub,
                        "reason": f"'{keyword}' suggests {_explain_keyword(keyword)}"
                    })
                    break

        results["sensitive"] = sensitive[:10]

        # Risk rating
        if len(sensitive) >= 5 or results["total_found"] > 30:
            results["risk"] = "high"
        elif len(sensitive) >= 2 or results["total_found"] > 15:
            results["risk"] = "medium"
        else:
            results["risk"] = "low"

    except Exception as e:
        results["error"] = str(e)

    return results


def _explain_keyword(keyword: str) -> str:
    explanations = {
        "admin": "an administrative interface exposed to the internet",
        "api": "an API endpoint that may expose backend data",
        "vpn": "a remote access gateway — a common attack target",
        "remote": "remote access infrastructure",
        "portal": "an employee or customer portal",
        "login": "an authentication page",
        "dev": "a development environment (often less secure)",
        "staging": "a staging environment (often mirrors production)",
        "test": "a test environment (often unmonitored)",
        "backup": "backup infrastructure",
        "internal": "internal tooling exposed publicly",
        "mail": "mail server infrastructure",
        "smtp": "an email sending server",
        "ftp": "a file transfer server",
        "ssh": "an SSH endpoint",
        "jenkins": "a CI/CD build server (frequent attack target)",
        "jira": "a project management system",
        "confluence": "an internal wiki/documentation system",
        "gitlab": "a source code repository",
        "grafana": "a monitoring dashboard",
        "kibana": "a log analytics interface",
        "elastic": "an Elasticsearch instance (often misconfigured)"
    }
    return explanations.get(keyword, "a potentially sensitive service")
