"""
breach_check.py
Checks if a domain's email addresses appear in public data breaches.
Uses HaveIBeenPwned v3 API — public data, legally designed for this purpose.
"""

import requests
import os


# Known major breaches with plain-English descriptions
BREACH_DESCRIPTIONS = {
    "LinkedIn": "professional profile and contact data",
    "Adobe": "email addresses and encrypted passwords",
    "Dropbox": "email addresses and hashed passwords",
    "LastPass": "encrypted password vault data",
    "Twitter": "email addresses and phone numbers",
    "Facebook": "phone numbers, names, and email addresses",
    "RockYou2021": "a massive compiled password list used by attackers",
    "Collection1": "email addresses and passwords from multiple sources",
    "Canva": "names, email addresses, and hashed passwords",
    "Chegg": "names, email addresses, and shipping addresses",
    "Gravatar": "email addresses and public profile data",
    "HaveibeenpwnedCom": "test data",
}


def check_breaches(domain: str) -> dict:
    results = {
        "breach_count": 0,
        "breaches": [],
        "risk": "low",
        "summary": ""
    }

    api_key = os.environ.get("HIBP_API_KEY", "")

    try:
        headers = {"User-Agent": "BreachMirror-Security-Scanner/1.0"}
        if api_key:
            headers["hibp-api-key"] = api_key

        # Domain search endpoint
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            # Returns dict of email: [breach names]
            all_breaches = set()
            affected_emails = len(data)

            for email, breach_list in data.items():
                for b in breach_list:
                    all_breaches.add(b)

            breach_list_clean = []
            for breach_name in list(all_breaches)[:10]:
                description = BREACH_DESCRIPTIONS.get(breach_name, "account credentials and personal data")
                breach_list_clean.append({
                    "name": breach_name,
                    "description": description
                })

            results["breach_count"] = len(all_breaches)
            results["affected_emails"] = affected_emails
            results["breaches"] = breach_list_clean

        elif response.status_code == 404:
            # No breaches found — good news
            results["summary"] = "No known breaches found for this domain."
            return results

        elif response.status_code == 401:
            # No API key — use fallback
            results = _fallback_breach_check(domain)
            return results

        else:
            results = _fallback_breach_check(domain)
            return results

    except Exception:
        results = _fallback_breach_check(domain)
        return results

    # Risk scoring
    count = results["breach_count"]
    if count >= 5:
        results["risk"] = "critical"
    elif count >= 3:
        results["risk"] = "high"
    elif count >= 1:
        results["risk"] = "medium"
    else:
        results["risk"] = "low"

    return results


def _fallback_breach_check(domain: str) -> dict:
    """
    Fallback when no HIBP API key is available.
    Checks the public breach list without domain-specific results.
    Returns a note to user rather than fake data.
    """
    return {
        "breach_count": None,
        "breaches": [],
        "risk": "unknown",
        "summary": "Add a free HaveIBeenPwned API key in .env to enable breach detection.",
        "fallback": True
    }
