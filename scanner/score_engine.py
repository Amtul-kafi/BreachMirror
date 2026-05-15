"""
score_engine.py
Calculates an overall exposure score (0-100) from all scan results.
Higher = more exposed to attackers.
"""


RISK_WEIGHTS = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 0,
    "unknown": 5,
}


def calculate_score(results: dict) -> dict:
    score = 0
    findings = []

    email = results.get("email_security", {})
    subdomains = results.get("subdomains", {})
    breaches = results.get("breaches", {})

    # ── Email Security Scoring ─────────────────────────────────

    spf_risk = email.get("spf", {}).get("risk", "high")
    score += RISK_WEIGHTS.get(spf_risk, 0)
    if spf_risk in ("high", "critical"):
        findings.append({
            "severity": spf_risk,
            "title": "No SPF record found",
            "plain_english": "Anyone can send emails pretending to be your company. This is the #1 tool for CEO fraud and phishing attacks.",
            "fix": "Add an SPF record to your DNS settings."
        })
    elif spf_risk == "medium":
        findings.append({
            "severity": "medium",
            "title": "Weak SPF configuration",
            "plain_english": "Your email anti-spoofing is configured but not fully enforced.",
            "fix": "Change your SPF record to end with '-all' instead of '~all'."
        })

    dmarc_risk = email.get("dmarc", {}).get("risk", "critical")
    score += RISK_WEIGHTS.get(dmarc_risk, 0)
    dmarc_policy = email.get("dmarc", {}).get("policy")
    if dmarc_risk == "critical":
        findings.append({
            "severity": "critical",
            "title": "No DMARC policy",
            "plain_english": "Your domain has no protection against email impersonation. Attackers can send emails from your exact domain to your customers, partners, and employees.",
            "fix": "Add a DMARC record. Start with p=none to monitor, then move to p=reject."
        })
    elif dmarc_policy == "none":
        findings.append({
            "severity": "high",
            "title": "DMARC set to monitor-only",
            "plain_english": "You're watching email fraud happen but not stopping it.",
            "fix": "Change your DMARC policy from p=none to p=quarantine or p=reject."
        })

    dkim_risk = email.get("dkim", {}).get("risk", "medium")
    score += RISK_WEIGHTS.get(dkim_risk, 0)
    if dkim_risk == "medium":
        findings.append({
            "severity": "medium",
            "title": "DKIM not detected",
            "plain_english": "Email signatures that prove your emails are genuine could not be verified. This weakens trust in your outbound communications.",
            "fix": "Enable DKIM signing through your email provider."
        })

    # ── Subdomain Scoring ─────────────────────────────────────

    sub_risk = subdomains.get("risk", "low")
    score += RISK_WEIGHTS.get(sub_risk, 0)
    sensitive = subdomains.get("sensitive", [])
    total_subs = subdomains.get("total_found", 0)

    if sensitive:
        findings.append({
            "severity": sub_risk,
            "title": f"{len(sensitive)} sensitive subdomains publicly visible",
            "plain_english": f"Attacker-facing services like {', '.join([s['subdomain'] for s in sensitive[:3]])} are visible to anyone scanning your domain.",
            "fix": "Audit whether each sensitive subdomain needs to be publicly accessible. Move internal tools behind a VPN."
        })
    elif total_subs > 10:
        findings.append({
            "severity": "low",
            "title": f"{total_subs} subdomains publicly listed",
            "plain_english": "Your domain has a large public footprint. More surface area means more potential entry points.",
            "fix": "Review your subdomain list and remove or restrict anything not meant to be public."
        })

    # ── Breach Scoring ────────────────────────────────────────

    breach_count = breaches.get("breach_count")
    breach_risk = breaches.get("risk", "low")

    if breach_count and breach_count > 0:
        score += RISK_WEIGHTS.get(breach_risk, 0)
        findings.append({
            "severity": breach_risk,
            "title": f"Credentials found in {breach_count} data breach{'es' if breach_count > 1 else ''}",
            "plain_english": f"Employee email addresses from your domain have appeared in {breach_count} public data breach{'es' if breach_count > 1 else ''}. Attackers use these lists to attempt logins to your systems.",
            "fix": "Force a password reset for all affected accounts. Enable MFA company-wide."
        })

    # ── Final Score ───────────────────────────────────────────

    score = min(score, 100)

    if score >= 70:
        rating = "Critical"
        color = "critical"
        summary = "Severe exposure. Multiple high-priority attack vectors are publicly visible."
    elif score >= 45:
        rating = "High"
        color = "high"
        summary = "Significant exposure. An attacker has useful information about your systems."
    elif score >= 20:
        rating = "Medium"
        color = "medium"
        summary = "Moderate exposure. Some risks present but no critical vulnerabilities detected."
    else:
        rating = "Low"
        color = "low"
        summary = "Low exposure. Your public-facing security posture looks reasonable."

    # Sort findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return {
        "value": score,
        "rating": rating,
        "color": color,
        "summary": summary,
        "findings": findings
    }
