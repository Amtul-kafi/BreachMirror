"""
dns_check.py
Checks public DNS records for email security configuration.
SPF, DMARC, DKIM — all public records, zero system access.
"""

import dns.resolver


def check_email_security(domain: str) -> dict:
    results = {
        "spf": {"present": False, "record": None, "risk": None},
        "dmarc": {"present": False, "record": None, "policy": None, "risk": None},
        "dkim": {"present": False, "risk": None},
        "mx": {"present": False, "records": [], "risk": None},
    }

    # ── SPF Check ──────────────────────────────────────────────
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith("v=spf1"):
                results["spf"]["present"] = True
                results["spf"]["record"] = txt[:120]
                if "+all" in txt:
                    results["spf"]["risk"] = "critical"
                elif "~all" in txt:
                    results["spf"]["risk"] = "medium"
                elif "-all" in txt:
                    results["spf"]["risk"] = "low"
                else:
                    results["spf"]["risk"] = "medium"
                break
        if not results["spf"]["present"]:
            results["spf"]["risk"] = "high"
    except Exception:
        results["spf"]["risk"] = "high"

    # ── DMARC Check ────────────────────────────────────────────
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for rdata in answers:
            txt = str(rdata).strip('"')
            if "v=DMARC1" in txt:
                results["dmarc"]["present"] = True
                results["dmarc"]["record"] = txt[:120]
                if "p=none" in txt:
                    results["dmarc"]["policy"] = "none"
                    results["dmarc"]["risk"] = "high"
                elif "p=quarantine" in txt:
                    results["dmarc"]["policy"] = "quarantine"
                    results["dmarc"]["risk"] = "medium"
                elif "p=reject" in txt:
                    results["dmarc"]["policy"] = "reject"
                    results["dmarc"]["risk"] = "low"
                break
        if not results["dmarc"]["present"]:
            results["dmarc"]["risk"] = "critical"
    except Exception:
        results["dmarc"]["risk"] = "critical"

    # ── DKIM Check (common selectors) ─────────────────────────
    dkim_selectors = ["default", "google", "k1", "mail", "dkim", "selector1", "selector2"]
    for selector in dkim_selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            dns.resolver.resolve(dkim_domain, "TXT")
            results["dkim"]["present"] = True
            results["dkim"]["risk"] = "low"
            break
        except Exception:
            continue
    if not results["dkim"]["present"]:
        results["dkim"]["risk"] = "medium"

    # ── MX Records ────────────────────────────────────────────
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_list = []
        for rdata in answers:
            mx_list.append(str(rdata.exchange).rstrip("."))
        results["mx"]["present"] = True
        results["mx"]["records"] = mx_list[:5]
        results["mx"]["risk"] = "low"
    except Exception:
        results["mx"]["risk"] = "medium"

    return results
