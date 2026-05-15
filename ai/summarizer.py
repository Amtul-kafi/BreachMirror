"""
summarizer.py
Generates a plain-English CEO summary from scan results using Claude.
"""

import os
from anthropic import Anthropic

client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are a cybersecurity risk communicator writing exclusively for CEOs and business executives — not technical staff.

Your job is to write ONE paragraph (4-6 sentences maximum) that:
1. States what an attacker can currently see or exploit about this company from public data
2. Explains the real business consequence in plain English (reputation, revenue, operations, fraud risk)
3. Names the single most important thing to fix first
4. Uses zero technical jargon — no CVEs, no protocol names, no acronyms

Rules:
- Never invent numbers or statistics not present in the scan data
- Never say "it appears" or "it seems" — be direct
- Write as if briefing a Fortune 500 CEO who has 45 seconds
- End with one concrete action they can delegate today
- Do not mention the tool name or refer to yourself"""


def generate_ceo_summary(domain: str, results: dict) -> str:
    score = results.get("score", {})
    email = results.get("email_security", {})
    subdomains = results.get("subdomains", {})
    breaches = results.get("breaches", {})

    # Build structured context for the prompt
    findings_text = ""
    for f in score.get("findings", []):
        findings_text += f"- [{f['severity'].upper()}] {f['title']}: {f['plain_english']}\n"

    breach_text = ""
    if breaches.get("breach_count") and breaches["breach_count"] > 0:
        names = [b["name"] for b in breaches.get("breaches", [])[:3]]
        breach_text = f"Credentials found in {breaches['breach_count']} breaches including: {', '.join(names)}."

    subdomain_text = ""
    sensitive = subdomains.get("sensitive", [])
    if sensitive:
        subdomain_text = f"Sensitive public subdomains: {', '.join([s['subdomain'] for s in sensitive[:4]])}."

    user_message = f"""Domain scanned: {domain}
Overall exposure score: {score.get('value', 0)}/100 ({score.get('rating', 'Unknown')})

Key findings:
{findings_text if findings_text else 'No critical findings.'}

{breach_text}
{subdomain_text}

Write the CEO summary paragraph now."""

    try:
        response = client.messages.create(
            model="claude-opus-4-5",
            max_tokens=300,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}]
        )
        return response.content[0].text.strip()
    except Exception as e:
        return f"Scan complete. Exposure score: {score.get('value', 0)}/100. Review the findings below for detailed recommendations."
