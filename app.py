"""
BreachMirror
------------
Shows any business exactly what an attacker sees when they look at them.
Uses only 100% public data — no systems are accessed or tested.

Author: Amatul Kafi Bhatti
License: Proprietary (see LICENSE)
"""

import os
import json
from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv

from scanner.dns_check import check_email_security
from scanner.subdomain_scan import get_subdomains
from scanner.breach_check import check_breaches
from scanner.score_engine import calculate_score
from ai.summarizer import generate_ceo_summary

load_dotenv()

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    domain = data.get("domain", "").strip().lower()

    # Basic cleanup
    domain = domain.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]

    if not domain or "." not in domain:
        return jsonify({"error": "Please enter a valid domain (e.g. company.com)"}), 400

    try:
        results = {}

        # Run all scanners
        results["email_security"] = check_email_security(domain)
        results["subdomains"] = get_subdomains(domain)
        results["breaches"] = check_breaches(domain)
        results["score"] = calculate_score(results)

        # Generate CEO summary via Claude
        results["ceo_summary"] = generate_ceo_summary(domain, results)

        return jsonify(results)

    except Exception as e:
        app.logger.error(f"Scan error for {domain}: {e}")
        return jsonify({"error": "Scan failed. Please try again."}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    app.run(host="0.0.0.0", port=port, debug=debug)
