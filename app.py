from flask import Flask, render_template, request, send_file
import socket
import requests
from urllib.parse import urlparse

from scanner import scan_website
from risk_engine import analyze_security
from report import generate_pdf

app = Flask(__name__)

# =========================
# HOME ROUTE
# =========================
@app.route("/", methods=["GET", "POST"])
def index():

    result = None

    if request.method == "POST":

        url = request.form["url"]

        # =========================
        # BASIC CLEANING
        # =========================
        if not url.startswith("http"):
            url = "https://" + url

        domain = urlparse(url).netloc

        # =========================
        # SCAN MODULE
        # =========================
        scan = scan_website(url)

        headers = scan["headers"]
        ssl_status = scan["ssl"]
        ports = scan["ports"]
        http_status = scan["http_status"]
        ip = scan["ip"]

        # =========================
        # RISK ENGINE
        # =========================
        risk = analyze_security(headers, url, ssl_status)

        # =========================
        # AI VULNERABILITY FORMAT FIX
        # =========================
        issues_with_ai = []
        for issue in risk["issues"]:
            issues_with_ai.append({
                "name": issue,
                "explanation": {
                    "meaning": f"{issue} affects website security posture.",
                    "risk": "Can expose system to cyber attacks if not fixed.",
                    "fix": "Follow security best practices and enable proper headers."
                }
            })

        # =========================
        # FINAL SUMMARY (IMPORTANT FIX)
        # =========================
        score = risk["score"]

        if score >= 80:
            final_summary = "Strong security posture. Minimal vulnerabilities detected."
        elif score >= 50:
            final_summary = "Moderate security weaknesses detected. Improvements recommended."
        else:
            final_summary = "High risk detected. Immediate security improvements required."

        # =========================
        # FINAL RESULT OBJECT
        # =========================
        result = {
            "url": url,
            "domain": domain,
            "ip": ip,
            "http_status": http_status,
            "headers": headers,
            "ssl": ssl_status,
            "ports": ports,
            "risk_score": score,
            "risk_level": risk["level"],
            "issues": issues_with_ai,
            "final_summary": final_summary
        }

        # =========================
        # SAVE PDF REPORT
        # =========================
        generate_pdf(result)

    return render_template("index.html", result=result)


# =========================
# DOWNLOAD PDF ROUTE
# =========================
@app.route("/download-report")
def download_report():
    return send_file("reports/security_report.pdf", as_attachment=True)


# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    app.run(debug=True)