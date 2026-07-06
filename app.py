from flask import Flask, render_template, request, send_file
from urllib.parse import urlparse
import os
import traceback

from scanner import scan_website
from risk_engine import analyze_security
from report import generate_pdf

app = Flask(__name__)

# Ensure reports folder exists (Render safe)
os.makedirs("reports", exist_ok=True)


# -----------------------------
# CVSS ENGINE
# -----------------------------
def get_cvss(issue_name):
    name = str(issue_name).lower()

    if "ssl" in name or "https" in name:
        return 9.0, "CRITICAL"
    elif "content security policy" in name or "csp" in name:
        return 7.5, "HIGH"
    elif "clickjacking" in name or "frame" in name:
        return 6.5, "MEDIUM"
    elif "mime" in name:
        return 6.0, "MEDIUM"
    elif "hsts" in name:
        return 6.5, "MEDIUM"
    else:
        return 5.0, "LOW"


# -----------------------------
# HOME ROUTE
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def index():

    result = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if not url:
            return render_template("index.html", result=None)

        if not url.startswith("http"):
            url = "https://" + url

        domain = urlparse(url).netloc

        # -----------------------------
        # SCANNER (SAFE MODE)
        # -----------------------------
        try:
            scan = scan_website(url)
        except Exception:
            return render_template("index.html", result={
                "url": url,
                "domain": "Scan Failed",
                "ip": "Unknown",
                "http_status": "Error",
                "headers": {},
                "ssl": False,
                "ports": [],
                "risk_score": 0,
                "risk_level": "SCAN FAILED",
                "issues": [],
                "final_summary": "Unable to complete scan due to system error.",
                "safety_verdict": "SCAN FAILED"
            })

        ip = scan.get("ip", "Unknown")
        headers = scan.get("headers", {})
        ssl_status = scan.get("ssl", False)
        ports = scan.get("ports", [])
        http_status = scan.get("http_status", 0)

        # -----------------------------
        # RISK ENGINE (SAFE MODE)
        # -----------------------------
        try:
            risk = analyze_security(headers, url, ssl_status)
        except Exception:
            risk = {
                "issues": [],
                "score": 50,
                "level": "UNKNOWN"
            }

        issues_raw = risk.get("issues", [])
        score = risk.get("score", 50)
        level = risk.get("level", "UNKNOWN")

        # -----------------------------
        # NORMALIZE LEVEL (FIX)
        # -----------------------------
        if level != "SCAN FAILED":
            if score >= 85:
                level = "LOW"
            elif score >= 60:
                level = "MEDIUM"
            else:
                level = "HIGH"

        # -----------------------------
        # BUILD ISSUES (SAFE LOOP)
        # -----------------------------
        issues_with_ai = []

        for issue in issues_raw:
            name = issue.get("name", "Unknown Issue")

            cvss, severity = get_cvss(name)

            issues_with_ai.append({
                "name": name,
                "description": issue.get("description", "No description available"),
                "impact": issue.get("impact", "Unknown impact"),
                "fix": issue.get("fix", "No fix provided"),
                "cvss_score": cvss,
                "severity": severity
            })

        # -----------------------------
        # FINAL VERDICT SYSTEM (FIXED)
        # -----------------------------
        # FINAL STATUS SYSTEM (CLEAN SOC STYLE)

if score >= 85:
    risk_level = "LOW"
    verdict = "SECURE"
    summary = "Strong security posture with minimal risk."
elif score >= 60:
    risk_level = "MEDIUM"
    verdict = "MODERATE RISK"
    summary = "Some vulnerabilities detected. Improvements recommended."
else:
    risk_level = "HIGH"
    verdict = "HIGH RISK"
    summary = "Critical vulnerabilities detected. Immediate action required."
        # -----------------------------
        # FINAL RESULT OBJECT
        # -----------------------------
        result = {
            "url": url,
            "domain": domain,
            "ip": ip,
            "http_status": http_status,
            "headers": headers,
            "ssl": ssl_status,
            "ports": ports,
            "risk_score": score,
            "risk_level": level,
            "issues": issues_with_ai,
            "final_summary": summary,
            "safety_verdict": verdict
        }

        # -----------------------------
        # PDF GENERATION
        # -----------------------------
        try:
            generate_pdf(result)
        except Exception:
            print(traceback.format_exc())

    return render_template("index.html", result=result)


# -----------------------------
# DOWNLOAD REPORT
# -----------------------------
@app.route("/download-report")
def download_report():
    return send_file("reports/security_report.pdf", as_attachment=True)


# -----------------------------
# RENDER ENTRY POINT
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)