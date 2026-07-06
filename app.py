from flask import Flask, render_template, request, send_file
from urllib.parse import urlparse
import os

from scanner import scan_website
from risk_engine import analyze_security
from report import generate_pdf

app = Flask(__name__)

# -----------------------------
# CVSS ENGINE
# -----------------------------
def get_cvss(issue_name):
    name = issue_name.lower()

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
        # SCANNER (SAFE)
        # -----------------------------
        scan = scan_website(url)

        ip = scan.get("ip", "Unknown")
        headers = scan.get("headers", {})
        ssl_status = scan.get("ssl", False)
        ports = scan.get("ports", [])
        http_status = scan.get("http_status", 0)

        # -----------------------------
        # RISK ENGINE
        # -----------------------------
        risk = analyze_security(headers, url, ssl_status)

        issues_raw = risk.get("issues", [])
        score = risk.get("score", 0)
        level = risk.get("level", "UNKNOWN")

        # -----------------------------
        # BUILD VULNERABILITY REPORT
        # -----------------------------
        issues_with_ai = []

        for issue in issues_raw:
            cvss, severity = get_cvss(issue["name"])

            issues_with_ai.append({
                "name": issue["name"],
                "description": issue.get("description", ""),
                "impact": issue.get("impact", ""),
                "fix": issue.get("fix", ""),
                "cvss_score": cvss,
                "severity": severity
            })

        # -----------------------------
        # FINAL VERDICT SYSTEM
        # -----------------------------
        if score >= 85:
            verdict = "SAFE"
            summary = "Strong security posture with minimal risk."
        elif score >= 60:
            verdict = "MODERATE"
            summary = "Some vulnerabilities detected. Improvements recommended."
        else:
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
        # PDF GENERATION (SAFE)
        # -----------------------------
        try:
            generate_pdf(result)
        except Exception as e:
            print("PDF Error:", e)

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