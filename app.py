from flask import Flask, render_template, request, send_file
from urllib.parse import urlparse
import os
import traceback

from scanner import scan_website
from risk_engine import analyze_security
from report import generate_pdf

app = Flask(__name__)

# Ensure reports folder exists
os.makedirs("reports", exist_ok=True)

# -----------------------------
# CVSS ENGINE
# -----------------------------
def get_cvss(issue_name):
    name = str(issue_name).lower()

    if "ssl" in name or "https" in name:
        return 9.0, "CRITICAL"
    elif "csp" in name:
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
        # SAFE SCANNER
        # -----------------------------
        try:
            scan = scan_website(url)
        except Exception:
            scan = {
                "ip": "Unknown",
                "headers": {},
                "ssl": False,
                "ports": [],
                "http_status": "Error"
            }

        ip = scan.get("ip", "Unknown")
        headers = scan.get("headers", {})
        ssl_status = scan.get("ssl", False)
        ports = scan.get("ports", [])
        http_status = scan.get("http_status", 0)

        # -----------------------------
        # RISK ENGINE
        # -----------------------------
        try:
            risk = analyze_security(headers, url, ssl_status)
        except Exception:
            risk = {"issues": [], "score": 0, "level": "ERROR"}

        issues_raw = risk.get("issues", [])
        score = risk.get("score", 0)

        issues_with_ai = []

        # -----------------------------
        # BUILD ISSUES
        # -----------------------------
        for issue in issues_raw:
            name = issue.get("name", "Unknown Issue")
            cvss, severity = get_cvss(name)

            issues_with_ai.append({
                "name": name,
                "description": issue.get("description", ""),
                "impact": issue.get("impact", ""),
                "fix": issue.get("fix", ""),
                "cvss_score": cvss,
                "severity": severity
            })

        issue_count = len(issues_with_ai)
                # -----------------------------
        # FIX: CONSISTENCY RULE
        # -----------------------------
        if score < 85 and issue_count == 0:
            issues_with_ai.append({
                "name": "Security Risk Detected (Automated)",
                "description": "No explicit vulnerabilities found but score indicates weakness.",
                "impact": "Misconfiguration or hidden risk possible.",
                "fix": "Run full OWASP security audit.",
                "cvss_score": 5.0,
                "severity": "MEDIUM"
            })
            issue_count = 1

        # -----------------------------
        # FINAL SOC CLASSIFICATION (FIXED)
        # -----------------------------
        if score == 0 and issue_count == 0:
            risk_level = "UNKNOWN"
            verdict = "NO DATA"
            summary = "Scan failed or returned no valid security data."

        elif score >= 85:
            risk_level = "LOW"
            verdict = "SAFE"
            summary = "System shows strong security posture."

        elif score >= 75:
            risk_level = "LOW"
            verdict = "MOSTLY SAFE"
            summary = "Minor improvements recommended."

        elif score >= 60:
            risk_level = "MEDIUM"
            verdict = "MODERATE RISK"
            summary = "Security weaknesses detected."

        elif score >= 40:
            risk_level = "HIGH"
            verdict = "HIGH RISK"
            summary = "Significant vulnerabilities detected."

        else:
            risk_level = "CRITICAL"
            verdict = "CRITICAL RISK"
            summary = "System is highly vulnerable."

        # -----------------------------
        # FINAL RESULT
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
            "risk_level": risk_level,
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
# RUN APP
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)