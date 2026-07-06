from flask import Flask, render_template, request, send_file
from urllib.parse import urlparse
import os

from scanner import scan_website
from risk_engine import analyze_security
from report import generate_pdf

app = Flask(__name__)

# =========================
# CVSS Helper Function
# =========================
def get_cvss(issue):
    issue = issue.lower()

    if "ssl" in issue or "https" in issue:
        return 7.5, "HIGH"
    elif "header" in issue:
        return 5.0, "MEDIUM"
    elif "port" in issue:
        return 6.5, "MEDIUM"
    elif "dns" in issue:
        return 4.0, "LOW"
    elif "ip" in issue:
        return 3.0, "LOW"
    else:
        return 5.0, "MEDIUM"


@app.route("/", methods=["GET", "POST"])
def index():

    result = None

    if request.method == "POST":

        url = request.form["url"]

        if not url.startswith("http"):
            url = "https://" + url

        domain = urlparse(url).netloc

        # =========================
        # SCANNER
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
        # CVSS ENRICHMENT
        # =========================
        issues_with_ai = []

        for issue in risk["issues"]:
            score, severity = get_cvss(issue)

            issues_with_ai.append({
                "name": issue,
                "cvss_score": score,
                "severity": severity,
                "explanation": {
                    "meaning": f"{issue} affects website security posture.",
                    "risk": f"Severity: {severity} (CVSS {score})",
                    "fix": "Apply proper security hardening and configuration updates."
                }
            })

        # =========================
        # FINAL VERDICT SYSTEM
        # =========================
        score = risk["score"]

        if score >= 80:
            final_summary = "SAFE TO USE – Strong security posture with minimal risk."
            safety_verdict = "SAFE"
        elif score >= 50:
            final_summary = "USE WITH CAUTION – Moderate security weaknesses detected."
            safety_verdict = "CAUTION"
        else:
            final_summary = "NOT SAFE – Significant vulnerabilities detected."
            safety_verdict = "NOT SAFE"

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
            "final_summary": final_summary,
            "safety_verdict": safety_verdict
        }

        # =========================
        # PDF GENERATION
        # =========================
        generate_pdf(result)

    return render_template("index.html", result=result)


@app.route("/download-report")
def download_report():
    return send_file("reports/security_report.pdf", as_attachment=True)


# =========================
# RENDER SAFE SERVER START
# =========================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)