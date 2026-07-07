from flask import Flask, render_template, request, send_file
from urllib.parse import urlparse
import os
import traceback

from scanner import scan_website
from risk_engine import analyze_security
from report import generate_pdf

app = Flask(__name__)

# -----------------------------
# Ensure reports folder exists
# -----------------------------
os.makedirs("reports", exist_ok=True)


# -----------------------------
# CVSS ENGINE
# -----------------------------
def get_cvss(issue_name):

    name = str(issue_name).lower()

    if "ssl" in name or "https" in name:
        return 9.0, "CRITICAL"

    elif "content-security-policy" in name or "csp" in name:
        return 7.5, "HIGH"

    elif "frame" in name or "clickjacking" in name:
        return 6.5, "MEDIUM"

    elif "hsts" in name:
        return 6.5, "MEDIUM"

    elif "content-type" in name or "mime" in name:
        return 6.0, "MEDIUM"

    return 5.0, "LOW"


# -----------------------------
# HOME PAGE
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def index():

    result = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if url == "":
            return render_template("index.html", result=None)

        if not url.startswith("http"):
            url = "https://" + url

        domain = urlparse(url).netloc

        # -----------------------------
        # WEBSITE SCAN
        # -----------------------------
        try:
            scan = scan_website(url)

        except Exception:

            print(traceback.format_exc())

            scan = {
                "ip": "Unknown",
                "headers": {},
                "ssl": False,
                "ports": [],
                "http_status": 0
            }

        ip = scan.get("ip", "Unknown")
        headers = scan.get("headers", {})
        ssl_status = scan.get("ssl", False)
        ports = scan.get("ports", [])
        http_status = scan.get("http_status", 0)

        # -----------------------------
        # SECURITY ANALYSIS
        # -----------------------------
        try:

            risk = analyze_security(
                headers=headers,
                url=url,
                ssl_status=ssl_status
            )

        except Exception:

            print(traceback.format_exc())

            risk = {
                "score": 0,
                "level": "UNKNOWN",
                "issues": []
            }

        score = risk.get("score", 0)
        issues = risk.get("issues", [])

        issues_with_cvss = []

        for issue in issues:

            cvss_score, severity = get_cvss(issue["name"])

            issues_with_cvss.append({
                "name": issue["name"],
                "description": issue["description"],
                "impact": issue["impact"],
                "fix": issue["fix"],
                "cvss_score": cvss_score,
                "severity": severity
            })

        issue_count = len(issues_with_cvss)
                # -----------------------------
        # FINAL CLASSIFICATION
        # -----------------------------
        if score >= 85:
            risk_level = "LOW"
            verdict = "SAFE"
            summary = (
                "The website demonstrates a strong security posture. "
                "No major security weaknesses were identified during the assessment."
            )

        elif score >= 70:
            risk_level = "LOW"
            verdict = "MOSTLY SAFE"
            summary = (
                "The website is generally secure. "
                "Some improvements are recommended to further strengthen security."
            )

        elif score >= 50:
            risk_level = "MEDIUM"
            verdict = "MODERATE RISK"
            summary = (
                "Several security weaknesses were identified. "
                "Review and implement the recommended fixes."
            )

        elif score >= 25:
            risk_level = "HIGH"
            verdict = "HIGH RISK"
            summary = (
                "Multiple vulnerabilities were detected. "
                "Immediate remediation is recommended."
            )

        else:
            risk_level = "CRITICAL"
            verdict = "CRITICAL RISK"
            summary = (
                "Critical security weaknesses were detected. "
                "The website should be reviewed before production use."
            )

        # -----------------------------
        # BUILD RESULT OBJECT
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
            "safety_verdict": verdict,
            "final_summary": summary,
            "issues": issues_with_cvss
        }

        # -----------------------------
        # GENERATE PDF
        # -----------------------------
        try:
            generate_pdf(result)

        except Exception:
            print(traceback.format_exc())

    return render_template(
        "index.html",
        result=result
    )


# -----------------------------
# DOWNLOAD REPORT
# -----------------------------
@app.route("/download-report")
def download_report():

    pdf_path = "reports/security_report.pdf"

    if os.path.exists(pdf_path):
        return send_file(
            pdf_path,
            as_attachment=True
        )

    return "Report not found.", 404


# -----------------------------
# START APPLICATION
# -----------------------------
if __name__ == "__main__":

    port = int(os.environ.get("PORT", 10000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )