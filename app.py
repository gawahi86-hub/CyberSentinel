from flask import Flask, render_template, request, send_file
from urllib.parse import urlparse
import os

from scanner import scan_website
from risk_engine import analyze_security
from report import generate_pdf

app = Flask(__name__)

# -------------------------
# CVSS helper (simple)
# -------------------------
def get_cvss(issue):
    issue = issue.lower()

    if "ssl" in issue or "https" in issue:
        return 7.5, "HIGH"
    elif "header" in issue:
        return 5.0, "MEDIUM"
    elif "port" in issue:
        return 6.0, "MEDIUM"
    else:
        return 4.0, "LOW"


@app.route("/", methods=["GET", "POST"])
def index():

    result = None

    if request.method == "POST":

        url = request.form.get("url", "").strip()

        if not url:
            return render_template("index.html", result={"error": "No URL provided"})

        if not url.startswith("http"):
            url = "https://" + url

        domain = urlparse(url).netloc

        # -------------------------
        # SCANNER (SAFE)
        # -------------------------
        scan = scan_website(url)

        headers = scan.get("headers", {})
        ssl_status = scan.get("ssl", False)
        ports = scan.get("ports", [])
        http_status = scan.get("http_status", 0)
        ip = scan.get("ip", "Unknown")

        # -------------------------
        # RISK ENGINE
        # -------------------------
        risk = analyze_security(headers, url, ssl_status)

        issues_raw = risk.get("issues", [])
        score = risk.get("score", 0)
        level = risk.get("level", "UNKNOWN")

        # -------------------------
        # CVSS ENRICHMENT
        # -------------------------
        issues_with_ai = []

        for issue in issues_raw:
            cvss, severity = get_cvss(issue)

            issues_with_ai.append({
                "name": issue,
                "cvss_score": cvss,
                "severity": severity,
                "explanation": {
                    "meaning": f"{issue} affects security posture.",
                    "risk": f"Severity {severity} (CVSS {cvss})",
                    "fix": "Apply proper security hardening."
                }
            })

        # -------------------------
        # FINAL VERDICT
        # -------------------------
        if score >= 80:
            verdict = "SAFE"
            summary = "Strong security posture."
        elif score >= 50:
            verdict = "CAUTION"
            summary = "Moderate risks detected."
        else:
            verdict = "NOT SAFE"
            summary = "High risk detected."

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

        generate_pdf(result)

    return render_template("index.html", result=result)


@app.route("/download-report")
def download_report():
    return send_file("reports/security_report.pdf", as_attachment=True)


# -------------------------
# RENDER SAFE START
# -------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)