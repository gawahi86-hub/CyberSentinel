from flask import Flask, render_template, request, send_file
from urllib.parse import urlparse

from scanner import scan_website
from risk_engine import analyze_security
from report import generate_pdf

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():

    result = None

    if request.method == "POST":

        url = request.form["url"]

        if not url.startswith("http"):
            url = "https://" + url

        domain = urlparse(url).netloc

        scan = scan_website(url)

        headers = scan["headers"]
        ssl_status = scan["ssl"]
        ports = scan["ports"]
        http_status = scan["http_status"]
        ip = scan["ip"]

        risk = analyze_security(headers, url, ssl_status)

        issues_with_ai = []
        for issue in risk["issues"]:
            issues_with_ai.append({
                "name": issue,
                "explanation": {
                    "meaning": f"{issue} affects website security posture.",
                    "risk": "Can expose system to cyber attacks.",
                    "fix": "Enable proper security headers and SSL configuration."
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

        generate_pdf(result)

    return render_template("index.html", result=result)


@app.route("/download-report")
def download_report():
    return send_file("reports/security_report.pdf", as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)