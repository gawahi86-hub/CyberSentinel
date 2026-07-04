from flask import Flask, render_template, request, send_file
import os
import whois
import dns.resolver

from scanner import (
    get_ip,
    get_http_status,
    get_security_headers,
    get_ssl_info,
    run_port_scan
)

from risk_engine import analyze_security
from database import init_db, save_scan, get_scans
from report import generate_pdf

app = Flask(__name__)
init_db()


def clean_domain(value):
    value = (value or "").strip()
    value = value.replace("https://", "").replace("http://", "")
    return value.split("/")[0]


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    history = get_scans()

    if request.method == "POST":
        raw = request.form.get("url", "")
        domain = clean_domain(raw)

        if domain:
            url = "https://" + domain

            ip = get_ip(domain)

            # ✅ SAFE WHOIS
            try:
                whois_info = str(whois.whois(domain))
            except:
                whois_info = "Unavailable"

            # ✅ SAFE DNS (NO FREEZE ON RENDER)
            try:
                answers = dns.resolver.resolve(domain, "A", lifetime=2)
                dns_records = [str(x) for x in answers]
            except:
                dns_records = []

            headers = get_security_headers(domain)
            ssl_info = get_ssl_info(domain)
            ports = run_port_scan(domain)
            http_status = get_http_status(domain)

            risk = analyze_security(headers, url, ssl_info.get("status", "Unavailable"))

            result = {
                "url": url,
                "domain": domain,
                "ip": ip,
                "whois": whois_info,
                "dns": dns_records,
                "http_status": http_status,
                "headers": headers,
                "ssl": ssl_info,
                "ports": ports,
                "risk_score": risk["score"],
                "risk_level": risk["level"],
                "issues": risk["issues"],
            }

            save_scan(url, domain, risk["score"], risk["level"])
            history = get_scans()

    return render_template(
        "index.html",
        result=result,
        history=history
    )


# 🚀 FIXED DOWNLOAD ROUTE (STABLE + SAFE FILE NAME)
@app.route("/download-report")
def download_report():
    history = get_scans()

    if not history:
        return "No scan data available", 404

    latest = history[0]

    url = latest[1]
    domain = latest[2]
    score = latest[3]
    level = latest[4]

    result = {
        "url": url,
        "domain": domain,
        "ip": "",
        "risk_score": score,
        "risk_level": level,
        "issues": []
    }

    pdf_path = generate_pdf(result)

    if not pdf_path:
        return "PDF generation failed", 500

    # ✅ CLEAN FILE NAME
    safe_domain = domain.replace(".", "_")
    filename = f"CyberSentinel_{safe_domain}_Report.pdf"

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=filename
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)