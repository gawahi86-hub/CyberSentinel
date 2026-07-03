from flask import Flask, render_template, request
import os
import socket
import whois
import dns.resolver
import requests

from scanner import get_ip, get_http_status, get_security_headers, get_ssl_info, run_port_scan
from risk_engine import analyze_security
from database import init_db, save_scan, get_scans
from report import generate_pdf

app = Flask(__name__)
init_db()

def clean_domain(value):
    value = (value or "").strip()
    value = value.replace("https://","").replace("http://","")
    return value.split("/")[0]

@app.route("/", methods=["GET","POST"])
def index():
    result = None
    pdf_file = None
    history = get_scans()

    if request.method == "POST":
        raw = request.form.get("url","")
        domain = clean_domain(raw)

        if domain:
            url = "https://" + domain
            ip = get_ip(domain)

            try:
                whois_info = str(whois.whois(domain))
            except Exception:
                whois_info = "Unavailable"

            try:
                dns_records = [str(x) for x in dns.resolver.resolve(domain,"A")]
            except Exception:
                dns_records = []

            headers = get_security_headers(domain)
            ssl_info = get_ssl_info(domain)
            ports = run_port_scan(domain)
            http_status = get_http_status(domain)

            risk = analyze_security(headers, url, ssl_info.get("status","Unavailable"))

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
            pdf_file = generate_pdf(result)

    return render_template(
        "index.html",
        result=result,
        history=history,
        pdf_file=pdf_file
    )

if __name__ == "__main__":
    port = int(os.environ.get("PORT",10000))
    app.run(host="0.0.0.0", port=port)
