import os
from flask import Flask, render_template, request, send_file

from recon import run_recon
from scanner import run_port_scan
from risk_engine import analyze_security
from database import init_db, save_scan, get_scans
from report import generate_pdf

app = Flask(__name__)

init_db()


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    pdf_file = None

    history = get_scans()

    if request.method == "POST":
        url = request.form.get("url")

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # Recon
        recon_data = run_recon(url)

        # Scan
        port_results = run_port_scan(recon_data["domain"])

        # Risk
        score, level, issues = analyze_security(
            recon_data["headers"],
            url
        )

        result = {
            "url": url,
            "domain": recon_data["domain"],
            "ip": recon_data["ip"],
            "dns": recon_data["dns"],
            "headers": recon_data["headers"],
            "whois": recon_data["whois"],
            "ports": port_results,
            "risk_score": score,
            "risk_level": level,
            "issues": issues if issues else []
        }

        save_scan(url, recon_data["domain"], score, level)
        history = get_scans()

        pdf_path = generate_pdf(result)
        pdf_file = os.path.basename(pdf_path)

    return render_template(
        "index.html",
        result=result,
        history=history,
        pdf_file=pdf_file
    )


@app.route("/download/<filename>")
def download_file(filename):
    path = os.path.join("reports", filename)
    return send_file(path, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True, port=5001)