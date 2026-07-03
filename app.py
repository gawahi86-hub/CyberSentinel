from flask import Flask, render_template, request
import socket
import whois
import dns.resolver
import requests
import os

app = Flask(__name__)


# -----------------------------
# SAFE RESULT HANDLING FUNCTION
# -----------------------------
def safe_get(func, default="Error"):
    try:
        return func()
    except Exception:
        return default


# -----------------------------
# HOME ROUTE
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        target = request.form.get("target", "").strip()

        if not target:
            result = {
                "error": "Please enter a domain name."
            }
            return render_template("index.html", result=result)

        # Resolve IP
        ip = safe_get(lambda: socket.gethostbyname(target))

        # WHOIS Lookup
        whois_info = safe_get(lambda: str(whois.whois(target)))

        # DNS Lookup
        dns_records = safe_get(
            lambda: [str(record) for record in dns.resolver.resolve(target, "A")],
            []
        )

        # HTTP Status
        http_status = safe_get(
            lambda: requests.get(
                f"http://{target}",
                timeout=5,
                headers={"User-Agent": "CyberSentinel"}
            ).status_code
        )

        result = {
            "target": target,
            "ip": ip,
            "whois": whois_info[:1000],
            "dns": dns_records,
            "http_status": http_status
        }

    return render_template("index.html", result=result)


# -----------------------------
# START APPLICATION
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)