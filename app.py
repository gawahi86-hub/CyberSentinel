from flask import Flask, render_template, request, redirect, url_for
import socket
import whois
import dns.resolver
import requests

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
        target = request.form.get("target")

        if not target:
            result = {
                "error": "No target provided"
            }
            return render_template("index.html", result=result)

        # -----------------------------
        # BASIC RECON
        # -----------------------------
        ip = safe_get(lambda: socket.gethostbyname(target))

        # -----------------------------
        # WHOIS LOOKUP
        # -----------------------------
        whois_info = safe_get(lambda: str(whois.whois(target)))

        # -----------------------------
        # DNS LOOKUP
        # -----------------------------
        dns_records = safe_get(lambda: [str(r) for r in dns.resolver.resolve(target, "A")])

        # -----------------------------
        # HTTP CHECK
        # -----------------------------
        http_status = safe_get(lambda: requests.get("http://" + target, timeout=5).status_code)

        # -----------------------------
        # FINAL RESULT STRUCTURE
        # -----------------------------
        result = {
            "target": target,
            "ip": ip,
            "whois": whois_info[:1000],  # prevent huge output crash
            "dns": dns_records,
            "http_status": http_status
        }

    return render_template("index.html", result=result)


# -----------------------------
# RUN APP (RENDER READY)
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)