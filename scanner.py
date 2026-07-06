import requests
import socket
import whois
import dns.resolver
from urllib.parse import urlparse
from datetime import datetime


def scan_website(url):
    result = {
        "url": url,
        "scan_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        "status_code": None,
        "title": None,
        "server_ip": None,
        "whois": {},
        "dns_records": {},
        "security_headers": {},
        "risk_score": 0,
        "risk_level": "Unknown",
        "errors": []
    }

    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    # ----------------------------
    # 1. HTTP Request
    # ----------------------------
    try:
        response = requests.get(url, timeout=10)
        result["status_code"] = response.status_code

        # Title extraction
        if "<title>" in response.text.lower():
            start = response.text.lower().find("<title>")
            end = response.text.lower().find("</title>")
            result["title"] = response.text[start + 7:end].strip()

        # Security headers
        headers = response.headers
        result["security_headers"] = {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "Server": headers.get("Server")
        }

    except Exception as e:
        result["errors"].append(f"HTTP Error: {str(e)}")

    # ----------------------------
    # 2. IP Lookup
    # ----------------------------
    try:
        result["server_ip"] = socket.gethostbyname(domain)
    except Exception as e:
        result["errors"].append(f"DNS resolution failed: {str(e)}")

    # ----------------------------
    # 3. WHOIS Lookup
    # ----------------------------
    try:
        domain_info = whois.whois(domain)

        result["whois"] = {
            "domain_name": str(domain_info.domain_name),
            "registrar": domain_info.registrar,
            "creation_date": str(domain_info.creation_date),
            "expiration_date": str(domain_info.expiration_date),
            "country": domain_info.country
        }
    except Exception as e:
        result["errors"].append(f"WHOIS failed: {str(e)}")

    # ----------------------------
    # 4. DNS Records
    # ----------------------------
    try:
        records = {}

        for rtype in ["A", "MX", "NS", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [r.to_text() for r in answers]
            except:
                records[rtype] = []

        result["dns_records"] = records

    except Exception as e:
        result["errors"].append(f"DNS lookup failed: {str(e)}")

    # ----------------------------
    # 5. Risk Scoring Engine
    # ----------------------------
    risk = 0

    # HTTPS check
    if not url.startswith("https"):
        risk += 25

    # Missing security headers
    headers = result["security_headers"]
    if not headers.get("Content-Security-Policy"):
        risk += 10
    if not headers.get("X-Frame-Options"):
        risk += 10
    if not headers.get("Strict-Transport-Security"):
        risk += 10

    # HTTP status check
    if result["status_code"] and result["status_code"] >= 400:
        risk += 25

    # WHOIS missing info
    if not result["whois"].get("registrar"):
        risk += 10

    result["risk_score"] = min(risk, 100)

    # Risk level
    if risk < 30:
        result["risk_level"] = "LOW"
    elif risk < 70:
        result["risk_level"] = "MEDIUM"
    else:
        result["risk_level"] = "HIGH"

    return result