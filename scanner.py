import socket
import requests
from urllib.parse import urlparse

def scan_website(url):

    try:
        # Normalize URL
        parsed = urlparse(url)
        domain = parsed.netloc

        if not domain:
            domain = url

        # HTTP request
        response = requests.get(url, timeout=5)

        # Real IP resolution
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = "Unknown"

        # Real headers
        headers = dict(response.headers)

        # REAL SSL DETECTION (better logic)
        ssl = False
        if url.startswith("https"):
            ssl = True
        if response.url.startswith("https"):
            ssl = True

        return {
            "ip": ip,
            "headers": headers,
            "ssl": ssl,
            "ports": [],  # optional (keep empty for realism)
            "http_status": response.status_code
        }

    except Exception:
        return {
            "ip": "Unknown",
            "headers": {},
            "ssl": False,
            "ports": [],
            "http_status": 0
        }