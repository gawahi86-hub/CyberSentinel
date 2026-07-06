import socket
import requests

def scan_website(url):

    try:
        response = requests.get(url, timeout=5)

        ip = socket.gethostbyname(url.replace("https://", "").replace("http://", ""))

        headers = dict(response.headers)

        return {
            "ip": ip,
            "headers": headers,
            "ssl": url.startswith("https"),
            "ports": [80, 443],
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