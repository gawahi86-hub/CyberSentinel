import socket
import requests
import time
from urllib.parse import urlparse


# -----------------------------
# Common ports to check
# -----------------------------
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 8080]


def check_open_ports(domain):

    open_ports = []

    for port in COMMON_PORTS:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)

        try:
            if sock.connect_ex((domain, port)) == 0:
                open_ports.append(port)
        except:
            pass

        sock.close()

    return open_ports


# -----------------------------
# Website Scanner
# -----------------------------
def scan_website(url):

    try:

        # Normalize URL
        parsed = urlparse(url)
        domain = parsed.netloc

        if not domain:
            domain = url

        # Measure response time
        start = time.time()

        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": "CyberSentinel Scanner"
            }
        )

        end = time.time()

        response_time = round((end - start) * 1000, 2)

        # Resolve IP
        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "Unknown"

        headers = dict(response.headers)

        # SSL Detection
        ssl = response.url.startswith("https")

        # Detect Server
        server = headers.get("Server", "Unknown")

        # Detect Technology
        technology = headers.get("X-Powered-By", "Not Disclosed")

        # Cookie Analysis
        cookies = []

        for cookie in response.cookies:

            cookies.append({
                "name": cookie.name,
                "secure": cookie.secure,
                "httponly": "HttpOnly" in str(cookie),
                "samesite": cookie._rest.get("SameSite", "Not Set")
            })

        # Scan Common Ports
        open_ports = check_open_ports(domain)

        return {

            "ip": ip,

            "headers": headers,

            "ssl": ssl,

            "ports": open_ports,

            "http_status": response.status_code,

            "response_time": response_time,

            "server": server,

            "technology": technology,

            "cookies": cookies

        }

    except Exception:

        return {

            "ip": "Unknown",

            "headers": {},

            "ssl": False,

            "ports": [],

            "http_status": 0,

            "response_time": 0,

            "server": "Unknown",

            "technology": "Unknown",

            "cookies": []

        }