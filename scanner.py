import socket
import ssl
import requests

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
}


def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "Unavailable"


def get_http_status(domain):
    try:
        response = requests.get(
            f"https://{domain}",
            timeout=5,
            headers={"User-Agent": "CyberSentinel"}
        )
        return response.status_code
    except Exception:
        try:
            response = requests.get(
                f"http://{domain}",
                timeout=5,
                headers={"User-Agent": "CyberSentinel"}
            )
            return response.status_code
        except Exception:
            return "Unavailable"


def get_security_headers(domain):
    headers_found = {}

    try:
        response = requests.get(
            f"https://{domain}",
            timeout=5,
            headers={"User-Agent": "CyberSentinel"}
        )

        important_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]

        for header in important_headers:
            headers_found[header] = response.headers.get(header, "Missing")

    except Exception:
        for header in [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy"
        ]:
            headers_found[header] = "Unavailable"

    return headers_found


def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()

        with context.wrap_socket(
            socket.socket(),
            server_hostname=domain
        ) as conn:

            conn.settimeout(5)
            conn.connect((domain, 443))

            cert = conn.getpeercert()

            return {
                "issuer": cert.get("issuer"),
                "expires": cert.get("notAfter"),
                "status": "Valid"
            }

    except Exception:
        return {
            "issuer": "Unavailable",
            "expires": "Unavailable",
            "status": "Unavailable"
        }


# Public deployment:
# Active port scanning is intentionally disabled.
def run_port_scan(domain):
    return []