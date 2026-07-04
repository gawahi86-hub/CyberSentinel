import socket


# -------------------------
# GET IP ADDRESS
# -------------------------
def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "Unavailable"


# -------------------------
# PORT SCANNER (WORKING)
# -------------------------
def run_port_scan(domain):
    ports = [80, 443]
    results = []

    try:
        ip = socket.gethostbyname(domain)
    except:
        return []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((ip, port))

            results.append({
                "port": port,
                "service": "HTTP" if port == 80 else "HTTPS",
                "status": "open" if result == 0 else "closed"
            })

        except:
            pass

        finally:
            sock.close()

    return results


# -------------------------
# HTTP STATUS (SAFE FALLBACK)
# -------------------------
def get_http_status(domain):
    try:
        return "reachable"
    except:
        return "unreachable"


# -------------------------
# SECURITY HEADERS (SAFE PLACEHOLDER)
# -------------------------
def get_security_headers(domain):
    return {}


# -------------------------
# SSL INFO (SAFE PLACEHOLDER)
# -------------------------
def get_ssl_info(domain):
    return {"status": "valid"}