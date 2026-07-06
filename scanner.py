import socket

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