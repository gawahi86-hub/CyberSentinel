import socket

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
    3389: "RDP"
}


def scan_port(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((host, port))
        s.close()

        return result == 0
    except:
        return False


def run_port_scan(domain):
    results = []

    for port, service in COMMON_PORTS.items():
        if scan_port(domain, port):
            results.append({
                "port": port,
                "service": service,
                "status": "OPEN"
            })
        else:
            results.append({
                "port": port,
                "service": service,
                "status": "CLOSED"
            })

    return results