def analyze_security(headers, url, ssl_status):

    vulnerabilities = []

    def add_vuln(name, desc, impact, fix, penalty):
        vulnerabilities.append({
            "name": name,
            "description": desc,
            "impact": impact,
            "fix": fix,
            "severity_penalty": penalty
        })

    score = 100

    # SSL check
    if not ssl_status:
        add_vuln(
            "Missing HTTPS (SSL/TLS)",
            "No encrypted connection.",
            "Data interception risk.",
            "Enable HTTPS with SSL certificate.",
            30
        )

    # Headers
    security_headers = {
        "Content-Security-Policy": (
            "Missing CSP",
            "XSS risk",
            "Add CSP header",
            15
        ),
        "X-Frame-Options": (
            "Missing X-Frame-Options",
            "Clickjacking risk",
            "Set DENY or SAMEORIGIN",
            10
        ),
        "Strict-Transport-Security": (
            "Missing HSTS",
            "Downgrade attacks possible",
            "Enable HSTS",
            15
        )
    }

    for h, data in security_headers.items():
        if h not in headers:
            add_vuln(*data)

    # FINAL SCORE = ONLY FROM VULNERABILITIES
    score = 100 - sum(v["severity_penalty"] for v in vulnerabilities)
    score = max(0, min(score, 100))

    # LEVEL
    if score >= 85:
        level = "LOW"
    elif score >= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "score": score,
        "level": level,
        "issues": vulnerabilities
    }