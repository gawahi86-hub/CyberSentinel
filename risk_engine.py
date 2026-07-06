def analyze_security(headers, url, ssl_status):

    vulnerabilities = []
    score = 100

    def add_vuln(name, desc, impact, fix, penalty):
        vulnerabilities.append({
            "name": name,
            "description": desc,
            "impact": impact,
            "fix": fix
        })
        return penalty

    # ---------------- SSL CHECK ----------------
    if not ssl_status:
        score -= add_vuln(
            "Missing HTTPS (SSL/TLS)",
            "Website is not using encrypted connection.",
            "Data can be intercepted (MITM attacks).",
            "Install SSL certificate and force HTTPS redirect.",
            30
        )

    # ---------------- SECURITY HEADERS ----------------
    security_headers = {
        "Content-Security-Policy": (
            "Missing Content Security Policy header",
            "Allows XSS (Cross-Site Scripting) attacks",
            "Add CSP header to restrict scripts and sources",
            15
        ),
        "X-Frame-Options": (
            "Missing X-Frame-Options",
            "Website vulnerable to clickjacking attacks",
            "Set X-Frame-Options: DENY or SAMEORIGIN",
            10
        ),
        "X-Content-Type-Options": (
            "Missing X-Content-Type-Options",
            "MIME sniffing attacks possible",
            "Set X-Content-Type-Options: nosniff",
            10
        ),
        "Strict-Transport-Security": (
            "Missing HSTS header",
            "Downgrade attacks possible",
            "Enable HSTS header",
            15
        )
    }

    for header, data in security_headers.items():
        if header not in headers:
            score -= add_vuln(*data)

    # ---------------- FINAL RISK LEVEL ----------------
    if score >= 85:
        level = "LOW"
    elif score >= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "score": max(score, 0),
        "level": level,
        "issues": vulnerabilities
    }