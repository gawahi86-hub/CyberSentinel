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

    # Start with perfect score
    score = 100

    # ---------------- SSL CHECK ----------------
    if not ssl_status:
        add_vuln(
            "Missing HTTPS (SSL/TLS)",
            "Website is not using an encrypted HTTPS connection.",
            "Data transmitted between users and the website may be intercepted.",
            "Install a valid SSL/TLS certificate and redirect all traffic to HTTPS.",
            30
        )

    # ---------------- SECURITY HEADERS ----------------
    security_headers = {
        "Content-Security-Policy": (
            "Missing Content-Security-Policy",
            "Cross-Site Scripting (XSS) attacks may be easier.",
            "Implement a strong Content-Security-Policy header.",
            15
        ),
        "X-Frame-Options": (
            "Missing X-Frame-Options",
            "Website may be vulnerable to clickjacking.",
            "Set X-Frame-Options to DENY or SAMEORIGIN.",
            10
        ),
        "Strict-Transport-Security": (
            "Missing HSTS Header",
            "Users could be vulnerable to protocol downgrade attacks.",
            "Enable Strict-Transport-Security with an appropriate max-age.",
            15
        ),
        "X-Content-Type-Options": (
            "Missing X-Content-Type-Options",
            "Browser MIME sniffing attacks may be possible.",
            "Set X-Content-Type-Options to nosniff.",
            10
        )
    }

    for header, values in security_headers.items():

        if header not in headers:

            add_vuln(
                values[0],
                values[1],
                values[1],
                values[2],
                values[3]
            )

    # ---------------- SCORE ----------------

    total_penalty = sum(v["severity_penalty"] for v in vulnerabilities)

    score = max(0, 100 - total_penalty)

    # ---------------- RISK LEVEL ----------------

    if score >= 85:
        level = "LOW"

    elif score >= 60:
        level = "MEDIUM"

    elif score >= 40:
        level = "HIGH"

    else:
        level = "CRITICAL"

    return {
        "score": score,
        "level": level,
        "issues": vulnerabilities
    }