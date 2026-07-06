def analyze_security(headers, url, ssl_status):

    vulnerabilities = []
    score = 100

    def add_vuln(name, desc, impact, fix, penalty):
        vulnerabilities.append({
            "name": name,
            "description": desc,
            "impact": impact,
            "fix": fix,
            "severity_penalty": penalty
        })
        return penalty

    # ---------------- SSL CHECK ----------------
    if not ssl_status:
        score -= add_vuln(
            "Missing HTTPS (SSL/TLS)",
            "Website is not using encrypted connection.",
            "Data can be intercepted via MITM attacks.",
            "Install SSL certificate and force HTTPS redirect.",
            30
        )

    # ---------------- SECURITY HEADERS ----------------
    security_headers = {
        "Content-Security-Policy": (
            "Missing Content-Security-Policy header",
            "Allows Cross-Site Scripting (XSS) attacks",
            "Add CSP header to restrict scripts and sources",
            15
        ),
        "X-Frame-Options": (
            "Missing X-Frame-Options",
            "Vulnerable to clickjacking attacks",
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
            "Enable HSTS with long max-age",
            15
        )
    }

    for header, data in security_headers.items():
        if header not in headers:
            score -= add_vuln(*data)

    # ---------------- FINAL SCORE SAFETY ----------------
    score = max(0, min(score, 100))

    # ---------------- RISK LEVEL ----------------
    if score >= 85:
        level = "LOW"
    elif score >= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    # ---------------- CONSISTENCY FIX (IMPORTANT) ----------------
    # Ensure vulnerabilities ALWAYS match risk output
    if score < 85 and len(vulnerabilities) == 0:

        if score < 60:
            vulnerabilities.append({
                "name": "Critical Security Posture Weakness",
                "description": "System shows high risk based on security scoring model, but no direct header-based vulnerabilities were detected.",
                "impact": "Possible hidden misconfigurations, outdated server configuration, or untested attack surface.",
                "fix": "Perform full penetration testing and enable OWASP recommended security headers.",
                "severity_penalty": 20
            })
        else:
            vulnerabilities.append({
                "name": "Minor Security Hardening Required",
                "description": "No direct vulnerabilities detected, but security posture is not fully hardened.",
                "impact": "System may be exposed to low-risk or unknown vulnerabilities.",
                "fix": "Enable missing security headers and enforce HTTPS across all endpoints.",
                "severity_penalty": 10
            })

        # Adjust score to reflect added finding
        score = max(0, score - vulnerabilities[-1]["severity_penalty"])

    return {
        "score": score,
        "level": level,
        "issues": vulnerabilities
    }