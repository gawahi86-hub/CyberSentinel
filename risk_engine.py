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

    # ---------------- SSL CHECK ----------------
    if not ssl_status:
        add_vuln(
            "Missing HTTPS (SSL/TLS)",
            "No encrypted connection.",
            "Data interception risk.",
            "Enable HTTPS with SSL certificate.",
            30
        )

    # ---------------- SECURITY HEADERS ----------------
    security_headers = {
        "Content-Security-Policy": (
            "Missing CSP header",
            "XSS attack risk",
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
            "Missing HSTS header",
            "Downgrade attack risk",
            "Enable HSTS",
            15
        )
    }

    for h, data in security_headers.items():
        if h not in headers:
            add_vuln(*data)

    # ---------------- SCORE CALCULATION ----------------
    if len(vulnerabilities) == 0:
        score = 100
    else:
        total_penalty = sum(v["severity_penalty"] for v in vulnerabilities)
        score = 100 - total_penalty
        score = max(0, min(score, 100))

    # ---------------- LEVEL (SAFE LOGIC) ----------------
    if score >= 85:
        level = "HIGH"
    elif score >= 60:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "CRITICAL"

    # ---------------- SAFETY FIX ----------------
    # If no vulnerabilities but low score → fix inconsistency
    if len(vulnerabilities) == 0 and score < 100:
        level = "LOW"
        score = 0

    return {
        "score": score,
        "level": level,
        "issues": vulnerabilities
    }