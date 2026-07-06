def analyze_security(headers, url, ssl_status):

    score = 100
    issues = []

    # SSL check
    if ssl_status != "valid":
        score -= 25
        issues.append("SSL certificate issue detected")

    # Security headers check
    required_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    for h in required_headers:
        if h not in headers:
            score -= 10
            issues.append(f"Missing {h}")

    # final logic
    if score >= 80:
        level = "LOW"
    elif score >= 50:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "score": max(score, 0),
        "level": level,
        "issues": issues
    }