def analyze_security(headers, url, ssl_status):

    issues = []
    score = 100

    # SSL check
    if not ssl_status:
        issues.append("Missing SSL (HTTPS)")
        score -= 25

    # Security headers checks
    required_headers = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options"
    ]

    for h in required_headers:
        if h not in headers:
            issues.append(f"Missing security header: {h}")
            score -= 10

    # Final level
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