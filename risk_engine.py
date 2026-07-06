def analyze_security(headers, url, ssl_status):
    score = 100
    issues = []
    reasons = []
    recommendations = []

    # SECURITY HEADERS CHECK
    required_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    for h in required_headers:
        if h not in headers:
            score -= 15
            issues.append(f"Missing {h}")
            reasons.append(f"{h} missing → OWASP A05: Security Misconfiguration")
            recommendations.append(f"Enable {h} header")

    # SSL CHECK
    if ssl_status != "valid":
        score -= 20
        issues.append("SSL Certificate issue")
        reasons.append("Invalid SSL → Data interception risk")
        recommendations.append("Fix SSL certificate")

    # FINAL RISK LEVEL
    if score >= 80:
        level = "LOW"
    elif score >= 50:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "score": max(score, 0),
        "level": level,
        "issues": issues,
        "reasons": reasons,
        "recommendations": recommendations
    }