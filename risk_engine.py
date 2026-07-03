def analyze_security(headers, url):
    score = 100
    issues = []

    # ----------------------------
    # SECURITY HEADERS CHECK
    # ----------------------------
    security_headers = {
        "Content-Security-Policy": "Missing CSP",
        "X-Frame-Options": "Missing Clickjacking protection",
        "X-XSS-Protection": "Missing XSS protection",
        "Strict-Transport-Security": "Missing HSTS"
    }

    for header, issue in security_headers.items():
        if header not in headers:
            score -= 10
            issues.append(issue)

    # ----------------------------
    # HTTPS CHECK
    # ----------------------------
    if not url.startswith("https"):
        score -= 20
        issues.append("Website not using HTTPS")

    # ----------------------------
    # FINAL RISK LEVEL
    # ----------------------------
    if score >= 80:
        level = "LOW"
    elif score >= 50:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return score, level, issues