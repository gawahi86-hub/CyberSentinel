def analyze_security(headers, url, ssl_status="Unavailable"):
    score = 100
    issues = []

    # ----------------------------
    # SECURITY HEADERS CHECK
    # ----------------------------
    required_headers = {
        "Content-Security-Policy": "Missing Content Security Policy (CSP)",
        "Strict-Transport-Security": "Missing HTTP Strict Transport Security (HSTS)",
        "X-Frame-Options": "Missing X-Frame-Options",
        "X-Content-Type-Options": "Missing X-Content-Type-Options",
        "Referrer-Policy": "Missing Referrer-Policy",
        "Permissions-Policy": "Missing Permissions-Policy"
    }

    for header, message in required_headers.items():
        value = headers.get(header)

        if value in [None, "", "Missing", "Unavailable"]:
            score -= 10
            issues.append(message)

    # ----------------------------
    # HTTPS CHECK
    # ----------------------------
    if not url.lower().startswith("https://"):
        score -= 15
        issues.append("Website is not using HTTPS")

    # ----------------------------
    # SSL CERTIFICATE CHECK
    # ----------------------------
    if ssl_status != "Valid":
        score -= 15
        issues.append("SSL certificate unavailable or invalid")

    # ----------------------------
    # KEEP SCORE IN RANGE
    # ----------------------------
    score = max(0, min(score, 100))

    # ----------------------------
    # RISK LEVEL
    # ----------------------------
    if score >= 85:
        level = "LOW"
    elif score >= 60:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "score": score,
        "level": level,
        "issues": issues
    }