def analyze_security(headers, url, ssl_status):
    score = 0
    issues = []

    # -------------------------
    # HEADER CHECKS
    # -------------------------
    if "Content-Security-Policy" not in headers:
        score += 20
        issues.append("Missing Content-Security-Policy (CSP)")

    if "Strict-Transport-Security" not in headers:
        score += 20
        issues.append("Missing HSTS")

    if "X-Content-Type-Options" not in headers:
        score += 10
        issues.append("Missing X-Content-Type-Options")

    if "Referrer-Policy" not in headers:
        score += 10
        issues.append("Missing Referrer-Policy")

    if "Permissions-Policy" not in headers:
        score += 10
        issues.append("Missing Permissions-Policy")

    # -------------------------
    # SSL CHECK
    # -------------------------
    if ssl_status != "valid":
        score += 30
        issues.append("SSL Certificate Issue")

    # -------------------------
    # SCORE LIMIT (safety cap)
    # -------------------------
    if score > 100:
        score = 100

    # -------------------------
    # FIXED RISK LEVEL LOGIC
    # -------------------------
    if score < 40:
        level = "LOW"
    elif score < 70:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "score": score,
        "level": level,
        "issues": issues
    }