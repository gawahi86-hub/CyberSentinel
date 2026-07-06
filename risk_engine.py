def analyze_security(headers, url, ssl_status):

    issues = []
    score = 0

    headers = {k.lower(): v for k, v in headers.items()} if isinstance(headers, dict) else {}

    # =========================
    # SECURITY HEADER CHECKS
    # =========================

    if "content-security-policy" not in headers:
        issues.append("Missing Content-Security-Policy")
        score += 30

    if "strict-transport-security" not in headers:
        issues.append("Missing HSTS")
        score += 25

    if "x-content-type-options" not in headers:
        issues.append("Missing X-Content-Type-Options")
        score += 10

    if "referrer-policy" not in headers:
        issues.append("Missing Referrer-Policy")
        score += 10

    if "permissions-policy" not in headers:
        issues.append("Missing Permissions-Policy")
        score += 15

    # =========================
    # SSL CHECK
    # =========================

    if not ssl_status or ssl_status.lower() != "valid":
        issues.append("SSL Certificate Issue")
        score += 20

    # =========================
    # FINAL SCORE LIMIT
    # =========================

    if score > 100:
        score = 100

    # =========================
    # RISK LEVEL LOGIC (FIXED)
    # =========================

    if score <= 40:
        level = "LOW"
    elif score <= 70:
        level = "MEDIUM"
    else:
        level = "HIGH"

    # =========================
    # OPTIONAL SMART ADDITION
    # =========================

    if score == 0:
        issues.append("No security issues detected")

    return {
        "score": score,
        "level": level,
        "issues": issues
    }