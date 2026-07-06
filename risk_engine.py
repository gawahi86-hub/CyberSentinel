def analyze_security(headers, url, ssl_status):

    issues = []
    score = 100  # start from safe baseline

    # =========================
    # SECURITY HEADERS (REAL IMPACT MODEL)
    # =========================

    if not headers.get("content-security-policy"):
        issues.append("Missing Content-Security-Policy")
        score -= 20

    if not headers.get("strict-transport-security"):
        issues.append("Missing HSTS")
        score -= 15

    if not headers.get("x-content-type-options"):
        issues.append("Missing X-Content-Type-Options")
        score -= 10

    if not headers.get("referrer-policy"):
        issues.append("Missing Referrer-Policy")
        score -= 10

    if not headers.get("permissions-policy"):
        issues.append("Missing Permissions-Policy")
        score -= 10

    # =========================
    # SSL CHECK
    # =========================

    if not ssl_status or ssl_status.lower() != "valid":
        issues.append("Invalid or Missing SSL Certificate")
        score -= 25

    # =========================
    # SAFETY CLAMP
    # =========================

    score = max(0, min(score, 100))

    # =========================
    # FINAL RISK LEVEL (REAL MODEL)
    # =========================

    if score >= 80:
        level = "LOW"
    elif score >= 50:
        level = "MEDIUM"
    else:
        level = "HIGH"

    return {
        "score": score,
        "level": level,
        "issues": issues
    }