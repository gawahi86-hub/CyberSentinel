def analyze_security(headers, url, ssl_status):

    issues = []

    # normalize score properly
    score = 100

    # normalize header values (IMPORTANT FIX)
    def missing(value):
        return value is None or value == "" or value == "None"

    # =========================
    # SECURITY HEADERS
    # =========================

    if missing(headers.get("content-security-policy")):
        issues.append("Missing Content-Security-Policy")
        score -= 18

    if missing(headers.get("strict-transport-security")):
        issues.append("Missing HSTS")
        score -= 15

    if missing(headers.get("x-content-type-options")):
        issues.append("Missing X-Content-Type-Options")
        score -= 10

    if missing(headers.get("referrer-policy")):
        issues.append("Missing Referrer-Policy")
        score -= 8

    if missing(headers.get("permissions-policy")):
        issues.append("Missing Permissions-Policy")
        score -= 8

    # =========================
    # SSL CHECK (FIXED LOGIC)
    # =========================

    if ssl_status is None or ssl_status.lower() != "valid":
        issues.append("SSL Certificate Issue")
        score -= 25

    # =========================
    # SAFETY RULE (IMPORTANT FIX)
    # =========================

    # prevent fake extreme values
    if len(issues) == 0:
        score = 95  # even secure sites are not perfect 100

    # clamp score
    score = max(0, min(score, 100))

    # =========================
    # RISK LEVEL
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