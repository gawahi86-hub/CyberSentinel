def explain_issue(issue):

    issue = issue.lower().strip()

    data = {
        "content-security-policy": {
            "meaning": "The website does not restrict which scripts and resources are allowed to run.",
            "risk": "High risk of Cross-Site Scripting (XSS) and code injection attacks.",
            "fix": "Implement Content-Security-Policy (CSP) header to restrict allowed sources (scripts, styles, images).",
            "cvss": 7.5,
            "severity": "HIGH"
        },

        "hsts": {
            "meaning": "Website does not enforce secure HTTPS connections.",
            "risk": "Attackers can intercept or downgrade traffic using Man-in-the-Middle attacks.",
            "fix": "Enable Strict-Transport-Security (HSTS) with long max-age and includeSubDomains.",
            "cvss": 7.0,
            "severity": "HIGH"
        },

        "x-content-type-options": {
            "meaning": "Browser may incorrectly interpret file types.",
            "risk": "Can lead to MIME-sniffing attacks and malicious file execution.",
            "fix": "Set X-Content-Type-Options: nosniff.",
            "cvss": 6.0,
            "severity": "MEDIUM"
        },

        "referrer-policy": {
            "meaning": "Website may leak URL information to external websites.",
            "risk": "Sensitive data leakage through HTTP referrer headers.",
            "fix": "Configure strict Referrer-Policy (e.g., no-referrer or same-origin).",
            "cvss": 5.5,
            "severity": "MEDIUM"
        },

        "permissions-policy": {
            "meaning": "Browser security features are not restricted.",
            "risk": "Unauthorized access to camera, microphone, and device sensors.",
            "fix": "Define Permissions-Policy to restrict sensitive browser features.",
            "cvss": 6.5,
            "severity": "MEDIUM"
        },

        "clickjacking": {
            "meaning": "Website can be embedded in malicious frames.",
            "risk": "Users may be tricked into clicking hidden malicious buttons.",
            "fix": "Use X-Frame-Options: DENY or SAMEORIGIN.",
            "cvss": 6.5,
            "severity": "MEDIUM"
        },

        "ssl": {
            "meaning": "Weak or missing SSL/TLS configuration.",
            "risk": "Traffic can be intercepted or decrypted.",
            "fix": "Use TLS 1.2+ or TLS 1.3 with strong cipher suites.",
            "cvss": 9.0,
            "severity": "CRITICAL"
        }
    }

    # smarter matching (not exact only)
    for key in data:
        if key in issue:
            return data[key]

    return {
        "meaning": "Security issue detected during automated scan.",
        "risk": "Potential vulnerability may be exploited by attackers.",
        "fix": "Perform manual security audit and apply best practices.",
        "cvss": 5.0,
        "severity": "LOW"
    }