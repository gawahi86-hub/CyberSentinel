def explain_issue(issue):

    issue = issue.lower()

    data = {
        "missing content-security-policy": {
            "meaning": "Website does not define which scripts are allowed to run.",
            "risk": "Attackers can inject malicious JavaScript (XSS attack).",
            "fix": "Add Content-Security-Policy header to restrict scripts."
        },

        "missing hsts": {
            "meaning": "Website does not force secure HTTPS connections.",
            "risk": "Attackers can intercept traffic (Man-in-the-Middle attack).",
            "fix": "Enable HTTP Strict Transport Security (HSTS)."
        },

        "missing x-content-type-options": {
            "meaning": "Browser may misinterpret file types.",
            "risk": "Can lead to MIME-based attacks.",
            "fix": "Set X-Content-Type-Options: nosniff."
        },

        "missing referrer-policy": {
            "meaning": "Website may leak URL information to other sites.",
            "risk": "Sensitive data leakage through referrer headers.",
            "fix": "Set strict Referrer-Policy settings."
        },

        "missing permissions-policy": {
            "meaning": "Browser features are not restricted.",
            "risk": "Camera, microphone or sensors may be abused.",
            "fix": "Define Permissions-Policy headers."
        }
    }

    return data.get(issue, {
        "meaning": "Security issue detected during scan.",
        "risk": "Potential vulnerability exists.",
        "fix": "Manual security review recommended."
    })