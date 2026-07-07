def calculate_risk_score(issues):

    if not issues:
        return 0


    total_score = 0


    for issue in issues:

        cvss = issue.get(
            "cvss",
            issue.get(
                "cvss_score",
                0
            )
        )


        try:

            total_score += float(cvss)

        except:

            pass



    average = total_score / len(issues)


    # Convert CVSS average to security score

    security_score = round(
        average * 10,
        2
    )


    return security_score





def classify_risk(score):


    if score <= 20:

        return (
            "LOW",
            "SAFE"
        )


    elif score <= 40:

        return (
            "LOW",
            "MOSTLY SAFE"
        )


    elif score <= 60:

        return (
            "MEDIUM",
            "MODERATE RISK"
        )


    elif score <= 80:

        return (
            "HIGH",
            "HIGH RISK"
        )


    else:

        return (
            "CRITICAL",
            "CRITICAL RISK"
        )






def analyze_security(
        headers,
        url,
        ssl_status
):


    issues=[]



    # Header analysis

    security_headers={


        "Content-Security-Policy":
        {
            "title":
            "Missing Content Security Policy",

            "cvss":
            5.3,

            "severity":
            "Medium",

            "recommendation":
            "Implement Content-Security-Policy header."

        },


        "Strict-Transport-Security":
        {

            "title":
            "Missing HSTS Header",

            "cvss":
            5.3,

            "severity":
            "Medium",

            "recommendation":
            "Enable Strict-Transport-Security."

        },


        "X-Frame-Options":
        {

            "title":
            "Missing Clickjacking Protection",

            "cvss":
            4.7,

            "severity":
            "Medium",

            "recommendation":
            "Enable X-Frame-Options."

        },


        "X-Content-Type-Options":
        {

            "title":
            "Missing MIME Protection",

            "cvss":
            4.7,

            "severity":
            "Medium",

            "recommendation":
            "Enable X-Content-Type-Options."

        }

    }




    for header,data in security_headers.items():


        if header not in headers:


            issues.append({

                "name":
                data["title"],

                "description":
                f"{header} security header is missing.",

                "impact":
                "This reduces browser-based security protection.",

                "fix":
                data["recommendation"],

                "cvss":
                data["cvss"],

                "severity":
                data["severity"]

            })




    score = calculate_risk_score(
        issues
    )


    level, verdict = classify_risk(
        score
    )



    return {


        "score":
        score,


        "level":
        level,


        "verdict":
        verdict,


        "issues":
        issues

    }