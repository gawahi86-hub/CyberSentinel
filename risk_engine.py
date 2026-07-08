# ---------------------------------
# CyberSentinel v2.1
# Professional Security Risk Engine
# ---------------------------------


# ---------------------------------
# Calculate CVSS Based Risk Score
# ---------------------------------

def calculate_risk_score(findings):

    if not findings:
        return 0


    total = 0


    for finding in findings:

        try:

            cvss = float(
                finding.get(
                    "cvss",
                    0
                )
            )

        except:

            cvss = 0



        total += cvss



    # Normalize score

    score = min(
        total,
        100
    )


    return round(
        score,
        1
    )





# ---------------------------------
# Risk Classification
# ---------------------------------

def classify_risk(score):


    if score <= 20:

        return {

            "level":
            "LOW",

            "verdict":
            "SAFE",

            "summary":
            (
                "The website demonstrates a good "
                "security posture. Only minor or no "
                "security issues were identified."
            )

        }



    elif score <= 50:

        return {


            "level":
            "MEDIUM",


            "verdict":
            "MODERATE RISK",


            "summary":
            (
                "Some security weaknesses were identified. "
                "Recommended fixes should be implemented."
            )

        }



    elif score <= 80:


        return {


            "level":
            "HIGH",


            "verdict":
            "HIGH RISK",


            "summary":
            (
                "Multiple security issues were detected. "
                "Immediate security improvements are "
                "recommended."
            )

        }



    else:


        return {


            "level":
            "CRITICAL",


            "verdict":
            "CRITICAL RISK",


            "summary":
            (
                "Critical security problems were detected. "
                "Immediate security action is required."
            )

        }





# ---------------------------------
# Security Grade
# ---------------------------------

def calculate_grade(score):


    if score <= 20:

        return "A"


    elif score <= 50:

        return "B"


    elif score <= 80:

        return "C"


    elif score <= 95:

        return "D"


    else:

        return "F"





# ---------------------------------
# Main Security Analysis
# ---------------------------------

def analyze_security(findings):


    score = calculate_risk_score(
        findings
    )


    risk = classify_risk(
        score
    )


    grade = calculate_grade(
        score
    )



    return {


        "risk_score":
        score,


        "risk_level":
        risk["level"],


        "safety_verdict":
        risk["verdict"],


        "final_summary":
        risk["summary"],


        "security_grade":
        grade,


        "issues":
        findings

    }