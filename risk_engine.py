# ---------------------------------
# CyberSentinel Risk Engine
# Professional Security Risk Scoring
# ---------------------------------


# ---------------------------------
# Calculate Weighted Risk Score
# ---------------------------------

def calculate_risk_score(findings):

    total_score = 0


    severity_weights = {

        "CRITICAL": 1.5,

        "HIGH": 1.0,

        "MEDIUM": 0.5,

        "LOW": 0.2,

        "INFO": 0

    }



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



        severity = finding.get(
            "severity",
            "INFO"
        ).upper()



        weight = severity_weights.get(
            severity,
            0
        )



        total_score += (
            cvss * weight
        )



    # Maximum score

    total_score = min(
        total_score,
        100
    )



    return round(
        total_score,
        1
    )





# ---------------------------------
# Risk Classification
# ---------------------------------

def classify_risk(score):


    if score <= 15:


        return {

            "level":
            "LOW",


            "verdict":
            "SAFE",


            "summary":
            (
                "The website demonstrates a strong "
                "security posture. Only minor security "
                "improvements were identified."
            )

        }




    elif score <= 35:


        return {


            "level":
            "LOW",


            "verdict":
            "MOSTLY SAFE",


            "summary":
            (
                "The website is generally secure. "
                "Some security hardening recommendations "
                "are available to improve protection."
            )

        }





    elif score <= 60:


        return {


            "level":
            "MEDIUM",


            "verdict":
            "MODERATE RISK",


            "summary":
            (
                "Security weaknesses were identified. "
                "Recommended improvements should be "
                "implemented."
            )

        }





    elif score <= 85:


        return {


            "level":
            "HIGH",


            "verdict":
            "HIGH RISK",


            "summary":
            (
                "Multiple security issues were detected. "
                "Immediate remediation is recommended."
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
# Security Grade System
# ---------------------------------

def calculate_grade(score):


    if score <= 15:

        return "A"


    elif score <= 35:

        return "B"


    elif score <= 60:

        return "C"


    elif score <= 85:

        return "D"


    else:

        return "F"







# ---------------------------------
# Main Analysis Function
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


        "score":
        score,


        "level":
        risk["level"],


        "verdict":
        risk["verdict"],


        "summary":
        risk["summary"],


        "grade":
        grade,


        "issues":
        findings

    }