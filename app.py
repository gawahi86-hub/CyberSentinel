from flask import Flask, render_template, request, send_file

from urllib.parse import urlparse

import os
import traceback


from scanner import scan_website
from report import generate_pdf



app = Flask(__name__)


os.makedirs(
    "reports",
    exist_ok=True
)




# ---------------------------------
# Calculate Risk Score
# ---------------------------------

def calculate_risk_score(findings):

    if not findings:
        return 0


    total = 0


    for item in findings:

        total += float(
            item.get(
                "cvss",
                0
            )
        )


    # Limit score to 100

    score = min(
        round(total,1),
        100
    )


    return score





# ---------------------------------
# Risk Classification
# ---------------------------------

def classify_risk(score):


    if score <= 20:

        return (
            "LOW",
            "SAFE",
            "The website demonstrates a good security posture. Only minor or no security issues were identified."
        )


    elif score <= 50:

        return (
            "MEDIUM",
            "MODERATE RISK",
            "Some security weaknesses were identified. Recommended fixes should be implemented."
        )


    elif score <= 80:

        return (
            "HIGH",
            "HIGH RISK",
            "Multiple security issues were detected. Immediate security improvements are recommended."
        )


    else:

        return (
            "CRITICAL",
            "CRITICAL RISK",
            "Critical security problems were detected. The website requires immediate review."
        )







# ---------------------------------
# HOME PAGE
# ---------------------------------

@app.route(
    "/",
    methods=["GET","POST"]
)

def index():


    result=None



    if request.method=="POST":


        user_url=request.form.get(
            "url",
            ""
        ).strip()



        if not user_url:

            return render_template(
                "index.html",
                result=None
            )



        try:


            # Scanner handles normalization

            scan=scan_website(
                user_url
            )



        except Exception:


            print(
                traceback.format_exc()
            )


            scan={

                "url":
                user_url,

                "ip":
                "Unknown",

                "headers":
                {},

                "ssl":
                False,

                "ports":
                [],

                "http_status":
                "Unavailable",

                "response_time":
                0,

                "server":
                "Unknown",

                "technology":
                "Unknown",

                "findings":[{

                    "name":
                    "Scanner Error",

                    "title":
                    "Scanner Error",

                    "severity":
                    "INFO",

                    "cvss":
                    0,

                    "description":
                    "Scanner failed.",

                    "recommendation":
                    "Check URL."

                }]

            }




        findings=scan.get(
            "findings",
            []
        )



        risk_score=calculate_risk_score(
            findings
        )



        risk_level, verdict, summary = classify_risk(
            risk_score
        )



        parsed=urlparse(
            scan.get(
                "url",
                user_url
            )
        )



        # ---------------------------------
        # Prepare Issues For Dashboard/PDF
        # ---------------------------------

        issues=[]


        for finding in findings:


            issues.append({

                "name":
                finding.get(
                    "name",
                    finding.get(
                        "title",
                        ""
                    )
                ),


                "description":
                finding.get(
                    "description",
                    ""
                ),


                "impact":
                finding.get(
                    "business_impact",
                    ""
                ),


                "fix":
                finding.get(
                    "recommendation",
                    ""
                ),


                "recommendation":
                finding.get(
                    "recommendation",
                    ""
                ),


                "simple_explanation":
                finding.get(
                    "simple_explanation",
                    ""
                ),


                "technical_explanation":
                finding.get(
                    "technical_explanation",
                    ""
                ),


                "cvss":
                finding.get(
                    "cvss",
                    0
                ),


                "cvss_score":
                finding.get(
                    "cvss",
                    0
                ),


                "severity":
                finding.get(
                    "severity",
                    "INFO"
                )

            })





        result={


            "url":
            scan.get(
                "url",
                user_url
            ),


            "domain":
            parsed.netloc,


            "ip":
            scan.get(
                "ip",
                "Unknown"
            ),


            "http_status":
            scan.get(
                "http_status",
                "Unknown"
            ),


            "headers":
            scan.get(
                "headers",
                {}
            ),


            "ssl":
            scan.get(
                "ssl",
                False
            ),


            "ports":
            scan.get(
                "ports",
                []
            ),


            "server":
            scan.get(
                "server",
                "Unknown"
            ),


            "technology":
            scan.get(
                "technology",
                "Unknown"
            ),


            "response_time":
            scan.get(
                "response_time",
                0
            ),


            "cookies":
            scan.get(
                "cookies",
                []
            ),


            "risk_score":
            risk_score,


            "risk_level":
            risk_level,


            "safety_verdict":
            verdict,


            "final_summary":
            summary,


            "issues":
            issues

        }




        try:

            generate_pdf(
                result
            )


        except Exception:


            print(
                traceback.format_exc()
            )





    return render_template(
        "index.html",
        result=result
    )








# ---------------------------------
# DOWNLOAD REPORT
# ---------------------------------

@app.route(
    "/download-report"
)

def download_report():


    file="reports/security_report.pdf"



    if os.path.exists(file):

        return send_file(
            file,
            as_attachment=True
        )



    return "Report not found",404







# ---------------------------------
# START SERVER
# ---------------------------------

if __name__=="__main__":


    port=int(
        os.environ.get(
            "PORT",
            10000
        )
    )


    app.run(

        host="0.0.0.0",

        port=port,

        debug=False

    )