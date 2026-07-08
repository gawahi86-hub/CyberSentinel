from flask import Flask, render_template, request, send_file

from urllib.parse import urlparse

import os
import traceback


from scanner import scan_website
from report import generate_pdf



app = Flask(__name__)



BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


REPORT_FOLDER = os.path.join(
    BASE_DIR,
    "reports"
)


os.makedirs(
    REPORT_FOLDER,
    exist_ok=True
)


PDF_FILE = os.path.join(
    REPORT_FOLDER,
    "security_report.pdf"
)





# ---------------------------------
# Risk Score
# ---------------------------------

def calculate_risk_score(findings):

    if not findings:
        return 0


    score = 0


    for item in findings:

        score += float(
            item.get(
                "cvss",
                0
            )
        )


    return min(
        round(score,1),
        100
    )






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


    elif score <=50:

        return (
            "MEDIUM",
            "MODERATE RISK",
            "Some security weaknesses were identified. Recommended fixes should be implemented."
        )


    elif score <=80:

        return (
            "HIGH",
            "HIGH RISK",
            "Multiple security issues were detected. Immediate security improvements are recommended."
        )


    else:

        return (
            "CRITICAL",
            "CRITICAL RISK",
            "Critical security problems were detected. Immediate review is required."
        )






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

            scan=scan_website(
                user_url
            )


        except Exception:


            print(
                traceback.format_exc()
            )


            scan={

                "url":user_url,

                "findings":[]

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


                "simple_explanation":
                finding.get(
                    "simple_explanation",
                    ""
                ),


                "business_impact":
                finding.get(
                    "business_impact",
                    finding.get(
                        "impact",
                        ""
                    )
                ),


                "impact":
                finding.get(
                    "impact",
                    finding.get(
                        "business_impact",
                        ""
                    )
                ),



                "recommendation":
                finding.get(
                    "recommendation",
                    ""
                ),



                "technical_explanation":
                finding.get(
                    "technical_explanation",
                    finding.get(
                        "description",
                        ""
                    )
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
                ),



                # NEW

                "owasp":
                finding.get(
                    "owasp",
                    "A05:2021 - Security Misconfiguration"
                ),



                "affected_component":
                finding.get(
                    "affected_component",
                    "Website Security Configuration"
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



            "risk_score":
            risk_score,



            "risk_level":
            risk_level,



            "safety_verdict":
            verdict,



            "final_summary":
            summary,



            "issues":
            issues,



            # NEW SCAN INFORMATION

            "scanner_version":
            scan.get(
                "scanner_version",
                "CyberSentinel v2.1"
            ),



            "scan_time":
            scan.get(
                "scan_time",
                "Unknown"
            ),



            "scan_status":
            scan.get(
                "scan_status",
                "Completed"
            )

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






@app.route(
    "/download-report"
)

def download_report():


    if os.path.exists(
        PDF_FILE
    ):

        return send_file(

            PDF_FILE,

            as_attachment=True,

            download_name="CyberSentinel_Security_Report.pdf"

        )


    return (
        "Report not found",
        404
    )






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