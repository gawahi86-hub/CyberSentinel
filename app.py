from flask import Flask, render_template, request, send_file

from urllib.parse import urlparse

import os
import traceback


from scanner import scan_website

from report import generate_pdf





# ==================================================
# CyberSentinel SOC Dashboard
# Flask Application
# ==================================================


app = Flask(__name__)





# ==================================================
# REPORT CONFIGURATION
# ==================================================

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







# ==================================================
# ISSUE FORMATTER
# ==================================================

def format_findings(findings):


    issues = []



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

                ""

            ),



            "technical_explanation":

            finding.get(

                "technical_explanation",

                ""

            ),



            "recommendation":

            finding.get(

                "recommendation",

                ""

            ),



            "severity":

            finding.get(

                "severity",

                "INFO"

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

            )

        })



    return issues






# ==================================================
# HOME ROUTE
# ==================================================

@app.route(

    "/",

    methods=["GET", "POST"]

)


def index():

    result = None



    if request.method == "POST":


        user_url = request.form.get(

            "url",

            ""

        ).strip()



        if not user_url:


            return render_template(

                "index.html",

                result=None

            )




        try:


            scan = scan_website(

                user_url

            )



        except Exception:


            print(

                traceback.format_exc()

            )



            scan = {


                "url":

                user_url,


                "findings":

                []

            }






        findings = scan.get(

            "findings",

            []

        )




        parsed = urlparse(

            scan.get(

                "url",

                user_url

            )

        )



        issues = format_findings(

            findings

        )



        result = {


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



            "headers":

            scan.get(

                "headers",

                {}

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



            "issues":

            issues,



            "risk_score":

            scan.get(

                "risk_score",

                0

            ),



            "risk_level":

            scan.get(

                "risk_level",

                "UNKNOWN"

            ),



            "security_grade":

            scan.get(

                "security_grade",

                "N/A"

            ),



            "safety_verdict":

            scan.get(

                "safety_verdict",

                "UNKNOWN"

            ),



            "final_summary":

            scan.get(

                "final_summary",

                ""

            ),



            "scan_status":

            scan.get(

                "scan_status",

                "Unknown"

            )

        }






        # ==================================================
        # GENERATE PDF REPORT
        # ==================================================

        try:


            generate_pdf(

                result

            )



            print(

                "PDF Generated:",

                PDF_FILE

            )



        except Exception:


            print(

                "PDF Generation Error"

            )


            print(

                traceback.format_exc()

            )






    return render_template(

        "index.html",

        result=result

    )







# ==================================================
# DOWNLOAD PDF REPORT
# ==================================================

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

            download_name=

            "CyberSentinel_Security_Report.pdf"

        )



    return (

        "Report not found. Run a scan first.",

        404

    )





# ==================================================
# HEALTH CHECK
# ==================================================

@app.route(

    "/health"

)


def health():

    return {


        "status":

        "CyberSentinel Running"


    }