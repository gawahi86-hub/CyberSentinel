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
# HOME PAGE
# ---------------------------------

@app.route("/", methods=["GET","POST"])
def index():


    result=None



    if request.method=="POST":


        url=request.form.get(
            "url",
            ""
        ).strip()



        if not url:

            return render_template(
                "index.html",
                result=None
            )



        if not url.startswith(
            "http"
        ):

            url="https://" + url



        domain=urlparse(
            url
        ).netloc



        # -----------------------------
        # RUN SCANNER
        # -----------------------------

        try:

            scan=scan_website(
                url
            )


        except Exception:


            print(
                traceback.format_exc()
            )


            scan={

                "ip":
                "Unknown",

                "headers":
                {},

                "ssl":
                False,

                "ports":
                [],

                "http_status":
                0,

                "response_time":
                0,

                "server":
                "Unknown",

                "technology":
                "Unknown",

                "cookies":
                [],

                "findings":
                [],

                "risk_score":
                0
            }



        findings=scan.get(
            "findings",
            []
        )



        # -----------------------------
        # RISK CALCULATION
        # -----------------------------


        risk_score=scan.get(
            "risk_score",
            0
        )



        if risk_score <=20:

            risk_level="LOW"
            verdict="SAFE"


            summary=(

                "The website demonstrates "
                "a good security posture. "
                "Only minor or no security "
                "issues were identified."

            )



        elif risk_score <=50:


            risk_level="MEDIUM"
            verdict="MODERATE RISK"


            summary=(

                "Some security weaknesses "
                "were identified. "
                "Recommended fixes should "
                "be implemented."

            )



        elif risk_score <=80:


            risk_level="HIGH"
            verdict="HIGH RISK"


            summary=(

                "Multiple security issues "
                "were detected. Immediate "
                "security improvements are "
                "recommended."

            )



        else:


            risk_level="CRITICAL"
            verdict="CRITICAL RISK"


            summary=(

                "Critical security problems "
                "were detected. The website "
                "requires immediate review."

            )





        # -----------------------------
        # FINAL RESULT
        # -----------------------------


        result={


            "url":
            url,


            "domain":
            domain,


            "ip":
            scan.get(
                "ip"
            ),


            "http_status":
            scan.get(
                "http_status"
            ),


            "headers":
            scan.get(
                "headers"
            ),


            "ssl":
            scan.get(
                "ssl"
            ),


            "ports":
            scan.get(
                "ports"
            ),


            "server":
            scan.get(
                "server"
            ),


            "technology":
            scan.get(
                "technology"
            ),


            "response_time":
            scan.get(
                "response_time"
            ),


            "cookies":
            scan.get(
                "cookies"
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
            findings

        }





        # -----------------------------
        # CREATE PDF
        # -----------------------------

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
# DOWNLOAD PDF
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