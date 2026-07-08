# ---------------------------------
# CyberSentinel v2.0
# Professional SOC PDF Report Generator
# ---------------------------------

import os

from datetime import datetime

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    Image
)

from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors



# ---------------------------------
# AI RECOMMENDATION ENGINE
# ---------------------------------

def generate_ai_recommendations(data):

    recommendations = []


    score = data.get(
        "risk_score",
        0
    )


    issues = data.get(
        "issues",
        []
    )


    if score <= 20:

        recommendations.append(
            "Maintain current security controls and perform regular vulnerability monitoring."
        )

        recommendations.append(
            "Continue periodic security assessments."
        )


    elif score <= 50:

        recommendations.append(
            "Review and remediate identified security weaknesses."
        )

        recommendations.append(
            "Improve security headers and website configuration."
        )


    elif score <= 80:

        recommendations.append(
            "Immediate remediation is recommended for detected vulnerabilities."
        )

        recommendations.append(
            "Perform penetration testing and configuration review."
        )


    else:

        recommendations.append(
            "Critical vulnerabilities require immediate security action."
        )

        recommendations.append(
            "Conduct complete security audit and incident response review."
        )



    for issue in issues:

        name = issue.get(
            "name",
            ""
        ).lower()


        if "cookie" in name:

            recommendations.append(
                "Secure cookies using Secure, HttpOnly and SameSite attributes."
            )


        if "content" in name:

            recommendations.append(
                "Implement Content Security Policy to reduce script injection risks."
            )


        if "https" in name or "ssl" in name:

            recommendations.append(
                "Maintain strong TLS configuration and HTTPS enforcement."
            )


        if "port" in name:

            recommendations.append(
                "Close unnecessary exposed network services."
            )


    return list(set(recommendations))



# ---------------------------------
# PDF GENERATOR
# ---------------------------------

def generate_pdf(data):


    base_dir = os.path.dirname(
        os.path.abspath(__file__)
    )


    reports_folder = os.path.join(
        base_dir,
        "reports"
    )


    os.makedirs(
        reports_folder,
        exist_ok=True
    )


    file_path = os.path.join(
        reports_folder,
        "security_report.pdf"
    )



    doc = SimpleDocTemplate(

        file_path,

        pagesize=A4,

        rightMargin=40,

        leftMargin=40,

        topMargin=40,

        bottomMargin=40

    )



    styles = getSampleStyleSheet()



    title_style = ParagraphStyle(

        "title",

        parent=styles["Title"],

        fontSize=26,

        alignment=1,

        textColor=colors.HexColor("#0b5394")

    )



    heading_style = ParagraphStyle(

        "heading",

        parent=styles["Heading2"],

        textColor=colors.HexColor("#1e3a8a")

    )



    normal = styles["Normal"]



    elements = []



    # ---------------------------------
    # COVER PAGE
    # ---------------------------------

    logo_path = os.path.join(

        base_dir,

        "static",

        "logo.png"

    )


    if os.path.exists(logo_path):

        elements.append(
            Image(
                logo_path,
                width=100,
                height=100
            )
        )

        elements.append(
            Spacer(1,20)
        )


    elements.append(

        Paragraph(
            "🛡 CYBERSENTINEL",
            title_style
        )

    )


    elements.append(
        Spacer(1,15)
    )


    elements.append(

        Paragraph(

            "Professional Website Security Assessment Report",

            normal

        )

    )


    elements.append(
        Spacer(1,20)
    )


    elements.append(

        Paragraph(

            "Generated: " +
            str(datetime.now()),

            normal

        )

    )


    elements.append(
        Spacer(1,30)
    )



    # ---------------------------------
    # EXECUTIVE SUMMARY
    # ---------------------------------

    elements.append(

        Paragraph(
            "Executive Summary",
            heading_style
        )

    )


    summary_table = Table([

        [

            "Verdict",

            data.get(
                "safety_verdict",
                ""
            )

        ],

        [

            "Risk Level",

            data.get(
                "risk_level",
                ""
            )

        ],

        [

            "Risk Score",

            str(
                data.get(
                    "risk_score",
                    0
                )
            )

        ]


    ])


    summary_table.setStyle(

        TableStyle([

            (
                "GRID",
                (0,0),
                (-1,-1),
                0.5,
                colors.grey
            )

        ])

    )


    elements.append(
        summary_table
    )


    elements.append(
        Spacer(1,15)
    )


    elements.append(

        Paragraph(

            data.get(
                "final_summary",
                ""
            ),

            normal

        )

    )



    elements.append(
        Spacer(1,20)
    )



    # ---------------------------------
    # TECHNICAL INFORMATION
    # ---------------------------------

    elements.append(

        Paragraph(
            "Technical Information",
            heading_style
        )

    )


    ssl_data = data.get(
        "ssl",
        {}
    )


    ssl_text = (

        "Status: "
        + str(ssl_data.get("status","Unknown"))
        +
        "<br/>Issuer: "
        + str(ssl_data.get("issuer","Unknown"))
        +
        "<br/>Expiry: "
        + str(ssl_data.get("expiry","Unknown"))
        +
        "<br/>Days Remaining: "
        + str(ssl_data.get("days_remaining","0"))

    )



    technology = data.get(
        "technology",
        ""
    )


    if isinstance(
        technology,
        list
    ):

        technology=", ".join(
            technology
        )



    technical_table = Table([

        [
            "Website",
            data.get("url","")
        ],

        [
            "IP Address",
            str(data.get("ip",""))
        ],

        [
            "HTTP Status",
            str(data.get("http_status",""))
        ],

        [
            "SSL Certificate",
            ssl_text
        ],

        [
            "Server",
            data.get("server","")
        ],

        [
            "Technology",
            technology
        ],

        [
            "Response Time",
            str(data.get("response_time",""))+" ms"
        ]

    ])



    technical_table.setStyle(

        TableStyle([

            (
                "GRID",
                (0,0),
                (-1,-1),
                0.5,
                colors.grey
            )

        ])

    )


    elements.append(
        technical_table
    )


    elements.append(
        Spacer(1,20)
    )



    # ---------------------------------
    # OPEN PORTS
    # ---------------------------------

    elements.append(

        Paragraph(
            "Open Ports Analysis",
            heading_style
        )

    )


    ports=data.get(
        "ports",
        []
    )


    port_table=[

        [
            "Port",
            "Service"
        ]

    ]


    for port in ports:

        port_table.append(

            [

                str(port.get("port")),

                port.get("service")

            ]

        )



    if len(port_table)==1:

        port_table.append(
            [
                "None",
                "No open ports detected"
            ]
        )



    ports_table=Table(
        port_table
    )


    ports_table.setStyle(

        TableStyle([

            (
                "GRID",
                (0,0),
                (-1,-1),
                0.5,
                colors.grey
            )

        ])

    )


    elements.append(
        ports_table
    )


    elements.append(
        Spacer(1,20)
    )



    # ---------------------------------
    # VULNERABILITIES
    # ---------------------------------

    elements.append(

        Paragraph(

            "Security Vulnerabilities & CVSS Analysis",

            heading_style

        )

    )



    issues=data.get(
        "issues",
        []
    )



    vulnerability_table=[

        [

            "Issue",

            "Severity",

            "CVSS",

            "OWASP",

            "Recommendation"

        ]

    ]



    for issue in issues:


        vulnerability_table.append(

            [

                issue.get("name",""),

                issue.get("severity",""),

                str(issue.get("cvss",0)),

                issue.get("owasp",""),

                issue.get("recommendation","")

            ]

        )



    if len(vulnerability_table)==1:

        vulnerability_table.append(

            [

                "No vulnerabilities",

                "-",

                "0",

                "-",

                "Maintain security"

            ]

        )



    vuln_table=Table(
        vulnerability_table,
        repeatRows=1
    )


    vuln_table.setStyle(

        TableStyle([

            (
                "GRID",
                (0,0),
                (-1,-1),
                0.5,
                colors.grey
            )

        ])

    )


    elements.append(
        vuln_table
    )


    elements.append(
        Spacer(1,20)
    )



    # ---------------------------------
    # RECOMMENDATIONS
    # ---------------------------------

    elements.append(

        Paragraph(

            "AI Security Recommendations",

            heading_style

        )

    )


    for recommendation in generate_ai_recommendations(data):

        elements.append(

            Paragraph(

                "• "+recommendation,

                normal

            )

        )


    elements.append(
        Spacer(1,20)
    )


    elements.append(

        Paragraph(

            "CyberSentinel SOC Platform | Intelligent Security Analysis Engine",

            normal

        )

    )



    doc.build(
        elements
    )


    print(
        "Report generated:",
        file_path
    )