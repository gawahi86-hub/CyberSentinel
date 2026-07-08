import os

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)

from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4

from datetime import datetime



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
            "Maintain current security controls and continue regular security monitoring."
        )

        recommendations.append(
            "Perform periodic vulnerability assessments."
        )


    elif score <= 50:

        recommendations.append(
            "Review and fix identified security weaknesses."
        )

        recommendations.append(
            "Improve website security headers and configuration."
        )


    elif score <= 80:

        recommendations.append(
            "Immediate remediation is recommended for detected vulnerabilities."
        )

        recommendations.append(
            "Perform penetration testing and security configuration review."
        )


    else:

        recommendations.append(
            "Critical security issues require immediate attention."
        )

        recommendations.append(
            "Perform complete security audit and incident response review."
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


        if "content" in name or "csp" in name:

            recommendations.append(
                "Implement Content Security Policy to reduce script injection risks."
            )


        if "ssl" in name or "https" in name:

            recommendations.append(
                "Ensure strong TLS configuration and HTTPS enforcement."
            )


        if "port" in name:

            recommendations.append(
                "Close unnecessary exposed network services."
            )



    return list(
        set(recommendations)
    )





# ---------------------------------
# PDF GENERATOR
# ---------------------------------

def generate_pdf(data):


    # FIXED REPORT LOCATION

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

        textColor=colors.HexColor(
            "#0b5394"
        )

    )



    heading_style = ParagraphStyle(

        "heading",

        parent=styles["Heading2"],

        textColor=colors.HexColor(
            "#1e3a8a"
        )

    )



    normal = styles["Normal"]



    elements = []



    # COVER

    elements.append(
        Paragraph(
            "🛡 CYBERSENTINEL",
            title_style
        )
    )


    elements.append(
        Spacer(
            1,
            15
        )
    )


    elements.append(
        Paragraph(
            "Professional Website Security Assessment Report",
            normal
        )
    )


    elements.append(
        Spacer(
            1,
            20
        )
    )


    elements.append(
        Paragraph(
            "Generated: " + str(datetime.now()),
            normal
        )
    )


    elements.append(
        Spacer(
            1,
            25
        )
    )



    # SUMMARY

    elements.append(
        Paragraph(
            "Executive Summary",
            heading_style
        )
    )


    summary = [

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

    ]



    table = Table(
        summary
    )


    table.setStyle(

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
        table
    )


    elements.append(
        Spacer(
            1,
            15
        )
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
        Spacer(
            1,
            20
        )
    )



    # TECHNICAL DATA

    elements.append(
        Paragraph(
            "Technical Information",
            heading_style
        )
    )


    technical = [

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
            "SSL Enabled",
            str(data.get("ssl",""))
        ],

        [
            "Server",
            data.get("server","")
        ],

        [
            "Technology",
            data.get("technology","")
        ],

        [
            "Response Time",
            str(data.get("response_time",""))+" ms"
        ]

    ]



    tech_table = Table(
        technical
    )


    tech_table.setStyle(

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
        tech_table
    )


    elements.append(
        Spacer(
            1,
            20
        )
    )



    # SECURITY FINDINGS

    elements.append(
        Paragraph(
            "Security Vulnerabilities & CVSS Analysis",
            heading_style
        )
    )


    issues = data.get(
        "issues",
        []
    )


    if issues:


        vuln = [

            [
                "Issue",
                "Severity",
                "CVSS",
                "Recommendation"
            ]

        ]


        for issue in issues:


            vuln.append(

                [

                    issue.get(
                        "name",
                        ""
                    ),

                    issue.get(
                        "severity",
                        ""
                    ),

                    str(
                        issue.get(
                            "cvss",
                            0
                        )
                    ),

                    issue.get(
                        "recommendation",
                        ""
                    )

                ]

            )



        vuln_table = Table(
            vuln,
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


    else:

        elements.append(
            Paragraph(
                "No vulnerabilities detected.",
                normal
            )
        )



    elements.append(
        Spacer(
            1,
            20
        )
    )



    # AI RECOMMENDATIONS

    elements.append(
        Paragraph(
            "AI Security Recommendations",
            heading_style
        )
    )


    for rec in generate_ai_recommendations(data):

        elements.append(
            Paragraph(
                "• " + rec,
                normal
            )
        )



    elements.append(
        Spacer(
            1,
            20
        )
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