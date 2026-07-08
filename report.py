# ---------------------------------
# CyberSentinel v2.1
# Professional SOC Security Report Generator
# ---------------------------------

import os

from datetime import datetime

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

from reportlab.lib.pagesizes import A4

from reportlab.lib import colors





# ---------------------------------
# AI SECURITY RECOMMENDATIONS
# ---------------------------------

def generate_ai_recommendations(data):

    recommendations = []


    score = data.get(
        "risk_score",
        0
    )


    if score <= 20:

        recommendations.append(
            "Maintain current security controls and perform regular vulnerability assessments."
        )


    elif score <= 50:

        recommendations.append(
            "Review identified weaknesses and improve security configurations."
        )


    elif score <= 80:

        recommendations.append(
            "Prioritize remediation of detected vulnerabilities."
        )


    else:

        recommendations.append(
            "Immediate security review and incident response actions are recommended."
        )



    for issue in data.get(
        "issues",
        []
    ):


        name = issue.get(
            "name",
            ""
        ).lower()



        if "cookie" in name:

            recommendations.append(
                "Enable Secure, HttpOnly and SameSite cookie attributes."
            )


        if "content" in name:

            recommendations.append(
                "Implement Content Security Policy to reduce script injection risks."
            )


        if "https" in name:

            recommendations.append(
                "Enable HTTPS enforcement and HSTS security policy."
            )


        if "port" in name:

            recommendations.append(
                "Disable unnecessary exposed services."
            )



    return list(
        set(recommendations)
    )







# ---------------------------------
# PDF GENERATOR
# ---------------------------------

def generate_pdf(data):


    base_dir = os.path.dirname(
        os.path.abspath(__file__)
    )


    reports = os.path.join(
        base_dir,
        "reports"
    )


    os.makedirs(
        reports,
        exist_ok=True
    )


    file_path = os.path.join(
        reports,
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

        alignment=1,

        fontSize=26,

        textColor=colors.HexColor(
            "#1d4ed8"
        )

    )



    heading_style = ParagraphStyle(

        "heading",

        parent=styles["Heading2"],

        textColor=colors.HexColor(
            "#1e40af"
        )

    )



    normal = styles["Normal"]



    elements = []





    # COVER

    elements.append(

        Paragraph(
            "🛡 CYBERSENTINEL SOC",
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

            "Generated: "
            +
            datetime.now().strftime(
                "%d %B %Y %H:%M:%S"
            ),

            normal

        )

    )


    elements.append(
        Spacer(1,20)
    )






    # SCAN INFORMATION

    elements.append(

        Paragraph(
            "Scan Information",
            heading_style
        )

    )



    scan_table = Table([

        [
            "Scanner",
            data.get(
                "scanner_version",
                "CyberSentinel v2.1"
            )
        ],

        [
            "Scan Time",
            data.get(
                "scan_time",
                "Unknown"
            )
        ],

        [
            "Status",
            data.get(
                "scan_status",
                "Success"
            )
        ]

    ])



    scan_table.setStyle(

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
        scan_table
    )


    elements.append(
        Spacer(1,20)
    )






    # SUMMARY

    elements.append(

        Paragraph(
            "Executive Summary",
            heading_style
        )

    )



    summary = Table([


        [
            "Risk Score",
            str(
                data.get(
                    "risk_score",
                    0
                )
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
            "Verdict",
            data.get(
                "safety_verdict",
                ""
            )
        ]

    ])



    summary.setStyle(

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
        summary
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







    # TECHNICAL INFORMATION

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


    technical = [


        [
            "Website",
            data.get(
                "url",
                ""
            )
        ],


        [
            "IP Address",
            str(
                data.get(
                    "ip",
                    ""
                )
            )
        ],


        [
            "HTTP Status",
            str(
                data.get(
                    "http_status",
                    ""
                )
            )
        ],


        [
            "SSL Certificate",
            str(
                ssl_data
            )
        ],


        [
            "Server",
            str(
                data.get(
                    "server",
                    ""
                )
            )
        ],


        [
            "Technology",
            str(
                data.get(
                    "technology",
                    ""
                )
            )
        ],


        [
            "Response Time",
            str(
                data.get(
                    "response_time",
                    0
                )
            )
            +
            " ms"
        ],


        [
            "Open Ports",
            str(
                data.get(
                    "ports",
                    []
                )
            )
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
        Spacer(1,20)
    )






    # FINDINGS

    elements.append(

        Paragraph(
            "Security Vulnerabilities & Improvements",
            heading_style
        )

    )



    issues = data.get(
        "issues",
        []
    )


    if issues:


        for issue in issues:


            elements.append(

                Paragraph(

                    "<b>Finding:</b> "
                    +
                    issue.get(
                        "name",
                        ""
                    ),

                    normal

                )

            )


            elements.append(

                Paragraph(

                    "<b>CVSS:</b> "
                    +
                    str(
                        issue.get(
                            "cvss",
                            0
                        )
                    ),

                    normal

                )

            )


            elements.append(

                Paragraph(

                    "<b>Severity:</b> "
                    +
                    issue.get(
                        "severity",
                        ""
                    ),

                    normal

                )

            )


            elements.append(

                Paragraph(

                    "<b>OWASP:</b> "
                    +
                    issue.get(
                        "owasp",
                        ""
                    ),

                    normal

                )

            )


            elements.append(

                Paragraph(

                    "<b>Affected Component:</b> "
                    +
                    issue.get(
                        "affected_component",
                        ""
                    ),

                    normal

                )

            )


            elements.append(

                Paragraph(

                    "<b>Impact:</b> "
                    +
                    issue.get(
                        "impact",
                        ""
                    ),

                    normal

                )

            )


            elements.append(

                Paragraph(

                    "<b>How To Fix:</b> "
                    +
                    issue.get(
                        "recommendation",
                        ""
                    ),

                    normal

                )

            )


            elements.append(

                Paragraph(

                    "<b>Technical Details:</b> "
                    +
                    issue.get(
                        "technical_explanation",
                        ""
                    ),

                    normal

                )

            )


            elements.append(
                Spacer(1,12)
            )



    else:


        elements.append(

            Paragraph(
                "No vulnerabilities detected.",
                normal
            )

        )







    # AI SECTION

    elements.append(
        Spacer(1,20)
    )


    elements.append(

        Paragraph(
            "AI Security Recommendations",
            heading_style
        )

    )



    for recommendation in generate_ai_recommendations(data):


        elements.append(

            Paragraph(

                "• "
                +
                recommendation,

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