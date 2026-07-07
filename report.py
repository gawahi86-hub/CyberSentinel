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

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4

from datetime import datetime
import os



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
            "Maintain current security controls and perform regular security monitoring."
        )

        recommendations.append(
            "Continue vulnerability assessments to maintain security posture."
        )


    elif score <= 50:

        recommendations.append(
            "Review and fix medium severity security weaknesses."
        )

        recommendations.append(
            "Improve HTTP security headers and web application configuration."
        )


    elif score <= 80:

        recommendations.append(
            "Immediate remediation is recommended for identified vulnerabilities."
        )

        recommendations.append(
            "Perform penetration testing and security configuration review."
        )


    else:

        recommendations.append(
            "Critical vulnerabilities require immediate attention."
        )

        recommendations.append(
            "Perform complete security audit and incident response assessment."
        )



    for issue in issues:


        name = issue.get(
            "name",
            ""
        ).lower()



        if "ssl" in name or "https" in name:

            recommendations.append(
                "Upgrade SSL/TLS configuration and enforce secure HTTPS communication."
            )


        if "csp" in name:

            recommendations.append(
                "Implement a strict Content Security Policy to reduce XSS risks."
            )


        if "cookie" in name:

            recommendations.append(
                "Secure cookies using Secure, HttpOnly and SameSite attributes."
            )


        if "port" in name:

            recommendations.append(
                "Close unnecessary exposed ports and restrict external access."
            )



    return list(
        set(recommendations)
    )





# ---------------------------------
# PDF GENERATOR
# ---------------------------------

def generate_pdf(data):


    file_path = (
        "reports/security_report.pdf"
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


    subtitle_style = ParagraphStyle(

        "subtitle",

        parent=styles["Normal"],

        alignment=1,

        fontSize=13

    )



    heading_style = ParagraphStyle(

        "heading",

        parent=styles["Heading2"],

        textColor=colors.HexColor(
            "#1e3a8a"
        )

    )


    normal = styles["Normal"]



    elements=[]



    # ---------------------------------
    # COVER PAGE
    # ---------------------------------


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
            subtitle_style
        )
    )


    elements.append(
        Spacer(1,20)
    )


    elements.append(
        Paragraph(
            f"Generated: {datetime.now()}",
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


    summary_table=[

        [
            "Security Verdict",
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



    t=Table(
        summary_table,
        colWidths=[150,250]
    )


    t.setStyle(

        TableStyle([

            (
                "GRID",
                (0,0),
                (-1,-1),
                0.5,
                colors.grey
            ),

            (
                "BACKGROUND",
                (0,0),
                (0,-1),
                colors.HexColor(
                    "#dbeafe"
                )
            )

        ])

    )


    elements.append(t)


    elements.append(
        Spacer(1,20)
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
    # TECHNICAL DETAILS
    # ---------------------------------


    elements.append(
        Paragraph(
            "Technical Information",
            heading_style
        )
    )


    technical=[

        [
            "Website",
            data.get(
                "url",
                ""
            )
        ],

        [
            "IP Address",
            data.get(
                "ip",
                ""
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
            "SSL Enabled",
            str(
                data.get(
                    "ssl",
                    False
                )
            )
        ],

        [
            "Server",
            data.get(
                "server",
                "Unknown"
            )
        ],

        [
            "Technology",
            data.get(
                "technology",
                "Unknown"
            )
        ],

        [
            "Response Time",
            str(
                data.get(
                    "response_time",
                    0
                )
            )+" ms"
        ]

    ]



    t2=Table(
        technical,
        colWidths=[150,250]
    )


    t2.setStyle(

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


    elements.append(t2)


    elements.append(
        Spacer(1,20)
    )





    # ---------------------------------
    # VULNERABILITY REPORT
    # ---------------------------------


    elements.append(
        Paragraph(
            "Security Findings & CVSS Analysis",
            heading_style
        )
    )



    issues=data.get(
        "issues",
        []
    )



    if issues:


        table=[

            [
                "Issue",
                "Severity",
                "CVSS",
                "Impact",
                "Fix"
            ]

        ]


        for issue in issues:


            table.append(

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
                            issue.get(
                                "cvss_score",
                                ""
                            )
                        )
                    ),


                    issue.get(
                        "description",
                        ""
                    ),


                    issue.get(
                        "recommendation",
                        issue.get(
                            "fix",
                            ""
                        )
                    )

                ]

            )



        vuln_table=Table(
            table,
            repeatRows=1
        )


        vuln_table.setStyle(

            TableStyle([

                (
                    "BACKGROUND",
                    (0,0),
                    (-1,0),
                    colors.HexColor(
                        "#1e3a8a"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0,0),
                    (-1,0),
                    colors.white
                ),

                (
                    "GRID",
                    (0,0),
                    (-1,-1),
                    0.5,
                    colors.grey
                ),

                (
                    "FONTSIZE",
                    (0,0),
                    (-1,-1),
                    8
                )

            ])

        )


        elements.append(
            vuln_table
        )


    else:

        elements.append(
            Paragraph(
                "No security vulnerabilities detected.",
                normal
            )
        )



    elements.append(
        Spacer(1,20)
    )





    # ---------------------------------
    # PORTS
    # ---------------------------------

    elements.append(
        Paragraph(
            "Open Ports",
            heading_style
        )
    )


    ports=data.get(
        "ports",
        []
    )


    elements.append(

        Paragraph(

            str(ports)
            if ports
            else
            "No exposed common ports detected.",

            normal

        )

    )



    elements.append(
        Spacer(1,20)
    )





    # ---------------------------------
    # AI RECOMMENDATIONS
    # ---------------------------------


    elements.append(
        Paragraph(
            "AI Security Recommendations",
            heading_style
        )
    )


    for rec in generate_ai_recommendations(data):

        elements.append(

            Paragraph(
                "• "+rec,
                normal
            )

        )



    elements.append(
        Spacer(1,25)
    )



    elements.append(

        Paragraph(

            "CyberSentinel SOC Platform | Intelligent Security Analysis Engine",

            subtitle_style

        )

    )



    doc.build(
        elements
    )