import os

from datetime import datetime

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)

from reportlab.lib.styles import (
    getSampleStyleSheet,
    ParagraphStyle
)

from reportlab.lib.pagesizes import A4

from reportlab.lib import colors

from reportlab.lib.units import inch





# ==================================================
# CyberSentinel Professional PDF Report Engine
# ==================================================





# ==================================================
# AI SECURITY RECOMMENDATION ENGINE
# ==================================================

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

            "Maintain current security controls and perform regular vulnerability assessments."

        )


        recommendations.append(

            "Continue monitoring website security posture."

        )



    elif score <= 50:


        recommendations.append(

            "Resolve identified medium-risk security weaknesses."

        )


        recommendations.append(

            "Improve HTTP security headers and website configuration."

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

            "Critical vulnerabilities require immediate security action."

        )


        recommendations.append(

            "Perform full security audit and incident response assessment."

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




        if "content" in name or "policy" in name:


            recommendations.append(

                "Implement Content Security Policy to reduce script injection attacks."

            )




        if "port" in name:


            recommendations.append(

                "Review exposed network services and close unnecessary ports."

            )




        if "https" in name or "transport" in name:


            recommendations.append(

                "Enforce HTTPS and maintain strong TLS configuration."

            )




    return list(

        set(

            recommendations

        )

    )






# ==================================================
# PDF FOOTER
# ==================================================

def add_page_number(canvas, doc):


    canvas.saveState()



    canvas.setFont(

        "Helvetica",

        8

    )



    canvas.drawString(

        40,

        20,

        "CyberSentinel SOC Security Platform"

    )



    canvas.drawRightString(

        550,

        20,

        "Page %d" % doc.page

    )



    canvas.restoreState()
    # ==================================================
# PDF GENERATOR
# ==================================================

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

        bottomMargin=50

    )






    styles = getSampleStyleSheet()





    title_style = ParagraphStyle(

        "CyberSentinelTitle",

        parent=styles["Title"],

        fontSize=26,

        alignment=1,

        textColor=colors.HexColor(

            "#1d4ed8"

        )

    )





    subtitle_style = ParagraphStyle(

        "Subtitle",

        parent=styles["Normal"],

        fontSize=13,

        alignment=1

    )





    heading_style = ParagraphStyle(

        "Heading",

        parent=styles["Heading2"],

        textColor=colors.HexColor(

            "#1e40af"

        )

    )





    normal = styles["Normal"]





    elements = []







    # ==================================================
    # COVER PAGE
    # ==================================================


    elements.append(

        Spacer(

            1,

            40

        )

    )





    elements.append(

        Paragraph(

            "🛡 CyberSentinel",

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

            subtitle_style

        )

    )




    elements.append(

        Spacer(

            1,

            30

        )

    )





    cover_data = [


        [

            "Report Generated",

            str(datetime.now())

        ],



        [

            "Target Website",

            data.get(

                "url",

                ""

            )

        ],



        [

            "Report Type",

            "Automated SOC Security Assessment"

        ]

    ]





    cover_table = Table(

        cover_data

    )




    cover_table.setStyle(

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

        cover_table

    )




    elements.append(

        Spacer(

            1,

            30

        )

    )







    elements.append(

        Paragraph(

            "CyberSentinel Security Operations Center",

            heading_style

        )

    )




    elements.append(

        Paragraph(

            "This report provides an automated security analysis including vulnerabilities, CVSS ratings, risk classification and recommended improvements.",

            normal

        )

    )





    elements.append(

        PageBreak()

    )








    # ==================================================
    # EXECUTIVE SUMMARY
    # ==================================================


    elements.append(

        Paragraph(

            "Executive Security Summary",

            heading_style

        )

    )




    summary_table = Table([


        [

            "Risk Score",

            str(

                data.get(

                    "risk_score",

                    0

                )

            ) + "/100"

        ],



        [

            "Security Grade",

            data.get(

                "security_grade",

                "N/A"

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

            "Final Verdict",

            data.get(

                "safety_verdict",

                ""

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
        # ==================================================
    # TECHNICAL INFORMATION
    # ==================================================

    elements.append(

        Paragraph(

            "Technical Information",

            heading_style

        )

    )



    technical_data = [


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

                    "Unknown"

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

            ) + " ms"

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





    technical_table = Table(

        technical_data

    )




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

        Spacer(

            1,

            20

        )

    )







    # ==================================================
    # VULNERABILITY ANALYSIS
    # ==================================================

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



        vulnerability_data = [

            [

                "Issue",

                "Severity",

                "CVSS",

                "Recommendation"

            ]

        ]




        for issue in issues:


            vulnerability_data.append(

                [

                    issue.get(

                        "name",

                        ""

                    ),



                    issue.get(

                        "severity",

                        "INFO"

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





        vulnerability_table = Table(

            vulnerability_data,

            repeatRows=1

        )





        vulnerability_table.setStyle(

            TableStyle([


                (

                    "GRID",

                    (0,0),

                    (-1,-1),

                    0.5,

                    colors.grey

                ),



                (

                    "VALIGN",

                    (0,0),

                    (-1,-1),

                    "TOP"

                )

            ])

        )





        elements.append(

            vulnerability_table

        )





    else:



        elements.append(

            Paragraph(

                "No security vulnerabilities detected.",

                normal

            )

        )





    elements.append(

        Spacer(

            1,

            20

        )

    )






    # ==================================================
    # DETAILED FINDINGS
    # ==================================================

    elements.append(

        Paragraph(

            "Detailed Findings",

            heading_style

        )

    )




    for issue in issues:



        elements.append(

            Paragraph(

                "⚠ " +

                issue.get(

                    "name",

                    ""

                ),

                normal

            )

        )



        elements.append(

            Paragraph(

                "Severity: "

                +

                issue.get(

                    "severity",

                    ""

                )

                +

                " | CVSS: "

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

                issue.get(

                    "description",

                    ""

                ),

                normal

            )

        )



        elements.append(

            Spacer(

                1,

                10

            )

        )
            # ==================================================
    # AI SECURITY RECOMMENDATIONS
    # ==================================================

    elements.append(

        Paragraph(

            "AI Security Recommendations",

            heading_style

        )

    )




    recommendations = generate_ai_recommendations(

        data

    )




    for recommendation in recommendations:


        elements.append(

            Paragraph(

                "• " + recommendation,

                normal

            )

        )



        elements.append(

            Spacer(

                1,

                5

            )

        )






    elements.append(

        Spacer(

            1,

            20

        )

    )





    # ==================================================
    # FINAL FOOTER MESSAGE
    # ==================================================

    elements.append(

        Paragraph(

            "CyberSentinel SOC Platform | Intelligent Website Security Analysis Engine",

            normal

        )

    )






    # ==================================================
    # BUILD PDF
    # ==================================================

    doc.build(

        elements,

        onFirstPage=add_page_number,

        onLaterPages=add_page_number

    )



    print(

        "Professional security report generated:",

        file_path

    )