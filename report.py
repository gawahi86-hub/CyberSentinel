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
            "Your website has a strong security posture. Continue regular monitoring."
        )


    elif score <= 50:

        recommendations.append(
            "Review the identified security improvements to strengthen protection."
        )


    elif score <= 80:

        recommendations.append(
            "Prioritize fixing medium and high severity security weaknesses."
        )


    else:

        recommendations.append(
            "Immediate security review is required due to significant risks."
        )



    for issue in issues:


        title = issue.get(
            "title",
            issue.get(
                "name",
                ""
            )
        ).lower()



        if "cookie" in title:

            recommendations.append(
                "Protect cookies using Secure, HttpOnly and SameSite settings."
            )


        if "content" in title:

            recommendations.append(
                "Implement browser security headers to reduce attack risks."
            )


        if "port" in title:

            recommendations.append(
                "Review exposed services and close unnecessary network ports."
            )


    return list(set(recommendations))






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



    heading_style = ParagraphStyle(

        "heading",

        parent=styles["Heading2"],

        textColor=colors.HexColor(
            "#1e3a8a"
        )

    )



    normal = styles["Normal"]



    small_style = ParagraphStyle(

        "small",

        parent=normal,

        fontSize=9

    )



    elements=[]





    # ---------------------------------
    # COVER
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

            normal

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
    # EXECUTIVE REPORT
    # ---------------------------------


    elements.append(

        Paragraph(

            "Executive Security Summary",

            heading_style

        )

    )



    summary=[

        [
            "Website Safety Result",
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
            "Security Score",
            str(
                data.get(
                    "risk_score",
                    0
                )
            )
        ]

    ]



    table=Table(
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


    elements.append(table)


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
        Spacer(1,25)
    )






    # ---------------------------------
    # TECHNICAL INFORMATION
    # ---------------------------------


    elements.append(

        Paragraph(

            "Technical Security Information",

            heading_style

        )

    )



    technical=[

        [
            "Website",
            data.get("url","")
        ],

        [
            "IP Address",
            data.get("ip","")
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
            data.get("server","Unknown")
        ],

        [
            "Technology",
            data.get("technology","Unknown")
        ]

    ]



    tech_table=Table(
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
        Spacer(1,25)
    )






    # ---------------------------------
    # FINDINGS
    # ---------------------------------


    elements.append(

        Paragraph(

            "Security Findings Explained",

            heading_style

        )

    )



    issues=data.get(
        "issues",
        []
    )



    if issues:


        for issue in issues:


            elements.append(

                Paragraph(

                    "⚠️ "
                    +
                    issue.get(
                        "title",
                        issue.get(
                            "name",
                            ""
                        )
                    ),

                    normal

                )

            )


            elements.append(

                Paragraph(

                    "<b>What does this mean?</b><br>"
                    +
                    issue.get(
                        "simple_explanation",
                        issue.get(
                            "description",
                            ""
                        )
                    ),

                    small_style

                )

            )



            elements.append(

                Paragraph(

                    "<b>Why does this matter?</b><br>"
                    +
                    issue.get(
                        "business_impact",
                        "Security improvement recommended."
                    ),

                    small_style

                )

            )



            elements.append(

                Paragraph(

                    "<b>Technical Details:</b><br>"
                    +
                    issue.get(
                        "technical_explanation",
                        ""
                    ),

                    small_style

                )

            )


            elements.append(

                Paragraph(

                    "<b>CVSS:</b> "
                    +
                    str(
                        issue.get(
                            "cvss",
                            issue.get(
                                "cvss_score",
                                0
                            )
                        )
                    )
                    +
                    " | <b>Severity:</b> "
                    +
                    issue.get(
                        "severity",
                        ""
                    ),

                    small_style

                )

            )


            elements.append(
                Spacer(1,15)
            )


    else:


        elements.append(

            Paragraph(

                "No security vulnerabilities detected.",

                normal

            )

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

            normal

        )

    )



    doc.build(
        elements
    )