from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from datetime import datetime


# -----------------------------
# AI RECOMMENDATION ENGINE
# -----------------------------
def generate_ai_recommendations(data):

    score = data.get("risk_score", 0)
    issues = data.get("issues", [])

    recommendations = []

    if score >= 85:
        recommendations.append("Maintain current security posture and continue monitoring regularly.")
        recommendations.append("Enable automated threat detection and SIEM integration.")
    elif score >= 60:
        recommendations.append("Strengthen missing security headers (CSP, HSTS, X-Frame-Options).")
        recommendations.append("Enable HTTPS enforcement across all endpoints.")
    else:
        recommendations.append("Immediate patching required for critical vulnerabilities.")
        recommendations.append("Perform full penetration testing and incident response review.")

    # Issue-based AI suggestions
    for issue in issues:
        name = issue.get("name", "").lower()

        if "ssl" in name:
            recommendations.append("Upgrade SSL/TLS configuration to TLS 1.2+ or TLS 1.3.")
        if "csp" in name:
            recommendations.append("Implement strict Content-Security-Policy headers.")
        if "clickjacking" in name:
            recommendations.append("Enable X-Frame-Options: DENY to prevent clickjacking attacks.")

    return list(set(recommendations))


# -----------------------------
# PDF GENERATOR
# -----------------------------
def generate_pdf(data):

    file_path = "reports/security_report.pdf"
    doc = SimpleDocTemplate(file_path, pagesize=A4)

    styles = getSampleStyleSheet()

    # -----------------------------
    # BRANDING STYLES
    # -----------------------------
    title_style = ParagraphStyle(
        "title",
        parent=styles["Title"],
        fontSize=24,
        textColor=colors.HexColor("#0b5394"),
        alignment=1,
        spaceAfter=10
    )

    brand_style = ParagraphStyle(
        "brand",
        parent=styles["Normal"],
        fontSize=12,
        textColor=colors.HexColor("#1f2937"),
        alignment=1,
        spaceAfter=20
    )

    header_style = ParagraphStyle(
        "header",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#111827"),
        spaceAfter=10
    )

    normal_style = styles["Normal"]

    elements = []

    # -----------------------------
    # BRAND HEADER
    # -----------------------------
    elements.append(Paragraph("🛡 CYBERSENTINEL", title_style))
    elements.append(Paragraph("SOC Security Intelligence Report", brand_style))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(f"Generated on: {datetime.now()}", normal_style))
    elements.append(Spacer(1, 15))

    # -----------------------------
    # TARGET INFO
    # -----------------------------
    elements.append(Paragraph("Target Overview", header_style))

    target_table = [
        ["URL", data.get("url", "")],
        ["IP Address", data.get("ip", "")],
        ["HTTP Status", str(data.get("http_status", ""))],
        ["Risk Score", str(data.get("risk_score", ""))],
        ["Verdict", data.get("safety_verdict", "")]
    ]

    t1 = Table(target_table)
    t1.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#dbeafe")),
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("PADDING", (0,0), (-1,-1), 6),
    ]))

    elements.append(t1)
    elements.append(Spacer(1, 20))

    # -----------------------------
    # SUMMARY
    # -----------------------------
    elements.append(Paragraph("Executive Summary", header_style))
    elements.append(Paragraph(data.get("final_summary", ""), normal_style))
    elements.append(Spacer(1, 15))

    # -----------------------------
    # VULNERABILITIES
    # -----------------------------
    elements.append(Paragraph("Security Vulnerabilities (CVSS Analysis)", header_style))

    issues = data.get("issues", [])

    if not issues:
        elements.append(Paragraph("No vulnerabilities detected.", normal_style))
    else:

        table_data = [["Issue", "CVSS", "Severity"]]

        for issue in issues:
            table_data.append([
                issue.get("name", ""),
                str(issue.get("cvss_score", "")),
                issue.get("severity", "")
            ])

        t2 = Table(table_data)

        t2.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1e3a8a")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#f8fafc")),
            ("PADDING", (0,0), (-1,-1), 6),
        ]))

        elements.append(t2)

    elements.append(Spacer(1, 20))

    # -----------------------------
    # AI RECOMMENDATIONS (NEW)
    # -----------------------------
    elements.append(Paragraph("AI Security Recommendations", header_style))

    recommendations = generate_ai_recommendations(data)

    for rec in recommendations:
        elements.append(Paragraph(f"• {rec}", normal_style))

    elements.append(Spacer(1, 20))

    # -----------------------------
    # FOOTER BRANDING
    # -----------------------------
    footer = Paragraph(
        "CyberSentinel SOC Platform • Intelligent Security Analysis Engine",
        brand_style
    )

    elements.append(footer)

    doc.build(elements)