from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime
import os


def risk_color(level):
    if level == "LOW":
        return colors.green
    elif level == "MEDIUM":
        return colors.orange
    else:
        return colors.red


def generate_pdf(result):

    file_path = "CyberSentinel_Report.pdf"
    c = canvas.Canvas(file_path, pagesize=letter)
    width, height = letter

    # =========================
    # COVER HEADER
    # =========================
    c.setFillColor(colors.darkblue)
    c.setFont("Helvetica-Bold", 20)
    c.drawString(150, height - 60, "CyberSentinel Security Report")

    c.setFont("Helvetica", 10)
    c.setFillColor(colors.black)
    c.drawString(190, height - 80, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # =========================
    # RISK BADGE
    # =========================
    level = result.get("risk_level", "HIGH")
    score = result.get("risk_score", 0)

    c.setFillColor(risk_color(level))
    c.rect(50, height - 130, 500, 30, fill=1)

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(60, height - 120, f"Risk Level: {level}   |   Score: {score}/100")

    # =========================
    # TARGET INFO BOX
    # =========================
    c.setFillColor(colors.lightgrey)
    c.rect(50, height - 200, 500, 50, fill=1)

    c.setFillColor(colors.black)
    c.setFont("Helvetica", 10)
    c.drawString(60, height - 180, f"Target URL: {result.get('url','')}")
    c.drawString(60, height - 195, f"Domain: {result.get('domain','')}")

    # =========================
    # ISSUES SECTION
    # =========================
    y = height - 240

    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(colors.black)
    c.drawString(50, y, "Vulnerability Issues")

    y -= 20
    c.setFont("Helvetica", 10)

    issues = result.get("issues", [])

    if not issues:
        c.setFillColor(colors.green)
        c.drawString(60, y, "✔ No major issues detected")
    else:
        for issue in issues:

            # color per issue severity style
            if "Missing" in issue:
                c.setFillColor(colors.orange)
            else:
                c.setFillColor(colors.red)

            c.drawString(60, y, f"• {issue}")
            y -= 15

            if y < 120:
                c.showPage()
                y = height - 50

    # =========================
    # RECOMMENDATIONS
    # =========================
    y -= 20
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Security Recommendations")

    y -= 20
    c.setFont("Helvetica", 10)

    recs = [
        "Enable Content-Security-Policy",
        "Enable HSTS (HTTPS enforcement)",
        "Add security headers",
        "Fix SSL configuration if invalid"
    ]

    for r in recs:
        c.setFillColor(colors.blue)
        c.drawString(60, y, f"✔ {r}")
        y -= 15

    # =========================
    # FOOTER
    # =========================
    c.setFont("Helvetica-Oblique", 9)
    c.setFillColor(colors.grey)
    c.drawString(180, 30, "CyberSentinel • Professional Security Intelligence Report")

    c.save()
    return file_path