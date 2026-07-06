from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from datetime import datetime
import os

def generate_pdf(result):

    file_path = "reports/security_report.pdf"
    c = canvas.Canvas(file_path, pagesize=letter)

    width, height = letter
    y = height - 60

    # =========================
    # HEADER
    # =========================
    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(colors.darkblue)
    c.drawString(50, y, "CyberSentinel Security Report")

    y -= 20
    c.setFont("Helvetica", 9)
    c.setFillColor(colors.grey)
    c.drawString(50, y, f"Generated: {datetime.now()}")

    y -= 40

    # =========================
    # TARGET INFO
    # =========================
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(colors.black)
    c.drawString(50, y, "Target Information")

    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(60, y, f"URL: {result['url']}")
    y -= 15
    c.drawString(60, y, f"Domain: {result['domain']}")
    y -= 15
    c.drawString(60, y, f"IP: {result['ip']}")

    y -= 40

    # =========================
    # RISK
    # =========================
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Risk Assessment")

    y -= 20

    score = result["risk_score"]

    if result["safety_verdict"] == "SAFE":
        color = colors.green
    elif result["safety_verdict"] == "CAUTION":
        color = colors.orange
    else:
        color = colors.red

    c.setFillColor(color)
    c.drawString(60, y, f"{score}/100 - {result['safety_verdict']}")

    y -= 40

    # =========================
    # VULNERABILITIES
    # =========================
    c.setFont("Helvetica-Bold", 12)
    c.setFillColor(colors.black)
    c.drawString(50, y, "Vulnerabilities")

    y -= 20

    for issue in result["issues"]:
        c.setFillColor(colors.red)
        c.drawString(60, y, f"- {issue['name']}")
        y -= 15

    y -= 40

    # =========================
    # FINAL VERDICT
    # =========================
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Final Verdict")

    y -= 20

    if result["safety_verdict"] == "SAFE":
        color = colors.green
    elif result["safety_verdict"] == "CAUTION":
        color = colors.orange
    else:
        color = colors.red

    c.setFillColor(color)
    c.setFont("Helvetica", 10)
    c.drawString(60, y, result["final_summary"])

    y -= 40

    # =========================
    # FOOTER
    # =========================
    c.setFillColor(colors.grey)
    c.setFont("Helvetica", 8)
    c.drawString(50, 30, "CyberSentinel Automated Security Report")

    c.save()

    return file_path