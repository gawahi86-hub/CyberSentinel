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
    # HEADER + LOGO
    # =========================
    logo_path = "reports/logo.png"

    if os.path.exists(logo_path):
        c.drawImage(logo_path, 40, height - 80, width=50, height=50, mask='auto')

    c.setFillColor(colors.darkblue)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(110, height - 50, "CyberSentinel Security Report")

    c.setFont("Helvetica", 9)
    c.setFillColor(colors.grey)
    c.drawString(110, height - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    y -= 100

    # =========================
    # TARGET INFO
    # =========================
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "1. Target Information")

    y -= 25
    c.setFont("Helvetica", 10)

    c.drawString(60, y, f"URL: {result['url']}")
    y -= 15
    c.drawString(60, y, f"Domain: {result['domain']}")
    y -= 15
    c.drawString(60, y, f"IP Address: {result['ip']}")

    y -= 40

    # =========================
    # RISK SCORE + CVSS STYLE
    # =========================
    score = result["risk_score"]

    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "2. Risk Score (CVSS-Based Model)")

    y -= 25

    if score >= 80:
        level = "LOW RISK"
        color = colors.green
        cvss = 2.5
    elif score >= 50:
        level = "MEDIUM RISK"
        color = colors.orange
        cvss = 6.5
    else:
        level = "HIGH RISK"
        color = colors.red
        cvss = 9.2

    c.setFillColor(color)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(60, y, f"Score: {score}/100 | CVSS: {cvss} | {level}")

    y -= 40

    # =========================
    # VULNERABILITY TABLE (WITH CVSS PER ISSUE)
    # =========================
    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "3. Vulnerability Analysis (CVSS Mapping)")

    y -= 25

    # table header
    c.setFillColor(colors.lightgrey)
    c.rect(50, y, 500, 20, fill=1)

    c.setFillColor(colors.black)
    c.setFont("Helvetica-Bold", 9)
    c.drawString(55, y + 5, "Issue")
    c.drawString(260, y + 5, "CVSS")
    c.drawString(340, y + 5, "Severity")

    y -= 20

    c.setFont("Helvetica", 9)

    if result["issues"]:
        for issue in result["issues"]:

            if y < 120:
                c.showPage()
                y = height - 60

            name = issue["name"]

            # =========================
            # CVSS LOGIC PER ISSUE
            # =========================
            if "CSP" in name or "HSTS" in name:
                cvss_score = 8.5
                severity = "CRITICAL"
                color = colors.red
            elif "X-Content-Type" in name or "Referrer" in name:
                cvss_score = 6.5
                severity = "MEDIUM"
                color = colors.orange
            else:
                cvss_score = 4.0
                severity = "LOW"
                color = colors.green

            c.setFillColor(colors.black)
            c.drawString(55, y, name[:35])

            c.drawString(260, y, str(cvss_score))

            c.setFillColor(color)
            c.drawString(340, y, severity)

            y -= 15
    else:
        c.setFillColor(colors.green)
        c.drawString(60, y, "No vulnerabilities detected.")
        y -= 20

    y -= 40

    # =========================
    # FINAL VERDICT BOX
    # =========================
    c.setFillColor(colors.darkblue)
    c.rect(50, y, 500, 60, fill=1)

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(60, y + 40, "FINAL SECURITY VERDICT")

    c.setFont("Helvetica", 10)
    c.drawString(60, y + 20, result["final_summary"])

    y -= 80

    # =========================
    # FOOTER
    # =========================
    c.setFillColor(colors.grey)
    c.setFont("Helvetica", 8)
    c.drawString(50, 30, "CyberSentinel - CVSS-Based Automated Security Assessment Report")

    c.save()

    return file_path