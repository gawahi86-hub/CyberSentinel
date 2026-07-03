import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


# ----------------------------
# GENERATE PDF REPORT
# ----------------------------
def generate_pdf(result):
    # Ensure reports folder exists
    os.makedirs("reports", exist_ok=True)

    file_path = f"reports/{result['domain']}_report.pdf"

    c = canvas.Canvas(file_path, pagesize=letter)

    y = 750

    # TITLE
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "CyberSentinel Security Report")

    y -= 40

    # BASIC INFO
    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"Target URL: {result['url']}")
    y -= 20
    c.drawString(50, y, f"Domain: {result['domain']}")
    y -= 20
    c.drawString(50, y, f"IP Address: {result['ip']}")
    y -= 20

    # RISK INFO
    c.drawString(50, y, f"Risk Score: {result['risk_score']}/100")
    y -= 20
    c.drawString(50, y, f"Risk Level: {result['risk_level']}")
    y -= 30

    # ISSUES
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Issues Found:")
    y -= 20

    c.setFont("Helvetica", 11)

    if result["issues"]:
        for issue in result["issues"]:
            c.drawString(60, y, f"- {issue}")
            y -= 15
            if y < 100:
                c.showPage()
                y = 750
    else:
        c.drawString(60, y, "No major issues detected")

    # FINAL SAVE
    c.save()

    return file_path