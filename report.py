from reportlab.lib import colors
from reportlab.pdfgen import canvas

def generate_pdf(result):

    file_path = "reports/security_report.pdf"
    c = canvas.Canvas(file_path)

    y = 800

    # =========================
    # TITLE
    # =========================
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "CyberSentinel Security Report")

    y -= 40

    # =========================
    # BASIC INFO
    # =========================
    c.setFont("Helvetica", 11)
    c.drawString(50, y, f"Target URL: {result['url']}")
    y -= 20
    c.drawString(50, y, f"Domain: {result['domain']}")
    y -= 20
    c.drawString(50, y, f"IP Address: {result['ip']}")
    y -= 20
    c.drawString(50, y, f"Risk Score: {result['risk_score']}/100")
    y -= 20
    c.drawString(50, y, f"Risk Level: {result['risk_level']}")

    y -= 40

    # =========================
    # FINAL SUMMARY (NEW ADDITION)
    # =========================
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Final Security Summary")

    y -= 25

    summary = result.get("final_summary", "No summary available.")

    if result["risk_score"] >= 80:
        color = colors.green
    elif result["risk_score"] >= 50:
        color = colors.orange
    else:
        color = colors.red

    c.setFillColor(color)
    c.setFont("Helvetica", 10)
    c.drawString(50, y, summary)

    y -= 30

    # =========================
    # AI NOTE
    # =========================
    c.setFillColor(colors.grey)
    c.drawString(50, y, "AI-driven automated security analysis based on system scanning.")

    c.save()

    return file_path