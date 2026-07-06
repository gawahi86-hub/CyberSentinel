from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime
import matplotlib.pyplot as plt


# =========================
# CREATE RISK CHART IMAGE
# =========================
def create_chart(low, medium, high):
    labels = ['Low', 'Medium', 'High']
    values = [low, medium, high]
    colors_list = ['green', 'orange', 'red']

    plt.figure(figsize=(4,3))
    plt.bar(labels, values, color=colors_list)
    plt.title("Risk Distribution")

    chart_path = "risk_chart.png"
    plt.savefig(chart_path)
    plt.close()

    return chart_path


# =========================
# PDF GENERATOR
# =========================
def generate_pdf(result):

    file_path = "CyberSentinel_Report.pdf"
    c = canvas.Canvas(file_path, pagesize=letter)
    width, height = letter

    # =========================
    # HEADER
    # =========================
    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(colors.darkblue)
    c.drawString(150, height - 50, "CyberSentinel Security Report")

    c.setFont("Helvetica", 9)
    c.setFillColor(colors.black)
    c.drawString(200, height - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # =========================
    # EXECUTIVE SUMMARY PAGE
    # =========================
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 120, "Executive Summary")

    c.setFont("Helvetica", 10)
    c.drawString(50, height - 150, f"Target: {result.get('url','')}")
    c.drawString(50, height - 165, f"Domain: {result.get('domain','')}")
    c.drawString(50, height - 180, f"Risk Score: {result.get('risk_score','')}/100")
    c.drawString(50, height - 195, f"Risk Level: {result.get('risk_level','')}")

    # =========================
    # RISK LEVEL MATRIX
    # =========================
    y = height - 240
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Risk Severity Matrix")

    c.setFont("Helvetica", 10)
    matrix = [
        ["0-40", "LOW", "Minimal risk"],
        ["41-70", "MEDIUM", "Moderate risk"],
        ["71-100", "HIGH", "Critical risk"]
    ]

    y -= 20
    for row in matrix:
        c.drawString(60, y, f"{row[0]}  |  {row[1]}  |  {row[2]}")
        y -= 15

    # =========================
    # ISSUES
    # =========================
    y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Detected Issues")

    y -= 20
    c.setFont("Helvetica", 10)

    issues = result.get("issues", [])
    if not issues:
        c.drawString(60, y, "No major issues detected")
        y -= 15
    else:
        for i in issues:
            c.drawString(60, y, f"- {i}")
            y -= 15

    # =========================
    # PORT TABLE
    # =========================
    y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Port Scan Results")

    y -= 20
    c.setFont("Helvetica", 10)

    ports = result.get("ports", [])

    if ports:
        c.drawString(60, y, "Port | Service | Status")
        y -= 15

        for p in ports:
            line = f"{p['port']} | {p['service']} | {p['status']}"
            c.drawString(60, y, line)
            y -= 15
    else:
        c.drawString(60, y, "No port data available")

    # =========================
    # CHART SECTION (NEW)
    # =========================
    chart_path = create_chart(
        result.get("low", 1),
        result.get("medium", 1),
        result.get("high", 1)
    )

    c.showPage()
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 50, "Risk Visualization")

    c.drawImage(chart_path, 50, height - 300, width=400, height=250)

    # =========================
    # FOOTER
    # =========================
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(170, 30, "CyberSentinel • Enterprise Security Report")

    c.save()
    return file_path