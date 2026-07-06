from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from datetime import datetime
import matplotlib.pyplot as plt
import os


def create_chart(low, medium, high):
    labels = ['Low', 'Medium', 'High']
    values = [low, medium, high]
    colors_list = ['green', 'orange', 'red']

    plt.figure(figsize=(4,3))
    plt.bar(labels, values, color=colors_list)
    plt.title("Risk Distribution")

    path = "risk_chart.png"
    plt.savefig(path)
    plt.close()

    return path


def generate_pdf(result):

    file_path = "CyberSentinel_Report.pdf"
    c = canvas.Canvas(file_path, pagesize=letter)
    width, height = letter

    # ======================
    # HEADER
    # ======================
    c.setFont("Helvetica-Bold", 18)
    c.setFillColor(colors.darkblue)
    c.drawString(140, height - 50, "CyberSentinel Security Report")

    c.setFont("Helvetica", 9)
    c.setFillColor(colors.black)
    c.drawString(200, height - 70,
                 f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ======================
    # EXECUTIVE SUMMARY
    # ======================
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, height - 120, "Executive Summary")

    c.setFont("Helvetica", 10)
    c.drawString(50, height - 145, f"Target: {result.get('url','')}")
    c.drawString(50, height - 160, f"Domain: {result.get('domain','')}")
    c.drawString(50, height - 175, f"Risk Score: {result.get('risk_score','')}/100")
    c.drawString(50, height - 190, f"Risk Level: {result.get('risk_level','')}")

    # ======================
    # ISSUES
    # ======================
    y = height - 230
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Detected Issues")

    y -= 20
    c.setFont("Helvetica", 10)

    issues = result.get("issues", [])
    if not issues:
        c.drawString(60, y, "No major issues detected")
    else:
        for i in issues:
            c.drawString(60, y, f"- {i}")
            y -= 15

    # ======================
    # RECOMMENDATIONS
    # ======================
    y -= 20
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, "Recommendations")

    y -= 20
    c.setFont("Helvetica", 10)

    recs = result.get("recommendations", [])
    if not recs:
        c.drawString(60, y, "No recommendations available")
    else:
        for r in recs:
            c.drawString(60, y, f"✔ {r}")
            y -= 15

    # ======================
    # PORT TABLE (CLEAN)
    # ======================
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

    # ======================
    # NEW PAGE - CHART
    # ======================
    chart_path = create_chart(
        result.get("low", 1),
        result.get("medium", 1),
        result.get("high", 1)
    )

    c.showPage()

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, height - 50, "Risk Visualization")

    c.drawImage(chart_path, 50, height - 300, width=400, height=250)

    # ======================
    # FOOTER
    # ======================
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(160, 30, "CyberSentinel • Security Intelligence Report")

    c.save()

    # cleanup chart file
    if os.path.exists(chart_path):
        os.remove(chart_path)

    return file_path