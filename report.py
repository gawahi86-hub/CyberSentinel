import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


# ----------------------------
# GENERATE PDF REPORT (CLOUD SAFE)
# ----------------------------
def generate_pdf(result):
    try:
        # Ensure reports folder exists (Render-safe)
        reports_dir = "/tmp/reports"
        os.makedirs(reports_dir, exist_ok=True)

        domain = result.get("domain", "unknown")
        file_path = os.path.join(reports_dir, f"{domain}_report.pdf")

        c = canvas.Canvas(file_path, pagesize=letter)

        y = 750

        # TITLE
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, y, "CyberSentinel Security Report")
        y -= 40

        # BASIC INFO
        c.setFont("Helvetica", 12)
        c.drawString(50, y, f"Target URL: {result.get('url', 'N/A')}")
        y -= 20
        c.drawString(50, y, f"Domain: {domain}")
        y -= 20
        c.drawString(50, y, f"IP Address: {result.get('ip', 'N/A')}")
        y -= 30

        # RISK INFO
        c.drawString(50, y, f"Risk Score: {result.get('risk_score', 0)}/100")
        y -= 20
        c.drawString(50, y, f"Risk Level: {result.get('risk_level', 'Unknown')}")
        y -= 30

        # ISSUES
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Issues Found:")
        y -= 20

        c.setFont("Helvetica", 11)

        issues = result.get("issues", [])

        if issues:
            for issue in issues:
                c.drawString(60, y, f"- {issue}")
                y -= 15

                if y < 100:
                    c.showPage()
                    y = 750
        else:
            c.drawString(60, y, "No major issues detected")

        c.save()

        return file_path

    except Exception as e:
        print("PDF Generation Error:", e)
        return None