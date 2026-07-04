import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def generate_pdf(result):
    try:
        # Safe folder for cloud deployments (Render / Linux servers)
        reports_dir = "/tmp/reports"
        os.makedirs(reports_dir, exist_ok=True)

        domain = result.get("domain", "unknown")
        file_path = os.path.join(reports_dir, f"{domain}_report.pdf")

        # Create PDF
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

        if isinstance(issues, list) and len(issues) > 0:
            for issue in issues:
                if y < 80:
                    c.showPage()
                    y = 750
                    c.setFont("Helvetica", 11)

                c.drawString(60, y, f"- {issue}")
                y -= 15
        else:
            c.drawString(60, y, "No major issues detected")

        # FINALIZE PDF
        c.save()

        # Safety check
        if os.path.exists(file_path):
            return file_path

        return None

    except Exception as e:
        print("PDF Generation Error:", e)
        return None