import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

# ---------------------------------------------------------------------------
# Color palette
# ---------------------------------------------------------------------------

C_BG       = colors.HexColor("#0a0805")
C_CARD     = colors.HexColor("#120f0a")
C_RED      = colors.HexColor("#ef4444")
C_ORANGE   = colors.HexColor("#f97316")
C_AMBER    = colors.HexColor("#f59e0b")
C_GREEN    = colors.HexColor("#22c55e")
C_BLUE     = colors.HexColor("#3b82f6")
C_TEXT     = colors.HexColor("#f5f0eb")
C_MUTED    = colors.HexColor("#94a3b8")
C_BORDER   = colors.HexColor("#1f1a14")
C_WHITE    = colors.white
C_BLACK    = colors.black

SEVERITY_COLORS = {
    "Critical": C_RED,
    "High":     C_ORANGE,
    "Medium":   C_AMBER,
    "Low":      C_BLUE,
    "Info":     C_MUTED,
}

# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------

def _build_styles():
    base = getSampleStyleSheet()

    styles = {
        "title": ParagraphStyle(
            "title",
            fontName="Helvetica-Bold",
            fontSize=28,
            textColor=C_TEXT,
            spaceAfter=6,
            alignment=TA_LEFT,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            fontName="Helvetica",
            fontSize=12,
            textColor=C_MUTED,
            spaceAfter=4,
            alignment=TA_LEFT,
        ),
        "h1": ParagraphStyle(
            "h1",
            fontName="Helvetica-Bold",
            fontSize=16,
            textColor=C_RED,
            spaceBefore=16,
            spaceAfter=8,
        ),
        "h2": ParagraphStyle(
            "h2",
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=C_AMBER,
            spaceBefore=10,
            spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body",
            fontName="Helvetica",
            fontSize=9,
            textColor=C_TEXT,
            spaceAfter=4,
            leading=14,
        ),
        "body_muted": ParagraphStyle(
            "body_muted",
            fontName="Helvetica",
            fontSize=8,
            textColor=C_MUTED,
            spaceAfter=3,
            leading=12,
        ),
        "mono": ParagraphStyle(
            "mono",
            fontName="Courier",
            fontSize=8,
            textColor=C_GREEN,
            spaceAfter=3,
            leading=12,
            backColor=C_CARD,
        ),
        "badge_critical": ParagraphStyle(
            "badge_critical",
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=C_WHITE,
            alignment=TA_CENTER,
        ),
        "disclaimer": ParagraphStyle(
            "disclaimer",
            fontName="Helvetica-Oblique",
            fontSize=7,
            textColor=C_MUTED,
            alignment=TA_CENTER,
            leading=10,
        ),
        "centered": ParagraphStyle(
            "centered",
            fontName="Helvetica",
            fontSize=10,
            textColor=C_TEXT,
            alignment=TA_CENTER,
        ),
    }
    return styles


# ---------------------------------------------------------------------------
# Page template with header/footer
# ---------------------------------------------------------------------------

class _PageTemplate:
    def __init__(self, target_info: str, classification: str = "CONFIDENTIAL"):
        self.target_info    = target_info
        self.classification = classification
        self.page_count     = 0

    def __call__(self, canvas, doc):
        self.page_count += 1
        canvas.saveState()

        W, H = A4

        # Top bar
        canvas.setFillColor(C_RED)
        canvas.rect(0, H - 28, W, 28, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(1.5 * cm, H - 18, "AutoSEC // SECURITY INTELLIGENCE REPORT")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(W - 1.5 * cm, H - 18, f"[{self.classification}]")

        # Bottom bar
        canvas.setFillColor(C_CARD)
        canvas.rect(0, 0, W, 22, fill=1, stroke=0)
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica", 7)
        canvas.drawString(1.5 * cm, 7,
            "AUTHORIZED USE ONLY — AI-generated findings require review by a qualified security professional.")
        canvas.drawRightString(W - 1.5 * cm, 7, f"Page {doc.page}")

        # Left border accent
        canvas.setFillColor(C_RED)
        canvas.rect(0, 22, 3, H - 50, fill=1, stroke=0)

        canvas.restoreState()


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _cover_page(styles: dict, target: str, org: str, risk_score: int) -> list:
    date_str = datetime.now().strftime("%B %d, %Y  %H:%M UTC")
    risk_color = (
        C_RED    if risk_score >= 75 else
        C_ORANGE if risk_score >= 50 else
        C_AMBER  if risk_score >= 25 else
        C_GREEN
    )
    risk_label = (
        "CRITICAL" if risk_score >= 75 else
        "HIGH"     if risk_score >= 50 else
        "MEDIUM"   if risk_score >= 25 else
        "LOW"
    )

    elements = [
        Spacer(1, 3 * cm),
        Paragraph("AutoSEC", ParagraphStyle(
            "logo", fontName="Helvetica-Bold", fontSize=48,
            textColor=C_RED, alignment=TA_LEFT,
        )),
        Paragraph("Autonomous Security Intelligence Platform", styles["subtitle"]),
        Spacer(1, 0.5 * cm),
        HRFlowable(width="100%", thickness=1, color=C_RED, spaceAfter=20),

        Paragraph("SECURITY INTELLIGENCE REPORT", ParagraphStyle(
            "rep_title", fontName="Helvetica-Bold", fontSize=20,
            textColor=C_TEXT, spaceAfter=6,
        )),
        Spacer(1, 0.5 * cm),

        # Info table
        Table([
            [Paragraph("Target:", styles["body_muted"]),
             Paragraph(str(target)[:80], styles["body"])],
            [Paragraph("Organization:", styles["body_muted"]),
             Paragraph(str(org) or "Not specified", styles["body"])],
            [Paragraph("Generated:", styles["body_muted"]),
             Paragraph(date_str, styles["body"])],
            [Paragraph("Classification:", styles["body_muted"]),
             Paragraph("CONFIDENTIAL", ParagraphStyle(
                 "conf", fontName="Helvetica-Bold", fontSize=9,
                 textColor=C_RED,
             ))],
        ], colWidths=[4 * cm, 12 * cm],
           style=TableStyle([
               ("BACKGROUND", (0, 0), (-1, -1), C_CARD),
               ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_CARD, C_BG]),
               ("TEXTCOLOR", (0, 0), (-1, -1), C_TEXT),
               ("FONTSIZE", (0, 0), (-1, -1), 9),
               ("TOPPADDING", (0, 0), (-1, -1), 6),
               ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
               ("LEFTPADDING", (0, 0), (-1, -1), 10),
               ("LINEBELOW", (0, -1), (-1, -1), 0.5, C_BORDER),
           ])),

        Spacer(1, 1 * cm),

        # Risk score
        Table([[
            Paragraph(f"OVERALL RISK SCORE", styles["body_muted"]),
            Paragraph(f"{risk_score}/100", ParagraphStyle(
                "risk_num", fontName="Helvetica-Bold", fontSize=36,
                textColor=risk_color, alignment=TA_RIGHT,
            )),
            Paragraph(risk_label, ParagraphStyle(
                "risk_lbl", fontName="Helvetica-Bold", fontSize=14,
                textColor=risk_color, alignment=TA_RIGHT,
            )),
        ]], colWidths=[8 * cm, 4 * cm, 4 * cm],
           style=TableStyle([
               ("BACKGROUND", (0, 0), (-1, -1), C_CARD),
               ("LINEABOVE", (0, 0), (-1, 0), 2, risk_color),
               ("TOPPADDING", (0, 0), (-1, -1), 12),
               ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
               ("LEFTPADDING", (0, 0), (-1, -1), 12),
               ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
           ])),

        Spacer(1, 0.5 * cm),
        Paragraph(
            "⚠ AUTHORIZED USE ONLY — This report contains sensitive security information. "
            "Only use findings on systems you own or have explicit written permission to test. "
            "All AI-generated findings require review by a qualified security professional.",
            styles["disclaimer"]
        ),
        PageBreak(),
    ]
    return elements


def _executive_summary_section(styles: dict, summary: str) -> list:
    elements = [
        Paragraph("Executive Summary", styles["h1"]),
        HRFlowable(width="100%", thickness=0.5, color=C_RED, spaceAfter=12),
        Paragraph(
            "The following non-technical summary is intended for executive leadership and CISO review.",
            styles["body_muted"]
        ),
        Spacer(1, 0.3 * cm),
    ]

    # Split summary into paragraphs
    for para in str(summary).split("\n"):
        para = para.strip()
        if para:
            if para.startswith("#"):
                elements.append(Paragraph(para.lstrip("#").strip(), styles["h2"]))
            else:
                elements.append(Paragraph(para, styles["body"]))
            elements.append(Spacer(1, 0.2 * cm))

    elements.append(PageBreak())
    return elements


def _technical_report_section(styles: dict, report: str) -> list:
    elements = [
        Paragraph("Technical Findings", styles["h1"]),
        HRFlowable(width="100%", thickness=0.5, color=C_RED, spaceAfter=12),
        Paragraph(
            "Detailed technical analysis for the security team. "
            "Includes CVE references, MITRE ATT&CK mappings, and remediation commands.",
            styles["body_muted"]
        ),
        Spacer(1, 0.3 * cm),
    ]

    for line in str(report).split("\n"):
        line = line.strip()
        if not line:
            elements.append(Spacer(1, 0.15 * cm))
            continue
        if line.startswith("##"):
            elements.append(Paragraph(line.lstrip("#").strip(), styles["h2"]))
        elif line.startswith("#"):
            elements.append(Paragraph(line.lstrip("#").strip(), styles["h1"]))
        elif line.startswith("```") or line.startswith("$") or line.startswith("sudo"):
            elements.append(Paragraph(line, styles["mono"]))
        else:
            elements.append(Paragraph(line, styles["body"]))

    elements.append(PageBreak())
    return elements


def _severity_table(styles: dict, findings: list) -> list:
    """findings = [{"title": str, "severity": str, "cve": str, "description": str}]"""
    elements = [
        Paragraph("Findings Summary", styles["h1"]),
        HRFlowable(width="100%", thickness=0.5, color=C_RED, spaceAfter=12),
    ]

    if not findings:
        elements.append(Paragraph("No structured findings available.", styles["body_muted"]))
        return elements

    table_data = [[
        Paragraph("Severity", styles["h2"]),
        Paragraph("Finding", styles["h2"]),
        Paragraph("CVE / Reference", styles["h2"]),
    ]]

    for f in findings[:20]:
        sev   = str(f.get("severity", "Info"))
        color = SEVERITY_COLORS.get(sev, C_MUTED)
        table_data.append([
            Paragraph(sev.upper(), ParagraphStyle(
                "sev_cell", fontName="Helvetica-Bold", fontSize=8,
                textColor=color,
            )),
            Paragraph(str(f.get("title", ""))[:80], styles["body"]),
            Paragraph(str(f.get("cve", "N/A"))[:20], styles["mono"]),
        ])

    table = Table(table_data, colWidths=[3 * cm, 11 * cm, 3 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_RED),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0),  9),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_CARD, C_BG]),
        ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
        ("FONTSIZE",      (0, 1), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.3, C_BORDER),
        ("GRID",          (0, 0), (-1, -1), 0.2, C_BORDER),
    ]))
    elements.append(table)
    elements.append(PageBreak())
    return elements


def _compliance_section(styles: dict, compliance: dict) -> list:
    elements = [
        Paragraph("Compliance Mapping", styles["h1"]),
        HRFlowable(width="100%", thickness=0.5, color=C_RED, spaceAfter=12),
        Paragraph(
            "Findings mapped to relevant compliance frameworks.",
            styles["body_muted"]
        ),
        Spacer(1, 0.3 * cm),
    ]

    if not compliance:
        elements.append(Paragraph("No compliance data available.", styles["body_muted"]))
        return elements

    table_data = [[
        Paragraph("Framework", styles["h2"]),
        Paragraph("Status", styles["h2"]),
        Paragraph("Notes", styles["h2"]),
    ]]

    status_colors = {
        "Compliant":     C_GREEN,
        "Partial":       C_AMBER,
        "Non-Compliant": C_RED,
        "N/A":           C_MUTED,
    }

    for framework, data in compliance.items():
        if isinstance(data, dict):
            status = str(data.get("status", "Unknown"))
            notes  = str(data.get("notes",  ""))[:120]
        else:
            status = str(data)
            notes  = ""

        s_color = status_colors.get(status, C_MUTED)
        table_data.append([
            Paragraph(str(framework), styles["body"]),
            Paragraph(status, ParagraphStyle(
                "status_cell", fontName="Helvetica-Bold",
                fontSize=8, textColor=s_color,
            )),
            Paragraph(notes, styles["body_muted"]),
        ])

    table = Table(table_data, colWidths=[4 * cm, 3.5 * cm, 9.5 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0),  C_RED),
        ("TEXTCOLOR",     (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_CARD, C_BG]),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("LINEBELOW",     (0, 0), (-1, -1), 0.3, C_BORDER),
    ]))
    elements.append(table)
    return elements


def _remediation_section(styles: dict, remediation_text: str) -> list:
    elements = [
        PageBreak(),
        Paragraph("Remediation Guide", styles["h1"]),
        HRFlowable(width="100%", thickness=0.5, color=C_RED, spaceAfter=12),
        Paragraph(
            "Prioritized technical remediation steps. "
            "All commands must be tested in a staging environment first.",
            styles["body_muted"]
        ),
        Spacer(1, 0.3 * cm),
    ]

    for line in str(remediation_text).split("\n"):
        line = line.strip()
        if not line:
            elements.append(Spacer(1, 0.1 * cm))
        elif line.startswith("#"):
            elements.append(Paragraph(line.lstrip("#").strip(), styles["h2"]))
        elif line.startswith("$") or line.startswith("sudo") or line.startswith("apt"):
            elements.append(Paragraph(line, styles["mono"]))
        else:
            elements.append(Paragraph(line, styles["body"]))

    return elements


# ---------------------------------------------------------------------------
# Main public function
# ---------------------------------------------------------------------------

def generate_pdf_report(
    target:            str,
    org_name:          str,
    risk_score:        int,
    executive_summary: str,
    technical_report:  str,
    compliance_mapping: dict,
    findings:          list  = None,
    remediation:       str   = "",
) -> bytes:
    """
    Generate a complete security report PDF.
    Returns raw bytes — save with open('report.pdf','wb').write(bytes).
    Or pass directly to st.download_button().
    """
    buffer = io.BytesIO()
    styles = _build_styles()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=1.8 * cm,
        rightMargin=1.5 * cm,
        topMargin=2.2 * cm,
        bottomMargin=1.8 * cm,
        title="AutoSEC Security Report",
        author="AutoSEC Platform",
    )

    page_cb = _PageTemplate(target_info=target)

    elements = []

    # 1. Cover
    elements.extend(_cover_page(styles, target, org_name, risk_score))

    # 2. Executive summary
    elements.extend(_executive_summary_section(styles, executive_summary))

    # 3. Findings table
    if findings:
        elements.extend(_severity_table(styles, findings))

    # 4. Technical report
    elements.extend(_technical_report_section(styles, technical_report))

    # 5. Remediation
    if remediation:
        elements.extend(_remediation_section(styles, remediation))

    # 6. Compliance
    elements.extend(_compliance_section(styles, compliance_mapping or {}))

    doc.build(elements, onFirstPage=page_cb, onLaterPages=page_cb)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Generating test PDF...")

    pdf_bytes = generate_pdf_report(
        target="203.0.113.45 / target.example.com",
        org_name="ACME Corporation",
        risk_score=78,
        executive_summary=(
            "# Risk Assessment\n"
            "Our analysis identified critical vulnerabilities in the target infrastructure. "
            "Immediate action is required to prevent potential data breach.\n\n"
            "# Business Impact\n"
            "Estimated risk of unauthorized data access is HIGH. "
            "Regulatory fines under GDPR could reach €20M or 4% of annual turnover.\n\n"
            "# Recommendation\n"
            "Engage your security team immediately. Estimated remediation time: 48-72 hours."
        ),
        technical_report=(
            "# Findings\n"
            "## CVE-2022-22965 (Spring4Shell)\n"
            "Critical RCE vulnerability in Spring Framework detected on port 8080.\n"
            "CVSS Score: 9.8 — Remotely exploitable without authentication.\n\n"
            "## Remediation\n"
            "$ sudo apt update && sudo apt upgrade -y spring-framework\n"
            "Verify: curl -I http://localhost:8080/health"
        ),
        compliance_mapping={
            "OWASP Top 10":  {"status": "Non-Compliant", "notes": "A1, A3, A5 violations"},
            "NIST CSF":      {"status": "Partial",       "notes": "Identify and Protect gaps"},
            "PCI-DSS":       {"status": "Non-Compliant", "notes": "Req 6.3.3 patch management"},
            "ISO 27001":     {"status": "Partial",       "notes": "A.12.6 technical vulnerabilities"},
        },
        findings=[
            {"severity": "Critical", "title": "Spring4Shell RCE",       "cve": "CVE-2022-22965"},
            {"severity": "High",     "title": "OpenSSH Username Enum",  "cve": "CVE-2016-6210"},
            {"severity": "Medium",   "title": "Apache Info Disclosure",  "cve": "CVE-2019-0220"},
        ],
        remediation=(
            "# Priority 1 — Critical (Complete within 24h)\n"
            "## Patch Spring Framework\n"
            "$ sudo apt update\n"
            "$ sudo apt install --only-upgrade libspring-java\n"
            "$ sudo systemctl restart tomcat9\n\n"
            "# Priority 2 — High (Complete within 72h)\n"
            "## Update OpenSSH\n"
            "$ sudo apt upgrade openssh-server\n"
            "$ sudo systemctl restart ssh"
        ),
    )

    with open("/tmp/autosec_test_report.pdf", "wb") as f:
        f.write(pdf_bytes)

    print(f"PDF generated: {len(pdf_bytes):,} bytes")
    print("Saved to /tmp/autosec_test_report.pdf")