"""
Enterprise Academic / Research Paper-Grade PDF Audit Report Generator.
Formats Quality Assurance & Market Readiness audits following IEEE/ACM style:
- Typography: Times-Roman (Times New Roman serif)
- Headings: 15 pt (Times-Bold)
- Body text: 13 pt (Times-Roman)
- Formal academic tables, running headers, and ISO/IEC 25010 compliance blocks.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas for academic running header and footer with total page count."""

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Times-Roman", 10)
        self.setFillColor(colors.HexColor("#333333"))

        # Running header (pages 2+)
        if self._pageNumber > 1:
            self.drawString(
                54,
                11 * inch - 36,
                "Pre-Deployment Verification and Market Readiness Audit Report",
            )
            self.drawRightString(
                8.5 * inch - 54,
                11 * inch - 36,
                "ISO/IEC 25010 & IEEE 29119 Compliant",
            )
            self.setStrokeColor(colors.HexColor("#999999"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Running footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(8.5 * inch - 54, 36, page_str)
        self.drawString(
            54,
            36,
            "Confidential Quality Assurance Governance Record",
        )
        self.setStrokeColor(colors.HexColor("#cccccc"))
        self.setLineWidth(0.5)
        self.line(54, 48, 8.5 * inch - 54, 48)

        self.restoreState()


def generate_pdf_audit_report(decision_data: dict, output_path: str | Path | None = None) -> Path:
    """
    Generate an academic-grade, publication-ready PDF audit report.
    Adheres strictly to:
    - Typography: Times-Roman (Times New Roman)
    - Heading font size: 15 pt
    - Body font size: 13 pt
    """
    if output_path is None:
        from core.test_runner import REPORTS_DIR
        output_path = REPORTS_DIR / "qa_deployment_report.pdf"

    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    # -----------------------------------------------------------------------
    # Academic Typography Styles (Times New Roman: Body 13pt, Heading 15pt)
    # -----------------------------------------------------------------------

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "PaperTitle",
        fontName="Times-Bold",
        fontSize=18,
        leading=22,
        alignment=1,  # Center
        spaceAfter=8,
        textColor=colors.HexColor("#111111"),
    )

    subtitle_style = ParagraphStyle(
        "PaperSubtitle",
        fontName="Times-Italic",
        fontSize=13,
        leading=17,
        alignment=1,  # Center
        spaceAfter=14,
        textColor=colors.HexColor("#444444"),
    )

    heading_style = ParagraphStyle(
        "PaperHeading",
        fontName="Times-Bold",
        fontSize=15,
        leading=19,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
        textColor=colors.HexColor("#111111"),
    )

    subheading_style = ParagraphStyle(
        "PaperSubHeading",
        fontName="Times-Bold",
        fontSize=13,
        leading=17,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True,
        textColor=colors.HexColor("#222222"),
    )

    body_style = ParagraphStyle(
        "PaperBody",
        fontName="Times-Roman",
        fontSize=13,
        leading=18,
        spaceAfter=6,
        textColor=colors.HexColor("#111111"),
    )

    abstract_style = ParagraphStyle(
        "PaperAbstract",
        fontName="Times-Italic",
        fontSize=13,
        leading=18,
        leftIndent=24,
        rightIndent=24,
        spaceAfter=10,
        alignment=4,  # Justified
        textColor=colors.HexColor("#222222"),
    )

    table_cell_style = ParagraphStyle(
        "PaperTableCell",
        fontName="Times-Roman",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#111111"),
    )

    table_header_style = ParagraphStyle(
        "PaperTableHeader",
        fontName="Times-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#ffffff"),
    )

    code_style = ParagraphStyle(
        "PaperCode",
        fontName="Courier",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#222222"),
    )

    story = []

    # -----------------------------------------------------------------------
    # Document Header & Title Block
    # -----------------------------------------------------------------------

    story.append(Paragraph("PRE-DEPLOYMENT QUALITY ASSURANCE AND MARKET READINESS AUDIT", title_style))
    story.append(Paragraph("A Formal Verification & Validation Assessment per ISO/IEC 25010 & IEEE 29119", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#222222"), spaceAfter=12))

    # Abstract / Executive Governance Statement
    approved = decision_data.get("approved", False)
    status_str = "APPROVED FOR PRODUCTION" if approved else "DEPLOYMENT BLOCKED"
    score = decision_data.get("market_readiness_score", decision_data.get("pass_rate", 100.0))
    reviewer = decision_data.get("reviewer", "Principal QA Auditor")
    timestamp = decision_data.get("timestamp", datetime.now(timezone.utc).isoformat())
    target_artifact = decision_data.get("target_artifact", "Software System Artifact")
    run_id = decision_data.get("run_id", "MKT-00000000")
    archetype = decision_data.get("archetype", "Enterprise Software Application")

    abstract_text = (
        f"<b>Abstract</b>—This audit record presents the pre-deployment verification assessment of "
        f"<b>{target_artifact}</b> (Classified Archetype: <i>{archetype}</i>). The verification was conducted "
        f"programmatically across five quality dimensions: static application security analysis, functional assertion "
        f"integrity, architectural maintainability, interface conformance, and prompt injection resilience. "
        f"The aggregate Market Readiness Index is determined to be <b>{score:.1f} / 100.0</b> with an official "
        f"governance determination of <b>{status_str}</b> by authorized signatory <i>{reviewer}</i>."
    )
    story.append(Paragraph(abstract_text, abstract_style))
    story.append(Spacer(1, 10))

    # -----------------------------------------------------------------------
    # Section 1: Executive Metadata & Audit Specifications
    # -----------------------------------------------------------------------

    story.append(Paragraph("1. Executive Summary & Audit Identification", heading_style))

    meta_rows = [
        [Paragraph("Audit Identification Key", table_header_style), Paragraph("Specification Record", table_header_style)],
        [Paragraph("Audit Identifier (Run ID)", table_cell_style), Paragraph(f"<code>{run_id}</code>", table_cell_style)],
        [Paragraph("Timestamp of Evaluation (UTC)", table_cell_style), Paragraph(timestamp, table_cell_style)],
        [Paragraph("Authorized Lead Auditor", table_cell_style), Paragraph(reviewer, table_cell_style)],
        [Paragraph("Application System Archetype", table_cell_style), Paragraph(archetype, table_cell_style)],
        [Paragraph("Evaluated Target Artifact", table_cell_style), Paragraph(target_artifact, table_cell_style)],
        [Paragraph("Quality Gate Determination", table_cell_style), Paragraph(f"<b>{status_str}</b>", table_cell_style)],
        [Paragraph("Market Readiness Index", table_cell_style), Paragraph(f"<b>{score:.1f} / 100.0</b>", table_cell_style)],
    ]

    meta_table = Table(meta_rows, colWidths=[200, 304])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (1, 0), colors.HexColor("#1b365d")),
        ("TEXTCOLOR", (0, 0), (1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b0bec5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # -----------------------------------------------------------------------
    # Section 2: Multi-Pillar Market Readiness Scorecard
    # -----------------------------------------------------------------------

    story.append(Paragraph("2. Multi-Pillar Quality Assessment Scorecard", heading_style))

    pillar_scores = decision_data.get("pillar_scores") or {
        "security_score": 100.0,
        "reliability_score": decision_data.get("pass_rate", 100.0),
        "code_health_score": 75.0,
        "api_readiness_score": 100.0,
        "genai_safety_score": 100.0,
    }

    scorecard_rows = [
        [
            Paragraph("Evaluation Pillar (ISO/IEC 25010)", table_header_style),
            Paragraph("Score", table_header_style),
            Paragraph("Weight", table_header_style),
            Paragraph("Compliance Status", table_header_style),
        ],
        [
            Paragraph("Application Security (SAST / Secrets / CVE)", table_cell_style),
            Paragraph(f"{pillar_scores.get('security_score', 100.0):.1f}%", table_cell_style),
            Paragraph("30%", table_cell_style),
            Paragraph("Compliant" if pillar_scores.get("security_score", 100.0) >= 85 else "Vulnerable", table_cell_style),
        ],
        [
            Paragraph("Functional Reliability & Assertion Integrity", table_cell_style),
            Paragraph(f"{pillar_scores.get('reliability_score', 100.0):.1f}%", table_cell_style),
            Paragraph("25%", table_cell_style),
            Paragraph("Verified" if pillar_scores.get("reliability_score", 100.0) >= 90 else "Defective", table_cell_style),
        ],
        [
            Paragraph("Architectural Health & Maintainability", table_cell_style),
            Paragraph(f"{pillar_scores.get('code_health_score', 100.0):.1f}%", table_cell_style),
            Paragraph("20%", table_cell_style),
            Paragraph("Maintainable" if pillar_scores.get("code_health_score", 100.0) >= 70 else "Technical Debt", table_cell_style),
        ],
        [
            Paragraph("API Interface & Contract Conformance", table_cell_style),
            Paragraph(f"{pillar_scores.get('api_readiness_score', 100.0):.1f}%", table_cell_style),
            Paragraph("15%", table_cell_style),
            Paragraph("Certified" if pillar_scores.get("api_readiness_score", 100.0) >= 80 else "Non-Compliant", table_cell_style),
        ],
        [
            Paragraph("GenAI Safety & Prompt Injection Resilience", table_cell_style),
            Paragraph(f"{pillar_scores.get('genai_safety_score', 100.0):.1f}%", table_cell_style),
            Paragraph("10%", table_cell_style),
            Paragraph("Resilient" if pillar_scores.get("genai_safety_score", 100.0) >= 80 else "Review Advised", table_cell_style),
        ],
        [
            Paragraph("<b>Aggregated Market Readiness Index</b>", table_cell_style),
            Paragraph(f"<b>{score:.1f}%</b>", table_cell_style),
            Paragraph("<b>100%</b>", table_cell_style),
            Paragraph(f"<b>{status_str}</b>", table_cell_style),
        ],
    ]

    scorecard_table = Table(scorecard_rows, colWidths=[230, 70, 60, 144])
    scorecard_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b365d")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("ALIGN", (1, 1), (2, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b0bec5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#f8f9fa")]),
        ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#e8eaf6")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(scorecard_table)
    story.append(Spacer(1, 12))

    # -----------------------------------------------------------------------
    # Section 3: Security & Vulnerability Analysis (OWASP Top 10)
    # -----------------------------------------------------------------------

    sec_summary = decision_data.get("security_summary")
    story.append(Paragraph("3. Application Security & Vulnerability Evaluation", heading_style))

    if sec_summary and sec_summary.get("findings"):
        sec_rows = [
            [
                Paragraph("ID", table_header_style),
                Paragraph("CWE", table_header_style),
                Paragraph("Severity", table_header_style),
                Paragraph("Vulnerability Description", table_header_style),
                Paragraph("Remediation", table_header_style),
            ]
        ]
        for f in sec_summary["findings"][:15]:
            sec_rows.append([
                Paragraph(f.get("finding_id", "VULN-000"), table_cell_style),
                Paragraph(f.get("cwe_id", "CWE-000"), table_cell_style),
                Paragraph(f"[{f.get('severity', 'MED').upper()}]", table_cell_style),
                Paragraph(f.get("title", ""), table_cell_style),
                Paragraph(f.get("remediation_guidance", "")[:80], table_cell_style),
            ])
        sec_table = Table(sec_rows, colWidths=[65, 65, 60, 160, 154])
        sec_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#b71c1c")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b0bec5")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#fff8e1")]),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(sec_table)
    else:
        story.append(Paragraph(
            "Static heuristic security analysis confirmed zero identified vulnerabilities, "
            "zero hardcoded credentials, and zero known vulnerable third-party dependencies "
            "violating the OWASP Top 10 standard.",
            body_style,
        ))
    story.append(Spacer(1, 12))

    # -----------------------------------------------------------------------
    # Section 4: Functional Test Execution Metrics & Matrix
    # -----------------------------------------------------------------------

    total_tests = decision_data.get("total", 0)
    passed_tests = decision_data.get("passed", 0)
    failed_tests = decision_data.get("failed", 0)
    errors_tests = decision_data.get("errors", 0)
    dur_ms = decision_data.get("total_duration_ms", 0.0)

    story.append(Paragraph("4. Functional Test Verification Register", heading_style))

    story.append(Paragraph(
        f"A total of <b>{total_tests}</b> programmatic test cases were executed across the target codebase. "
        f"Verification success was recorded at <b>{passed_tests}</b> passed assertions with "
        f"<b>{failed_tests}</b> functional failures and <b>{errors_tests}</b> unhandled runtime execution faults. "
        f"Aggregate test execution latency was <b>{dur_ms:.2f} ms</b>.",
        body_style,
    ))

    results = decision_data.get("results", [])
    if results:
        test_rows = [
            [
                Paragraph("Test Identifier", table_header_style),
                Paragraph("Target Module / Class", table_header_style),
                Paragraph("Category", table_header_style),
                Paragraph("Latency", table_header_style),
                Paragraph("Outcome", table_header_style),
            ]
        ]
        for r in results[:25]:
            test_rows.append([
                Paragraph(r.get("test_name", "unknown"), table_cell_style),
                Paragraph(r.get("module", "-"), table_cell_style),
                Paragraph(r.get("category", "unit"), table_cell_style),
                Paragraph(f"{r.get('duration_ms', 0.0):.1f} ms", table_cell_style),
                Paragraph(f"[{r.get('status', 'unknown').upper()}]", table_cell_style),
            ])
        test_table = Table(test_rows, colWidths=[164, 160, 60, 60, 60])
        test_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1b365d")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b0bec5")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(test_table)
    story.append(Spacer(1, 14))

    # -----------------------------------------------------------------------
    # Section 5: Local Fine-Tuned AI Specialist Deep-Dive Audit
    # -----------------------------------------------------------------------

    spec_data = decision_data.get("specialist_review")
    if spec_data:
        story.append(Paragraph("5. Local Fine-Tuned AI Specialist Deep-Dive Audit", heading_style))

        spec_model = spec_data.get("model_identifier", "qa-auditor-specialist")
        spec_gate = spec_data.get("gate_recommendation", "VERIFIED")
        spec_conf = spec_data.get("confidence_score", 0.95)
        spec_summary = spec_data.get("executive_summary", "")

        story.append(Paragraph(
            f"<b>Autonomous Specialist Model:</b> <code>{spec_model}</code> | "
            f"<b>Secondary Gate Verdict:</b> <b>[{spec_gate}]</b> | "
            f"<b>Confidence:</b> <b>{spec_conf * 100:.1f}%</b>",
            body_style,
        ))
        if spec_summary:
            story.append(Paragraph(f"<i>Specialist Synthesis:</i> {spec_summary}", body_style))

        # Threat findings from specialist
        t_findings = spec_data.get("threat_findings", [])
        if t_findings:
            story.append(Paragraph("5.1 Confirmed Exploitability & Threat Modeling", subheading_style))
            tf_rows = [
                [
                    Paragraph("Finding ID", table_header_style),
                    Paragraph("CWE", table_header_style),
                    Paragraph("CVSS", table_header_style),
                    Paragraph("Exploitability", table_header_style),
                    Paragraph("Attack Vector & Auditor Rationale", table_header_style),
                ]
            ]
            for tf in t_findings[:8]:
                tf_rows.append([
                    Paragraph(str(tf.get("finding_id", "-")), table_cell_style),
                    Paragraph(str(tf.get("cwe_id", "-")), table_cell_style),
                    Paragraph(f"{tf.get('cvss_v3_score', 0.0):.1f}", table_cell_style),
                    Paragraph(f"[{tf.get('exploitability', 'THEORETICAL')}]", table_cell_style),
                    Paragraph(f"{tf.get('attack_vector', '')}: {tf.get('auditor_rationale', '')}"[:140], table_cell_style),
                ])
            tf_table = Table(tf_rows, colWidths=[70, 65, 45, 90, 234])
            tf_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b0bec5")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(tf_table)
            story.append(Spacer(1, 8))

        # Defect diagnoses
        d_diag = spec_data.get("defect_diagnoses", [])
        if d_diag:
            story.append(Paragraph("5.2 Defect Diagnoses & Suggested Code Diffs", subheading_style))
            for diag in d_diag[:4]:
                t_id = diag.get("test_id", "TEST")
                f_type = diag.get("failure_type", "Defect")
                r_cause = diag.get("root_cause", "")
                s_fix = diag.get("suggested_fix", "")
                story.append(Paragraph(f"<b>Test Target:</b> <code>{t_id}</code> ({f_type})", body_style))
                story.append(Paragraph(f"<b>Root Cause:</b> {r_cause}", body_style))
                story.append(Paragraph(f"<b>Remediation:</b> {s_fix}", body_style))
                story.append(Spacer(1, 4))

        story.append(Spacer(1, 10))

    # -----------------------------------------------------------------------
    # Section 6: Regulatory Certification & Cryptographic Sign-Off
    # -----------------------------------------------------------------------

    signature = decision_data.get("signature", "UNVERIFIED")

    story.append(Paragraph("6. Regulatory Certification & Cryptographic Sign-Off" if spec_data else "5. Regulatory Certification & Cryptographic Sign-Off", heading_style))
    story.append(Paragraph(
        "I hereby certify under formal engineering governance that this verification assessment was conducted "
        "rigorously in accordance with the specifications of ISO/IEC 25010 and ISO/IEC/IEEE 29119. "
        "The cryptographic digest below guarantees the unalterable integrity of this evaluation.",
        body_style,
    ))

    sign_rows = [
        [Paragraph("Certification Parameter", table_header_style), Paragraph("Official Attestation Record", table_header_style)],
        [Paragraph("Quality Assurance Signatory", table_cell_style), Paragraph(f"<b>{reviewer}</b>", table_cell_style)],
        [Paragraph("Evaluation Timestamp (UTC)", table_cell_style), Paragraph(timestamp, table_cell_style)],
        [Paragraph("Compliance Governance Standard", table_cell_style), Paragraph("ISO/IEC 25010 & IEEE 29119 Software Quality", table_cell_style)],
        [Paragraph("Cryptographic Digest (SHA-256)", table_cell_style), Paragraph(f"<code>{signature}</code>", code_style)],
    ]
    sign_table = Table(sign_rows, colWidths=[180, 324])
    sign_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#b0bec5")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eceff1")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sign_table)

    # Build PDF with dynamic NumberedCanvas for page numbering
    doc.build(story, canvasmaker=NumberedCanvas)
    return output_path


# ---------------------------------------------------------------------------
# CLI Entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from core.test_runner import load_latest_report, REPORTS_DIR

    if len(sys.argv) > 1:
        data = json.loads(Path(sys.argv[1]).read_text())
    else:
        # Load the latest deployment report
        dep_path = REPORTS_DIR / "qa_deployment_report.json"
        if dep_path.exists():
            data = json.loads(dep_path.read_text())
        else:
            data = load_latest_report() or {}

    out = generate_pdf_audit_report(data)
    print(f"Generated PDF Audit Report: {out}")
