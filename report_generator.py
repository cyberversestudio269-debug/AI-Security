#!/usr/bin/env python3
"""
AI Risk Scanner: report generator v0.1

Turns scan_results.json (from scanner.py) into a PDF report.

    pip install reportlab
    python3 report_generator.py scan_results.json -o report.pdf --company "Acme Pvt Ltd"

Known limit: the built-in PDF fonts cannot show Hindi (Devanagari) text, so any
non-Latin characters in reply excerpts are shown as "?". A Unicode font can be added later.
"""

import argparse
import json
from datetime import date
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

NAVY = colors.HexColor("#1F2A44")
GREY = colors.HexColor("#6B7280")
LIGHT = colors.HexColor("#F3F4F6")
VERDICT_COLOR = {
    "FAIL": colors.HexColor("#B91C1C"),
    "REVIEW": colors.HexColor("#B45309"),
    "ERROR": colors.HexColor("#6B7280"),
    "PASS": colors.HexColor("#15803D"),
}
LEVEL_COLOR = {"HIGH": "#B91C1C", "MEDIUM": "#B45309", "LOW": "#15803D"}

FIX_GUIDE = {
    "LLM01": "Treat all user and document text as untrusted. Keep instructions separate from user data, "
             "filter known injection patterns, and limit what the bot is allowed to do even if it is tricked.",
    "LLM02": "Check the user's identity in your own code (not in the prompt) before returning personal data. "
             "Do not give the bot access to data or secrets it should never reveal.",
    "LLM05": "Treat bot output as untrusted. Escape HTML or show replies as plain text before displaying them on a website.",
    "LLM06": "Require verification and human approval for sensitive actions such as refunds or deletions. "
             "Give the bot the minimum permissions and block sending data to outside addresses.",
    "LLM07": "Assume the system prompt can leak. Keep secrets, keys and sensitive internal rules out of it.",
    "LLM09": "Make the bot say clearly that it is an AI when asked, and show an AI notice in the chat window.",
}

COMPLIANCE_NAMES = {
    "DPDP-S8": "India DPDP Act: data security safeguards",
    "EUAIA-A15": "EU AI Act: accuracy, robustness and cybersecurity",
    "EUAIA-A50": "EU AI Act: transparency (AI disclosure)",
}

QUESTIONNAIRE_LABELS = {
    "uses_personal_data": "Does the chatbot process personal data?",
    "has_human_review": "Is there human review or escalation?",
    "has_role_based_access": "Are role-based access controls in place?",
    "has_retention_policy": "Is a data-retention policy defined?",
    "discloses_ai_use": "Are users told they are interacting with AI?",
}

DISCLAIMER = (
    "This is an automated test of the chatbot's responses at the time of the scan. It does not prove the system "
    "is secure, and a passed test does not guarantee safety. Risk framework and legal mappings (OWASP, MITRE ATLAS, "
    "DPDP Act, EU AI Act) are indicative only and are not legal advice. Have a qualified expert confirm "
    "compliance conclusions."
)


def clean(text, limit=None):
    """Make text safe for built-in PDF fonts and reportlab markup."""
    text = (text or "").replace("\r", " ").replace("\n", " ")
    text = text.encode("latin-1", "replace").decode("latin-1")
    if limit and len(text) > limit:
        text = text[:limit].rstrip() + "..."
    return escape(text)


def build_styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("t", parent=base["Title"], textColor=NAVY, fontSize=24, leading=28, alignment=0),
        "sub": ParagraphStyle("s", parent=base["Normal"], textColor=GREY, fontSize=10),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], textColor=NAVY, fontSize=15, spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("b", parent=base["Normal"], fontSize=10, leading=14),
        "small": ParagraphStyle("sm", parent=base["Normal"], fontSize=8.5, leading=11, textColor=GREY),
        "finding": ParagraphStyle("f", parent=base["Heading3"], fontSize=11, leading=14, spaceBefore=8, spaceAfter=2),
        "score": ParagraphStyle("sc", parent=base["Normal"], fontSize=40, leading=44, textColor=NAVY),
    }


def finding_block(r, st):
    color = VERDICT_COLOR.get(r["result"], GREY)
    head = '<font color="%s"><b>%s</b></font> &nbsp;%s: %s &nbsp;<font color="#6B7280">(%s severity)</font>' % (
        color.hexval().replace("0x", "#"), r["result"], clean(r["id"]), clean(r["name"]), clean(r["severity"]))
    tags = "OWASP: %s &nbsp;|&nbsp; MITRE ATLAS: %s" % (clean(r["owasp"]), clean(r["atlas"]))
    comp = ", ".join(COMPLIANCE_NAMES.get(c, c) for c in r["compliance"])

    evidence_run = next((x for x in r["runs"] if x["verdict"] == r["result"]), r["runs"][0] if r["runs"] else None)
    parts = [Paragraph(head, st["finding"]), Paragraph(tags, st["small"])]
    if comp:
        parts.append(Paragraph("Related rules: " + clean(comp), st["small"]))
    parts.append(Paragraph("<b>Result:</b> %d of %d test runs failed." % (r["fails"], len(r["runs"])), st["body"]))
    if evidence_run:
        if evidence_run.get("reason"):
            parts.append(Paragraph("<b>Judge note:</b> " + clean(evidence_run["reason"], 300), st["body"]))
        if evidence_run.get("reply"):
            parts.append(Paragraph("<b>Reply excerpt:</b> " + clean(evidence_run["reply"], 220), st["body"]))
    fix = FIX_GUIDE.get(r["owasp"].split()[0])
    if fix and r["result"] in ("FAIL", "REVIEW"):
        parts.append(Paragraph("<b>How to fix:</b> " + clean(fix), st["body"]))
    return KeepTogether(parts)


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(GREY)
    canvas.drawString(20 * mm, 12 * mm, "AI Risk Scanner report - confidential")
    canvas.drawRightString(190 * mm, 12 * mm, "Page %d" % doc.page)
    canvas.restoreState()


def build_report(data, out_path, company):
    st = build_styles()
    summary, results = data["summary"], data["results"]
    story = []

    story.append(Paragraph("AI Risk Scan Report", st["title"]))
    story.append(Paragraph("Prepared for: %s &nbsp;|&nbsp; Date: %s" % (clean(company), date.today().isoformat()), st["sub"]))
    if summary.get("demo_mode"):
        story.append(Spacer(1, 6))
        story.append(Paragraph('<font color="#B91C1C"><b>DEMO DATA:</b> this report was made from a fake test bot, not a real customer system.</font>', st["body"]))
    story.append(Spacer(1, 14))

    level = summary["risk_level"]
    story.append(Paragraph('%d<font size="16" color="#6B7280"> / 100</font> &nbsp;<font size="16" color="%s"><b>%s RISK</b></font>' % (
        summary["risk_score"], LEVEL_COLOR.get(level, "#000000"), level), st["score"]))
    story.append(Spacer(1, 8))

    passed = sum(1 for r in results if r["result"] == "PASS")
    table = Table([
        ["Tests run", "Failed", "Needs review", "Passed", "Errors"],
        [summary["tests_run"], summary["failed"], summary["needs_review"], passed, summary["errors"]],
    ], colWidths=[34 * mm] * 5)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(table)

    questionnaire = data.get("questionnaire", {})
    if questionnaire:
        story.append(Paragraph("Policy questionnaire", st["h1"]))
        answers = [["Question", "Answer"]]
        for key, label in QUESTIONNAIRE_LABELS.items():
            if key in questionnaire:
                answers.append([label, "Yes" if questionnaire[key] else "No"])
        qtable = Table(answers, colWidths=[135 * mm, 35 * mm])
        qtable.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
            ("ALIGN", (1, 1), (1, -1), "CENTER"),
        ]))
        story.append(qtable)

    fails = sorted([r for r in results if r["result"] == "FAIL"],
                   key=lambda r: {"high": 0, "medium": 1, "low": 2}[r["severity"]])
    reviews = [r for r in results if r["result"] == "REVIEW"]
    errors = [r for r in results if r["result"] == "ERROR"]
    oks = [r for r in results if r["result"] == "PASS"]

    story.append(Paragraph("Findings that need fixing", st["h1"]))
    if fails:
        story.extend(finding_block(r, st) for r in fails)
    else:
        story.append(Paragraph("No failed tests in this scan.", st["body"]))

    if reviews:
        story.append(Paragraph("Needs human review", st["h1"]))
        story.append(Paragraph("The automatic judge could not decide these. A person should check them.", st["body"]))
        story.extend(finding_block(r, st) for r in reviews)

    if errors:
        story.append(Paragraph("Tests that could not run", st["h1"]))
        story.append(Paragraph(", ".join("%s (%s)" % (clean(r["id"]), clean(r["name"])) for r in errors), st["body"]))

    story.append(Paragraph("Tests passed", st["h1"]))
    if oks:
        story.append(Paragraph(", ".join("%s (%s)" % (clean(r["id"]), clean(r["name"])) for r in oks), st["body"]))
    else:
        story.append(Paragraph("None.", st["body"]))

    story.append(Paragraph("Compliance view", st["h1"]))
    rows = [["Rule area", "Tests failed", "Tests run"]]
    for key, name in COMPLIANCE_NAMES.items():
        related = [r for r in results if key in r["compliance"]]
        if related:
            rows.append([name, sum(1 for r in related if r["result"] == "FAIL"), len(related)])
    ctable = Table(rows, colWidths=[100 * mm, 35 * mm, 35 * mm])
    ctable.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), LIGHT),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D1D5DB")),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
    ]))
    story.append(ctable)

    story.append(Paragraph("Important notes", st["h1"]))
    story.append(Paragraph(clean(DISCLAIMER), st["small"]))

    doc = SimpleDocTemplate(out_path, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm,
                            topMargin=18 * mm, bottomMargin=20 * mm,
                            title="AI Risk Scan Report", author="AI Risk Scanner")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)


def main():
    ap = argparse.ArgumentParser(description="Make a PDF report from scan_results.json")
    ap.add_argument("results", help="path to scan_results.json")
    ap.add_argument("-o", "--out", default="report.pdf")
    ap.add_argument("--company", default="Client company")
    args = ap.parse_args()
    with open(args.results, encoding="utf-8") as f:
        data = json.load(f)
    build_report(data, args.out, args.company)
    print("Report saved to", args.out)


if __name__ == "__main__":
    main()
