"""Branded, in-memory PDF export for PhishAgent synthetic investigations."""
import io
import json
from pathlib import Path
from datetime import datetime, timezone
from html import escape as html_escape

from reporting_policy import POLICY_VERSION, policy_reference
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether

NAVY = colors.HexColor('#101E33')
BLUE = colors.HexColor('#2165BE')
PALE = colors.HexColor('#EAF2FC')
INK = colors.HexColor('#18283D')
MUTED = colors.HexColor('#52657B')
LINE = colors.HexColor('#D6E0EC')
RISK = {'Critical': '#B3263B', 'High': '#C45C1C', 'Medium': '#8A6A11', 'Low': '#247354'}

ASSETS = Path(__file__).resolve().parent / 'assets'

def report_fonts():
    """Use licensed Century Gothic files if supplied by the project owner; otherwise use safe PDF fonts."""
    fonts_dir = ASSETS / 'fonts'
    regular = fonts_dir / 'CenturyGothic.ttf'
    bold = fonts_dir / 'CenturyGothicBold.ttf'
    if regular.is_file() and bold.is_file():
        try:
            if 'PhishCentury' not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont('PhishCentury', str(regular)))
            if 'PhishCenturyBold' not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont('PhishCenturyBold', str(bold)))
            return 'PhishCentury', 'PhishCenturyBold'
        except Exception:
            pass
    return 'Helvetica', 'Helvetica-Bold'


def clean(value):
    """Safely render untrusted email text in ReportLab paragraphs."""
    if value is None:
        return 'Not recorded'
    return html_escape(str(value), quote=True).replace('\n', '<br/>')


def decode(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return {'message': value}
    return {'message': str(value)}


def build_investigation_pdf(*, email, incident, mailbox, notifications, trace, run, model, duration, successful):
    """Return PDF bytes; report only persisted or provided investigation evidence."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=19*mm, leftMargin=19*mm,
                            topMargin=25*mm, bottomMargin=20*mm, title='PhishAgent | Investigation Report',
                            author='PhishAgent — Synthetic Security Operations')
    FONT, FONT_BOLD = report_fonts()
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(name='PGTitle', fontName=FONT_BOLD, fontSize=18, leading=23, textColor=NAVY, spaceAfter=7))
    ss.add(ParagraphStyle(name='PGSection', fontName=FONT_BOLD, fontSize=11, leading=15, textColor=BLUE, spaceBefore=13, spaceAfter=6))
    ss.add(ParagraphStyle(name='PGBody', fontName=FONT, fontSize=8.6, leading=13, textColor=INK, spaceAfter=5, wordWrap='CJK'))
    ss.add(ParagraphStyle(name='PGSmall', fontName=FONT, fontSize=7.3, leading=11, textColor=MUTED, wordWrap='CJK'))
    ss.add(ParagraphStyle(name='PGLabel', fontName=FONT_BOLD, fontSize=8, leading=12, textColor=INK))
    ss.add(ParagraphStyle(name='PGTable', fontName=FONT, fontSize=7.7, leading=11, textColor=INK, wordWrap='CJK'))
    P = lambda text, style='PGBody': Paragraph(clean(text), ss[style])
    story = []
    severity = (incident or {}).get('risk_level') or 'Not recorded'
    status = 'VERIFIED SIMULATED WORKFLOW' if successful else 'INCOMPLETE / UNVERIFIED'
    report_id = email.get('id', 'Unknown')
    generated = datetime.now(timezone.utc).strftime('%d %b %Y, %H:%M UTC')
    story.append(P('SECURITY INVESTIGATION REPORT', 'PGTitle'))
    story.append(P('PHISHAGENT  /  ENTERPRISE SECURITY OPERATIONS  /  SIMULATION ONLY', 'PGSmall'))
    story.append(Spacer(1, 5*mm))

    def table(rows, widths=None, header=False):
        content = [[P(c, 'PGLabel' if header and i == 0 else 'PGTable') for c in row] for i, row in enumerate(rows)]
        t = Table(content, colWidths=widths, hAlign='LEFT', repeatRows=1 if header else 0)
        commands = [('VALIGN',(0,0),(-1,-1),'TOP'),('BOTTOMPADDING',(0,0),(-1,-1),7),
                    ('TOPPADDING',(0,0),(-1,-1),7),('LINEBELOW',(0,0),(-1,-2),0.4,LINE),
                    ('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9)]
        if header: commands.extend([('BACKGROUND',(0,0),(-1,0),PALE),('LINEBELOW',(0,0),(-1,0),1,BLUE)])
        t.setStyle(TableStyle(commands))
        return t

    story.append(table([
        ['CASE REFERENCE', report_id, 'INVESTIGATION STATUS', status],
        ['RISK SEVERITY', severity.upper(), 'THREAT TYPE', (incident or {}).get('threat_type') or 'Not recorded'],
        ['EXECUTION TIME', f'{float(duration or 0):.2f} seconds', 'REPORT GENERATED', generated],
    ], [31*mm, 55*mm, 40*mm, 45*mm]))
    story.append(Paragraph('01  |  EXECUTIVE SUMMARY', ss['PGSection']))
    story.append(P((incident or {}).get('reason') or 'No incident assessment was persisted. Review the execution trace for errors.'))
    story.append(P('Completion confirms the presence of required simulated records only; it does not prove that a real enterprise threat was contained.', 'PGSmall'))

    story.append(Paragraph('02  |  REPORTED EMAIL', ss['PGSection']))
    story.append(table([['Sender', email.get('sender','Not recorded')],['Subject',email.get('subject','Not recorded')],
                        ['Email ID', report_id]], [34*mm,137*mm]))
    story.append(Paragraph('03  |  THREAT ASSESSMENT & EVIDENCE', ss['PGSection']))
    story.append(table([['Attack technique',(incident or {}).get('attack_technique') or 'Not recorded'],
                        ['Observed evidence',(incident or {}).get('evidence') or 'No evidence recorded'],
                        ['Incident status',(incident or {}).get('status') or 'No incident recorded']], [34*mm,137*mm]))

    story.append(Paragraph('SECURITY POLICY REFERENCE', ss['PGSection']))
    policy = policy_reference(severity)
    story.append(table([['Policy version', POLICY_VERSION],
                        ['Classification rule', policy['classification_rule']],
                        ['Response policy', policy['response_rule']]], [34*mm,137*mm]))
    story.append(P('The AI assesses severity using policy guidance; Python enforces permitted simulated actions. Classification is not independently certified.', 'PGSmall'))

    story.append(Paragraph('04  |  EMPLOYEE EXPOSURE', ss['PGSection']))
    story.append(P(f'Synthetic recipients: {len(mailbox)}  |  Recorded link clicks: {sum(bool(x.get("clicked")) for x in mailbox)}. A click does not establish account compromise.'))
    if mailbox:
        story.append(table([['Recipient', 'Clicked', 'Mailbox status']] + [
            [r.get('recipient',''), 'Yes' if r.get('clicked') else 'No', r.get('status','')]
            for r in mailbox], [66*mm, 24*mm, 81*mm], header=True))
    else: story.append(P('No synthetic mailbox records found.'))

    story.append(Paragraph('05  |  SIMULATED RESPONSE ACTIONS', ss['PGSection']))
    response_notices = [n for n in notifications if n.get('kind') not in ('Report acknowledgment', 'Investigation status update')]
    if response_notices:
        story.append(table([['Action', 'Recipient', 'Recorded state']] + [
            [r.get('kind',''),r.get('recipient',''),r.get('status','')]
            for r in response_notices], [51*mm, 64*mm, 56*mm], header=True))
    else: story.append(P('No SOC escalation or training drafts were recorded.'))
    quarantine = sum(r.get('status') == 'Quarantined (simulation)' for r in mailbox)
    archived = sum(r.get('status') == 'Archived (simulation)' for r in mailbox)
    story.append(P(f'Simulated mailbox containment: {quarantine} quarantined; {archived} archived. No real inboxes were modified.', 'PGSmall'))

    story.append(Paragraph('REPORTING EMPLOYEE NOTIFICATIONS', ss['PGSection']))
    reporter_notices = [n for n in notifications if n.get('kind') in ('Report acknowledgment', 'Investigation status update')]
    if reporter_notices:
        story.append(table([['Notification', 'Recipient', 'State']] + [
            [n.get('kind',''), n.get('recipient',''), n.get('status','')]
            for n in reporter_notices], [56*mm, 64*mm, 51*mm], header=True))
    else:
        story.append(P('No reporting employee was selected; no reporter notification drafts were created.'))
    story.append(P('Notifications are simulated in-app records only; none are delivered.', 'PGSmall'))

    story.append(Paragraph('06  |  RESPONSE VERIFICATION', ss['PGSection']))
    verification = next((decode(t.get('result')) for t in reversed(trace) if t.get('tool') == 'verify_response'), None)
    if verification:
        checks = [
            ['Verification passed', 'Yes' if verification.get('verified') else 'No'],
            ['Outstanding actions', '; '.join(verification.get('outstanding_actions') or []) or 'None recorded'],
            ['Human SOC review required', 'Yes' if verification.get('human_review_required') else 'No'],
        ]
        story.append(table(checks,[55*mm,116*mm]))
    else: story.append(P('No verification tool result was recorded.'))

    story.append(Paragraph('07  |  AGENT EXECUTION AUDIT', ss['PGSection']))
    audit_rows = [['Step', 'Tool / action', 'Recorded result']]
    for t in trace:
        payload = decode(t.get('result'))
        if payload.get('error'):
            summary = 'ERROR: ' + str(payload['error'])
        elif t.get('tool') == 'verify_response':
            summary = 'Verified' if payload.get('verified') else 'Outstanding actions remain'
        elif t.get('tool') == 'create_incident':
            summary = f"Severity: {payload.get('risk_level','Not recorded')}"
        elif t.get('tool') == 'quarantine_simulated':
            summary = f"Quarantined copies: {payload.get('quarantined',0)}"
        elif t.get('tool') == 'audit_exposure':
            summary = f"Recorded clicks: {payload.get('clicked_count',0)}"
        else:
            summary = t.get('decision') or payload.get('message') or 'Action recorded'
        audit_rows.append([str(t.get('step','')),str(t.get('tool','')).replace('_',' ').title(),str(summary)[:260]])
    story.append(table(audit_rows,[13*mm,51*mm,107*mm],header=True))
    story.append(Spacer(1,5*mm))
    story.append(P(f'Model: {model or "Not recorded"}  |  Tool executions: {sum(t.get("tool") in {"inspect_email","audit_exposure","create_incident","quarantine_simulated","route_mail_simulated","recommend_identity_response","notify_soc","create_training","verify_response"} for t in trace)}', 'PGSmall'))
    story.append(P('CONFIDENTIAL DEMONSTRATION DATA  |  All emails, recipients, security actions, and notifications are synthetic. This report is not evidence of real-world containment.', 'PGSmall'))

    def page_frame(canvas, doc):
        canvas.saveState()
        w,h = A4
        canvas.setFillColor(NAVY)
        canvas.rect(0,h-15*mm,w,15*mm,stroke=0,fill=1)
        # Place a legible logo icon on a white tile in the navy running header.
        logo_icon = ASSETS / 'phishagent_icon.png'
        label_x = 19*mm
        if logo_icon.is_file():
            try:
                tile = 11*mm
                x, y = 19*mm, h-13*mm
                canvas.setFillColor(colors.white)
                canvas.roundRect(x, y, tile, tile, 2*mm, stroke=0, fill=1)
                canvas.drawImage(ImageReader(str(logo_icon)), x+1*mm, y+1*mm,
                                 width=tile-2*mm, height=tile-2*mm, preserveAspectRatio=True, mask='auto', anchor='c')
                label_x = x+tile+3*mm
            except Exception:
                pass
        canvas.setFont(FONT_BOLD,10)
        canvas.setFillColor(colors.white)
        canvas.drawString(label_x,h-10*mm,'PHISHAGENT')
        canvas.setFont(FONT,8)
        canvas.drawRightString(w-19*mm,h-10*mm,'SECURITY OPERATIONS')
        canvas.setStrokeColor(LINE)
        canvas.line(19*mm,15*mm,w-19*mm,15*mm)
        canvas.setFont(FONT,7)
        canvas.setFillColor(MUTED)
        canvas.drawString(19*mm,11*mm,'SIMULATED ENTERPRISE ENVIRONMENT  •  NOT A LIVE SOC ACTION')
        canvas.drawRightString(w-19*mm,11*mm,f'PAGE {doc.page}')
        canvas.restoreState()
    doc.build(story, onFirstPage=page_frame, onLaterPages=page_frame)
    return buffer.getvalue()
