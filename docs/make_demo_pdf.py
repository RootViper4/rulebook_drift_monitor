#!/usr/bin/env python3
"""Builds the page-by-page showcase guide PDF (light, clear black text)."""
import os
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Image,
                                PageBreak, Table, TableStyle)
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.lib.colors import HexColor

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, 'Rulebook_Drift_Monitor_Showcase_Guide.pdf')

INK = HexColor('#111827'); MUT = HexColor('#4b5563')
ACC = HexColor('#0b6bcb'); GOOD = HexColor('#047857')
SIDE = HexColor('#0d1526'); WHITE = colors.white
LINE = HexColor('#d8deea'); SOFT = HexColor('#eef4ff'); BAND = HexColor('#f3f6fc')

def st(name, **kw):
    base = dict(fontName='Helvetica', fontSize=9.6, leading=13.8,
                textColor=INK, alignment=TA_LEFT, spaceAfter=5)
    base.update(kw); return ParagraphStyle(name, **base)

H1 = st('H1', fontName='Helvetica-Bold', fontSize=16, leading=20, textColor=INK, spaceAfter=8)
H2 = st('H2', fontName='Helvetica-Bold', fontSize=11.5, leading=15, textColor=GOOD, spaceAfter=4, spaceBefore=6)
BODY = st('BODY', fontSize=9.6, leading=13.8)
BUL = st('BUL', fontSize=9.6, leading=13.8, leftIndent=12, bulletIndent=3, spaceAfter=3)
SMALL = st('SMALL', fontSize=8, leading=11, textColor=MUT)
CAP = st('CAP', fontSize=9, leading=12, textColor=MUT, spaceBefore=3, spaceAfter=6)

def P(t, s=BODY): return Paragraph(t, s)
def bullets(items, style=BUL):
    return [Paragraph(f'<bullet>&bull;</bullet>{t}', style) for t in items]

def light_table(header, rows, colw):
    data = [[Paragraph(f'<b>{h}</b>', st('th', textColor=ACC, fontName='Helvetica-Bold', fontSize=9)) for h in header]]
    for r in rows:
        data.append([Paragraph(str(c), st('td', fontSize=9)) for c in r])
    t = Table(data, colWidths=colw, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), SOFT),
        ('BOX', (0,0), (-1,-1), 0.6, LINE),
        ('INNERGRID', (0,0), (-1,-1), 0.4, LINE),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 4), ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [WHITE, BAND]),
    ]))
    return t

def screen_map(title, blocks):
    """Wireframe of a screen: blocks = list of (x0,y0,x1,y1,kind,label)."""
    W, H = 470, 290
    d = Drawing(W, H)
    d.add(Rect(0, 0, W, H, fillColor=WHITE, strokeColor=LINE, strokeWidth=1.4, rx=8))
    kinds = {'side': SIDE, 'top': WHITE, 'card': WHITE, 'card2': HexColor('#f7f9fd'), 'hero': SOFT, 'acc': SOFT, 'instr': HexColor('#e6f6f0')}
    txt = {'side': HexColor('#c6d0e4'), 'top': MUT, 'card': INK, 'card2': INK, 'hero': ACC, 'acc': ACC, 'instr': GOOD}
    for (x0, y0, x1, y1, k, label) in blocks:
        px0, py0 = x0/100.0*W, y0/100.0*H
        px1, py1 = x1/100.0*W, y1/100.0*H
        fill = kinds.get(k, WHITE)
        d.add(Rect(px0, py0, max(1,px1-px0), max(1,py1-py0),
                   fillColor=fill, strokeColor=LINE if k not in ('side',) else SIDE,
                   strokeWidth=1 if k not in ('side',) else 1.4, rx=3 if k!='side' else 0))
        if label:
            fsize = 8 if len(label) <= 34 else 7.2
            d.add(String(px0+5, py0+(py1-py0)/2-2.5, label, fontName='Helvetica',
                         fontSize=fsize, fillColor=txt.get(k, INK)))
    d.add(String(6, H-13, title, fontName='Helvetica-Bold', fontSize=9.5, fillColor=MUT))
    return d

def cover(canv, doc):
    canv.saveState()
    canv.setFillColor(HexColor('#0a0f1e')); canv.rect(0, 0, A4[0], A4[1], fill=1, stroke=0)
    canv.setFillColor(ACC); canv.rect(0, A4[1]-14*mm, A4[0], 2.2*mm, fill=1, stroke=0)
    canv.setFillColor(GOOD); canv.rect(0, 0, A4[0], 1.6*mm, fill=1, stroke=0)
    canv.setFillColor(colors.white); canv.setFont('Helvetica-Bold', 26)
    canv.drawString(22*mm, A4[1]-42*mm, 'Rulebook Drift Monitor')
    canv.setFont('Helvetica', 13); canv.setFillColor(HexColor('#8fa1bd'))
    canv.drawString(22*mm, A4[1]-50*mm, 'a model risk & governance platform for financial-crime detection rulebooks')
    canv.setFont('Helvetica-Bold', 11); canv.setFillColor(colors.white)
    canv.drawString(22*mm, A4[1]-72*mm, 'Interactive showcase guide')
    canv.setFont('Helvetica', 10); canv.setFillColor(HexColor('#8fa1bd'))
    canv.drawString(22*mm, A4[1]-77*mm, 'every page of the app explained - plus a 30-minute demo script and quick-start commands')
    canv.drawString(22*mm, 16*mm, 'Hackathon deliverable  -  figures drawn from the running instance')
    canv.restoreState()

def later(canv, doc):
    canv.saveState()
    canv.setFillColor(MUT); canv.setFont('Helvetica', 8)
    canv.drawRightString(A4[0]-18*mm, 12*mm, f'page {doc.page}')
    canv.drawString(18*mm, 12*mm, 'Rulebook Drift Monitor - showcase guide')
    canv.restoreState()

src = []
src.append(Paragraph('Rulebook Drift Monitor', H1))
src.append(P('A governance loop for financial-crime detection rulebooks. LLM agents red-team your typology playbook, '
             'quantify how well your indicator rules still catch threats, and let an analyst institute new rules '
             'that measurably close the gaps - every loop is measured, reproducible and exportable. This guide walks '
             'through every screen one by one.', BODY))
src.append(P('Core concepts', H2))
src.extend(bullets([
    '<b>Drift index (0-100):</b> how far the live rulebook has drifted from the risk baseline; 40+ is elevated, 70+ is red.',
    '<b>Typology x category matrix:</b> 35 red-team typologies (customer, product, delivery, geography...) against 14 rule categories.',
    '<b>Findings:</b> evasions the red team reproduced on real fixtures - an LLM drafts candidate red flags, the rule engine verifies them.',
    '<b>The amendment loop:</b> approve a finding and institute it as a new dedicated rule (DS-41+); the engine self-checks the new rule and the covered typology drops out of the drift measurement.',
    '<b>Diffable &amp; exportable:</b> each run is diffed against the previous (NEW / REPEAT / REGRESSED) and a compliance dossier is one click away (JSON + PDF).',
]))
src.append(P('Live state of this instance (at a glance)', H2))
src.append(light_table(['Metric', 'Value'], [
    ['Locked baseline rulebook', '40 rules (DS-01..DS-40), restored on Reset'],
    ['Latest completed run', 'run-b39c5c27 - 37 verified findings awaiting human approval'],
    ['Drift now', '52.9 (down from 54.6 baseline) after DS-41 institutionalised on TYP-001'],
], [120, 330]))
src.append(Spacer(1, 8))
src.append(P('How to run it yourself', H2))
src.extend(bullets([
    '<font face="Courier">python3 demo/web.py</font> then open <font face="Courier">http://127.0.0.1:5000</font>',
    'New scan on the Run Console, review, institute a rule, watch the dashboard &amp; forecast react, export the dossier.',
]))

pages = [
    ('Page 1 - the Run Console  (index.html)', 'Command centre: start scans, review findings, institute rules.',
     [(0,0,15,100,'side','v nav · Dashboard / Run Console / Catalog / Forecast / Docs'),
      (15,92,100,100,'top','topbar · page title · live pill  · analyst'),
      (17,80,98,90,'hero','hero · Drift detection run'),
      (17,74,98,78,'instr','banner · DS-41 indicator instituted, closes TYP-001 gap'),
      (17,56,70,72,'card','findings grid · 37 typologies, severities, drafted red flags'),
      (72,56,98,72,'card2','decision controls · accept / amend / reject'),
      (72,50,98,55,'card2','Review &amp; institute button (enabled after decision)'),
      (72,42,98,49,'acc','export buttons · dossier JSON + dossier PDF'),
      (72,36,98,41,'card2','Reset · restore shipped baseline'),
      (17,34,70,42,'card','diff summary · 0 new · 35 repeat · 3 regressed'),
      (17,20,70,32,'card2','probe panel · Run probe · verdict card')],
     bullets([
        '<b>New run button</b> starts a fresh red-team scan; the pipeline trace (retrieval -&gt; drafting -&gt; feasibility -&gt; rule engine) goes live as it runs.',
        '<b>Findings grid</b> - one finding per typology: typology, category, severity, evasion depth and its drafted red flag.',
        '<b>Decision controls</b> - accept / amend / reject set the status; <b>Review &amp; institute</b> commits it as a new rule.',
        '<b>Diff badges</b> - NEW (first seen) vs REPEAT, plus the summary line against the previous run.',
        '<b>Run toggles</b> - Reset, Export dossier JSON and Export dossier PDF.',
        '<b>Institutionalised banner</b> - appears once rules are in force (e.g. DS-41 · closes TYP-001).',
     ])),
    ('Adversarial red-team probe (Run probe)', 'A live attack simulation built into the console.',
     [(0,0,15,100,'side','same sidebar'),
      (15,92,100,100,'top','topbar'),
      (17,86,98,90,'hero','probe card · heading + Run probe button'),
      (17,30,98,84,'card','steps panel · what the critic checks for the claim'),
      (17,10,98,25,'acc','verdict strip · REJECTED · claim not reproducible (red-team)')],
     bullets([
        '<b>How it works</b> - hands the platform a poisoned typology: a prompt-injection payload plus an over-claimed evasion set.',
        '<b>Verification</b> - the engine re-runs feasibility checks; the steps panel shows exactly what was tested.',
        '<b>Verdict</b> - REJECTED when the over-claim does not reproduce; honestly FLAGGED if the injection truly bypasses the stack.',
        '<b>Live use</b> - one click, ~1 second, unambiguous result for the security story.',
     ])),
    ('Page 2 - Dashboard  (dashboard.html)', 'The 100-metre view: KPIs, forecast, pipeline, current run.',
     [(0,0,15,100,'side','v nav'),
      (15,92,100,100,'top','topbar'),
      (17,74,98,90,'card','KPI cards · drift index, rulebook, coverage, detected'),
      (17,54,98,72,'card','forecast card · measured history + projection + MAD band'),
      (17,38,98,52,'hero','agent pipeline diagram · 5 stages'),
      (17,24,98,36,'card2','evasion heatmap card (see next page)'),
      (17,8,98,22,'card2','run state footer · id, status, findings, discarded')],
     bullets([
        '<b>KPI cards</b> - drift index (with a pill "+ 1 typology gap closed"), rulebook size, rule coverage %, detected typologies.',
        '<b>Forecast card</b> - measured history line, projected +75.8 drift in 30 days and a backtested error band (MAD).',
        '<b>Pipeline diagram</b> - the five agent stages light up as a run progresses.',
        '<b>Run state footer</b> - current run id, status, findings and discarded counts.',
     ])),
    ('Evasion heatmap (dashboard)', 'Typology x category evasion, at a glance.',
     [(0,0,15,100,'side','v nav'),
      (15,92,100,100,'top','topbar'),
      (17,86,98,90,'hero','section title + description line'),
      (20,14,62,84,'card','heatmap grid · rows = typologies sort by severity, columns = 14 categories, counts in cells'),
      (64,40,98,84,'card2','row detail · severity dot, id, name, covered star'),
      (64,20,98,36,'acc','legend · 0 evaded -&gt; max, plus covered key')],
     bullets([
        '<b>Rows</b> are typologies sorted by severity (critical first) then total evasion; a severity dot sits on each row label.',
        '<b>Columns</b> are the 14 rule categories; intensity = number of evaded rules, printed inside the cell.',
        '<b>Right-most column</b> - total rules evaded per typology.',
        '<b>Green outline + star</b> - a covered typology is excluded from the drift measurement (DS-41 neutralises TYP-001).',
        '<b>Legend</b> - intensity scale and the covered key are drawn in the chart itself.',
     ])),
    ('Page 3 - Rule Catalog  (rules.html)', 'The rulebook, browseable and auditable.',
     [(0,0,15,100,'side','v nav'),
      (15,92,100,100,'top','topbar'),
      (17,82,98,90,'hero','hero · Rule catalog'),
      (17,74,98,80,'instr','institutionalised banner'),
      (17,64,98,72,'card','filter bar · search, type, severity, AI-relevance'),
      (17,12,98,62,'card','rule table · id, rule, category, type, severity, AI, source'),
      (17,2,98,10,'card2','footer note')],
     bullets([
        '<b>40 baseline rules</b> grouped by category - rule id, title, category, risk severity, conditions.',
        '<b>Star badge (instituted)</b> - a rule created through the amendment loop shows which finding it closes.',
        '<b>Filter/search</b> - narrow by text across id/title/conditions.',
        '<b>Audit story</b> - the catalog always reflects what is actually in force.',
     ])),
    ('Page 4 - Forecast  (forecast.html)', 'Where the drift is heading, with receipts.',
     [(0,0,15,100,'side','v nav'),
      (15,92,100,100,'top','topbar'),
      (17,78,98,90,'hero','hero · Where the rulebook drifts next'),
      (17,30,98,74,'card','trend chart · measured history + projection line + MAD confidence band'),
      (17,10,98,27,'acc','checkpoint callouts · post-amendment re-scan points')],
     bullets([
        '<b>Measured history</b> - seeded regulatory steady-state points plus your completed runs (currently 9 points).',
        '<b>Projection</b> - trend line to +30 days (~75.8): the board-facing number.',
        '<b>Backtest</b> - MAD / confidence band showing past-model accuracy.',
        '<b>Checkpoints</b> - every amendment appends a measured point, so the curve visibly bends when the analyst acts.',
     ])),
]
for title, sub, blocks, body in pages:
    src.append(PageBreak())
    src.append(Paragraph(title, H1))
    src.append(Paragraph(sub, CAP))
    src.append(screen_map(title.split('(')[0].strip() if '(' in title else title, blocks))
    src.append(Spacer(1, 4))
    src.extend(body)

src.append(PageBreak())
src.append(Paragraph('The amendment loop - the story to tell', H1))
src.append(light_table(['Stage', 'What happens', 'Where you see it'], [
    ['1 · Scan', 'Agent red team drafts a candidate red flag; the rule engine verifies it reproduces.', 'Run Console grid'],
    ['2 · Review', 'Analyst accepts the finding; Review &amp; institute is now enabled.', 'Finding card'],
    ['3 · Institute', 'Engine builds a dedicated DS-rule, self-checks it, commits it, marks the typology covered.', 'Finding card + banner'],
    ['4 · Measure', 'Post-amendment re-scan records a new drift point; the forecast recalibrates.', 'Dashboard + Forecast'],
    ['5 · Re-run', 'Next scan excludes the covered typology; its findings come back REPEAT / REGRESSED.', 'Run Console diff'],
    ['6 · Export', 'Dossier (JSON + PDF) assembles approved findings and amendments.', 'Export buttons'],
], [60, 250, 140]))

src.append(Paragraph('The 30-minute demo script', H1))
script = [
    ('0:00 Check-in', 'Show the live pill and the running server; open http://127.0.0.1:5000.'),
    ('0:02 The problem', 'One sentence: "Your indicator rulebook silently rots as real-world typologies change - we make that drift visible and closeable."'),
    ('0:03 Run Console', 'Point at a finding card. Accept TYP-001, then Review &amp; institute.'),
    ('0:06 The loop', 'Read the banner back: DS-41 instituted, TYP-001 gap closed; drift KPIs drop (54.6 -&gt; 52.9). Differentiator.'),
    ('0:09 Probe', 'Click Run probe; "REJECTED - not reproducible" in under a second.'),
    ('0:12 Dashboard', 'KPIs, then the heatmap: severity-sorted rows, green-outlined covered TYP-001, counts in cells.'),
    ('0:15 Forecast', 'The measured line + projection; the amendment checkpoint bends the curve.'),
    ('0:18 Re-run', 'New run (fast - cached drafting); findings return REPEAT with the summary diff.'),
    ('0:22 Export', 'Export dossier (JSON) and PDF; open it and show amendments + approved findings.'),
    ('0:25 Reset + Q&amp;A', 'Reset restores the pristine baseline (40 rules, clean history). Q&amp;A.'),
    ('0:28 Wrap', '"From a live red-team red flag to an instituted, measured, exportable rule in four clicks - that is the drift monitor."'),
]
src.append(light_table(['Time', 'Action'], script, [70, 380]))

src.append(Paragraph('Quick references', H1))
src.extend(bullets([
    '<font face="Courier">python3 demo/web.py</font> - start the app on port 5000 (all data synthetic / illustrative).',
    'Pages: <font face="Courier">/index.html</font> Run Console, <font face="Courier">/dashboard.html</font>, <font face="Courier">/rules.html</font>, <font face="Courier">/forecast.html</font>, <font face="Courier">/docs.html</font>.',
    'APIs: <font face="Courier">/api/run /reset /decide /institute /probe /dossier /dossier.pdf /dashboard /forecast /rules /state</font>.',
]))

doc = SimpleDocTemplate(OUT, pagesize=A4,
                        leftMargin=18*mm, rightMargin=18*mm,
                        topMargin=14*mm, bottomMargin=16*mm,
                        title='Rulebook Drift Monitor - Showcase Guide',
                        author='Hackathon')
doc.build(src, onFirstPage=cover, onLaterPages=later)
print('WROTE', OUT, os.path.getsize(OUT), 'bytes')