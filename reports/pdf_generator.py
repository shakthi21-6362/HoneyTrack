"""
HoneyTrack — HackerOne Style Cybersecurity Threat Intelligence Report Generator
Produces executive-grade, HackerOne-standard penetration testing and threat intelligence
advisories using ReportLab.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas


class HackerOneCanvas(canvas.Canvas):
    """
    Two-pass canvas for professional HackerOne-styled header, footer rules,
    confidentiality watermark, and 'Page X of Y' dynamic pagination.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_header_footer(num_pages)
            super().showPage()
        super().save()

    def draw_header_footer(self, page_count):
        self.saveState()
        page_w, page_h = letter

        # ── Top Running Header ──
        # Subtle top accent bar
        self.setFillColor(colors.HexColor("#0f172a"))  # Deep Slate
        self.rect(36, page_h - 28, page_w - 72, 1, fill=1, stroke=0)

        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#dc2626"))  # HackerOne Red
        self.drawString(36, page_h - 22, "HACKERONE // HONEYTRACK")

        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))  # Slate Muted
        self.drawString(160, page_h - 22, "SECURITY ADVISORY & INCIDENT INTELLIGENCE")
        self.drawRightString(page_w - 36, page_h - 22, "CONFIDENTIAL — TLP:AMBER+STRICT")

        # ── Bottom Running Footer ──
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.75)
        self.line(36, 32, page_w - 36, 32)

        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(36, 20, "HoneyTrack Deception Platform • Threat Attribution & Adversary Profiling • Automated Sensor Triage")
        self.drawRightString(page_w - 36, 20, f"Page {self._pageNumber} of {page_count}")

        self.restoreState()


def generate_threat_report_pdf(stats: dict, events: list, filter_summary: str = "All Recorded Telemetry") -> bytes:
    """
    Generates an executive-level HackerOne vulnerability & threat intelligence advisory PDF.
    
    Args:
        stats: Dictionary of aggregate statistics
        events: List of AttackEvent records
        filter_summary: Active filter scope description
        
    Returns:
        bytes: Binary PDF buffer
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=42,
        bottomMargin=42
    )

    # ── Professional Color Palette (HackerOne Dark Slate + Vibrant Accents) ──
    c_primary = colors.HexColor("#0f172a")      # Slate 900
    c_accent = colors.HexColor("#dc2626")       # Red 600 (Critical/HackerOne)
    c_blue = colors.HexColor("#2563eb")         # Blue 600
    c_amber = colors.HexColor("#d97706")        # Amber 600
    c_green = colors.HexColor("#16a34a")        # Green 600
    c_purple = colors.HexColor("#7c3aed")       # Tor Purple
    c_text_dark = colors.HexColor("#0f172a")    # Charcoal body text
    c_text_muted = colors.HexColor("#64748b")   # Slate 500
    c_border = colors.HexColor("#cbd5e1")       # Border grey
    c_border_light = colors.HexColor("#e2e8f0") # Subtle line
    c_card_bg = colors.HexColor("#f8fafc")      # Slate 50
    c_card_bg_alt = colors.HexColor("#f1f5f9")  # Slate 100
    c_dark_box = colors.HexColor("#090d16")     # Terminal background
    c_dark_text = colors.HexColor("#e2e8f0")    # Terminal text
    c_code_green = colors.HexColor("#4ade80")   # Terminal green

    # ── Typography Styles ──
    styles = getSampleStyleSheet()

    doc_id_style = ParagraphStyle(
        'DocIdStyle',
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=11,
        textColor=c_accent
    )

    title_style = ParagraphStyle(
        'MainTitle',
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=c_primary,
        spaceAfter=4
    )

    section_heading = ParagraphStyle(
        'SectionH1',
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=c_primary,
        spaceBefore=12,
        spaceAfter=5
    )

    meta_label = ParagraphStyle(
        'MetaLabel',
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=c_text_muted
    )

    meta_val = ParagraphStyle(
        'MetaVal',
        fontName='Helvetica',
        fontSize=8.5,
        leading=11,
        textColor=c_primary
    )

    meta_val_bold = ParagraphStyle(
        'MetaValBold',
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=c_primary
    )

    badge_crit = ParagraphStyle(
        'BadgeCrit',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#b91c1c")
    )

    badge_high = ParagraphStyle(
        'BadgeHigh',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#c2410c")
    )

    badge_tor = ParagraphStyle(
        'BadgeTor',
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=c_purple
    )

    exec_summary_style = ParagraphStyle(
        'ExecSummary',
        fontName='Helvetica',
        fontSize=8.5,
        leading=12.5,
        textColor=c_text_dark
    )

    tbl_header = ParagraphStyle(
        'TblHeader',
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor("#334155")
    )

    tbl_body = ParagraphStyle(
        'TblBody',
        fontName='Helvetica',
        fontSize=7.5,
        leading=9.5,
        textColor=c_text_dark
    )

    tbl_body_bold = ParagraphStyle(
        'TblBodyBold',
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=c_primary
    )

    tbl_mono = ParagraphStyle(
        'TblMono',
        fontName='Courier',
        fontSize=7,
        leading=8.5,
        textColor=colors.HexColor("#1e293b")
    )

    tbl_mono_red = ParagraphStyle(
        'TblMonoRed',
        fontName='Courier-Bold',
        fontSize=7,
        leading=8.5,
        textColor=c_accent
    )

    term_code = ParagraphStyle(
        'TermCode',
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=c_dark_text
    )

    term_prompt = ParagraphStyle(
        'TermPrompt',
        fontName='Courier-Bold',
        fontSize=7.5,
        leading=10,
        textColor=c_code_green
    )

    story = []

    # ─────────────────────────────────────────────────────────────
    # 1. HACKERONE ADVISORY HEADER BLOCK
    # ─────────────────────────────────────────────────────────────
    gen_time_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    report_id = f"H1-HT-{datetime.utcnow().strftime('%Y%m%d')}-{len(events):04d}"

    header_table_data = [
        [
            Paragraph(f"REPORT REFERENCE: <b>{report_id}</b>", doc_id_style),
            Paragraph("SECURITY CLASSIFICATION: <b>HIGH RISK INCIDENT</b>", badge_crit)
        ],
        [
            Paragraph("DEFENSIVE THREAT INTELLIGENCE & INCIDENT AUDIT", title_style),
            Paragraph("STATUS: <b>TRIAGED / ACTIVE MITIGATION</b>", badge_high)
        ]
    ]

    h_table = Table(header_table_data, colWidths=[380, 160])
    h_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 1),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
    ]))
    story.append(h_table)
    story.append(Spacer(1, 4))

    # ─────────────────────────────────────────────────────────────
    # 2. ADVISORY METADATA MATRIX (HackerOne Report Card)
    # ─────────────────────────────────────────────────────────────
    total_attacks = stats.get("total_attacks", len(events))
    unique_ips = stats.get("unique_ips", len({e.get("source_ip") for e in events if e.get("source_ip")}))
    unique_nations = stats.get("unique_countries", len({e.get("country") for e in events if e.get("country")}))
    tor_count = sum(1 for e in events if e.get("is_tor"))
    crit_count = sum(1 for e in events if e.get("risk_score", 0) >= 70)
    high_count = sum(1 for e in events if 40 <= e.get("risk_score", 0) < 70)

    # Determine peak CVSS / severity rating
    max_risk = max([e.get("risk_score", 0) for e in events], default=75)
    cvss_score = min(10.0, round(max_risk / 10.0, 1))

    meta_grid = [
        [
            Paragraph("ASSET IN SCOPE", meta_label),
            Paragraph("ATTACK VECTOR / WEAKNESS", meta_label),
            Paragraph("SEVERITY / THREAT LEVEL", meta_label),
            Paragraph("REPORTER / SENSOR FLEET", meta_label)
        ],
        [
            Paragraph("<b>HoneyTrack Decoy Fleet (SSH/HTTP/FTP)</b>", meta_val),
            Paragraph("CWE-307: Brute Force & Credential Spray", meta_val),
            Paragraph(f"<font color='#dc2626'><b>CRITICAL (CVSS {cvss_score})</b></font>", meta_val),
            Paragraph("Autonomous Deception Engine", meta_val)
        ],
        [
            Paragraph("INCIDENT TIMESTAMP", meta_label),
            Paragraph("FILTER & AUDIT SCOPE", meta_label),
            Paragraph("ANONYMIZED ORIGINS", meta_label),
            Paragraph("SENSOR TELEMETRY ENGINE", meta_label)
        ],
        [
            Paragraph(gen_time_str, meta_val),
            Paragraph(f"<b>{filter_summary}</b>", meta_val),
            Paragraph(f"<b>{tor_count} Tor Exit Nodes</b> Identified", badge_tor),
            Paragraph("SQLite3 DB + GeoIP Intelligence", meta_val)
        ]
    ]

    meta_table = Table(meta_grid, colWidths=[135, 145, 130, 130])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_card_bg),
        ('BOX', (0, 0), (-1, -1), 0.75, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))

    # ─────────────────────────────────────────────────────────────
    # 3. EXECUTIVE SUMMARY / VULNERABILITY NARRATIVE (Callout Box)
    # ─────────────────────────────────────────────────────────────
    if total_attacks > 0:
        exec_summary_text = (
            f"<b>Executive Briefing:</b> During active sensor operations, HoneyTrack trapped "
            f"<b>{total_attacks:,} unauthorized intrusion attempts</b> originating from <b>{unique_ips:,} distinct IPv4 hosts</b> "
            f"across <b>{unique_nations} geopolitical regions</b>. Telemetry indicates sustained adversarial reconnaissance, "
            f"automated credential stuffing targeting administrative credentials, and unauthorized command injection payloads. "
            f"Crucially, <b>{tor_count} transactions originated from validated Tor Exit Nodes</b>, demonstrating calculated evasion "
            f"of IP-based geolocation controls. Immediate boundary firewall drops and SSH key-only policies are advised."
        )
    else:
        exec_summary_text = (
            "<b>Executive Briefing:</b> Defensive honeypot sensors (SSH:2222, HTTP:8080, FTP:2121) are online and actively "
            "monitoring the network boundary. No unauthorized intrusion attempts have been intercepted during this operational "
            "session. Telemetry logs will automatically populate and trigger threat intelligence attribution upon inbound adversarial engagement."
        )

    summary_callout = Table([[Paragraph(exec_summary_text, exec_summary_style)]], colWidths=[540])
    summary_callout.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#fef2f2")),  # Soft red highlight
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#fecaca")),
        ('LINEBEFORE', (0, 0), (0, -1), 3.5, c_accent),                 # Thick red left accent
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(summary_callout)
    story.append(Spacer(1, 8))

    # ─────────────────────────────────────────────────────────────
    # 4. KEY PERFORMANCE METRICS MATRIX (KPI Cards)
    # ─────────────────────────────────────────────────────────────
    kpi_card_data = [
        [
            Paragraph("TOTAL INTERCEPTS", meta_label),
            Paragraph("UNIQUE ADVERSARIES", meta_label),
            Paragraph("ORIGIN NATIONS", meta_label),
            Paragraph("CRITICAL INCIDENTS", meta_label),
            Paragraph("TOR EXIT NODES", meta_label)
        ],
        [
            Paragraph(f"<font size='13' color='#0f172a'><b>{total_attacks:,}</b></font>", tbl_body_bold),
            Paragraph(f"<font size='13' color='#2563eb'><b>{unique_ips:,}</b></font>", tbl_body_bold),
            Paragraph(f"<font size='13' color='#16a34a'><b>{unique_nations:,}</b></font>", tbl_body_bold),
            Paragraph(f"<font size='13' color='#dc2626'><b>{crit_count:,}</b></font>", tbl_body_bold),
            Paragraph(f"<font size='13' color='#7c3aed'><b>{tor_count:,}</b></font>", tbl_body_bold)
        ],
        [
            Paragraph("Captured requests", meta_label),
            Paragraph("Isolated IP addresses", meta_label),
            Paragraph("Global sovereign sources", meta_label),
            Paragraph("Risk score &ge; 70", meta_label),
            Paragraph("Anonymized relays", meta_label)
        ]
    ]

    kpi_table = Table(kpi_card_data, colWidths=[108, 108, 108, 108, 108])
    kpi_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_card_bg),
        ('BOX', (0, 0), (-1, -1), 0.75, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 4),
        ('RIGHTPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 10))

    # ─────────────────────────────────────────────────────────────
    # 5. ATTACK SURFACE BREAKDOWN & GEOPOLITICAL SOURCING (2 Columns)
    # ─────────────────────────────────────────────────────────────
    story.append(Paragraph("1. ATTACK SURFACE & GEOPOLITICAL ADVERSARY DISTRIBUTION", section_heading))

    # Left: Services Breakdown
    services = stats.get("services", {})
    srv_rows = [
        [
            Paragraph("<b>Target Decoy</b>", tbl_header),
            Paragraph("<b>Protocol / Port</b>", tbl_header),
            Paragraph("<b>Attempts</b>", tbl_header),
            Paragraph("<b>Traffic Ratio</b>", tbl_header)
        ]
    ]
    port_map = {"SSH": "TCP / 2222", "HTTP": "TCP / 8080", "FTP": "TCP / 2121"}
    for srv, count in sorted(services.items(), key=lambda x: x[1], reverse=True):
        pct = f"{(count / total_attacks * 100):.1f}%" if total_attacks > 0 else "0.0%"
        srv_rows.append([
            Paragraph(f"<b>{srv} Honeypot</b>", tbl_body_bold),
            Paragraph(port_map.get(srv, "TCP / Decoy"), tbl_mono),
            Paragraph(f"{count:,}", tbl_body),
            Paragraph(f"<b>{pct}</b>", tbl_body)
        ])
    
    if len(srv_rows) == 1:
        srv_rows.append([Paragraph("No service data", tbl_body), Paragraph("-", tbl_body), Paragraph("0", tbl_body), Paragraph("0%", tbl_body)])

    srv_table = Table(srv_rows, colWidths=[85, 75, 55, 50])
    srv_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_card_bg_alt),
        ('BOX', (0, 0), (-1, -1), 0.75, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))

    # Right: Top Origin Nations
    top_countries = stats.get("top_countries", [])[:6]
    geo_rows = [
        [
            Paragraph("<b>Origin Country</b>", tbl_header),
            Paragraph("<b>Volume</b>", tbl_header),
            Paragraph("<b>Share</b>", tbl_header)
        ]
    ]
    for c in top_countries:
        c_name = c.get("country", "Unknown")
        c_cnt = c.get("count", 0)
        pct = f"{(c_cnt / total_attacks * 100):.1f}%" if total_attacks > 0 else "0.0%"
        geo_rows.append([
            Paragraph(f"<b>{c_name}</b>", tbl_body),
            Paragraph(f"{c_cnt:,}", tbl_body),
            Paragraph(pct, tbl_body_bold)
        ])

    if len(geo_rows) == 1:
        geo_rows.append([Paragraph("Unknown", tbl_body), Paragraph("0", tbl_body), Paragraph("0%", tbl_body)])

    geo_table = Table(geo_rows, colWidths=[130, 70, 65])
    geo_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_card_bg_alt),
        ('BOX', (0, 0), (-1, -1), 0.75, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 5),
        ('RIGHTPADDING', (0, 0), (-1, -1), 5),
    ]))

    two_col = Table([[srv_table, geo_table]], colWidths=[270, 270])
    two_col.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 0),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
    ]))
    story.append(two_col)
    story.append(Spacer(1, 8))

    # ─────────────────────────────────────────────────────────────
    # 6. EVIDENCE & PROOF OF CONCEPT: CAPTURED ATTACK PAYLOADS
    # ─────────────────────────────────────────────────────────────
    # Extract unique dangerous commands or payloads captured
    dangerous_cmds = []
    seen_cmds = set()
    for ev in events:
        cmd = ev.get("command")
        if cmd and cmd not in seen_cmds:
            seen_cmds.add(cmd)
            dangerous_cmds.append((ev.get("source_ip"), ev.get("service"), cmd, ev.get("risk_score", 50)))
        if len(dangerous_cmds) >= 5:
            break

    if dangerous_cmds:
        story.append(Paragraph("2. EVIDENCE / PROOF OF CONCEPT: CAPTURED EXPLOIT STRINGS & COMMANDS", section_heading))
        terminal_lines = [
            Paragraph("<font color='#94a3b8'># Captured terminal execution telemetry from authentic adversary connections:</font>", term_code)
        ]
        for ip, srv, cmd, score in dangerous_cmds:
            score_color = "#f87171" if score >= 70 else "#fde047"
            terminal_lines.append(
                Paragraph(f"<font color='#38bdf8'>[{srv}]</font> <font color='#a3e635'>{ip}</font> <font color='{score_color}'>[SEV-{score}]</font> <font color='#f43f5e'>$</font> <font color='#ffffff'><b>{cmd}</b></font>", term_code)
            )

        term_table = Table([[terminal_lines]], colWidths=[540])
        term_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), c_dark_box),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#1e293b")),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(term_table)
        story.append(Spacer(1, 8))

    # ─────────────────────────────────────────────────────────────
    # 7. FORENSIC AUDIT TRAIL / RAW TELEMETRY ARCHIVE
    # ─────────────────────────────────────────────────────────────
    story.append(Paragraph("3. RAW FORENSIC AUDIT TRAIL (FILTERED TELEMETRY ARCHIVE)", section_heading))

    table_headers = [
        Paragraph("<b>Time (UTC)</b>", tbl_header),
        Paragraph("<b>Attacker IP</b>", tbl_header),
        Paragraph("<b>Origin Location</b>", tbl_header),
        Paragraph("<b>Lat / Lon</b>", tbl_header),
        Paragraph("<b>ISP / Autonomous System</b>", tbl_header),
        Paragraph("<b>Svc</b>", tbl_header),
        Paragraph("<b>Vector</b>", tbl_header),
        Paragraph("<b>Payload / Identity</b>", tbl_header),
        Paragraph("<b>Risk</b>", tbl_header)
    ]

    event_rows = [table_headers]

    if not events:
        event_rows.append([
            Paragraph("—", tbl_mono),
            Paragraph("—", tbl_mono),
            Paragraph("Decoys Active", tbl_body),
            Paragraph("—", tbl_mono),
            Paragraph("Awaiting Probes", tbl_body),
            Paragraph("—", tbl_body),
            Paragraph("Listening", tbl_body),
            Paragraph("No interactions yet", tbl_mono),
            Paragraph("<font color='#16a34a'><b>0</b></font>", tbl_body_bold)
        ])

    # Limit to top 35 representative records so the PDF stays clean and fast
    for ev in events[:35]:
        ts = ev.get("timestamp", "")
        if ts:
            try:
                ts = ts.replace("T", " ")[:19]
            except Exception:
                pass
        
        ip_display = ev.get("source_ip", "-")
        if ev.get("is_tor"):
            ip_display = f"<b>{ip_display}</b> <font color='#7c3aed'><b>[TOR]</b></font>"

        city = ev.get("city") or "Unknown"
        country = ev.get("country") or "Unknown"
        loc_display = f"{city}, {country}"
        if len(loc_display) > 16:
            loc_display = loc_display[:15] + ".."

        lat = ev.get("latitude")
        lon = ev.get("longitude")
        coords = f"{lat:.2f},{lon:.2f}" if (lat is not None and lon is not None) else "N/A"

        isp = ev.get("isp") or "-"
        if len(isp) > 16:
            isp = isp[:15] + ".."

        svc = ev.get("service", "-")
        vector = ev.get("attack_type", "-")
        if len(vector) > 14:
            vector = vector[:13] + ".."

        cmd = ev.get("command")
        u = ev.get("username")
        p = ev.get("password")
        ua = ev.get("user_agent")

        if cmd:
            payload = f"&gt; {cmd}"
        elif u or p:
            payload = f"{u or '-'}:{p or '-'}"
        elif ua:
            payload = f"UA:{ua[:12]}.."
        else:
            payload = "-"

        if len(payload) > 22:
            payload = payload[:21] + ".."

        risk = ev.get("risk_score", 0)
        risk_color = "#dc2626" if risk >= 70 else ("#d97706" if risk >= 40 else "#16a34a")
        risk_display = f"<font color='{risk_color}'><b>{risk}</b></font>"

        event_rows.append([
            Paragraph(ts[11:] if len(ts) >= 19 else ts, tbl_mono),  # HH:MM:SS
            Paragraph(ip_display, tbl_mono),
            Paragraph(loc_display, tbl_body),
            Paragraph(coords, tbl_mono),
            Paragraph(isp, tbl_body),
            Paragraph(f"<b>{svc}</b>", tbl_body),
            Paragraph(vector, tbl_body),
            Paragraph(payload, tbl_mono),
            Paragraph(risk_display, tbl_body_bold)
        ])

    col_widths = [52, 78, 70, 52, 78, 26, 62, 92, 30]
    audit_table = Table(event_rows, colWidths=col_widths, repeatRows=1)
    audit_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_card_bg_alt),
        ('BOX', (0, 0), (-1, -1), 0.75, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.35, c_border_light),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, c_card_bg]),
        ('TOPPADDING', (0, 0), (-1, -1), 2.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 2.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 3),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        ('ALIGN', (-1, 0), (-1, -1), 'CENTER'),
        ('ALIGN', (5, 0), (5, -1), 'CENTER'),
    ]))
    story.append(audit_table)
    story.append(Spacer(1, 10))

    # ─────────────────────────────────────────────────────────────
    # 8. REMEDIATION & AUTOMATED FIREWALL MITIGATION DIRECTIVES
    # ─────────────────────────────────────────────────────────────
    story.append(Paragraph("4. REMEDIATION GUIDANCE & ACTIONABLE DEFENSIVE DIRECTIVES", section_heading))

    remediation_card = [
        [
            Paragraph("<b>VULNERABILITY REMEDIATION</b>", meta_label),
            Paragraph("<b>DEFENSIVE HARDENING DIRECTIVES</b>", meta_label)
        ],
        [
            Paragraph(
                "&bull; <b>Enforce Multi-Factor / SSH Keys:</b> Disable password-based root authentication across all internet-facing jump hosts (<code>PermitRootLogin prohibit-password</code>).<br/>"
                "&bull; <b>Deploy Adaptive Rate Limiting:</b> Implement <code>fail2ban</code> or cloud WAF rate-limiting to restrict consecutive failed authentication attempts.<br/>"
                "&bull; <b>Isolate Decoy DMZ:</b> Ensure all honeypot decoys remain in strictly partitioned VLANs with outbound egress blocking.",
                exec_summary_style
            ),
            Paragraph(
                "&bull; <b>Tor Anonymizer Policy:</b> If corporate services do not serve anonymized privacy clients, block ingress traffic from published Tor Exit lists.<br/>"
                "&bull; <b>Automated Blacklisting:</b> Push captured high-threat indicators of compromise (IoCs) to perimeter edge firewalls or SIEM rules.<br/>"
                "&bull; <b>Continuous Monitoring:</b> Retain HoneyTrack audit telemetry for 90 days for forensic adversary attribution.",
                exec_summary_style
            )
        ]
    ]

    rem_table = Table(remediation_card, colWidths=[270, 270])
    rem_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), c_card_bg),
        ('BOX', (0, 0), (-1, -1), 0.75, c_border),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, c_border_light),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 7),
        ('RIGHTPADDING', (0, 0), (-1, -1), 7),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(rem_table)
    story.append(Spacer(1, 6))

    # Top Offenders Firewall Drop Script
    top_offenders = []
    seen_ips = set()
    for ev in events:
        ip = ev.get("source_ip")
        if ip and ip not in seen_ips and ev.get("risk_score", 0) >= 55:
            seen_ips.add(ip)
            top_offenders.append(ip)
        if len(top_offenders) >= 4:
            break

    if top_offenders:
        fw_lines = [
            Paragraph("<font color='#94a3b8'># HackerOne Recommended Immediate Firewall Drop Directives (UFW / iptables):</font>", term_code)
        ]
        for bad_ip in top_offenders:
            fw_lines.append(
                Paragraph(f"<font color='#38bdf8'>sudo ufw insert 1 deny from {bad_ip} to any comment 'HoneyTrack HackerOne Advisory Block'</font>", term_code)
            )
            fw_lines.append(
                Paragraph(f"<font color='#a3e635'>sudo iptables -I INPUT 1 -s {bad_ip} -j DROP -m comment --comment 'HoneyTrack Auto-Drop'</font>", term_code)
            )

        fw_table = Table([[fw_lines]], colWidths=[540])
        fw_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), c_dark_box),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#1e293b")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(fw_table)

    # ─────────────────────────────────────────────────────────────
    # BUILD PDF
    # ─────────────────────────────────────────────────────────────
    doc.build(story, canvasmaker=HackerOneCanvas)
    return buffer.getvalue()
