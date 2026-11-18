import os
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


def generate_report(results):
    os.makedirs("reports", exist_ok=True)

    filename = "security_report_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".pdf"
    filepath = os.path.join("reports", filename)

    document = SimpleDocTemplate(
        filepath,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )

    styles = getSampleStyleSheet()
    
    # تخصيص الستايل
    title_style = ParagraphStyle("CyberTitle", parent=styles["Title"], textColor=colors.HexColor("#007c91"), fontSize=20)
    heading_style = ParagraphStyle("CyberHeading", parent=styles["Heading2"], textColor=colors.HexColor("#007c91"), spaceAfter=10)
    normal_style = styles["Normal"]

    story = []

    # ================= الترويسة =================
    story.append(Paragraph("CYBER INCOME LAB", title_style))
    story.append(Paragraph("Website Security Assessment Report", styles["Heading2"]))
    story.append(Spacer(1, 12))

    scan_data = results.get("scan", {})
    website = scan_data.get("url", "Unknown")
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story.append(Paragraph(f"<b>Website:</b> {website}", normal_style))
    story.append(Paragraph(f"<b>Scan Date:</b> {scan_date}", normal_style))
    story.append(Spacer(1, 15))

    # ================= نظرة عامة =================
    score = scan_data.get("score", 0)
    risk_data = results.get("risk", {})
    risk_level = risk_data.get("risk_level", "UNKNOWN")

    overview_data = [
        ["Security Score", "Risk Level"],
        [f"{score}%", risk_level]
    ]
    t_overview = Table(overview_data, colWidths=[80 * mm, 80 * mm])
    t_overview.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f0f4f8")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#333333")),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 1), (-1, 1), 16),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
    ]))
    story.append(t_overview)
    story.append(Spacer(1, 20))

    # ================= 1. Security Headers =================
    story.append(Paragraph("1. Security Headers", heading_style))
    headers = scan_data.get("headers", [])
    if headers:
        header_data = [["Header", "Status"]]
        for h in headers:
            status_color = "<font color='green'><b>FOUND</b></font>" if h["status"] == "FOUND" else "<font color='red'><b>MISSING</b></font>"
            header_data.append([h["header"], Paragraph(status_color, normal_style)])
        
        t_headers = Table(header_data, colWidths=[100 * mm, 60 * mm])
        t_headers.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e0e7ee")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t_headers)
    story.append(Spacer(1, 15))

    # ================= 2. Detected Technologies =================
    story.append(Paragraph("2. Detected Technologies", heading_style))
    techs = scan_data.get("technologies", [])
    if techs:
        tech_data = [["Category", "Technology"]]
        for t in techs:
            tech_data.append([t.get("name", ""), t.get("value", "")])
        t_techs = Table(tech_data, colWidths=[80 * mm, 80 * mm])
        t_techs.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e0e7ee")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t_techs)
    else:
        story.append(Paragraph("No specific technologies detected.", normal_style))
    story.append(Spacer(1, 15))

    # ================= 3. Cookie Security =================
    story.append(Paragraph("3. Cookie Security", heading_style))
    cookies = scan_data.get("cookie_security", [])
    if cookies:
        cookie_data = [["Cookie Name", "Secure", "HttpOnly", "SameSite"]]
        for c in cookies:
            secure_str = "<font color='green'>Yes</font>" if c.get("secure") else "<font color='red'>No</font>"
            http_str = "<font color='green'>Yes</font>" if c.get("httponly") else "<font color='red'>No</font>"
            cookie_data.append([c.get("name", ""), Paragraph(secure_str, normal_style), Paragraph(http_str, normal_style), c.get("samesite", "Not Set")])
        
        t_cookies = Table(cookie_data, colWidths=[60 * mm, 30 * mm, 30 * mm, 40 * mm])
        t_cookies.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e0e7ee")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t_cookies)
    else:
        story.append(Paragraph("No cookies found on the main page.", normal_style))
    story.append(Spacer(1, 15))

    # ================= 4. Risk Assessment =================
    story.append(Paragraph("4. Risk Assessment", heading_style))
    findings = risk_data.get("findings", [])
    if findings:
        risk_table_data = [["Finding", "Severity", "Score"]]
        for f in findings:
            risk_table_data.append([f.get("description", ""), f.get("severity", ""), str(f.get("risk_score", 0))])
        t_risk = Table(risk_table_data, colWidths=[100 * mm, 30 * mm, 30 * mm])
        t_risk.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e0e7ee")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t_risk)
    else:
        story.append(Paragraph("Excellent! No major security risks found.", normal_style))
    story.append(Spacer(1, 15))

    # ================= 5. SSL / TLS Analysis =================
    story.append(Paragraph("5. SSL / TLS Analysis", heading_style))
    ssl_data = results.get("ssl", {})
    if ssl_data.get("error"):
        story.append(Paragraph(f"Error: {ssl_data['error']}", normal_style))
    else:
        ssl_text = f"""
        <b>Status:</b> {"Valid" if ssl_data.get('valid') else "Invalid/Expired"}<br/>
        <b>TLS Version:</b> {ssl_data.get('tls_version', 'Unknown')}<br/>
        <b>Issuer:</b> {ssl_data.get('issuer', 'Unknown')}<br/>
        <b>Expires On:</b> {str(ssl_data.get('expires', ''))[:10]}
        """
        story.append(Paragraph(ssl_text, normal_style))
    story.append(Spacer(1, 15))

    # ================= 6. DNS Intelligence =================
    story.append(Paragraph("6. DNS Intelligence", heading_style))
    dns_data = results.get("dns", {})
    if dns_data.get("error"):
        story.append(Paragraph(f"Error: {dns_data['error']}", normal_style))
    else:
        records = dns_data.get("records", {})
        dns_table_data = [["Record Type", "Values"]]
        for r_type, r_values in records.items():
            val_str = ", ".join(r_values) if r_values else "None"
            dns_table_data.append([r_type, Paragraph(escape(val_str), normal_style)])
        
        t_dns = Table(dns_table_data, colWidths=[40 * mm, 120 * mm])
        t_dns.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e0e7ee")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t_dns)
    story.append(Spacer(1, 15))

    # ================= 7. WHOIS Lookup =================
    story.append(Paragraph("7. WHOIS Lookup", heading_style))
    whois_data = results.get("whois", {})
    if whois_data.get("error"):
        story.append(Paragraph(f"Error: {whois_data['error']}", normal_style))
    else:
        ns_str = ", ".join(whois_data.get("name_servers", [])) if whois_data.get("name_servers") else "None"
        
        whois_table_data = [
            ["Registrar", str(whois_data.get("registrar", "Unknown"))],
            ["Creation Date", str(whois_data.get("creation_date", "Unknown"))],
            ["Expiration Date", str(whois_data.get("expiration_date", "Unknown"))],
            ["Days Until Expiry", str(whois_data.get("days_until_expiry", "Unknown"))],
            ["Name Servers", Paragraph(escape(ns_str), normal_style)]
        ]
        
        t_whois = Table(whois_table_data, colWidths=[40 * mm, 120 * mm])
        t_whois.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f0f4f8")),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t_whois)
    story.append(Spacer(1, 15))

    # ================= 8. Subdomain Enumeration =================
    story.append(Paragraph("8. Subdomain Enumeration", heading_style))
    sub_data = results.get("subdomains", {})
    if sub_data.get("error"):
        story.append(Paragraph(f"Error: {sub_data['error']}", normal_style))
    else:
        total_found = sub_data.get("total_found", 0)
        story.append(Paragraph(f"<b>Subdomains Found:</b> {total_found}", normal_style))
        story.append(Spacer(1, 5))
        
        subs = sub_data.get("subdomains", [])
        if subs:
            sub_table_data = [["#", "Subdomain"]]
            for i, sub in enumerate(subs, 1):
                sub_table_data.append([str(i), Paragraph(escape(sub), normal_style)])
            
            t_subs = Table(sub_table_data, colWidths=[20 * mm, 140 * mm])
            t_subs.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e0e7ee")),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t_subs)
        else:
            story.append(Paragraph("No subdomains found.", normal_style))
    story.append(Spacer(1, 15))

    # ================= 9. Port Scanner =================
    story.append(Paragraph("9. Port Scanner Results", heading_style))
    port_data = results.get("ports", {})
    if port_data.get("error"):
        story.append(Paragraph(f"Error: {port_data['error']}", normal_style))
    else:
        open_ports = port_data.get("open_ports", [])
        ip_address = port_data.get("ip_address", "Unknown")
        story.append(Paragraph(f"<b>IP Address:</b> {ip_address}", normal_style))
        story.append(Spacer(1, 5))
        if open_ports:
            port_table_data = [["Port", "Service", "Status"]]
            for p in open_ports:
                port_table_data.append([str(p.get("port")), p.get("service", ""), "<font color='green'><b>OPEN</b></font>"])
            t_ports = Table(port_table_data, colWidths=[40 * mm, 80 * mm, 40 * mm])
            t_ports.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e0e7ee")),
                ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#cccccc")),
                ('PADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(t_ports)
        else:
            story.append(Paragraph("No common open ports detected.", normal_style))

    document.build(story)

    return filepath