import csv
import io
import json
from collections import Counter
from typing import List, Dict, Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from app.models.finding import Finding

class ExportService:
    @staticmethod
    def export_findings_csv(findings: List[Finding]) -> str:
        """Export findings to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        header = [
            "id", "scan_id", "vector_type", "entity_type", "entity_value",
            "severity", "confidence", "source_module", "created_at"
        ]
        writer.writerow(header)

        # Rows
        for finding in findings:
            row = [
                finding.id,
                finding.scan_id,
                finding.vector_type,
                finding.entity_type,
                finding.entity_value,
                finding.severity,
                finding.confidence,
                finding.source_module,
                finding.created_at.isoformat() if finding.created_at else ""
            ]
            writer.writerow(row)

        return output.getvalue()

    @staticmethod
    def export_findings_json(findings: List[Finding]) -> str:
        """Export findings to JSON format."""
        findings_list = []
        for finding in findings:
            findings_list.append({
                "id": finding.id,
                "scan_id": finding.scan_id,
                "vector_type": finding.vector_type,
                "entity_type": finding.entity_type,
                "entity_value": finding.entity_value,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "source_module": finding.source_module,
                "raw_data": finding.raw_data,
                "normalized_data": finding.normalized_data,
                "tags": finding.tags,
                "created_at": finding.created_at.isoformat() if finding.created_at else None
            })
        return json.dumps(findings_list, indent=2, default=str)

    @staticmethod
    def export_findings_pdf(findings: List[Finding]) -> bytes:
        """Export findings to a landscape PDF grouped by entity type."""
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=landscape(A4),
                                leftMargin=20*mm, rightMargin=20*mm,
                                topMargin=20*mm, bottomMargin=20*mm)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle', parent=styles['Heading1'],
            fontSize=20, spaceAfter=6,
        )
        subtitle_style = ParagraphStyle(
            'ReportSubtitle', parent=styles['Normal'],
            fontSize=10, textColor=colors.grey, spaceAfter=14,
        )
        group_style = ParagraphStyle(
            'GroupHeader', parent=styles['Heading2'],
            fontSize=12, spaceBefore=12, spaceAfter=4,
            textColor=colors.HexColor('#1e3a5f'),
        )
        cell_style = ParagraphStyle(
            'CellStyle', parent=styles['Normal'],
            fontSize=7, leading=9, alignment=TA_LEFT,
        )

        elements = []

        # ── Title block ──
        elements.append(Paragraph("OSINT Scan Report", title_style))
        elements.append(Paragraph(f"{len(findings)} total findings  ·  "
                                  f"Generated {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}",
                                  subtitle_style))

        # ── Summary card: count per entity type ──
        type_counts = Counter(f.entity_type for f in findings)
        severity_counts = Counter(f.severity or 'UNKNOWN' for f in findings)

        summary_style = ParagraphStyle(
            'SummaryCell', parent=styles['Normal'],
            fontSize=8, alignment=TA_CENTER,
        )
        summary_data = [["Entity Type", "Count"],
                        *[[k, str(v)] for k, v in sorted(type_counts.items(), key=lambda x: -x[1])]]
        summary_table = Table(summary_data, colWidths=[120, 60])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f7fa')]),
        ]))

        severity_data = [["Severity", "Count"],
                         *[[k, str(v)] for k, v in sorted(severity_counts.items(),
                           key=lambda x: {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3,'INFO':4,'UNKNOWN':5}.get(x[0],9))]]
        severity_table = Table(severity_data, colWidths=[80, 60])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f5f7fa')]),
        ]))

        # Side-by-side summary tables using a wrapper table
        elements.append(Table(
            [[summary_table, Spacer(20, 1), severity_table]],
            colWidths=[200, 20, 160],
        ))
        elements.append(Spacer(1, 16))

        # ── Separator ──
        sep_style = ParagraphStyle(
            'Sep', parent=styles['Normal'],
            fontSize=9, textColor=colors.HexColor('#888888'),
            spaceBefore=4, spaceAfter=4,
            alignment=TA_CENTER,
        )
        elements.append(Paragraph("─" * 100, sep_style))
        elements.append(Spacer(1, 8))

        # ── Findings table (6 columns) ──
        col_widths = [80, 28, 200, 55, 110, 55, 70]

        header_style = ParagraphStyle(
            'HeaderCell', parent=styles['Normal'],
            fontSize=8, alignment=TA_CENTER,
            textColor=colors.white, fontName='Helvetica-Bold',
        )
        table_data = [
            [Paragraph("Entity Type", header_style),
             Paragraph("Sev", header_style),
             Paragraph("Entity Value", header_style),
             Paragraph("Vector", header_style),
             Paragraph("Source", header_style),
             Paragraph("Conf", header_style),
             Paragraph("Created", header_style)]
        ]

        # Severity colour map for row backgrounds
        severity_bg = {
            'CRITICAL': colors.HexColor('#fce4e4'),
            'HIGH': colors.HexColor('#fff0e0'),
            'MEDIUM': colors.HexColor('#fffde6'),
            'LOW': colors.HexColor('#e8f5e9'),
            'INFO': colors.HexColor('#e3f2fd'),
        }
        severity_fg = {
            'CRITICAL': colors.HexColor('#b71c1c'),
            'HIGH': colors.HexColor('#e65100'),
            'MEDIUM': colors.HexColor('#f57f17'),
            'LOW': colors.HexColor('#1b5e20'),
            'INFO': colors.HexColor('#0d47a1'),
        }

        for f in findings:
            sev = (f.severity or 'INFO').upper()
            table_data.append([
                Paragraph(f.entity_type or '—', cell_style),
                Paragraph(sev, ParagraphStyle('SevCell', parent=cell_style,
                                              textColor=severity_fg.get(sev, colors.black),
                                              fontName='Helvetica-Bold', fontSize=7,
                                              alignment=TA_CENTER)),
                Paragraph(str(f.entity_value or '—'), cell_style),
                Paragraph(str(f.vector_type or '—'), cell_style),
                Paragraph(str(f.source_module or '—'), cell_style),
                Paragraph(f"{f.confidence:.0%}" if f.confidence else '—',
                          ParagraphStyle('ConfCell', parent=cell_style, alignment=TA_CENTER)),
                Paragraph(f.created_at.strftime('%m/%d %H:%M') if f.created_at else '—',
                          ParagraphStyle('DateCell', parent=cell_style, alignment=TA_CENTER)),
            ])

        table = Table(table_data, colWidths=col_widths, repeatRows=1)
        style_cmds = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e3a5f')),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#cccccc')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 1), (-1, -1), 2),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 2),
            ('LEFTPADDING', (0, 1), (-1, -1), 4),
            ('RIGHTPADDING', (0, 1), (-1, -1), 4),
        ]
        # Alternating row colours
        for i in range(1, len(table_data)):
            bg = colors.HexColor('#f5f7fa') if i % 2 == 0 else colors.white
            style_cmds.append(('BACKGROUND', (0, i), (-1, i), bg))

        table.setStyle(TableStyle(style_cmds))
        elements.append(table)

        # Build PDF
        doc.build(elements)
        buffer.seek(0)
        return buffer.getvalue()