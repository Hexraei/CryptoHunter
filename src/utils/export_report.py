"""
Report Export Module - Generate JSON, PDF, and CSV reports from analysis results.
"""

import os
import json
import csv
from datetime import datetime
from typing import Dict, List, Any
from io import BytesIO, StringIO

# PDF generation (using reportlab if available, fallback to simple HTML)
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


CRYPTO_CLASSES = {
    0: "Non-Crypto",
    1: "AES/Block Cipher",
    2: "Hash Function",
    3: "Stream Cipher",
    4: "Public Key",
    5: "Auth/MAC",
    6: "KDF",
    7: "PRNG",
    8: "XOR Cipher",
    9: "Post-Quantum"
}


def export_json(results: Dict, filepath: str = None) -> str:
    """
    Export analysis results as JSON.
    
    Args:
        results: Analysis results dictionary
        filepath: Optional file path to save to
        
    Returns:
        JSON string
    """
    export_data = {
        "export_info": {
            "format": "json",
            "generated_at": datetime.now().isoformat(),
            "version": "2.0.0"
        },
        "analysis": results
    }
    
    json_str = json.dumps(export_data, indent=2, default=str)
    
    if filepath:
        with open(filepath, 'w') as f:
            f.write(json_str)
    
    return json_str


def export_csv(results: Dict, filepath: str = None) -> str:
    """
    Export analysis results as CSV.
    
    Args:
        results: Analysis results dictionary
        filepath: Optional file path to save to
        
    Returns:
        CSV string
    """
    output = StringIO()
    
    # Flatten results into rows
    rows = []
    
    # Extract classifications
    classifications = results.get("classifications", results.get("results", []))
    
    for func in classifications:
        rows.append({
            "function_name": func.get("name", func.get("function_name", "")),
            "address": func.get("entry", func.get("address", "")),
            "class_id": func.get("class_id", 0),
            "class_name": func.get("class_name", CRYPTO_CLASSES.get(func.get("class_id", 0), "Unknown")),
            "confidence": func.get("confidence", 0),
            "is_crypto": 1 if func.get("class_id", 0) > 0 else 0
        })
    
    if rows:
        writer = csv.DictWriter(output, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    
    csv_str = output.getvalue()
    
    if filepath:
        with open(filepath, 'w', newline='') as f:
            f.write(csv_str)
    
    return csv_str


def export_pdf(results: Dict, filepath: str) -> bool:
    """
    Export analysis results as PDF.
    
    Args:
        results: Analysis results dictionary
        filepath: File path to save to
        
    Returns:
        True if successful
    """
    if REPORTLAB_AVAILABLE:
        return _export_pdf_reportlab(results, filepath)
    else:
        return _export_pdf_simple(results, filepath)


def _export_pdf_reportlab(results: Dict, filepath: str) -> bool:
    """Generate PDF using ReportLab."""
    doc = SimpleDocTemplate(filepath, pagesize=A4)
    story = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30
    )
    story.append(Paragraph("CryptoHunter Analysis Report", title_style))
    story.append(Spacer(1, 12))
    
    # Metadata
    metadata = results.get("metadata", {})
    story.append(Paragraph(f"<b>Binary:</b> {metadata.get('binary', 'Unknown')}", styles['Normal']))
    story.append(Paragraph(f"<b>Analysis Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    story.append(Paragraph(f"<b>Total Functions:</b> {metadata.get('total_functions', 0)}", styles['Normal']))
    story.append(Paragraph(f"<b>Crypto Functions:</b> {metadata.get('crypto_functions', 0)}", styles['Normal']))
    story.append(Spacer(1, 20))
    
    # Summary Table
    story.append(Paragraph("Summary", styles['Heading2']))
    summary = results.get("summary", {})
    summary_data = [
        ["Metric", "Value"],
        ["Crypto Detected", "Yes" if summary.get("crypto_detected") else "No"],
        ["Total Crypto Functions", str(summary.get("crypto_count", 0))],
        ["Protocols Detected", str(summary.get("protocols_detected", 0))],
    ]
    
    summary_table = Table(summary_data, colWidths=[200, 200])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Top Crypto Functions
    story.append(Paragraph("Detected Crypto Functions (Top 20)", styles['Heading2']))
    
    classifications = results.get("classifications", results.get("results", []))
    crypto_funcs = [f for f in classifications if f.get("class_id", 0) > 0]
    crypto_funcs.sort(key=lambda x: x.get("confidence", 0), reverse=True)
    
    if crypto_funcs:
        func_data = [["Function", "Class", "Confidence"]]
        for func in crypto_funcs[:20]:
            func_data.append([
                func.get("name", "")[:40],
                func.get("class_name", ""),
                f"{func.get('confidence', 0)*100:.1f}%"
            ])
        
        func_table = Table(func_data, colWidths=[200, 150, 80])
        func_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
        ]))
        story.append(func_table)
    
    # Protocols
    protocols = results.get("protocols", [])
    if protocols:
        story.append(Spacer(1, 20))
        story.append(Paragraph("Detected Protocols", styles['Heading2']))
        
        for proto in protocols:
            story.append(Paragraph(
                f"<b>{proto.get('name', '')}</b> - {proto.get('description', '')} ({proto.get('confidence', 0)*100:.0f}%)",
                styles['Normal']
            ))
    
    # Build PDF
    doc.build(story)
    return True


def _export_pdf_simple(results: Dict, filepath: str) -> bool:
    """Generate simple HTML report when ReportLab not available."""
    # Create HTML report instead
    html_path = filepath.replace('.pdf', '.html')
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>CryptoHunter Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #2c3e50; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        .crypto {{ background-color: #e8f8f5; }}
    </style>
</head>
<body>
    <h1>CryptoHunter Analysis Report</h1>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>Summary</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Total Functions</td><td>{results.get('metadata', {}).get('total_functions', 0)}</td></tr>
        <tr><td>Crypto Functions</td><td>{results.get('metadata', {}).get('crypto_functions', 0)}</td></tr>
    </table>
    
    <h2>Detected Crypto Functions</h2>
    <table>
        <tr><th>Function</th><th>Class</th><th>Confidence</th></tr>
"""
    
    classifications = results.get("classifications", results.get("results", []))
    for func in classifications[:50]:
        if func.get("class_id", 0) > 0:
            html_content += f"""        <tr class="crypto">
            <td>{func.get('name', '')}</td>
            <td>{func.get('class_name', '')}</td>
            <td>{func.get('confidence', 0)*100:.1f}%</td>
        </tr>
"""
    
    html_content += """    </table>
</body>
</html>"""
    
    with open(html_path, 'w') as f:
        f.write(html_content)
    
    return True


def generate_report(results: Dict, output_dir: str, job_id: str, formats: List[str] = None) -> Dict[str, str]:
    """
    Generate reports in multiple formats.
    
    Args:
        results: Analysis results
        output_dir: Output directory
        job_id: Job identifier
        formats: List of formats to generate (json, csv, pdf)
        
    Returns:
        Dictionary mapping format to file path
    """
    if formats is None:
        formats = ['json', 'csv', 'pdf']
    
    os.makedirs(output_dir, exist_ok=True)
    generated = {}
    
    for fmt in formats:
        filename = f"report_{job_id}.{fmt}"
        filepath = os.path.join(output_dir, filename)
        
        if fmt == 'json':
            export_json(results, filepath)
            generated['json'] = filepath
        elif fmt == 'csv':
            export_csv(results, filepath)
            generated['csv'] = filepath
        elif fmt == 'pdf':
            export_pdf(results, filepath)
            generated['pdf'] = filepath
    
    return generated
