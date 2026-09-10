"""Word-report export for analysed scan results."""
from pathlib import Path

from docx import Document

from modules.scanner.logic import ScanReport

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def export_scan_docx(destination, report: ScanReport) -> Path:
    """Create a local Word report from an analysed ScanReport.

    Only derived findings and listener tables are written - no passwords,
    no raw process command lines, no sensitive content beyond what the
    user already sees on screen.
    """
    path = Path(destination)
    if path.suffix.lower() != ".docx":
        raise ValueError("Choose a .docx report file.")
    document = Document()
    document.add_heading("Bastion - Scan Report", 0)
    document.add_paragraph(f"Scanned at: {report.scanned_at}")
    if report.firewall.available:
        state = "enabled" if report.firewall.enabled else "DISABLED"
        document.add_paragraph(
            f"Windows Defender Firewall: {state} "
            f"({report.firewall.enabled_profile_count} profile(s) active, "
            f"default inbound: {report.firewall.default_inbound or 'unknown'})."
        )

    if report.findings:
        document.add_heading("Findings", level=1)
        for finding in sorted(report.findings, key=lambda f: (SEVERITY_ORDER.index(f.severity) if f.severity in SEVERITY_ORDER else 9, f.title)):
            document.add_paragraph(f"[{finding.severity.upper()}] {finding.title}")
            document.add_paragraph(finding.detail, style="List Bullet")

    document.add_heading("Listening ports", level=1)
    if report.ports:
        table = document.add_table(rows=1, cols=5)
        for cell, label in zip(table.rows[0].cells, ("Protocol", "Port", "Address", "Process", "Firewall")):
            cell.text = label
        for record in report.ports:
            cells = table.add_row().cells
            truth = "allowed" if record.allowed is True else "blocked" if record.allowed is False else "unknown"
            values = (record.protocol, str(record.local_port), record.local_address,
                      record.process_name or str(record.process_id), truth)
            for cell, value in zip(cells, values):
                cell.text = value
    else:
        document.add_paragraph("No listening ports were reported.")

    document.add_heading("Services", level=1)
    if report.services:
        table = document.add_table(rows=1, cols=4)
        for cell, label in zip(table.rows[0].cells, ("Name", "Display name", "Status", "Start type")):
            cell.text = label
        for record in report.services:
            cells = table.add_row().cells
            for cell, value in zip(cells, (record.name, record.display_name, record.status, record.start_type)):
                cell.text = value
    else:
        document.add_paragraph("No services were reported.")

    document.add_heading("Installed hotfixes", level=1)
    if report.patches:
        table = document.add_table(rows=1, cols=3)
        for cell, label in zip(table.rows[0].cells, ("Hotfix ID", "Description", "Installed on")):
            cell.text = label
        for record in report.patches:
            cells = table.add_row().cells
            for cell, value in zip(cells, (record.hotfix_id, record.description, record.installed_on)):
                cell.text = value
    else:
        document.add_paragraph("No hotfix records were returned (see the findings for guidance).")

    document.add_paragraph(
        "This report was generated locally by Bastion. It reflects the state of this "
        "device at scan time and is intended for education and self-assessment."
    )
    document.save(path)
    return path
