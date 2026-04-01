from __future__ import annotations

from pathlib import Path

from reconmap.core.models import Finding, HostInfo, NextStep


def export_markdown(
    output_path: str | Path,
    hosts: list[HostInfo],
    findings: list[Finding],
    steps: list[NextStep],
) -> Path:
    path = Path(output_path)
    lines: list[str] = []
    # Prefix the markdown report with the new product name.  Previous
    # versions of this tool were branded ReconMap; ScanStrike uses a
    # different header to avoid confusion.
    lines.append("# ScanStrike Scan Summary\n")

    lines.append("## Hosts\n")
    for host in hosts:
        lines.append(f"### {host.ip} {f'({host.hostname})' if host.hostname else ''}".strip())
        lines.append("")
        lines.append(f"- Status: {host.status}")
        lines.append(f"- OS Guess: {host.os_guess or 'Unknown'}")
        lines.append(f"- Open Ports: {host.port_count}")
        for port in host.open_ports:
            version = port.display_version or "Unknown"
            lines.append(f"  - {port.port}/{port.protocol} - {port.service or 'unknown'} - {version}")
        lines.append("")

    lines.append("## Interesting Findings\n")
    for finding in findings:
        lines.append(f"- **[{finding.severity}]** {finding.host} {finding.port} - {finding.title}: {finding.details}")
    lines.append("")

    lines.append("## Suggested Next Steps\n")
    for step in steps:
        lines.append(f"- {step.host} {step.port} ({step.service}): {step.action}")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def export_html(
    output_path: str | Path,
    hosts: list[HostInfo],
    findings: list[Finding],
    steps: list[NextStep],
) -> Path:
    """Export scan results into an HTML document.

    The resulting report is structured with headings and tables.  Severity
    labels are colour coded inline using simple CSS styles.  Each host is
    listed along with its open ports and associated services.  Findings
    and next steps are presented in their own tables.  The caller is
    responsible for ensuring that lists of hosts, findings and steps
    come from the same scan session.

    Args:
        output_path: Where to write the HTML file.
        hosts: Parsed host information from the scan.
        findings: Calculated findings from the rules engine.
        steps: Suggested next steps from the rules engine.

    Returns:
        The resolved path where the report was written.
    """
    path = Path(output_path)
    # Basic CSS for table formatting and severity labels
    styles = """
    <style>
    body { font-family: Arial, sans-serif; line-height: 1.4; padding: 20px; }
    h1 { color: #333333; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
    th, td { border: 1px solid #ddd; padding: 8px; }
    th { background-color: #f2f2f2; }
    .sev-High { background-color: #ffcccc; }
    .sev-Medium { background-color: #fff5cc; }
    .sev-Info { background-color: #e6f7ff; }
    </style>
    """
    html_lines: list[str] = []
    html_lines.append("<html><head><meta charset='utf-8'><title>ScanStrike Report</title>")
    html_lines.append(styles)
    html_lines.append("</head><body>")
    html_lines.append("<h1>ScanStrike Scan Summary</h1>")

    # Hosts section
    html_lines.append("<h2>Hosts</h2>")
    for host in hosts:
        label = f"{host.ip} ({host.hostname})" if host.hostname else host.ip
        html_lines.append(f"<h3>{label}</h3>")
        html_lines.append("<ul>")
        html_lines.append(f"<li>Status: {host.status}</li>")
        html_lines.append(f"<li>OS Guess: {host.os_guess or 'Unknown'}</li>")
        html_lines.append(f"<li>Open Ports: {host.port_count}</li>")
        html_lines.append("</ul>")
        if host.open_ports:
            html_lines.append("<table><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr>")
            for p in host.open_ports:
                version = p.display_version or "Unknown"
                html_lines.append(f"<tr><td>{p.port}</td><td>{p.protocol}</td><td>{p.service or 'unknown'}</td><td>{version}</td></tr>")
            html_lines.append("</table>")

    # Findings section
    html_lines.append("<h2>Interesting Findings</h2>")
    if findings:
        html_lines.append("<table><tr><th>Severity</th><th>Host</th><th>Port</th><th>Title</th><th>Details</th></tr>")
        for f in findings:
            sev_class = f"sev-{f.severity}" if f.severity else ""
            html_lines.append(f"<tr class='{sev_class}'><td>{f.severity}</td><td>{f.host}</td><td>{f.port}</td><td>{f.title}</td><td>{f.details}</td></tr>")
        html_lines.append("</table>")
    else:
        html_lines.append("<p>No interesting findings were detected.</p>")

    # Next steps section
    html_lines.append("<h2>Suggested Next Steps</h2>")
    if steps:
        html_lines.append("<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Action</th></tr>")
        for s in steps:
            html_lines.append(f"<tr><td>{s.host}</td><td>{s.port}</td><td>{s.service}</td><td>{s.action}</td></tr>")
        html_lines.append("</table>")
    else:
        html_lines.append("<p>No suggested next steps generated.</p>")

    html_lines.append("</body></html>")
    path.write_text("\n".join(html_lines), encoding="utf-8")
    return path
