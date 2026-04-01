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
    lines.append("# ReconMap Scan Summary\n")

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
