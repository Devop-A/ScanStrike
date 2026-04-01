from __future__ import annotations

from reconmap.core.models import Finding, HostInfo, NextStep, PortInfo

SERVICE_ACTIONS: dict[str, list[str]] = {
    "ssh": [
        "Review SSH version and banner details.",
        "Validate authorized credentials if they are in scope.",
        "Check whether password auth is enabled and whether MFA is absent.",
    ],
    "ftp": [
        "Check for anonymous login if it is explicitly authorized.",
        "Review accessible files for configs, backups, and credential material.",
        "Assess whether upload capability could affect exposed web roots.",
    ],
    "http": [
        "Fingerprint the web stack and inspect HTTP headers.",
        "Enumerate directories, files, and likely admin/login panels.",
        "Review version strings and page content for outdated software.",
    ],
    "https": [
        "Fingerprint the web stack and inspect TLS details.",
        "Enumerate directories, files, and likely admin/login panels.",
        "Check certificates and subject alternative names for additional targets.",
    ],
    "microsoft-ds": [
        "Enumerate SMB shares and review access control.",
        "Check for guest/null access where authorized.",
        "Look for sensitive files, scripts, or domain information.",
    ],
    "netbios-ssn": [
        "Enumerate NetBIOS/SMB naming and share information.",
        "Correlate hostnames, users, and domains with other findings.",
    ],
    "rdp": [
        "Confirm whether Network Level Authentication is enabled.",
        "Review host exposure and test authorized access paths.",
        "Capture screenshots or notes on the login surface for reporting.",
    ],
    "ms-wbt-server": [
        "Confirm whether Network Level Authentication is enabled.",
        "Review host exposure and test authorized access paths.",
        "Capture screenshots or notes on the login surface for reporting.",
    ],
    "telnet": [
        "Assess whether Telnet is necessary and whether replacement is possible.",
        "Review for plaintext credential exposure on legacy devices.",
    ],
    "imap": [
        "Review mail service exposure, auth methods, and mailbox access controls.",
        "Check whether access could expose sensitive internal communications.",
    ],
    "imaps": [
        "Review mail service exposure, auth methods, and mailbox access controls.",
        "Check whether access could expose sensitive internal communications.",
    ],
    "pop3": [
        "Review mail service exposure, auth methods, and mailbox access controls.",
        "Check whether access could expose sensitive internal communications.",
    ],
    "pop3s": [
        "Review mail service exposure, auth methods, and mailbox access controls.",
        "Check whether access could expose sensitive internal communications.",
    ],
    "vnc": [
        "Review remote console exposure and authentication settings.",
        "Check whether the service leaks desktop or console metadata.",
    ],
    "mysql": [
        "Review remote database exposure and host-based access controls.",
        "Check versioning, SSL use, and authentication policy.",
    ],
    "postgresql": [
        "Review remote database exposure and host-based access controls.",
        "Check versioning, SSL use, and authentication policy.",
    ],
    "rpcbind": [
        "Enumerate RPC programs and review NFS or other linked services.",
    ],
}

INTERESTING_PORTS = {
    21: ("Medium", "FTP exposed"),
    22: ("Info", "SSH exposed"),
    23: ("High", "Telnet exposed"),
    25: ("Info", "SMTP exposed"),
    80: ("Info", "HTTP exposed"),
    111: ("Medium", "RPCBind exposed"),
    139: ("Medium", "NetBIOS exposed"),
    443: ("Info", "HTTPS exposed"),
    445: ("High", "SMB exposed"),
    1433: ("High", "MSSQL exposed"),
    1521: ("High", "Oracle DB exposed"),
    3306: ("High", "MySQL exposed"),
    3389: ("High", "RDP exposed"),
    5432: ("High", "PostgreSQL exposed"),
    5900: ("High", "VNC exposed"),
}

OUTDATED_KEYWORDS = {
    "apache": ["2.4.49", "2.4.50"],
    "openssh": ["5.", "6.", "7.0", "7.1", "7.2", "7.3", "7.4"],
    "samba": ["3.", "4.0", "4.1", "4.2", "4.3"],
}


def _detect_outdated(port: PortInfo) -> list[Finding]:
    findings: list[Finding] = []
    combined = f"{port.product} {port.version}".lower()
    for product_name, versions in OUTDATED_KEYWORDS.items():
        if product_name in combined:
            for version in versions:
                if version in combined:
                    findings.append(
                        Finding(
                            severity="Medium",
                            host="",
                            port=f"{port.port}/{port.protocol}",
                            title=f"Potentially outdated {product_name.title()} version",
                            details=f"Detected version string contains '{version}' in '{combined.strip()}'.",
                        )
                    )
                    break
    return findings


def build_findings_and_steps(hosts: list[HostInfo]) -> tuple[list[Finding], list[NextStep]]:
    findings: list[Finding] = []
    steps: list[NextStep] = []

    for host in hosts:
        for port in host.open_ports:
            if port.port in INTERESTING_PORTS:
                severity, title = INTERESTING_PORTS[port.port]
                findings.append(
                    Finding(
                        severity=severity,
                        host=host.ip,
                        port=f"{port.port}/{port.protocol}",
                        title=title,
                        details=f"Service '{port.service or 'unknown'}' is reachable on {host.ip}:{port.port}.",
                    )
                )

            if port.service.lower() in {"ftp"}:
                for script_line in port.scripts:
                    lower = script_line.lower()
                    if "anonymous" in lower and ("allowed" in lower or "success" in lower):
                        findings.append(
                            Finding(
                                severity="High",
                                host=host.ip,
                                port=f"{port.port}/{port.protocol}",
                                title="Anonymous FTP may be enabled",
                                details=script_line,
                            )
                        )

            for outdated in _detect_outdated(port):
                outdated.host = host.ip
                findings.append(outdated)

            actions = SERVICE_ACTIONS.get(port.service.lower(), [])
            for action in actions:
                steps.append(
                    NextStep(
                        host=host.ip,
                        port=f"{port.port}/{port.protocol}",
                        service=port.service or "unknown",
                        action=action,
                    )
                )

    return findings, steps
