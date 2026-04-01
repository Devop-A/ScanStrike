from __future__ import annotations

from reconmap.core.models import Finding, HostInfo, NextStep, PortInfo

# Mapping of services to a list of suggested follow‑up actions.
# When ScanStrike completes a scan, these actions are surfaced
# in the "Next Steps" tab to help the operator think like a
# penetration tester.  These lists have been expanded beyond
# the original set to include common enumeration tasks for
# high‑value services such as SMB and HTTP.  New services can
# be added here or through future plugin extensions.  Where
# appropriate, the tasks describe specific tools (e.g. Gobuster
# for web fuzzing or enum4linux for SMB enumeration) but they
# are not executed automatically; instead, the operator can copy
# and run them manually or integrate tooling via plugins.
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
        "Run dictionary attacks or use Nmap --script ftp-anon to verify anonymous access.",
    ],
    "http": [
        "Fingerprint the web stack and inspect HTTP headers.",
        "Enumerate directories, files, and likely admin/login panels (e.g. with Gobuster).",
        "Review version strings and page content for outdated software.",
        "Run web vulnerability scanners such as Nikto to look for misconfigurations.",
    ],
    "https": [
        "Fingerprint the web stack and inspect TLS details.",
        "Enumerate directories, files, and likely admin/login panels (e.g. with Gobuster).",
        "Check certificates and subject alternative names for additional targets.",
        "Run web vulnerability scanners such as Nikto to look for misconfigurations.",
    ],
    "microsoft-ds": [
        "Enumerate SMB shares and review access control (e.g. using smbclient or enum4linux).",
        "Check for guest/null access where authorized.",
        "Look for sensitive files, scripts, or domain information.",
        "Attempt to dump domain information if the service appears to be a domain controller.",
    ],
    "netbios-ssn": [
        "Enumerate NetBIOS/SMB naming and share information.",
        "Correlate hostnames, users, and domains with other findings.",
    ],
    "rdp": [
        "Confirm whether Network Level Authentication is enabled.",
        "Review host exposure and test authorized access paths.",
        "Capture screenshots or notes on the login surface for reporting.",
        "Consider using rdesktop or xfreerdp to test connectivity if allowed.",
    ],
    "ms-wbt-server": [
        "Confirm whether Network Level Authentication is enabled.",
        "Review host exposure and test authorized access paths.",
        "Capture screenshots or notes on the login surface for reporting.",
        "Consider using rdesktop or xfreerdp to test connectivity if allowed.",
    ],
    "telnet": [
        "Assess whether Telnet is necessary and whether replacement is possible.",
        "Review for plaintext credential exposure on legacy devices.",
        "Attempt to connect manually and look for banners or credential prompts.",
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
        "Use a VNC client to capture screenshots if authorized.",
    ],
    "mysql": [
        "Review remote database exposure and host‑based access controls.",
        "Check versioning, SSL use, and authentication policy.",
        "Attempt to connect with default or weak credentials where permitted.",
    ],
    "postgresql": [
        "Review remote database exposure and host‑based access controls.",
        "Check versioning, SSL use, and authentication policy.",
        "Attempt to connect with default or weak credentials where permitted.",
    ],
    "rpcbind": [
        "Enumerate RPC programs and review NFS or other linked services.",
    ],
    # Additional service aliases for convenience
    "smb": [
        "Enumerate SMB shares and review access control (e.g. using smbclient or enum4linux).",
        "Check for guest/null access where authorized.",
        "Look for sensitive files, scripts, or domain information.",
        "Attempt to dump domain information if the service appears to be a domain controller.",
    ],
}

# Simple flags indicating when a service may present additional attack surface.
# Each entry maps a lowercase service name to a tuple of (severity, message).
# These flags are used by the build_findings_and_steps() function to surface
# human‑readable findings like "Web service detected → high likelihood of attack surface".
SERVICE_FLAGS: dict[str, tuple[str, str]] = {
    "ftp": ("Medium", "Possible anonymous access"),
    "microsoft-ds": ("High", "SMB service exposed → potential internal network exposure"),
    "smb": ("High", "SMB service exposed → potential internal network exposure"),
    "netbios-ssn": ("Medium", "NetBIOS service exposed"),
    "rdp": ("High", "RDP service detected → remote access surface"),
    "ms-wbt-server": ("High", "RDP service detected → remote access surface"),
    "telnet": ("High", "Telnet detected → insecure protocol in use"),
    "http": ("Info", "Web service detected → high likelihood of attack surface"),
    "https": ("Info", "Web service detected → high likelihood of attack surface"),
    "unknown": ("Info", "Unknown service detected → needs fingerprinting"),
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
    """Construct lists of findings and next steps from parsed host information.

    This function produces human‑readable findings from open ports and services,
    leveraging both port‑based heuristics (e.g. certain TCP/UDP ports are always
    interesting) and service‑based flags (e.g. any HTTP service implies web
    enumeration).  It also surfaces potential issues such as anonymous FTP
    access, outdated service versions, and unknown services that require
    fingerprinting.  Suggested next steps are assembled from the
    SERVICE_ACTIONS mapping or, if the service is unknown, fall back to a
    generic fingerprinting recommendation.

    Args:
        hosts: A list of HostInfo objects populated from an Nmap XML file.

    Returns:
        A tuple containing two lists: findings and next steps.
    """
    findings: list[Finding] = []
    steps: list[NextStep] = []

    for host in hosts:
        for port in host.open_ports:
            service_name = port.service.lower() if port.service else ""

            # Flag interesting ports explicitly based on port number (original behaviour)
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

            # Add service‑specific flags.  If the service is blank or unknown, use
            # the 'unknown' key to encourage fingerprinting.  These flags are
            # separate from interesting ports so that something like HTTP on
            # port 8080 still triggers a web‑service finding.
            flag_key = service_name if service_name else "unknown"
            flag = SERVICE_FLAGS.get(flag_key)
            if flag:
                sev, msg = flag
                findings.append(
                    Finding(
                        severity=sev,
                        host=host.ip,
                        port=f"{port.port}/{port.protocol}",
                        title=msg,
                        details=f"Detected service '{port.service or 'unknown'}' on {host.ip}:{port.port}.",
                    )
                )

            # Detect anonymous FTP script results as before
            if service_name == "ftp":
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

            # Add outdated version findings
            for outdated in _detect_outdated(port):
                outdated.host = host.ip
                findings.append(outdated)

            # Determine next steps based on service.  Use synonyms for SMB.
            actions = SERVICE_ACTIONS.get(service_name, [])
            # For unknown services, suggest fingerprinting
            if not actions and not service_name:
                actions = ["Perform service fingerprinting to identify protocols and versions."]
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
