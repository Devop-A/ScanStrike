from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

SCAN_PROFILES: dict[str, list[str]] = {
    "Quick Scan": ["-T4", "-F"],
    "Service Scan": ["-sV"],
    "Default Scripts + Versions": ["-sC", "-sV"],
    "Full TCP": ["-p-"],
    "Aggressive": ["-A"],
    "Ping Sweep": ["-sn"],
}


@dataclass(slots=True)
class ScanPlan:
    command: list[str]
    xml_path: Path
    text_path: Path
    working_dir: Path


class ScannerError(Exception):
    pass


class Scanner:
    def __init__(self, output_dir: str | None = None) -> None:
        self.nmap_path = shutil.which("nmap")
        self.output_root = Path(output_dir) if output_dir else Path(tempfile.gettempdir()) / "reconmap"
        self.output_root.mkdir(parents=True, exist_ok=True)

    def ensure_nmap(self) -> None:
        if not self.nmap_path:
            raise ScannerError("Nmap was not found in PATH. Install nmap first.")

    def build_scan_plan(self, target: str, profile_name: str, custom_args: str = "") -> ScanPlan:
        self.ensure_nmap()
        if not target.strip():
            raise ScannerError("Target cannot be empty.")

        workdir = Path(tempfile.mkdtemp(prefix="reconmap_", dir=str(self.output_root)))
        xml_path = workdir / "scan.xml"
        text_path = workdir / "scan.nmap"

        profile_args = SCAN_PROFILES.get(profile_name, []).copy()
        extra_args = [arg for arg in custom_args.split() if arg.strip()]

        command = [
            self.nmap_path or "nmap",
            *profile_args,
            *extra_args,
            "-oX",
            str(xml_path),
            "-oN",
            str(text_path),
            target.strip(),
        ]
        return ScanPlan(command=command, xml_path=xml_path, text_path=text_path, working_dir=workdir)
