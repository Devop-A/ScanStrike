from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass(slots=True)
class PortInfo:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    scripts: list[str] = field(default_factory=list)

    @property
    def display_version(self) -> str:
        parts = [self.product.strip(), self.version.strip(), self.extrainfo.strip()]
        return " ".join([p for p in parts if p]).strip()


@dataclass(slots=True)
class HostInfo:
    ip: str
    hostname: str = ""
    status: str = "unknown"
    os_guess: str = ""
    ports: List[PortInfo] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortInfo]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def port_count(self) -> int:
        return len(self.open_ports)


@dataclass(slots=True)
class Finding:
    severity: str
    host: str
    port: str
    title: str
    details: str


@dataclass(slots=True)
class NextStep:
    host: str
    port: str
    service: str
    action: str
