from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from reconmap.core.models import HostInfo, PortInfo


def _safe_attr(element: ET.Element | None, name: str, default: str = "") -> str:
    if element is None:
        return default
    return element.attrib.get(name, default)


def parse_nmap_xml(xml_path: str | Path) -> list[HostInfo]:
    path = Path(xml_path)
    if not path.exists():
        raise FileNotFoundError(f"XML file not found: {path}")

    tree = ET.parse(path)
    root = tree.getroot()
    hosts: list[HostInfo] = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = _safe_attr(status_el, "state", "unknown")

        ip = ""
        for addr_el in host_el.findall("address"):
            if addr_el.attrib.get("addrtype") in {"ipv4", "ipv6"}:
                ip = addr_el.attrib.get("addr", "")
                break

        hostname = ""
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            hostname = _safe_attr(hn, "name", "")

        os_guess = ""
        os_el = host_el.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            os_guess = _safe_attr(osmatch, "name", "")

        host = HostInfo(ip=ip or "unknown", hostname=hostname, status=status, os_guess=os_guess)

        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                scripts: list[str] = []
                for script_el in port_el.findall("script"):
                    script_id = script_el.attrib.get("id", "script")
                    output = script_el.attrib.get("output", "").strip()
                    if output:
                        scripts.append(f"{script_id}: {output}")

                port = PortInfo(
                    port=int(port_el.attrib.get("portid", 0)),
                    protocol=port_el.attrib.get("protocol", "tcp"),
                    state=_safe_attr(state_el, "state", "unknown"),
                    service=_safe_attr(service_el, "name", ""),
                    product=_safe_attr(service_el, "product", ""),
                    version=_safe_attr(service_el, "version", ""),
                    extrainfo=_safe_attr(service_el, "extrainfo", ""),
                    tunnel=_safe_attr(service_el, "tunnel", ""),
                    scripts=scripts,
                )
                host.ports.append(port)

        hosts.append(host)

    return hosts
