"""Parse nmap's XML output into plain structures.

Uses only the standard library: the document is produced by the nmap
binary we invoked, not read from an untrusted source.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


class NmapXmlError(ValueError):
    """Raised when the document is not nmap XML we can read."""


@dataclass
class ParsedHost:
    address: str
    hostname: str | None = None
    state: str = "up"
    ports: list[dict] = field(default_factory=list)


def parse(xml_text: str) -> list[ParsedHost]:
    """Return one :class:`ParsedHost` per ``<host>`` element."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapXmlError(f"Malformed nmap XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise NmapXmlError(f"Unexpected root element: {root.tag!r}")

    hosts: list[ParsedHost] = []
    for host_el in root.findall("host"):
        address = _address(host_el)
        if not address:
            continue

        # nmap emits <status state="up"/> — the element is `status`,
        # the state is its attribute. Looking for a `state` element here
        # silently defaults every host to "up".
        status = host_el.find("status")
        state = status.get("state", "up") if status is not None else "up"

        hosts.append(
            ParsedHost(
                address=address,
                hostname=_hostname(host_el),
                state=state,
                ports=_ports(host_el),
            )
        )
    return hosts


def _address(host_el: ET.Element) -> str | None:
    """Prefer IPv4, then IPv6, then any other address type (e.g. MAC)."""
    candidates = host_el.findall("address")
    for want in ("ipv4", "ipv6"):
        for el in candidates:
            if el.get("addrtype") == want:
                return el.get("addr")
    for el in candidates:
        if el.get("addr"):
            return el.get("addr")
    return None


def _hostname(host_el: ET.Element) -> str | None:
    names = host_el.find("hostnames")
    if names is None:
        return None
    for hn in names.findall("hostname"):
        if hn.get("name"):
            return hn.get("name")
    return None


def _ports(host_el: ET.Element) -> list[dict]:
    """Collect only ports nmap reports as ``open`` — that is the set the
    change detector diffs against. ``closed``/``filtered`` ports are
    omitted by nmap in default output, and including them would make the
    baseline depend on scan flags rather than on real change."""
    ports_el = host_el.find("ports")
    if ports_el is None:
        return []

    out: list[dict] = []
    for port_el in ports_el.findall("port"):
        state_el = port_el.find("state")
        state = state_el.get("state", "unknown") if state_el is not None else "unknown"
        if state != "open":
            continue

        svc_el = port_el.find("service")
        port_id = port_el.get("portid")
        if port_id is None:
            continue
        try:
            port_num = int(port_id)
        except ValueError:
            continue

        out.append(
            {
                "port": port_num,
                "protocol": port_el.get("protocol", "tcp"),
                "state": state,
                "service_name": _attr(svc_el, "name"),
                "product": _attr(svc_el, "product"),
                "version": _attr(svc_el, "version"),
            }
        )
    return out


def _attr(el: ET.Element | None, name: str) -> str | None:
    if el is None:
        return None
    value = el.get(name)
    return value if value else None