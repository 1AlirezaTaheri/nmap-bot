"""Canonicalize parsed scan output into a stable snapshot.

The normalizer is what makes change detection possible: two runs must be
compared in exactly the same shape, regardless of nmap's ordering,
whitespace, or IPv6 casing.
"""

from __future__ import annotations

from parser.xml_parser import ParsedHost

Snapshot = dict


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    value = " ".join(value.split()).strip()
    return value or None


def normalize(parsed: list[ParsedHost]) -> Snapshot:
    """Return ``{"hosts": [...], "services": {address: [...]}}``.

    - only hosts whose state is ``up`` are kept (a down host carries no
      port information and would produce phantom "closed port" noise);
    - addresses are lowercased so IPv6 comparisons are stable;
    - ports are sorted numerically and de-duplicated;
    - strings are whitespace-normalized and empty strings become ``None``.
    """
    hosts: list[dict] = []
    services: dict[str, list[dict]] = {}

    kept: dict[str, dict] = {}
    for entry in parsed:
        if entry.state != "up":
            continue
        address = _clean(entry.address)
        if not address:
            continue
        kept[address.lower()] = {
            "address": address.lower(),
            "hostname": _clean(entry.hostname),
            "state": entry.state,
        }

    for address, host in kept.items():
        hosts.append(host)

    for entry in parsed:
        if entry.state != "up":
            continue
        address = (address_key := _clean(entry.address)) and address_key.lower()
        if not address or address not in kept:
            continue

        seen: dict[tuple[int, str], dict] = {}
        for port in entry.ports:
            key = (int(port["port"]), port.get("protocol", "tcp"))
            record = {
                "port": key[0],
                "protocol": key[1],
                "state": port.get("state", "open"),
                "service_name": _clean(port.get("service_name")),
                "product": _clean(port.get("product")),
                "version": _clean(port.get("version")),
            }
            seen[key] = record
        if seen:
            services[address] = [
                seen[k] for k in sorted(seen, key=lambda kp: (kp[0], kp[1]))
            ]

    hosts.sort(key=lambda h: h["address"])
    return {"hosts": hosts, "services": services}


def service_fingerprint(service: dict) -> str:
    """Stable, case-insensitive identity of a service for comparison."""
    parts = [
        (service.get("service_name") or "").strip().lower(),
        (service.get("product") or "").strip().lower(),
        (service.get("version") or "").strip().lower(),
    ]
    return " ".join(p for p in parts if p)