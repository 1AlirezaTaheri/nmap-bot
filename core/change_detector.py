"""Change Detection Engine — compare two normalized snapshots.

This is the heart of the product: it turns "here is what nmap found" into
"here is what *changed* since last time".

It is deliberately a pure module — no database, no Telegram, no I/O. That
makes the behaviour unit-testable and keeps the diff logic independent of
how scans are stored or reported.

Noise control
-------------
Ports on a *newly discovered* host are not reported as "new port" — a
brand-new host obviously has all its ports new, and emitting one line per
port would bury the signal. Only hosts present in both snapshots are
diffed port-by-port.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from parser.normalizer import service_fingerprint

NEW_HOST = "new_host"
CLOSED_HOST = "closed_host"
NEW_PORT = "new_port"
CLOSED_PORT = "closed_port"
SERVICE_CHANGE = "service_change"

# Display order for reports — most significant first.
ORDER = (NEW_HOST, NEW_PORT, SERVICE_CHANGE, CLOSED_PORT, CLOSED_HOST)

LABELS = {
    NEW_HOST: "New host",
    CLOSED_HOST: "Closed host",
    NEW_PORT: "New port",
    CLOSED_PORT: "Closed port",
    SERVICE_CHANGE: "Service changed",
}


@dataclass(frozen=True)
class Change:
    change_type: str
    host: str
    port: int | None = None
    protocol: str | None = None
    old_value: str | None = None
    new_value: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _service_text(service: dict) -> str:
    """Readable service identity, e.g. ``Apache httpd 2.4.49``."""
    parts = [
        (service.get("service_name") or "").strip(),
        (service.get("product") or "").strip(),
        (service.get("version") or "").strip(),
    ]
    return " ".join(p for p in parts if p)


def detect(previous: dict | None, current: dict) -> list[Change]:
    """Diff ``current`` against ``previous``.

    ``previous`` may be ``None`` on a target's first scan, in which case
    everything in ``current`` is reported as new — which is the honest
    answer, and it teaches the operator what the baseline is.
    """
    if previous is None:
        previous = {"hosts": [], "services": {}}

    prev_hosts = {h["address"]: h for h in previous.get("hosts", [])}
    curr_hosts = {h["address"]: h for h in current.get("hosts", [])}
    prev_svcs = previous.get("services", {}) or {}
    curr_svcs = current.get("services", {}) or {}

    changes: list[Change] = []

    added = set(curr_hosts) - set(prev_hosts)
    removed = set(prev_hosts) - set(curr_hosts)

    for address in sorted(added):
        changes.append(Change(change_type=NEW_HOST, host=address))

    for address in sorted(removed):
        changes.append(Change(change_type=CLOSED_HOST, host=address))

    for address in sorted(set(curr_hosts) & set(prev_hosts)):
        before = {int(s["port"]) for s in prev_svcs.get(address, [])}
        after = {int(s["port"]) for s in curr_svcs.get(address, [])}

        for port in sorted(after - before):
            changes.append(
                Change(change_type=NEW_PORT, host=address, port=port, protocol="tcp")
            )
        for port in sorted(before - after):
            changes.append(
                Change(change_type=CLOSED_PORT, host=address, port=port, protocol="tcp")
            )

        before_map = {int(s["port"]): s for s in prev_svcs.get(address, [])}
        after_map = {int(s["port"]): s for s in curr_svcs.get(address, [])}
        for port in sorted(set(before_map) & set(after_map)):
            old = before_map[port]
            new = after_map[port]
            if service_fingerprint(old) != service_fingerprint(new):
                changes.append(
                    Change(
                        change_type=SERVICE_CHANGE,
                        host=address,
                        port=port,
                        protocol=new.get("protocol", "tcp"),
                        old_value=_service_text(old) or "(unknown)",
                        new_value=_service_text(new) or "(unknown)",
                    )
                )

    rank = {t: i for i, t in enumerate(ORDER)}
    changes.sort(
        key=lambda c: (
            rank.get(c.change_type, len(ORDER)),
            c.host,
            c.port if c.port is not None else -1,
        )
    )
    return changes


def summarize(changes: list[Change]) -> dict[str, int]:
    """Counts per change type, in display order."""
    return {t: sum(1 for c in changes if c.change_type == t) for t in ORDER}


def summary_text(changes: list[Change]) -> str:
    """Compact one-liner, e.g. ``+1 host, +1 port, +1 service change, -1 port``."""
    counts = summarize(changes)
    pieces: list[str] = []
    if counts[NEW_HOST]:
        pieces.append(f"+{counts[NEW_HOST]} host")
    if counts[NEW_PORT]:
        pieces.append(f"+{counts[NEW_PORT]} port")
    if counts[SERVICE_CHANGE]:
        pieces.append(f"+{counts[SERVICE_CHANGE]} service change")
    if counts[CLOSED_PORT]:
        pieces.append(f"-{counts[CLOSED_PORT]} port")
    if counts[CLOSED_HOST]:
        pieces.append(f"-{counts[CLOSED_HOST]} host")
    return ", ".join(pieces) if pieces else "no changes"