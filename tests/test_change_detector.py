"""Tests for the Change Detection Engine — the core of the product."""

from __future__ import annotations

from core.change_detector import (
    CLOSED_HOST,
    CLOSED_PORT,
    NEW_HOST,
    NEW_PORT,
    SERVICE_CHANGE,
    detect,
    summarize,
    summary_text,
)


def snap(hosts: list[str], ports: dict[str, list[tuple]] | None = None) -> dict:
    """Build a normalized snapshot: hosts list + services by address.

    ``ports`` maps address -> [(port, name, product, version), ...]
    """
    ports = ports or {}
    return {
        "hosts": [{"address": h, "hostname": None, "state": "up"} for h in hosts],
        "services": {
            address: [
                {
                    "port": p,
                    "protocol": "tcp",
                    "state": "open",
                    "service_name": name,
                    "product": product,
                    "version": version,
                }
                for (p, name, product, version) in entries
            ]
            for address, entries in ports.items()
        },
    }


def types(changes):
    return [c.change_type for c in changes]


class TestNewAndGone:
    def test_new_host_detected(self):
        prev = snap(["10.0.0.1"], {"10.0.0.1": [(22, "ssh", None, None)]})
        curr = snap(
            ["10.0.0.1", "10.0.0.2"],
            {"10.0.0.1": [(22, "ssh", None, None)],
             "10.0.0.2": [(80, "http", None, None)]},
        )
        changes = detect(prev, curr)
        assert types(changes) == [NEW_HOST]
        assert changes[0].host == "10.0.0.2"

    def test_closed_host_detected(self):
        prev = snap(["10.0.0.1", "10.0.0.2"])
        curr = snap(["10.0.0.1"])
        changes = detect(prev, curr)
        assert types(changes) == [CLOSED_HOST]
        assert changes[0].host == "10.0.0.2"

    def test_first_scan_with_no_baseline(self):
        curr = snap(["10.0.0.1"], {"10.0.0.1": [(22, "ssh", None, None)]})
        changes = detect(None, curr)
        assert types(changes) == [NEW_HOST]

    def test_identical_scans_report_nothing(self):
        s = snap(["10.0.0.1"], {"10.0.0.1": [(22, "ssh", None, None)]})
        assert detect(s, dict(s)) == []


class TestPortDiff:
    def test_new_port(self):
        prev = snap(["10.0.0.1"], {"10.0.0.1": [(22, "ssh", None, None)]})
        curr = snap(
            ["10.0.0.1"],
            {"10.0.0.1": [(22, "ssh", None, None), (8080, "http", None, None)]},
        )
        changes = detect(prev, curr)
        assert types(changes) == [NEW_PORT]
        assert changes[0].port == 8080

    def test_closed_port(self):
        prev = snap(
            ["10.0.0.1"], {"10.0.0.1": [(23, "telnet", None, None)]}
        )
        curr = snap(["10.0.0.1"], {"10.0.0.1": []})
        changes = detect(prev, curr)
        assert types(changes) == [CLOSED_PORT]
        assert changes[0].port == 23

    def test_ports_of_new_host_are_not_reported_as_new_port(self):
        """Noise control: a brand-new host's ports are implied by NEW_HOST."""
        prev = snap(["10.0.0.1"])
        curr = snap(
            ["10.0.0.1", "10.0.0.9"],
            {"10.0.0.9": [(22, "ssh", None, None), (80, "http", None, None)]},
        )
        changes = detect(prev, curr)
        assert types(changes) == [NEW_HOST]


class TestServiceChanges:
    def test_product_change_detected(self):
        prev = snap(
            ["10.0.0.1"], {"10.0.0.1": [(80, "http", "Apache", "2.4.49")]}
        )
        curr = snap(
            ["10.0.0.1"], {"10.0.0.1": [(80, "http", "nginx", "1.18.0")]}
        )
        changes = detect(prev, curr)
        assert types(changes) == [SERVICE_CHANGE]
        c = changes[0]
        assert "Apache" in c.old_value and "nginx" in c.new_value
        assert c.port == 80

    def test_fingerprint_ignores_case_and_whitespace(self):
        prev = snap(
            ["10.0.0.1"], {"10.0.0.1": [(80, "http", "Apache", "2.4")]}
        )
        curr = snap(
            ["10.0.0.1"], {"10.0.0.1": [(80, "HTTP", "apache", " 2.4 ")]}
        )
        assert detect(prev, curr) == []

    def test_version_bump_is_a_change(self):
        prev = snap(
            ["10.0.0.1"], {"10.0.0.1": [(22, "ssh", "OpenSSH", "8.2")]}
        )
        curr = snap(
            ["10.0.0.1"], {"10.0.0.1": [(22, "ssh", "OpenSSH", "8.4")]}
        )
        assert types(detect(prev, curr)) == [SERVICE_CHANGE]

    def test_same_port_different_service(self):
        prev = snap(["10.0.0.1"], {"10.0.0.1": [(8080, "http-proxy", None, None)]})
        curr = snap(["10.0.0.1"], {"10.0.0.1": [(8080, "unknown", None, None)]})
        assert types(detect(prev, curr)) == [SERVICE_CHANGE]


class TestSummary:
    def test_summary_text_matches_image_example(self):
        # Mirrors the architecture diagram's demo output:
        #   New host: 192.168.1.37
        #   New port: 192.168.1.17:8080      <- existing host gains a port
        #   Service changed: 192.168.1.10 (Apache -> nginx)
        #   Closed port: 192.168.1.21:23
        #   Summary: +1 host, +1 port, +1 service change, -1 port
        prev = snap(
            ["10.0.0.10", "10.0.0.17", "10.0.0.21"],
            {
                "10.0.0.10": [(80, "http", "Apache", "2.4")],
                "10.0.0.21": [(23, "telnet", None, None)],
            },
        )
        curr = snap(
            ["10.0.0.10", "10.0.0.17", "10.0.0.21", "10.0.0.37"],
            {
                "10.0.0.10": [(80, "http", "nginx", "1.18")],
                "10.0.0.17": [(8080, "http", None, None)],
                "10.0.0.21": [],
                "10.0.0.37": [(17, "unknown", None, None)],
            },
        )
        changes = detect(prev, curr)
        text = summary_text(changes)
        assert "+1 host" in text
        assert "+1 port" in text
        assert "service change" in text
        assert "-1 port" in text
        assert "-1 host" not in text

    def test_summarize_counts_each_type(self):
        prev = snap(["10.0.0.1"], {"10.0.0.1": [(23, "telnet", None, None)]})
        curr = snap(["10.0.0.2"], {"10.0.0.2": [(80, "http", None, None)]})
        counts = summarize(detect(prev, curr))
        assert counts[NEW_HOST] == 1
        assert counts[CLOSED_HOST] == 1
        assert counts[NEW_PORT] == 0  # ports of brand-new hosts suppressed

    def test_no_changes_summary(self):
        assert summary_text([]) == "no changes"