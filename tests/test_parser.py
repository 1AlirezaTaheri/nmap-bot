"""Tests for nmap XML parsing and normalization."""

from __future__ import annotations

import pytest

from parser import xml_parser
from parser.normalizer import normalize, service_fingerprint
from parser.xml_parser import NmapXmlError

SAMPLE = """<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -F -T4 -oX - 192.168.1.10" version="7.95">
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="web.lab" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/></port>
      <port protocol="tcp" portid="23"><state state="closed"/>
        <service name="telnet"/></port>
      <port protocol="tcp" portid="443"><state state="filtered"/></port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
  </host>
  <runstats><finished time="1"/><hosts up="1" down="1" total="2"/></runstats>
</nmaprun>
"""


class TestParser:
    def test_parses_hosts(self):
        hosts = xml_parser.parse(SAMPLE)
        assert len(hosts) == 2
        assert hosts[0].address == "192.168.1.10"
        assert hosts[0].hostname == "web.lab"
        assert hosts[1].state == "down"

    def test_keeps_only_open_ports(self):
        hosts = xml_parser.parse(SAMPLE)
        ports = {p["port"] for p in hosts[0].ports}
        assert ports == {80, 22}  # 23 closed, 443 filtered are dropped

    def test_extracts_service_metadata(self):
        host = xml_parser.parse(SAMPLE)[0]
        http = next(p for p in host.ports if p["port"] == 80)
        assert http["service_name"] == "http"
        assert http["product"] == "nginx"
        assert http["version"] == "1.18.0"

    def test_rejects_non_nmap_xml(self):
        with pytest.raises(NmapXmlError):
            xml_parser.parse("<html><body>proxy error</body></html>")

    def test_rejects_malformed(self):
        with pytest.raises(NmapXmlError):
            xml_parser.parse("this is not xml at all")


class TestNormalizer:
    def test_drops_down_hosts(self):
        snap = normalize(xml_parser.parse(SAMPLE))
        assert [h["address"] for h in snap["hosts"]] == ["192.168.1.10"]

    def test_sorts_hosts_and_ports(self):
        raw = """<?xml version="1.0"?><nmaprun>
          <host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="90"><state state="open"/></port>
              <port protocol="tcp" portid="22"><state state="open"/></port>
            </ports></host>
          <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/></host>
        </nmaprun>"""
        snap = normalize(xml_parser.parse(raw))
        assert [h["address"] for h in snap["hosts"]] == ["10.0.0.1", "10.0.0.2"]
        assert [p["port"] for p in snap["services"]["10.0.0.2"]] == [22, 90]

    def test_normalizes_whitespace_in_service_fields(self):
        raw = """<?xml version="1.0"?><nmaprun>
          <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
            <ports><port protocol="tcp" portid="80"><state state="open"/>
              <service name="http   " product="   nginx"/></port>
            </ports></host></nmaprun>"""
        svc = normalize(xml_parser.parse(raw))["services"]["10.0.0.1"][0]
        assert svc["service_name"] == "http"
        assert svc["product"] == "nginx"

    def test_deduplicates_identical_ports(self):
        raw = """<?xml version="1.0"?><nmaprun>
          <host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="22"><state state="open"/></port>
              <port protocol="tcp" portid="22"><state state="open"/></port>
            </ports></host></nmaprun>"""
        snap = normalize(xml_parser.parse(raw))
        assert len(snap["services"]["10.0.0.1"]) == 1


class TestFingerprint:
    def test_case_insensitive(self):
        a = {"service_name": "HTTP", "product": "Nginx", "version": "1.0"}
        b = {"service_name": "http", "product": "nginx", "version": "1.0"}
        assert service_fingerprint(a) == service_fingerprint(b)

    def test_ignores_missing_vs_empty(self):
        a = {"service_name": "http", "product": None, "version": ""}
        b = {"service_name": "http", "product": "", "version": None}
        assert service_fingerprint(a) == service_fingerprint(b)