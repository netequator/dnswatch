"""Deterministic unit tests for dnswatch in-memory sinkhole blocklist."""

from __future__ import annotations

import pytest

from dnswatch.sinkhole import SinkholeBlocklist


def test_sinkhole_exact_match() -> None:
    bl = SinkholeBlocklist()
    bl.add("ads.example.com")
    bl.add("TRACKING.BAD.NET.")

    assert bl.is_blocked("ads.example.com") is True
    assert bl.is_blocked("tracking.bad.net") is True
    assert bl.is_blocked("tracking.bad.net.") is True
    assert bl.is_blocked("other.example.com") is False
    assert bl.is_blocked("example.com") is False
    assert "ads.example.com" in bl


def test_sinkhole_wildcard_matching() -> None:
    bl = SinkholeBlocklist()
    bl.add("*.malware.test")

    # Base domain and any subdomain match
    assert bl.is_blocked("malware.test") is True
    assert bl.is_blocked("c2.malware.test") is True
    assert bl.is_blocked("chunk1.beacon.c2.malware.test") is True
    assert bl.is_blocked("othermalware.test") is False
    assert bl.is_blocked("nottest") is False


def test_sinkhole_hosts_file_parsing() -> None:
    bl = SinkholeBlocklist()
    sample_hosts = (
        "# This is a sample hosts blocklist\n"
        "0.0.0.0 ads.adnetwork.com\n"
        "127.0.0.1 telemetry.tracker.io # inline comment\n"
        "::1 ipv6.badactor.org\n"
        "# Empty lines and bad lines ignored\n"
        "\n"
        "malware.direct.net\n"
        "*.wildcard.bad.com\n"
    )
    count = bl.load_text(sample_hosts)
    assert count >= 5
    assert bl.is_blocked("ads.adnetwork.com") is True
    assert bl.is_blocked("telemetry.tracker.io") is True
    assert bl.is_blocked("ipv6.badactor.org") is True
    assert bl.is_blocked("malware.direct.net") is True
    assert bl.is_blocked("sub.wildcard.bad.com") is True
    assert bl.is_blocked("clean-domain.com") is False


def test_sinkhole_empty_and_comments() -> None:
    bl = SinkholeBlocklist()
    bl.add("")
    bl.add("   ")
    bl.add("# just a comment")
    assert len(bl) == 0
    assert bl.is_blocked("") is False


def test_sinkhole_file_not_found() -> None:
    bl = SinkholeBlocklist()
    with pytest.raises(FileNotFoundError):
        bl.load_file("/nonexistent/path/to/blocklist.txt")
