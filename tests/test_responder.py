"""Deterministic unit tests for dnswatch RFC 1035 synthetic response generator."""

from __future__ import annotations

import pytest

from dnswatch.constants import RCODE_NXDOMAIN, TYPE_A, TYPE_AAAA
from dnswatch.parser import parse_dns_packet
from dnswatch.responder import build_sinkhole_response


def make_raw_query(txid: int, qname: str, qtype: int = 1) -> bytes:
    """Helper to construct a raw RFC 1035 wire query."""
    header = txid.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname_bytes = bytearray()
    for part in qname.split("."):
        qname_bytes.append(len(part))
        qname_bytes.extend(part.encode("ascii"))
    qname_bytes.append(0)
    qtail = qtype.to_bytes(2, "big") + (1).to_bytes(2, "big")  # QTYPE, QCLASS=IN
    return header + bytes(qname_bytes) + qtail


def test_build_sinkhole_response_a_record() -> None:
    query = make_raw_query(0x1337, "ads.bad.com", TYPE_A)
    resp = build_sinkhole_response(query, sink_ip="0.0.0.0", ttl=300)

    # Parse synthesized response with our own wire dissector
    packet = parse_dns_packet(resp)
    assert packet.header.txid == 0x1337
    assert packet.header.qr == "response"
    assert packet.header.aa is True
    assert packet.header.rd is True
    assert packet.header.ra is True
    assert packet.header.rcode == "NOERROR"
    assert len(packet.questions) == 1
    assert packet.questions[0].name == "ads.bad.com"
    assert packet.questions[0].qtype == TYPE_A

    assert len(packet.answers) == 1
    ans = packet.answers[0]
    assert ans.name == "ads.bad.com"
    assert ans.rtype == TYPE_A
    assert ans.ttl == 300
    assert ans.rdata == "0.0.0.0"


def test_build_sinkhole_response_custom_ip() -> None:
    query = make_raw_query(0xBEEF, "malware.test", TYPE_A)
    resp = build_sinkhole_response(query, sink_ip="127.0.0.1", ttl=60)

    packet = parse_dns_packet(resp)
    assert packet.header.txid == 0xBEEF
    assert len(packet.answers) == 1
    assert packet.answers[0].rdata == "127.0.0.1"


def test_build_sinkhole_response_aaaa_record() -> None:
    query = make_raw_query(0xCAFE, "ipv6.sinkhole.test", TYPE_AAAA)
    resp = build_sinkhole_response(query, sink_ipv6="::1", ttl=120)

    packet = parse_dns_packet(resp)
    assert packet.header.txid == 0xCAFE
    assert packet.header.qr == "response"
    assert len(packet.answers) == 1
    assert packet.answers[0].rtype == TYPE_AAAA
    assert packet.answers[0].rdata in ("::1", "0000:0000:0000:0000:0000:0000:0000:0001")


def test_build_sinkhole_response_nxdomain() -> None:
    query = make_raw_query(0x55AA, "blocked.host.org", TYPE_A)
    resp = build_sinkhole_response(query, rcode=RCODE_NXDOMAIN)

    packet = parse_dns_packet(resp)
    assert packet.header.txid == 0x55AA
    assert packet.header.qr == "response"
    assert packet.header.rcode == "NXDOMAIN"
    assert len(packet.answers) == 0


def test_build_sinkhole_response_truncated_error() -> None:
    short_buf = b"\x12\x34\x01\x00"
    with pytest.raises(ValueError, match="too short"):
        build_sinkhole_response(short_buf)


def test_build_sinkhole_response_zero_questions_error() -> None:
    zero_q_header = b"\x12\x34\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    with pytest.raises(ValueError, match="zero questions"):
        build_sinkhole_response(zero_q_header)
