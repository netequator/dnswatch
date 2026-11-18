"""Deterministic unit test suite for dnswatch RFC 1035 and RFC 6891 wire-format parser."""

from __future__ import annotations

import json

import pytest

from dnswatch.constants import TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_OPT, TYPE_PTR, TYPE_TXT
from dnswatch.parser import decode_name, parse_dns_packet, parse_header


def test_parse_header_query() -> None:
    wire = (
        b"\xaa\xbb"  # txid 0xAABB
        b"\x01\x00"  # flags: standard query, RD=1
        b"\x00\x01"  # qdcount = 1
        b"\x00\x00"  # ancount = 0
        b"\x00\x00"  # nscount = 0
        b"\x00\x00"  # arcount = 0
    )
    hdr = parse_header(wire)
    assert hdr.txid == 0xAABB
    assert hdr.qr == "query"
    assert hdr.opcode == 0
    assert not hdr.aa
    assert not hdr.tc
    assert hdr.rd
    assert not hdr.ra
    assert hdr.rcode == "NOERROR"
    assert hdr.qdcount == 1
    assert hdr.ancount == 0


def test_parse_header_response_flags() -> None:
    wire = (
        b"\x12\x34"  # txid 0x1234
        b"\x85\x83"  # QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCODE=3 (NXDOMAIN)
        b"\x00\x01"  # qdcount = 1
        b"\x00\x00"  # ancount = 0
        b"\x00\x01"  # nscount = 1
        b"\x00\x00"  # arcount = 0
    )
    hdr = parse_header(wire)
    assert hdr.txid == 0x1234
    assert hdr.qr == "response"
    assert hdr.aa
    assert hdr.rd
    assert hdr.ra
    assert hdr.rcode == "NXDOMAIN"
    assert hdr.rcode_num == 3
    assert hdr.nscount == 1


def test_parse_header_truncated() -> None:
    with pytest.raises(ValueError, match="Packet too short"):
        parse_header(b"\x00" * 11)


def test_decode_name_simple() -> None:
    wire = b"\x03www\x07example\x03com\x00"
    name, next_off = decode_name(wire, 0)
    assert name == "www.example.com"
    assert next_off == len(wire)


def test_decode_name_root() -> None:
    wire = b"\x00"
    name, next_off = decode_name(wire, 0)
    assert name == "."
    assert next_off == 1


def test_decode_name_compression_pointer() -> None:
    wire = (
        b"\x00" * 12
        + b"\x07example\x03com\x00"  # offset 12..24
        + b"\x03foo\xc0\x0c"  # offset 25: "foo" -> pointer to byte 12 ("example.com")
    )
    name, next_off = decode_name(wire, 25)
    assert name == "foo.example.com"
    assert next_off == 31  # offset 25 + 4 ("\x03foo") + 2 (pointer)


def test_decode_name_cursor_lock() -> None:
    wire = (
        b"\x00" * 12
        + b"\x03com\x00"  # offset 12: "com"
        + b"\x07example\xc0\x0c"  # offset 17: "example" -> pointer to 12 ("com")
        + b"\x03www\xc0\x11"  # offset 27: "www" -> pointer to 17 ("example.com")
        + b"\x00\x01\x00\x01"  # trailing fields
    )
    name, next_off = decode_name(wire, 27)
    assert name == "www.example.com"
    # First pointer was encountered at 27 + 4 = 31. Pointer takes 2 bytes. Return must be 33.
    assert next_off == 33


def test_decode_name_loop_trap() -> None:
    buf = bytearray(40)
    buf[20:22] = b"\xc0\x14"  # pointer to byte 20 itself
    with pytest.raises(ValueError, match="Compression pointer loop"):
        decode_name(buf, 20)


def test_decode_name_hop_limit() -> None:
    buf = bytearray(100)
    # Build 20 pointer hops
    for i in range(20):
        target = (i + 1) * 2
        buf[i * 2 : (i * 2) + 2] = bytes([0xC0 | (target >> 8), target & 0xFF])
    with pytest.raises(ValueError, match="Exceeded maximum pointer hops"):
        decode_name(buf, 0, max_hops=10)


def test_parse_a_record() -> None:
    packet_bytes = (
        b"\x12\x34"  # txid
        b"\x81\x80"  # standard response NOERROR
        b"\x00\x01"  # 1 question
        b"\x00\x01"  # 1 answer
        b"\x00\x00\x00\x00"
        b"\x07example\x03com\x00"  # QNAME
        b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
        b"\xc0\x0c"  # Answer NAME pointer to offset 12 (example.com)
        b"\x00\x01"  # TYPE=A
        b"\x00\x01"  # CLASS=IN
        b"\x00\x00\x01\x2c"  # TTL=300
        b"\x00\x04"  # RDLENGTH=4
        b"\x5d\xb8\xd8\x22"  # RDATA: 93.184.216.34
    )
    pkt = parse_dns_packet(packet_bytes)
    assert pkt.header.ancount == 1
    assert len(pkt.answers) == 1
    ans = pkt.answers[0]
    assert ans.name == "example.com"
    assert ans.rtype == TYPE_A
    assert ans.rtype_name == "A"
    assert ans.rclass_name == "IN"
    assert ans.ttl == 300
    assert ans.rdata == "93.184.216.34"


def test_parse_aaaa_record() -> None:
    packet_bytes = (
        b"\x56\x78"
        b"\x81\x80"
        b"\x00\x01\x00\x01\x00\x00\x00\x00"
        b"\x04ipv6\x03lab\x00"
        b"\x00\x1c\x00\x01"  # QTYPE=AAAA, QCLASS=IN
        b"\xc0\x0c"
        b"\x00\x1c"  # TYPE=AAAA (28)
        b"\x00\x01"  # CLASS=IN
        b"\x00\x00\x0e\x10"  # TTL=3600
        b"\x00\x10"  # RDLENGTH=16
        b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"  # 2001:db8::1
    )
    pkt = parse_dns_packet(packet_bytes)
    assert len(pkt.answers) == 1
    ans = pkt.answers[0]
    assert ans.rtype == TYPE_AAAA
    assert ans.rtype_name == "AAAA"
    assert ans.rdata == "2001:db8::1"


def test_parse_cname_record() -> None:
    packet_bytes = (
        b"\x99\x99"
        b"\x81\x80"
        b"\x00\x01\x00\x01\x00\x00\x00\x00"
        b"\x05alias\x03com\x00"  # offset 12..22
        b"\x00\x05\x00\x01"
        b"\xc0\x0c"  # Name points to alias.com
        b"\x00\x05\x00\x01"  # CNAME, IN
        b"\x00\x00\x00\x3c"  # TTL=60
        b"\x00\x0c"  # RDLENGTH=12 ("\x06target\x03com\x00")
        b"\x06target\x03com\x00"  # RDATA: target.com
    )
    pkt = parse_dns_packet(packet_bytes)
    assert len(pkt.answers) == 1
    ans = pkt.answers[0]
    assert ans.rtype == TYPE_CNAME
    assert ans.rdata == "target.com"


def test_parse_ptr_record() -> None:
    packet_bytes = (
        b"\x11\x22"
        b"\x81\x80"
        b"\x00\x01\x00\x01\x00\x00\x00\x00"
        b"\x011\x011\x03168\x03192\x07in-addr\x04arpa\x00"
        b"\x00\x0c\x00\x01"  # PTR, IN
        b"\xc0\x0c"
        b"\x00\x0c\x00\x01"
        b"\x00\x00\x03\x84"  # TTL=900
        b"\x00\x0b"  # RDLENGTH=11
        b"\x06router\x03lan\x00"
    )
    pkt = parse_dns_packet(packet_bytes)
    assert len(pkt.answers) == 1
    ans = pkt.answers[0]
    assert ans.rtype == TYPE_PTR
    assert ans.rdata == "router.lan"


def test_parse_txt_record_single_and_multi_chunk() -> None:
    # Multi-chunk TXT record (e.g., SPF record split across chunks)
    packet_bytes = (
        b"\x44\x55"
        b"\x81\x80"
        b"\x00\x01\x00\x01\x00\x00\x00\x00"
        b"\x07example\x03com\x00"
        b"\x00\x10\x00\x01"  # TXT, IN
        b"\xc0\x0c"
        b"\x00\x10\x00\x01"  # TXT, IN
        b"\x00\x00\x01\x2c"  # TTL=300
        b"\x00\x10"  # RDLENGTH=16 (11 bytes chunk1 + 5 bytes chunk2)
        b"\x0av=spf1 mx "  # Chunk 1: 1 length byte + 10 chars
        b"\x04-all"  # Chunk 2: 1 length byte + 4 chars
    )
    pkt = parse_dns_packet(packet_bytes)
    assert len(pkt.answers) == 1
    ans = pkt.answers[0]
    assert ans.rtype == TYPE_TXT
    assert isinstance(ans.rdata, list)
    assert ans.rdata[0] == "v=spf1 mx "
    assert len(ans.rdata) == 2


def test_parse_opt_edns0_record() -> None:
    # RFC 6891 OPT record in Additional section
    packet_bytes = (
        b"\x77\x88"
        b"\x01\x00"  # Query
        b"\x00\x01\x00\x00\x00\x00\x00\x01"  # 1 question, 0 answer, 0 authority, 1 additional
        b"\x07example\x03com\x00"
        b"\x00\x01\x00\x01"  # Question: example.com A IN
        b"\x00"  # Root domain for OPT record
        b"\x00\x29"  # TYPE=OPT (41)
        b"\x10\x00"  # CLASS=4096 (UDP payload size)
        b"\x00\x00\x80\x00"  # TTL: ext_rcode=0, ver=0, DO bit=1 (0x8000), Z=0
        b"\x00\x00"  # RDLENGTH=0 (no options)
    )
    pkt = parse_dns_packet(packet_bytes)
    assert len(pkt.additionals) == 1
    opt = pkt.additionals[0]
    assert opt.rtype == TYPE_OPT
    assert opt.edns_payload_size == 4096
    assert opt.edns_version == 0
    assert opt.edns_do is True
    assert pkt.edns0 is not None
    assert pkt.edns0.edns_payload_size == 4096


def test_truncated_rdata_bounds_check() -> None:
    # Declare RDLENGTH=10, but provide only 2 bytes
    packet_bytes = (
        b"\x11\x11"
        b"\x81\x80"
        b"\x00\x01\x00\x01\x00\x00\x00\x00"
        b"\x04test\x00"
        b"\x00\x01\x00\x01"
        b"\xc0\x0c"
        b"\x00\x01\x00\x01"
        b"\x00\x00\x00\x3c"
        b"\x00\x0a"  # RDLENGTH=10
        b"\x01\x02"  # Only 2 bytes remaining
    )
    with pytest.raises(ValueError, match="Truncated RDATA"):
        parse_dns_packet(packet_bytes)


def test_invalid_ipv4_length_check() -> None:
    packet_bytes = (
        b"\x22\x22"
        b"\x81\x80"
        b"\x00\x01\x00\x01\x00\x00\x00\x00"
        b"\x04test\x00"
        b"\x00\x01\x00\x01"
        b"\xc0\x0c"
        b"\x00\x01\x00\x01"
        b"\x00\x00\x00\x3c"
        b"\x00\x03"  # RDLENGTH=3 (invalid for IPv4 A)
        b"\x01\x02\x03"
    )
    with pytest.raises(ValueError, match="Invalid IPv4 A record RDATA length"):
        parse_dns_packet(packet_bytes)


def test_packet_jsonl_serialization() -> None:
    packet_bytes = (
        b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01"
        b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04\x5d\xb8\xd8\x22"
    )
    pkt = parse_dns_packet(packet_bytes)
    json_str = pkt.to_jsonl()
    data = json.loads(json_str)
    assert data["header"]["txid"] == 0x1234
    assert data["answers"][0]["rdata"] == "93.184.216.34"
