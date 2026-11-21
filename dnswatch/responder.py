"""Zero-dependency RFC 1035 synthetic DNS response generator for sinkholing."""

from __future__ import annotations

import socket
import struct

from dnswatch.constants import (
    CLASS_IN,
    HEADER_LENGTH,
    RCODE_NOERROR,
    TYPE_A,
    TYPE_AAAA,
)
from dnswatch.parser import decode_name


def build_sinkhole_response(
    query_buf: bytes,
    sink_ip: str = "0.0.0.0",
    sink_ipv6: str = "::",
    rcode: int = RCODE_NOERROR,
    ttl: int = 60,
) -> bytes:
    """Synthesize a raw RFC 1035 DNS response echoing the query transaction ID and question.

    Arguments:
        query_buf: Raw bytes of the incoming DNS query packet.
        sink_ip: IPv4 address to return for A queries (default: "0.0.0.0").
        sink_ipv6: IPv6 address to return for AAAA queries (default: "::").
        rcode: Response code (default: RCODE_NOERROR; use RCODE_NXDOMAIN for NXDOMAIN sinkhole).
        ttl: Time-To-Live for synthetic resource records (default: 60s).

    Returns:
        Raw bytes of the synthesized RFC 1035 DNS response.
    """
    if len(query_buf) < HEADER_LENGTH:
        err = (
            f"Query packet too short for DNS header ({len(query_buf)} bytes, "
            f"required {HEADER_LENGTH})"
        )
        raise ValueError(err)

    txid, query_flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", query_buf[:HEADER_LENGTH])
    if qdcount == 0:
        raise ValueError("Cannot synthesize response for DNS query with zero questions")

    # Extract first question section (QNAME, QTYPE, QCLASS)
    _, qname_end = decode_name(query_buf, HEADER_LENGTH)
    if qname_end + 4 > len(query_buf):
        raise ValueError("Truncated question section in query packet")

    qtype, qclass = struct.unpack("!HH", query_buf[qname_end : qname_end + 4])
    question_bytes = query_buf[HEADER_LENGTH : qname_end + 4]

    # Calculate response flags:
    # QR=1 (response, bit 15)
    # AA=1 (authoritative answer, bit 10)
    # RD=echoed from query (bit 8)
    # RA=1 (recursion available, bit 7)
    # RCODE=rcode (bits 3..0)
    query_rd = (query_flags >> 8) & 0x01
    resp_flags = 0x8000 | 0x0400 | (query_rd << 8) | 0x0080 | (rcode & 0x0F)

    # If NXDOMAIN was requested or non-IP query type in NOERROR mode, don't return IP answer
    ancount = 0
    answer_bytes = b""

    if rcode == RCODE_NOERROR:
        if qtype == TYPE_A:
            # Pointer 0xC00C points to QNAME at offset 12 (0x000C)
            ptr = b"\xc0\x0c"
            ip_raw = socket.inet_aton(sink_ip)
            answer_bytes = (
                ptr
                + struct.pack("!HHIH", TYPE_A, CLASS_IN, ttl, len(ip_raw))
                + ip_raw
            )
            ancount = 1
        elif qtype == TYPE_AAAA:
            ptr = b"\xc0\x0c"
            try:
                ip_raw = socket.inet_pton(socket.AF_INET6, sink_ipv6)
            except (socket.error, OSError):
                # Fallback for systems with restricted inet_pton or invalid format
                ip_raw = b"\x00" * 16
            answer_bytes = (
                ptr
                + struct.pack("!HHIH", TYPE_AAAA, CLASS_IN, ttl, len(ip_raw))
                + ip_raw
            )
            ancount = 1

    header = struct.pack("!HHHHHH", txid, resp_flags, 1, ancount, 0, 0)
    return header + question_bytes + answer_bytes
