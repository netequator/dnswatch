"""Zero-dependency RFC 1035 and RFC 6891 wire-format DNS packet parser."""

from __future__ import annotations

import socket
import struct

from dnswatch.constants import (
    HEADER_LENGTH,
    MAX_NAME_LENGTH,
    MAX_POINTER_HOPS,
    QCLASS_MAP,
    QTYPE_MAP,
    RCODE_MAP,
    RR_FIXED_HEADER_LENGTH,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    TYPE_MX,
    TYPE_NS,
    TYPE_OPT,
    TYPE_PTR,
    TYPE_SOA,
    TYPE_TXT,
)
from dnswatch.models import DNSHeader, DNSPacket, DNSQuestion, DNSResourceRecord, EDNS0Option


def parse_header(buf: bytes) -> DNSHeader:
    """Parse the fixed 12-byte DNS message header."""
    if len(buf) < HEADER_LENGTH:
        raise ValueError(
            f"Packet too short for DNS header ({len(buf)} bytes, required {HEADER_LENGTH})"
        )

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", buf[:HEADER_LENGTH])

    qr = (flags >> 15) & 0x01
    opcode = (flags >> 11) & 0x0F
    aa = bool((flags >> 10) & 0x01)
    tc = bool((flags >> 9) & 0x01)
    rd = bool((flags >> 8) & 0x01)
    ra = bool((flags >> 7) & 0x01)
    z = (flags >> 4) & 0x07
    rcode_num = flags & 0x0F

    return DNSHeader(
        txid=txid,
        qr="response" if qr else "query",
        opcode=opcode,
        aa=aa,
        tc=tc,
        rd=rd,
        ra=ra,
        z=z,
        rcode=RCODE_MAP.get(rcode_num, str(rcode_num)),
        rcode_num=rcode_num,
        qdcount=qdcount,
        ancount=ancount,
        nscount=nscount,
        arcount=arcount,
    )


def decode_name(buf: bytes, offset: int, max_hops: int = MAX_POINTER_HOPS) -> tuple[str, int]:
    """Decode a length-prefixed domain name with pointer loop and bounds protection.

    Implements RFC 1035 Section 4.1.4 name decompression:
    - Cursor lock on first jump (jumped = False) to prevent stream desynchronization.
    - Visited set tracking and hop limit ceiling to defend against circular compression bombs.
    """
    labels: list[str] = []
    visited: set[int] = set()
    jumped = False
    next_offset = offset
    hops = 0

    while offset < len(buf):
        length = buf[offset]
        if length == 0:
            if not jumped:
                next_offset = offset + 1
            break

        # Check for 2-byte compression pointer (0xC0 prefix)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("Truncated compression pointer")
            ptr_offset = ((length & 0x3F) << 8) | buf[offset + 1]

            if ptr_offset in visited or ptr_offset >= len(buf):
                raise ValueError(f"Compression pointer loop or out-of-bounds offset: {ptr_offset}")
            visited.add(ptr_offset)

            hops += 1
            if hops > max_hops:
                raise ValueError(f"Exceeded maximum pointer hops ({max_hops})")

            # Lock return offset on the first pointer jump
            if not jumped:
                next_offset = offset + 2
                jumped = True

            offset = ptr_offset
            continue

        offset += 1
        if offset + length > len(buf):
            raise ValueError("Truncated label in domain name")
        if length > 63:
            raise ValueError(f"Label exceeds RFC maximum length 63 ({length})")

        label_bytes = buf[offset : offset + length]
        labels.append(label_bytes.decode("ascii", errors="replace"))
        offset += length

    domain_name = ".".join(labels) if labels else "."
    if len(domain_name) > MAX_NAME_LENGTH:
        raise ValueError(
            f"Domain name exceeds RFC maximum length {MAX_NAME_LENGTH} ({len(domain_name)})"
        )

    return domain_name, next_offset


def parse_questions(buf: bytes, offset: int, count: int) -> tuple[list[DNSQuestion], int]:
    """Parse Question section entries."""
    questions: list[DNSQuestion] = []
    for _ in range(count):
        if offset >= len(buf):
            break
        qname, offset = decode_name(buf, offset)
        if offset + 4 > len(buf):
            raise ValueError("Truncated QTYPE/QCLASS field in Question section")

        qtype, qclass = struct.unpack("!HH", buf[offset : offset + 4])
        offset += 4

        questions.append(
            DNSQuestion(
                name=qname,
                qtype=qtype,
                qtype_name=QTYPE_MAP.get(qtype, f"TYPE_{qtype}"),
                qclass=qclass,
                qclass_name=QCLASS_MAP.get(qclass, str(qclass)),
            )
        )

    return questions, offset


def parse_resource_records(
    buf: bytes, offset: int, count: int
) -> tuple[list[DNSResourceRecord], int]:
    """Parse Resource Records from Answer, Authority, or Additional sections.

    Supports A, AAAA, CNAME, PTR, TXT, MX, SOA, and RFC 6891 EDNS0 OPT records.
    """
    records: list[DNSResourceRecord] = []

    for _ in range(count):
        if offset >= len(buf):
            break

        name, offset = decode_name(buf, offset)

        if offset + RR_FIXED_HEADER_LENGTH > len(buf):
            raise ValueError(
                f"Truncated Resource Record header (needs {RR_FIXED_HEADER_LENGTH} "
                f"bytes at offset {offset})"
            )

        rtype, rclass, ttl, rdlength = struct.unpack(
            "!HHIH", buf[offset : offset + RR_FIXED_HEADER_LENGTH]
        )
        offset += RR_FIXED_HEADER_LENGTH

        rdata_offset = offset
        if rdata_offset + rdlength > len(buf):
            raise ValueError(
                f"Truncated RDATA: needs {rdlength} bytes at offset {rdata_offset}, "
                f"buffer ends at {len(buf)}"
            )

        rdata_bytes = buf[rdata_offset : rdata_offset + rdlength]
        parsed_rdata: str | list[str] | dict[str, object] | None = None

        # OPT-specific properties
        edns_payload_size = None
        edns_ext_rcode = None
        edns_version = None
        edns_do = None
        edns_options: list[EDNS0Option] = []

        if rtype == TYPE_A:
            if rdlength != 4:
                raise ValueError(
                    f"Invalid IPv4 A record RDATA length: {rdlength} (must be 4 bytes)"
                )
            parsed_rdata = socket.inet_ntop(socket.AF_INET, rdata_bytes)

        elif rtype == TYPE_AAAA:
            if rdlength != 16:
                raise ValueError(
                    f"Invalid IPv6 AAAA record RDATA length: {rdlength} (must be 16 bytes)"
                )
            parsed_rdata = socket.inet_ntop(socket.AF_INET6, rdata_bytes)

        elif rtype in (TYPE_CNAME, TYPE_PTR, TYPE_NS):
            target_name, _ = decode_name(buf, rdata_offset)
            parsed_rdata = target_name

        elif rtype == TYPE_TXT:
            chunks: list[str] = []
            txt_cursor = 0
            while txt_cursor < rdlength:
                chunk_len = rdata_bytes[txt_cursor]
                txt_cursor += 1
                if txt_cursor + chunk_len > rdlength:
                    raise ValueError(
                        f"Truncated TXT chunk: length {chunk_len} exceeds RDATA boundary"
                    )
                raw_chunk = rdata_bytes[txt_cursor : txt_cursor + chunk_len]
                chunk = raw_chunk.decode("utf-8", errors="replace")
                chunks.append(chunk)
                txt_cursor += chunk_len
            parsed_rdata = chunks if len(chunks) > 1 else (chunks[0] if chunks else "")

        elif rtype == TYPE_MX:
            if rdlength < 3:
                raise ValueError(
                    f"Truncated MX RDATA length: {rdlength} (minimum 3 bytes required)"
                )
            preference = struct.unpack("!H", rdata_bytes[:2])[0]
            exchange, _ = decode_name(buf, rdata_offset + 2)
            parsed_rdata = {"preference": preference, "exchange": exchange}

        elif rtype == TYPE_SOA:
            mname, soa_offset = decode_name(buf, rdata_offset)
            rname, soa_offset = decode_name(buf, soa_offset)
            if soa_offset + 20 > rdata_offset + rdlength:
                raise ValueError("Truncated SOA timer fields")
            serial, refresh, retry, expire, minimum = struct.unpack(
                "!IIIII", buf[soa_offset : soa_offset + 20]
            )
            parsed_rdata = {
                "mname": mname,
                "rname": rname,
                "serial": serial,
                "refresh": refresh,
                "retry": retry,
                "expire": expire,
                "minimum": minimum,
            }

        elif rtype == TYPE_OPT:
            # RFC 6891 EDNS(0) OPT Pseudo-Record
            edns_payload_size = rclass  # Requestor's UDP payload size
            edns_ext_rcode = (ttl >> 24) & 0xFF
            edns_version = (ttl >> 16) & 0xFF
            edns_do = bool((ttl >> 15) & 0x01)  # DNSSEC OK bit
            # Parse variable length options in RDATA
            opt_cursor = 0
            while opt_cursor + 4 <= rdlength:
                opt_code, opt_len = struct.unpack("!HH", rdata_bytes[opt_cursor : opt_cursor + 4])
                opt_cursor += 4
                if opt_cursor + opt_len > rdlength:
                    raise ValueError("Truncated EDNS0 option data")
                opt_data = rdata_bytes[opt_cursor : opt_cursor + opt_len]
                edns_options.append(EDNS0Option(code=opt_code, length=opt_len, data=opt_data))
                opt_cursor += opt_len
            parsed_rdata = f"EDNS0 udp={edns_payload_size} ver={edns_version} do={int(edns_do)}"

        else:
            # Fallback for unhandled types: store raw hex representation
            parsed_rdata = rdata_bytes.hex()

        offset = rdata_offset + rdlength

        records.append(
            DNSResourceRecord(
                name=name,
                rtype=rtype,
                rtype_name=QTYPE_MAP.get(rtype, f"TYPE_{rtype}"),
                rclass=rclass,
                rclass_name="IN" if rclass == 1 else str(rclass),
                ttl=ttl,
                rdlength=rdlength,
                rdata=parsed_rdata,
                edns_payload_size=edns_payload_size,
                edns_ext_rcode=edns_ext_rcode,
                edns_version=edns_version,
                edns_do=edns_do,
                edns_options=edns_options,
            )
        )

    return records, offset


def parse_dns_packet(buf: bytes) -> DNSPacket:
    """Parse complete DNS wire-format datagram into structured DNSPacket."""
    header = parse_header(buf)
    offset = HEADER_LENGTH

    questions, offset = parse_questions(buf, offset, header.qdcount)
    answers, offset = parse_resource_records(buf, offset, header.ancount)
    authorities, offset = parse_resource_records(buf, offset, header.nscount)
    additionals, offset = parse_resource_records(buf, offset, header.arcount)

    return DNSPacket(
        header=header,
        questions=questions,
        answers=answers,
        authorities=authorities,
        additionals=additionals,
        bytes_parsed=offset,
        total_len=len(buf),
    )
