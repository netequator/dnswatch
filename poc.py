"""dnswatch - proof of concept wire-format dns parser.

Minimal zero-dependency dissector for UDP port 53 DNS traffic.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys

# DNS Type mapping for core query types
QTYPE_MAP = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    255: "ANY",
}

RCODE_MAP = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def parse_header(buf: bytes) -> dict:
    """Parse the fixed 12-byte DNS message header."""
    if len(buf) < 12:
        raise ValueError(f"Packet too short for DNS header ({len(buf)} bytes)")

    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", buf[:12])

    qr = (flags >> 15) & 0x01
    opcode = (flags >> 11) & 0x0F
    aa = (flags >> 10) & 0x01
    tc = (flags >> 9) & 0x01
    rd = (flags >> 8) & 0x01
    ra = (flags >> 7) & 0x01
    z = (flags >> 4) & 0x07
    rcode = flags & 0x0F

    return {
        "txid": txid,
        "qr": "response" if qr else "query",
        "opcode": opcode,
        "aa": bool(aa),
        "tc": bool(tc),
        "rd": bool(rd),
        "ra": bool(ra),
        "z": z,
        "rcode": RCODE_MAP.get(rcode, str(rcode)),
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }


def decode_name(buf: bytes, offset: int, max_hops: int = 16) -> tuple[str, int]:
    """Decode a length-prefixed domain name with pointer loop protection."""
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
                raise ValueError(f"Pointer loop or out-of-bounds offset: {ptr_offset}")
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

    domain_name = ".".join(labels)
    if len(domain_name) > 253:
        raise ValueError(f"Domain name exceeds RFC maximum length 253 ({len(domain_name)})")

    return domain_name, next_offset


def parse_dns_packet(buf: bytes) -> dict:
    """Parse complete DNS message containing header and question section."""
    header = parse_header(buf)
    offset = 12
    questions = []

    for _ in range(header["qdcount"]):
        if offset >= len(buf):
            break
        qname, offset = decode_name(buf, offset)
        if offset + 4 > len(buf):
            raise ValueError("Truncated QTYPE/QCLASS field")
        qtype_num, qclass_num = struct.unpack("!HH", buf[offset : offset + 4])
        offset += 4

        questions.append({
            "name": qname,
            "type": QTYPE_MAP.get(qtype_num, f"TYPE_{qtype_num}"),
            "class": "IN" if qclass_num == 1 else str(qclass_num),
        })

    return {
        "header": header,
        "questions": questions,
        "bytes_parsed": offset,
        "total_len": len(buf),
    }


def run_self_test() -> None:
    """Validate parser against synthetic test frames."""
    # Synthetic DNS query for "example.com" Type A, Class IN
    sample = (
        b"\x13\x37"  # Transaction ID 0x1337
        b"\x01\x00"  # Standard query, RD bit set
        b"\x00\x01"  # QDCOUNT = 1
        b"\x00\x00"  # ANCOUNT = 0
        b"\x00\x00"  # NSCOUNT = 0
        b"\x00\x00"  # ARCOUNT = 0
        b"\x07example\x03com\x00"  # QNAME: example.com
        b"\x00\x01"  # QTYPE: A
        b"\x00\x01"  # QCLASS: IN
    )

    result = parse_dns_packet(sample)
    assert result["header"]["txid"] == 0x1337
    assert result["header"]["qr"] == "query"
    assert len(result["questions"]) == 1
    assert result["questions"][0]["name"] == "example.com"
    assert result["questions"][0]["type"] == "A"
    assert result["questions"][0]["class"] == "IN"

    # Validate compression pointer resolution
    comp_buf = bytearray(40)
    comp_buf[12:25] = b"\x07example\x03com\x00"
    comp_buf[30:32] = b"\xc0\x0c"  # pointer to byte 12
    p_name, p_next = decode_name(comp_buf, 30)
    assert p_name == "example.com"
    assert p_next == 32

    # Validate circular pointer loop trap
    comp_buf[30:32] = b"\xc0\x1e"  # pointer to itself (byte 30)
    loop_caught = False
    try:
        decode_name(comp_buf, 30)
    except ValueError:
        loop_caught = True
    assert loop_caught, "Circular pointer loop was not trapped"

    print("self-test passed: header, qname, compression pointers, and loop bounds verified")


def listen_loop(host: str, port: int) -> None:
    """Run interactive UDP listener for local lab verification."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"listening for DNS datagrams on {host}:{port} ...")

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                parsed = parse_dns_packet(data)
                q_desc = parsed["questions"][0]["name"] if parsed["questions"] else "none"
                print(f"[{addr[0]}:{addr[1]}] txid=0x{parsed['header']['txid']:04x} "
                      f"type={parsed['header']['qr']} qname={q_desc}")
            except (ValueError, struct.error) as ex:
                print(f"[{addr[0]}:{addr[1]}] parse error: {ex}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\nlistener stopped")
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="dnswatch wire-format parser poc")
    parser.add_argument("--test", action="store_true", help="run internal self-test")
    parser.add_argument("--listen", action="store_true", help="start local udp listener")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5353, help="bind port (default: 5353)")
    args = parser.parse_args()

    if args.test or len(sys.argv) == 1:
        run_self_test()
    if args.listen:
        listen_loop(args.host, args.port)


if __name__ == "__main__":
    main()
