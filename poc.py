"""dnswatch - proof of concept wire-format dns parser.

Backward-compatible shim delegating to the modular dnswatch package.
"""

from __future__ import annotations

import argparse
import sys

from dnswatch.parser import decode_name, parse_dns_packet


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
    assert result.header.txid == 0x1337
    assert result.header.qr == "query"
    assert len(result.questions) == 1
    assert result.questions[0].name == "example.com"
    assert result.questions[0].qtype_name == "A"
    assert result.questions[0].qclass_name == "IN"

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


def main() -> None:
    parser = argparse.ArgumentParser(description="dnswatch wire-format parser poc shim")
    parser.add_argument("--test", action="store_true", help="run internal self-test")
    parser.add_argument("--listen", action="store_true", help="start local udp listener")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5353, help="bind port (default: 5353)")
    args = parser.parse_args()

    if args.test or len(sys.argv) == 1:
        run_self_test()
    if args.listen:
        from dnswatch.cli import listen_loop
        listen_loop(args.host, args.port)


if __name__ == "__main__":
    main()
