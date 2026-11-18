"""Command-line interface for dnswatch passive DNS network monitor."""

from __future__ import annotations

import argparse
import socket
import struct
import sys

from dnswatch.parser import parse_dns_packet


def listen_loop(host: str, port: int, jsonl: bool = False) -> None:
    """Run interactive UDP listener for local lab verification."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"listening for DNS datagrams on {host}:{port} ...", file=sys.stderr)

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                packet = parse_dns_packet(data)
                if jsonl:
                    print(packet.to_jsonl())
                else:
                    q_desc = packet.questions[0].name if packet.questions else "none"
                    q_type = packet.questions[0].qtype_name if packet.questions else "-"
                    ans_desc = f"{len(packet.answers)} answers" if packet.answers else "no answers"
                    print(
                        f"[{addr[0]}:{addr[1]}] txid=0x{packet.header.txid:04x} "
                        f"{packet.header.qr} {q_type} {q_desc} -> "
                        f"{packet.header.rcode} ({ans_desc})"
                    )
            except (ValueError, struct.error) as ex:
                print(f"[{addr[0]}:{addr[1]}] parse error: {ex}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\nlistener stopped", file=sys.stderr)
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dnswatch",
        description="Zero-dependency passive DNS network monitor & wire-format parser",
    )
    parser.add_argument("--listen", action="store_true", help="start local udp listener")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5353, help="bind port (default: 5353)")
    parser.add_argument("--jsonl", action="store_true", help="emit normalized JSONL event stream")
    args = parser.parse_args()

    if args.listen:
        listen_loop(args.host, args.port, jsonl=args.jsonl)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
