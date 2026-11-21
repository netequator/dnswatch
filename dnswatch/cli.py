"""Command-line interface for dnswatch passive DNS network monitor & sinkhole."""

from __future__ import annotations

import argparse
import json
import socket
import struct
import sys
import time

from dnswatch.constants import RCODE_NOERROR, RCODE_NXDOMAIN
from dnswatch.parser import parse_dns_packet
from dnswatch.rebinding import detect_dns_rebinding
from dnswatch.responder import build_sinkhole_response
from dnswatch.sinkhole import SinkholeBlocklist


def listen_loop(
    host: str,
    port: int,
    jsonl: bool = False,
    blocklist: SinkholeBlocklist | None = None,
    sink_ip: str = "0.0.0.0",
    sink_mode: str = "a",
    check_rebinding: bool = True,
) -> None:
    """Run interactive UDP listener for local lab verification and sinkhole response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))

    status = f"active ({len(blocklist)} rules, return {sink_ip})" if blocklist else "disabled"
    print(
        f"listening for DNS datagrams on {host}:{port} [sinkhole: {status}] ...",
        file=sys.stderr,
    )

    rcode = RCODE_NXDOMAIN if sink_mode.lower() == "nxdomain" else RCODE_NOERROR

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                packet = parse_dns_packet(data)
                is_query = packet.header.qr == "query"
                q_name = packet.questions[0].name if packet.questions else ""

                # Sinkhole interception
                if is_query and blocklist and q_name and blocklist.is_blocked(q_name):
                    resp_bytes = build_sinkhole_response(data, sink_ip=sink_ip, rcode=rcode)
                    sock.sendto(resp_bytes, addr)
                    sink_event = {
                        "timestamp": time.time(),
                        "event": "sinkhole_intercepted",
                        "client": f"{addr[0]}:{addr[1]}",
                        "domain": q_name,
                        "action": "nxdomain" if rcode == RCODE_NXDOMAIN else f"a_{sink_ip}",
                    }
                    if jsonl:
                        print(json.dumps(sink_event))
                    else:
                        target = "NXDOMAIN" if rcode == RCODE_NXDOMAIN else sink_ip
                        print(f"[SINKHOLE] [{addr[0]}:{addr[1]}] blocked {q_name} -> {target}")
                    continue

                # DNS Rebinding detection on responses
                if check_rebinding and packet.header.qr == "response":
                    rebinding_alerts = detect_dns_rebinding(packet)
                    for alert in rebinding_alerts:
                        alert_dict = {
                            "timestamp": alert.timestamp,
                            "event": "dns_rebinding_alert",
                            "domain": alert.domain,
                            "ip": alert.ip,
                            "category": alert.range_category,
                        }
                        if jsonl:
                            print(json.dumps(alert_dict))
                        else:
                            print(
                                f"[REBINDING ALERT] domain={alert.domain} resolved to "
                                f"{alert.ip} ({alert.range_category})",
                                file=sys.stderr,
                            )

                # Standard telemetry output
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
        description="Zero-dependency passive DNS network monitor & sinkhole responder",
    )
    parser.add_argument("--listen", action="store_true", help="start local udp listener")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5353, help="bind port (default: 5353)")
    parser.add_argument("--jsonl", action="store_true", help="emit normalized JSONL event stream")
    parser.add_argument("--sinkhole", type=str, default=None, help="path to flat blocklist file")
    parser.add_argument(
        "--sink-ip", default="0.0.0.0", help="ip to return when sinkholing (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--sink-mode", choices=["a", "nxdomain"], default="a", help="sinkhole response mode"
    )
    parser.add_argument(
        "--no-rebinding", action="store_true", help="disable DNS rebinding anomaly detection"
    )
    args = parser.parse_args()

    blocklist: SinkholeBlocklist | None = None
    if args.sinkhole:
        blocklist = SinkholeBlocklist()
        try:
            count = blocklist.load_file(args.sinkhole)
            print(f"loaded {count} blocklist rules from {args.sinkhole}", file=sys.stderr)
        except FileNotFoundError as err:
            print(f"error: {err}", file=sys.stderr)
            sys.exit(1)

    if args.listen:
        listen_loop(
            args.host,
            args.port,
            jsonl=args.jsonl,
            blocklist=blocklist,
            sink_ip=args.sink_ip,
            sink_mode=args.sink_mode,
            check_rebinding=not args.no_rebinding,
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
