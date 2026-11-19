# dnswatch — Wire-Format DNS Protocol Dissector & Covert Tunneling Detector

A zero-dependency passive Domain Name System (DNS) packet dissector, covert tunneling detector, and security telemetry engine written strictly for Python 3.10+ standard library.

![dnswatch Pipeline Architecture](assets/dnswatch-pipeline.svg)

---

## OVERVIEW

`dnswatch` passively dissects raw DNS wire datagrams across `UDP/53` and length-prefixed `TCP/53`. It decapsulates raw network frames (Ethernet, 802.1Q/802.1ad VLAN tags, IPv4, IPv6 with extension headers), unpacks RFC 1035 wire structures, resolves compressed domain names with circular pointer protection, inspects RFC 6891 EDNS(0) pseudo-records, and detects covert tunneling via mathematical Shannon entropy scoring.

### Core Capabilities

- **Zero-Dependency Wire Dissection:** Parses DNS datagrams directly from binary byte buffers using standard library `struct` and `socket`. No C extensions, external resolvers, or heavy packet capture dependencies.
- **Envelope Decapsulation & VLAN Peeling:** Strips Layer 2 Ethernet frames and peels single (802.1Q) and double (802.1ad QinQ) VLAN tags. Decapsulates IPv4 (with IHL checks and fragment detection) and IPv6 (traversing Hop-by-Hop, Routing, Fragment, AH, and Destination Options).
- **RFC 1035 §4.1.4 Pointer Safety:** Full label decompression with cursor lock. On the initial compression pointer jump (`0xC000 | offset`), the return cursor is locked to avoid pointer desynchronization. Circular pointer loops (`0xC0 0x1E`) are trapped with a strict 16-hop ceiling.
- **Resource Record Decoding:** Dissects Answer, Authority, and Additional sections for `A` (RFC 1035), `AAAA` (RFC 3596), `CNAME`, `PTR`, `NS`, `MX`, `SOA`, and `TXT` (single and multi-chunk character-strings).
- **RFC 6891 EDNS(0) OPT Pseudo-Record Dissection:** Unpacks `TYPE 41` pseudo-records, exposing requestor UDP payload size (`CLASS`), extended RCODE, EDNS version, DNSSEC OK (`DO`) bit, and option attributes.
- **Shannon Entropy Tunneling Detector:** Computes normalized Shannon entropy $H(X) = -\sum p_i \log_2(p_i)$ to identify encrypted and compressed data exfiltration (e.g. `iodine`, `dnscat2`) across both single labels and multi-label subdomain prefixes.
- **NXDOMAIN Rate Tracking:** Rolling 60-second sliding-window tracker evaluating per-client query volume and flagging anomalous `NXDOMAIN` failure ratios characteristic of Domain Generation Algorithms (DGA).

---

## WIRE PROTOCOL SPECIFICATION

### Fixed 12-Byte Header Format (RFC 1035 §4.1.1)

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Transaction ID (16)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|QR|   Opcode  |AA|TC|RD|RA| Z  | RCODE |                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Question Count (QDCOUNT)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Answer Count (ANCOUNT)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Authority Count (NSCOUNT)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Additional Count (ARCOUNT)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Invariant Defenses & Edge Cases

| Attack / Edge Case | Invariant Rule | Defense Mechanism |
| :--- | :--- | :--- |
| **Compression Pointer Loop** | Visited offset set tracking | Maximum 16 hops; loops raise `ValueError("circular pointer loop")`. |
| **Pointer Desynchronization** | Cursor lock on first jump | Locks `next_offset = offset + 2` on initial pointer encounter. |
| **Non-Initial IPv4 Fragments** | Fragment offset $> 0$ | Flagged as `is_fragment=True`; L4 parsing bypassed. |
| **IPv6 Extension Chaining** | Next header traversal | Bounded extension header parser supporting Hop-by-Hop, Routing, AH, and DstOpts. |
| **TCP Stream Framing** | RFC 1035 §4.2.2 2-byte prefix | Extracts 2-byte big-endian message length prefix before dissecting. |
| **Buffer Overflow via EDNS0** | Advertised UDP buffer size | Flags advertised payloads $\ge 4096$B paired with `ANY`/`TXT` queries. |
| **Single-Label Exfiltration** | Label length $\ge 20$B, $H \ge 3.75$b | Detects Base32/Base64/hex payload channels inside isolated labels. |
| **Multi-Label Chunked Tunnel** | Subdomain prefix $\ge 32$B, $H \ge 3.75$b | Concatenates subdomains to catch chunked exfiltration (`iodine`, `dnscat2`). |

---

## ARCHITECTURE & MODULES

```text
dnswatch/
├── __init__.py         # Public exports (parsers, models, entropy, tracker)
├── constants.py        # RFC 1035 / RFC 6891 types, classes, and rcodes
├── models.py           # Immutable dataclasses (DNSHeader, DNSPacket, DNSResourceRecord)
├── parser.py           # Wire unpacker, name decompression, and JSONL serializer
├── envelope.py         # L2/L3/L4 decapsulation, VLAN peeling, fragment detection
├── entropy.py          # Shannon entropy calculator and tunnel detection heuristics
├── tracker.py          # Sliding-window NXDOMAIN burst rate monitor
└── cli.py              # Live capture, local listener, and JSONL stream CLI
```

---

## USAGE

### Command-Line Interface

#### 1. Passive Local UDP Listener (Lab Testing)

Start a non-privileged local listener on loopback port `5353`:

```bash
dnswatch --listen --host 127.0.0.1 --port 5353
```

Send a test DNS query from another terminal:

```bash
dig @127.0.0.1 -p 5353 example.com A
```

#### 2. Self-Test Mode

Execute the built-in synthetic byte fixture validation suite:

```bash
python poc.py --test
```

### Programmatic Python API

#### Decapsulate Packet Envelope & Parse DNS Wire Data

```python
from dnswatch import unwrap_dns_payload, parse_dns_packet

# Raw packet buffer from AF_PACKET, Npcap, or PCAP reader
raw_packet = b"..." 

# Decapsulate Ethernet, VLAN tags, IP, and UDP/TCP headers
envelope = unwrap_dns_payload(raw_packet, dns_only=True)
if envelope and envelope.payload:
    dns_msg = parse_dns_packet(envelope.payload)
    print(f"TXID: {dns_msg.header.txid:#06x} | RCODE: {dns_msg.header.rcode}")
    for q in dns_msg.questions:
        print(f"Query: {q.name} ({q.qtype_name})")
    for ans in dns_msg.answers:
        print(f"Answer: {ans.name} -> {ans.rdata} (TTL: {ans.ttl})")
```

#### Covert Tunneling & Entropy Analysis

```python
from dnswatch import analyze_domain

# High-entropy single-label tunnel test
result = analyze_domain("v8k9w2x4m1n7q5p3r6t0y8z1b4c7d2e9.tunnel.evil.com")
print(result.is_suspicious)       # True
print(result.anomaly_type)        # "high_entropy_label"
print(result.max_label_entropy)   # 3.9141 bits

# Multi-label chunked prefix test (iodine-style)
result = analyze_domain("x9k2m4p8q1w3.r5t7y0z2b6c1.d4e8f3g7h1j5.corp.com")
print(result.is_suspicious)       # True
print(result.anomaly_type)        # "high_entropy_chunked_prefix"
print(result.prefix_entropy)      # 4.8505 bits
```

#### NXDOMAIN Sliding-Window Rate Tracker

```python
from dnswatch import NXDOMAINTracker

tracker = NXDOMAINTracker(window_sec=60.0, min_queries=10, min_nxdomain=5, ratio_threshold=0.5)

# Record response codes per client IP
anomaly = tracker.record_query("192.168.1.100", "NXDOMAIN")
if anomaly:
    print(f"ALERT: Client {anomaly.client_ip} exceeded NXDOMAIN threshold: "
          f"{anomaly.nxdomain_count}/{anomaly.total_queries} queries ({anomaly.nxdomain_ratio:.1%})")
```

---

## DETERMINISTIC TESTING

The test suite runs against synthetic wire datagrams and deterministic byte fixtures:

```bash
pytest tests/ -v
```

```text
tests/test_entropy.py::test_shannon_entropy_known_values PASSED
tests/test_entropy.py::test_normal_domains_not_suspicious PASSED
tests/test_entropy.py::test_single_label_tunneling_detection PASSED
tests/test_entropy.py::test_chunked_multi_label_tunneling_detection PASSED
tests/test_entropy.py::test_empty_and_root_domain_handling PASSED
tests/test_envelope.py::test_unwrap_ethernet_ipv4_udp_dns PASSED
tests/test_envelope.py::test_unwrap_8021q_vlan_peeling PASSED
tests/test_envelope.py::test_unwrap_qinq_double_vlan_peeling PASSED
tests/test_envelope.py::test_unwrap_ipv6_udp_dns PASSED
tests/test_envelope.py::test_unwrap_ipv6_hop_by_hop_extension PASSED
tests/test_envelope.py::test_unwrap_tcp_dns_framing PASSED
tests/test_envelope.py::test_unwrap_ipv4_non_initial_fragment PASSED
tests/test_envelope.py::test_unwrap_raw_ip_packet PASSED
tests/test_envelope.py::test_filter_non_dns_traffic PASSED
tests/test_envelope.py::test_truncated_buffer_handling PASSED
tests/test_parser.py::test_parse_header_query PASSED
tests/test_parser.py::test_parse_header_response_flags PASSED
tests/test_parser.py::test_decode_name_compression_pointer PASSED
tests/test_parser.py::test_decode_name_cursor_lock PASSED
tests/test_parser.py::test_decode_name_loop_trap PASSED
tests/test_parser.py::test_parse_a_record PASSED
tests/test_parser.py::test_parse_aaaa_record PASSED
tests/test_parser.py::test_parse_opt_edns0_record PASSED
tests/test_tracker.py::test_tracker_burst_detection PASSED
============================== 36 passed in 0.13s ==============================
```
