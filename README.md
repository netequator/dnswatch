# dnswatch — Passive DNS Network Monitor & Wire-Format Parser

`dnswatch` is a zero-dependency passive Domain Name System (DNS) packet decoder, security telemetry generator, and lightweight controlled lab sinkhole daemon.

Built strictly on Python 3.10+ standard library (`struct.unpack` and `socket`), it parses raw DNS datagrams on `UDP/53` (and length-prefixed `TCP/53`) without external DNS resolver dependencies or C-extensions.

---

## PROJECT STATUS: DAY 1 PROOF OF CONCEPT (PoC)

This repository is currently in its initial bootstrapping phase. The Day 1 milestone implements a minimal binary dissector for the fixed 12-byte DNS header and length-prefixed QNAME question sections.

### Architecture Roadmap

- **Day 1 (Current):** Minimal PoC (`poc.py`) — 12-byte header unpacking, RFC 1035 label decompression with cursor lock, and pointer loop safety bounds.
- **Day 2:** Resource Record parser (A, AAAA, CNAME, TXT, PTR) + RFC 6891 EDNS(0) `OPT` pseudo-record dissection + request/response RTT correlation.
- **Day 3:** Subdomain Shannon entropy scoring engine (DNS tunneling detection) + rolling NXDOMAIN burst rate limiter.
- **Day 4:** Controlled local lab sinkhole responder (`--blocklist`), CLI packaging, 100% deterministic unit test suite, and `v0.1.0` release.

---

## THREAT MODEL & DETECTION SURFACE

1. **DNS Tunneling & Data Exfiltration:** Encoded binary data hidden inside high-entropy subdomain labels (e.g. `iodine`, `dnscat2`).
2. **Domain Generation Algorithms (DGA):** High-frequency resolution bursts generating elevated `NXDOMAIN` failure ratios.
3. **Amplification & Buffer Anomalies:** Oversized `TXT` queries, `ANY` queries, and advertised `EDNS(0)` payload buffer sizes exceeding 4096 bytes.
4. **Compression Pointer Denial of Service:** Malformed self-referential compression pointers (`0xC000 | offset`) designed to trigger infinite loops or recursion stack exhaustion in naive decoders.

---

## USAGE (PoC)

### Run Self-Test
Validates header unpacking, question parsing, compression pointer resolution, and circular loop trap against synthetic byte frames:

```bash
python poc.py --test
```

### Start Local UDP Listener
Listens on local loopback port for non-privileged testing:

```bash
python poc.py --listen --host 127.0.0.1 --port 5353
```

Send a test DNS query from another terminal:

```bash
dig @127.0.0.1 -p 5353 example.com A
```

---

## PROTOCOL REFERENCES

- **RFC 1035:** Domain Names — Implementation and Specification
- **RFC 6891:** Extension Mechanisms for DNS (EDNS(0))
- **RFC 3596:** DNS Extensions to Support IP Version 6 (AAAA Records)

---

## LICENSE

BSD-3-Clause
