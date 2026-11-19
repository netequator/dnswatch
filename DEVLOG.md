# DEVLOG.md — dnswatch Engineering Journal

## 2026-11-17 — Day 1: Bootstrap PoC & RFC 1035 Name Decompression

### Design Notes
- Initialized repository for Month 1, Project 2 (`dnswatch`).
- Implemented minimal zero-dependency binary dissector in `poc.py`:
  - 12-byte fixed header unpacker via `struct.unpack("!HHHHHH", buf[:12])`.
  - Flags bitfield extraction: QR, Opcode (4b), AA, TC, RD, RA, Z (3b), and RCODE (4b).
  - Question section unpacker: extracts QNAME labels, QTYPE, and QCLASS.
- Resolved RFC 1035 §4.1.4 pointer cursor desynchronization bug:
  - Pointer jump (`0xC000 | offset`) redirects parser to previous label sequence.
  - Implemented cursor lock: on the *first* compression pointer jump, lock `next_offset = offset + 2`. Subsequent jumps follow pointer chains without updating `next_offset`.
  - Bounded recursion: tracks `visited` set to trap circular self-referential loops (`0xC0 0x1E`), capping maximum hops at 16.
- Added synthetic self-test validating valid queries, forward compression pointers, and loop detection.

### Verification
- `python poc.py --test`: passed (`self-test passed: header, qname, compression pointers, and loop bounds verified`).
- `ruff check poc.py`: passed (`0` errors).

### Remote Bootstrap
- Published repository to GitHub: `netequator/dnswatch` (commit `406ca73`).
- Configured topics: `dns`, `network-security`, `packet-sniffer`, `python3`, `rfc1035`, `traffic-analysis`.
- Filed tracking Issue #1: `decode resource records (a, aaaa, cname, txt, ptr) and edns0 opt` (https://github.com/netequator/dnswatch/issues/1).

### Next Steps (Day 2)
- Extract modular package structure (`dnswatch/parser.py`, `dnswatch/cli.py`).
- Implement Resource Record dissection for Answer, Authority, and Additional sections (A, AAAA, CNAME, TXT, PTR).
- Implement RFC 6891 EDNS(0) `OPT` pseudo-record parsing (`TYPE 41`).
- Open feature branch (`feature/rr-dissector`) and submit PR resolving Issue #1.


## 2026-11-18 — Day 2: Modular Package Extraction & Resource Record Dissection (Issue #1)

### Design Notes
- Refactored `poc.py` into a modular package architecture (`dnswatch/__init__.py`, `constants.py`, `models.py`, `parser.py`, `cli.py`).
- Added formal `pyproject.toml` with `dnswatch` console entrypoint and zero external dependencies.
- Implemented 10-byte Resource Record header unpacking across Answer, Authority, and Additional sections.
- Implemented type-specific RDATA decoders:
  - `A` (TYPE 1): 4-byte IPv4 wire to presentation format (`socket.inet_ntop`).
  - `AAAA` (TYPE 28): 16-byte IPv6 wire to RFC 5952 normalized presentation format.
  - `CNAME` (TYPE 5), `PTR` (TYPE 12), `NS` (TYPE 2): RFC 1035 compressed name decoding with cursor lock.
  - `TXT` (TYPE 16): Single and multi-chunk character-string sequence extraction.
  - `MX` (TYPE 15): Preference integer + exchange domain name.
  - `SOA` (TYPE 6): MNAME, RNAME, and 5-field timer unpacking.
  - `OPT` (TYPE 41, RFC 6891 EDNS0): Requestor UDP payload size (`CLASS`), extended RCODE, EDNS version, and DNSSEC DO bit.
- Added strict defensive wire invariants:
  - Truncated RR header and RDATA boundary checks against buffer length.
  - Strict length validation for IPv4 (4B) and IPv6 (16B).
  - Trapping pointer loops and out-of-bounds pointer offsets inside RDATA.
- Maintained `poc.py` as a backward-compatible shim.

### Verification
- `ruff check .`: passed (`0` errors).
- `pytest tests/ -v`: 18 passed in 0.16s.
- `python poc.py --test`: passed.
- `dnswatch --help`: verified console script execution.


## 2026-11-19 — Day 3: Envelope Decapsulation, Shannon Entropy & NXDOMAIN Tracker (Issue #3)

### Design Notes
- Implemented wire envelope decapsulation helper `unwrap_dns_payload` (`dnswatch/envelope.py`):
  - Strips Ethernet II framing and peels single (802.1Q) and double (802.1ad QinQ) VLAN tags.
  - Handles IPv4 headers with IHL verification and fragmentation detection (flags non-initial fragments where L4 is absent).
  - Handles IPv6 headers with extension header traversal (Hop-by-Hop, Routing, Fragment, Destination Options, AH).
  - Decapsulates UDP and TCP with RFC 1035 §4.2.2 2-byte big-endian message length prefix framing.
  - Added raw IP auto-detection for TUN/WireGuard captures.
- Implemented Shannon entropy computation and DNS tunneling detection (`dnswatch/entropy.py`):
  - Normalized mathematical Shannon entropy $H(X) = -\sum p_i \log_2(p_i)$ over lowercase character frequencies.
  - Single-label tunneling detector: triggers on label length $\ge 20$ and entropy $\ge 3.75$ bits.
  - Chunked multi-label prefix detector: concatenates subdomain prefix labels, triggering on combined prefix length $\ge 32$ and entropy $\ge 3.75$ bits to detect covert iodine and dnscat2 tunneling.
- Implemented sliding-window NXDOMAIN burst tracker (`dnswatch/tracker.py`):
  - Tracks rolling 60-second query window per client IP.
  - Flags NXDOMAIN bursts when query count $\ge 10$ and NXDOMAIN ratio $\ge 50\%$.
  - Includes memory conservation pruning for inactive client state.

### Verification
- `ruff check .`: passed (`0` errors across all modules and tests).
- `pytest tests/ -v`: 36 passed in 0.13s.


