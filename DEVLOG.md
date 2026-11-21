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




## 2026-11-21 — Day 4: RFC 1035 Synthetic Responder, Blocklist Engine & DNS Rebinding Detector (Issue #5)

### Design Notes
- Implemented zero-dependency RFC 1035 synthetic response generator (`dnswatch/responder.py`):
  - Echoes query transaction ID, validates bounds and non-empty Question sections.
  - Slices QNAME, QTYPE, and QCLASS while constructing authoritative response flags (`QR=1`, `AA=1`, `RA=1`, and preserves `RD`).
  - Implements pointer compression back to QNAME at byte offset 12 (`b"\xc0\x0c"`).
  - Serializes synthetic `A` records (`0.0.0.0` or user-defined IP) and `AAAA` records (`::` or user-defined IPv6).
  - Supports authoritative `NXDOMAIN` (RCODE 3) generation with `ANCOUNT=0`.
- Implemented in-memory domain blocklist matcher (`dnswatch/sinkhole.py`):
  - Ingests plain text and hosts-file formats (`0.0.0.0 bad.org`, `127.0.0.1 tracker.com`, comments `#`).
  - Implements $O(1)$ exact domain hash matching and $O(k)$ parent label wildcard suffix lookups (`*.malware.test`).
- Implemented DNS Rebinding security anomaly detector (`dnswatch/rebinding.py`):
  - Traverses response Answer sections and inspects resolved `A` and `AAAA` addresses.
  - Automatically exempts legitimate reserved internal namespaces (`.local`, `.lan`, `.internal`, `.home.arpa`, `localhost`).
  - Flags SSRF DNS rebinding attacks when public domain names map to RFC 1918 private IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), CGNAT (`100.64.0.0/10`), or IPv6 loopback (`::1`) and ULA (`fc00::/7`).
- Integrated into CLI console engine (`dnswatch/cli.py`):
  - Added CLI parameters: `--sinkhole <file>`, `--sink-ip <ip>`, `--sink-mode <a|nxdomain>`, `--no-rebinding`.
  - Intercepts blocked UDP queries on the listening socket and delivers synthetic RFC 1035 answers with JSONL audit events.

### Verification
- `ruff check .`: passed (`0` errors across all modules and tests).
- `pytest tests/ -v`: 51 passed in 0.35s (100% pass rate).


## 2026-11-21 — Session 2: Repository Community Health & Governance Standards

### Design Notes
- Added complete suite of five standard open-source governance and community health files matching `neighwatch`:
  - `LICENSE`: BSD-3-Clause matching SPDX format for `netequator` (2026).
  - `SECURITY.md`: Supported versions (0.1.x), threat model (wire parser bounds, pointer loops, EDNS0 limits, synthetic responder), and confidential disclosure process.
  - `CONTRIBUTING.md`: Development setup, zero-dependency requirements, deterministic testing guidelines, and commit message formats.
  - `CODE_OF_CONDUCT.md`: Professional conduct standards rooted in technical rigor and mutual respect.
  - `CITATION.cff`: Citation metadata format activating GitHub's native "Cite this repository" sidebar feature.
- Committed under permanent standing exemption (`debaf9d`) and synchronized with `origin/main` and release tag `v0.1.0`.
