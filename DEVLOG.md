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

