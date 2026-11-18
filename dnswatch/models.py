"""Data models and normalized representations for parsed DNS messages."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class DNSHeader:
    """Fixed 12-byte DNS header fields."""

    txid: int
    qr: str  # "query" or "response"
    opcode: int
    aa: bool
    tc: bool
    rd: bool
    ra: bool
    z: int
    rcode: str
    rcode_num: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int


@dataclass(frozen=True)
class DNSQuestion:
    """Single Question section entry."""

    name: str
    qtype: int
    qtype_name: str
    qclass: int
    qclass_name: str


@dataclass(frozen=True)
class EDNS0Option:
    """RFC 6891 EDNS(0) variable option entry."""

    code: int
    length: int
    data: bytes


@dataclass
class DNSResourceRecord:
    """Parsed Resource Record from Answer, Authority, or Additional sections."""

    name: str
    rtype: int
    rtype_name: str
    rclass: int
    rclass_name: str
    ttl: int
    rdlength: int
    rdata: str | list[str] | dict[str, object] | None = None
    # RFC 6891 EDNS(0) OPT specific fields
    edns_payload_size: int | None = None
    edns_ext_rcode: int | None = None
    edns_version: int | None = None
    edns_do: bool | None = None
    edns_options: list[EDNS0Option] = field(default_factory=list)


@dataclass
class DNSPacket:
    """Complete parsed DNS wire-format message."""

    header: DNSHeader
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSResourceRecord] = field(default_factory=list)
    authorities: list[DNSResourceRecord] = field(default_factory=list)
    additionals: list[DNSResourceRecord] = field(default_factory=list)
    bytes_parsed: int = 0
    total_len: int = 0

    @property
    def is_query(self) -> bool:
        return self.header.qr == "query"

    @property
    def is_response(self) -> bool:
        return self.header.qr == "response"

    @property
    def edns0(self) -> DNSResourceRecord | None:
        """Return the OPT pseudo-record if present in the Additional section."""
        for rr in self.additionals:
            if rr.rtype == 41:  # TYPE_OPT
                return rr
        return None

    def to_dict(self) -> dict[str, object]:
        """Convert message to dictionary compatible with JSON serialization."""
        return {
            "header": asdict(self.header),
            "questions": [asdict(q) for q in self.questions],
            "answers": [self._format_rr(rr) for rr in self.answers],
            "authorities": [self._format_rr(rr) for rr in self.authorities],
            "additionals": [self._format_rr(rr) for rr in self.additionals],
            "bytes_parsed": self.bytes_parsed,
            "total_len": self.total_len,
        }

    def to_jsonl(self) -> str:
        """Serialize parsed message to single-line JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @staticmethod
    def _format_rr(rr: DNSResourceRecord) -> dict[str, object]:
        res: dict[str, object] = {
            "name": rr.name,
            "type": rr.rtype_name,
            "class": rr.rclass_name,
            "ttl": rr.ttl,
            "rdlength": rr.rdlength,
            "rdata": rr.rdata,
        }
        if rr.rtype == 41:
            res["edns"] = {
                "udp_payload_size": rr.edns_payload_size,
                "extended_rcode": rr.edns_ext_rcode,
                "version": rr.edns_version,
                "do": rr.edns_do,
                "options_count": len(rr.edns_options),
            }
        return res
