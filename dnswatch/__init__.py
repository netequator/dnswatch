"""dnswatch - Zero-dependency passive DNS network monitor & wire-format parser."""

from dnswatch.constants import QCLASS_MAP, QTYPE_MAP, RCODE_MAP
from dnswatch.models import DNSHeader, DNSPacket, DNSQuestion, DNSResourceRecord, EDNS0Option
from dnswatch.parser import decode_name, parse_dns_packet, parse_header

__version__ = "0.1.0"

__all__ = [
    "QCLASS_MAP",
    "QTYPE_MAP",
    "RCODE_MAP",
    "DNSHeader",
    "DNSPacket",
    "DNSQuestion",
    "DNSResourceRecord",
    "EDNS0Option",
    "decode_name",
    "parse_dns_packet",
    "parse_header",
]
