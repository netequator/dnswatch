"""dnswatch - Zero-dependency passive DNS network monitor & wire-format parser."""

from dnswatch.constants import QCLASS_MAP, QTYPE_MAP, RCODE_MAP
from dnswatch.entropy import DomainEntropyResult, analyze_domain, shannon_entropy
from dnswatch.envelope import ParsedEnvelope, unwrap_dns_payload
from dnswatch.models import DNSHeader, DNSPacket, DNSQuestion, DNSResourceRecord, EDNS0Option
from dnswatch.parser import decode_name, parse_dns_packet, parse_header
from dnswatch.tracker import NXDOMAINBurstAnomaly, NXDOMAINTracker

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
    "ParsedEnvelope",
    "unwrap_dns_payload",
    "DomainEntropyResult",
    "analyze_domain",
    "shannon_entropy",
    "NXDOMAINBurstAnomaly",
    "NXDOMAINTracker",
    "decode_name",
    "parse_dns_packet",
    "parse_header",
]
