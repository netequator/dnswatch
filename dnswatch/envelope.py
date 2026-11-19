"""Zero-dependency packet envelope decapsulation and VLAN peeling.

Handles Layer 2 (Ethernet II, 802.1Q/802.1ad VLAN tags), Layer 3 (IPv4, IPv6
with extension header traversal), and Layer 4 (UDP, TCP length-prefixed framing).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

# EtherTypes
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_8021Q = 0x8100
ETHERTYPE_8021AD = 0x88A8

# IP Protocols
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# IPv6 Extension Headers
IPV6_EXT_HOP_BY_HOP = 0
IPV6_EXT_ROUTING = 43
IPV6_EXT_FRAGMENT = 44
IPV6_EXT_ESP = 50
IPV6_EXT_AH = 51
IPV6_EXT_DEST_OPTS = 60
IPV6_EXT_MOBILITY = 135

IPV6_EXT_HEADERS = {
    IPV6_EXT_HOP_BY_HOP,
    IPV6_EXT_ROUTING,
    IPV6_EXT_FRAGMENT,
    IPV6_EXT_DEST_OPTS,
    IPV6_EXT_AH,
}


@dataclass(frozen=True)
class ParsedEnvelope:
    """Normalized representation of decapsulated packet envelope."""

    link_type: str
    vlan_tags: list[int] = field(default_factory=list)
    network_proto: str = ""  # "ipv4" or "ipv6"
    transport_proto: str = ""  # "udp" or "tcp"
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    payload: bytes = b""
    is_fragment: bool = False
    is_dns: bool = False


def unwrap_dns_payload(buf: bytes, dns_only: bool = True) -> ParsedEnvelope | None:
    """Decapsulate a raw packet buffer down to its L4 DNS wire payload.

    Supports Ethernet frames, 802.1Q/802.1ad VLAN peeling, IPv4/IPv6, and UDP/TCP.
    Also auto-detects raw IP packets (without L2 header).

    Args:
        buf: Raw byte buffer from raw socket, AF_PACKET, or PCAP packet record.
        dns_only: If True, filters strictly for ports 53 or 5353 (mDNS).

    Returns:
        ParsedEnvelope if successfully decapsulated, or None on truncation / non-DNS.
    """
    if len(buf) < 14:
        return None

    offset = 0
    vlan_tags: list[int] = []
    link_type = "raw_ip"

    # Auto-detect if raw IP (Version 4 or 6) or Ethernet frame
    first_nibble = buf[0] >> 4
    if first_nibble == 4 and len(buf) >= 20:
        ethertype = ETHERTYPE_IPV4
    elif first_nibble == 6 and len(buf) >= 40:
        ethertype = ETHERTYPE_IPV6
    else:
        # Standard Ethernet II header (14 bytes)
        link_type = "ethernet"
        if len(buf) < 14:
            return None
        ethertype = struct.unpack("!H", buf[12:14])[0]
        offset = 14

        # Peel 802.1Q and 802.1ad VLAN tags (up to 4 tags to prevent infinite loops)
        while ethertype in (ETHERTYPE_8021Q, ETHERTYPE_8021AD):
            if len(buf) < offset + 4:
                return None
            tci, inner_type = struct.unpack("!HH", buf[offset : offset + 4])
            vid = tci & 0x0FFF
            vlan_tags.append(vid)
            ethertype = inner_type
            offset += 4

    src_ip = ""
    dst_ip = ""
    proto = 0
    network_proto = ""
    is_fragment = False

    if ethertype == ETHERTYPE_IPV4:
        network_proto = "ipv4"
        if len(buf) < offset + 20:
            return None

        ver_ihl = buf[offset]
        if (ver_ihl >> 4) != 4:
            return None

        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(buf) < offset + ihl:
            return None

        # Check IPv4 total length
        total_len = struct.unpack("!H", buf[offset + 2 : offset + 4])[0]

        # Fragmentation check: flags (3 bits) and fragment offset (13 bits)
        flags_frag = struct.unpack("!H", buf[offset + 6 : offset + 8])[0]
        frag_offset = (flags_frag & 0x1FFF) * 8
        is_fragment = frag_offset > 0 or bool(flags_frag & 0x2000)

        proto = buf[offset + 9]
        src_ip = socket.inet_ntoa(buf[offset + 12 : offset + 16])
        dst_ip = socket.inet_ntoa(buf[offset + 16 : offset + 20])

        if frag_offset > 0:
            # Non-initial fragment: L4 header absent
            return ParsedEnvelope(
                link_type=link_type,
                vlan_tags=vlan_tags,
                network_proto=network_proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                is_fragment=True,
            )

        # Slice to IPv4 payload bounded by total_len if valid
        ip_payload_len = total_len - ihl if total_len >= ihl else len(buf) - (offset + ihl)
        end_offset = min(len(buf), offset + ihl + ip_payload_len)
        buf = buf[:end_offset]
        offset += ihl

    elif ethertype == ETHERTYPE_IPV6:
        network_proto = "ipv6"
        if len(buf) < offset + 40:
            return None

        ver = buf[offset] >> 4
        if ver != 6:
            return None

        payload_len = struct.unpack("!H", buf[offset + 4 : offset + 6])[0]
        next_header = buf[offset + 6]
        src_ip = socket.inet_ntop(socket.AF_INET6, buf[offset + 8 : offset + 24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, buf[offset + 24 : offset + 40])
        end_offset = min(len(buf), offset + 40 + payload_len)
        buf = buf[:end_offset]
        offset += 40

        # Traversal of IPv6 Extension Headers
        ext_hops = 0
        while next_header in IPV6_EXT_HEADERS and ext_hops < 8:
            ext_hops += 1
            if len(buf) < offset + 8:
                return None

            curr_header = next_header
            next_header = buf[offset]

            if curr_header == IPV6_EXT_FRAGMENT:
                # Fixed 8-byte fragment header
                frag_info = struct.unpack("!H", buf[offset + 2 : offset + 4])[0]
                frag_offset = frag_info >> 3
                if frag_offset > 0:
                    return ParsedEnvelope(
                        link_type=link_type,
                        vlan_tags=vlan_tags,
                        network_proto=network_proto,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        is_fragment=True,
                    )
                offset += 8
            elif curr_header == IPV6_EXT_AH:
                # AH payload len is in 4-byte words minus 2
                ah_len = (buf[offset + 1] + 2) * 4
                if len(buf) < offset + ah_len:
                    return None
                offset += ah_len
            else:
                # Hop-by-hop, Routing, Destination Options: (hdr_ext_len + 1) * 8
                hdr_len = (buf[offset + 1] + 1) * 8
                if len(buf) < offset + hdr_len:
                    return None
                offset += hdr_len

        proto = next_header
    else:
        # Non-IP frame
        return None

    # Layer 4 Decapsulation
    transport_proto = ""
    src_port = 0
    dst_port = 0
    payload = b""

    if proto == IPPROTO_UDP:
        transport_proto = "udp"
        if len(buf) < offset + 8:
            return None
        src_port, dst_port, udp_len = struct.unpack("!HHH", buf[offset : offset + 6])
        if udp_len < 8:
            return None
        payload = buf[offset + 8 : offset + udp_len]

    elif proto == IPPROTO_TCP:
        transport_proto = "tcp"
        if len(buf) < offset + 20:
            return None
        src_port, dst_port = struct.unpack("!HH", buf[offset : offset + 4])
        data_offset = ((buf[offset + 12] >> 4) & 0x0F) * 4
        if len(buf) < offset + data_offset:
            return None

        tcp_payload = buf[offset + data_offset :]
        # TCP DNS messages have a 2-byte big-endian message length prefix (RFC 1035 §4.2.2)
        if len(tcp_payload) >= 2:
            msg_len = struct.unpack("!H", tcp_payload[:2])[0]
            payload = tcp_payload[2 : 2 + msg_len]
        else:
            payload = b""
    else:
        return None

    is_dns = src_port in (53, 5353) or dst_port in (53, 5353)
    if dns_only and not is_dns:
        return None

    return ParsedEnvelope(
        link_type=link_type,
        vlan_tags=vlan_tags,
        network_proto=network_proto,
        transport_proto=transport_proto,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
        is_fragment=is_fragment,
        is_dns=is_dns,
    )
