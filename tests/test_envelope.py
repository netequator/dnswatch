"""Deterministic wire-level unit tests for envelope decapsulation and VLAN peeling."""

import socket
import struct

from dnswatch.envelope import (
    ETHERTYPE_8021AD,
    ETHERTYPE_8021Q,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    IPPROTO_TCP,
    IPPROTO_UDP,
    unwrap_dns_payload,
)


def _build_ethernet(ethertype: int, vlan_tags: list[int] | None = None) -> bytes:
    dst_mac = b"\x00\x11\x22\x33\x44\x55"
    src_mac = b"\xaa\xbb\xcc\xdd\xee\xff"
    res = dst_mac + src_mac

    if not vlan_tags:
        return res + struct.pack("!H", ethertype)

    for i, vid in enumerate(vlan_tags):
        outer_type = ETHERTYPE_8021AD if (len(vlan_tags) > 1 and i == 0) else ETHERTYPE_8021Q
        inner_type = ethertype if i == len(vlan_tags) - 1 else ETHERTYPE_8021Q
        tci = vid & 0x0FFF
        res += struct.pack("!HHH", outer_type, tci, inner_type)

    return res


def _build_ipv4(
    src_ip: str, dst_ip: str, proto: int, payload: bytes, frag_offset: int = 0
) -> bytes:
    ihl = 5
    ver_ihl = (4 << 4) | ihl
    total_len = 20 + len(payload)
    flags_frag = (frag_offset // 8) & 0x1FFF
    ttl = 64
    checksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl,
        0,
        total_len,
        0x1234,
        flags_frag,
        ttl,
        proto,
        checksum,
        src_bytes,
        dst_bytes,
    )
    return header + payload


def _build_ipv6(src_ip: str, dst_ip: str, next_header: int, payload: bytes) -> bytes:
    ver_tc_fl = 6 << 28
    payload_len = len(payload)
    hop_limit = 64
    src_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    header = struct.pack(
        "!IHBB16s16s", ver_tc_fl, payload_len, next_header, hop_limit, src_bytes, dst_bytes
    )
    return header + payload


def _build_udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    checksum = 0
    header = struct.pack("!HHHH", src_port, dst_port, length, checksum)
    return header + payload


def _build_tcp(src_port: int, dst_port: int, payload: bytes, prefix_len: bool = True) -> bytes:
    seq = 1000
    ack = 0
    data_offset = 5
    offset_flags = (data_offset << 12) | 0x0010  # ACK flag
    window = 65535
    checksum = 0
    urg = 0
    header = struct.pack(
        "!HHIIHHHH", src_port, dst_port, seq, ack, offset_flags, window, checksum, urg
    )
    if prefix_len:
        data = struct.pack("!H", len(payload)) + payload
    else:
        data = payload
    return header + data


def test_unwrap_ethernet_ipv4_udp_dns():
    dns_wire = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01"
    )
    udp = _build_udp(53123, 53, dns_wire)
    ip = _build_ipv4("192.168.1.50", "8.8.8.8", IPPROTO_UDP, udp)
    eth = _build_ethernet(ETHERTYPE_IPV4) + ip

    env = unwrap_dns_payload(eth)
    assert env is not None
    assert env.link_type == "ethernet"
    assert env.network_proto == "ipv4"
    assert env.transport_proto == "udp"
    assert env.src_ip == "192.168.1.50"
    assert env.dst_ip == "8.8.8.8"
    assert env.src_port == 53123
    assert env.dst_port == 53
    assert env.vlan_tags == []
    assert env.payload == dns_wire
    assert env.is_fragment is False
    assert env.is_dns is True


def test_unwrap_8021q_vlan_peeling():
    dns_wire = b"\x56\x78\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    udp = _build_udp(53, 54321, dns_wire)
    ip = _build_ipv4("1.1.1.1", "10.0.0.5", IPPROTO_UDP, udp)
    # 802.1Q tag with VID 100
    eth = b"\x00\x11\x22\x33\x44\x55\xaa\xbb\xcc\xdd\xee\xff"
    tci = 100
    eth += struct.pack("!HH", ETHERTYPE_8021Q, tci)
    eth += struct.pack("!H", ETHERTYPE_IPV4)
    eth += ip

    env = unwrap_dns_payload(eth)
    assert env is not None
    assert env.vlan_tags == [100]
    assert env.src_ip == "1.1.1.1"
    assert env.dst_ip == "10.0.0.5"
    assert env.payload == dns_wire


def test_unwrap_qinq_double_vlan_peeling():
    dns_wire = b"\x9a\xbc\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    udp = _build_udp(53, 40000, dns_wire)
    ip = _build_ipv4("192.168.10.1", "192.168.10.2", IPPROTO_UDP, udp)

    # 802.1ad outer (VID 200) + 802.1Q inner (VID 10)
    eth = b"\x00\x11\x22\x33\x44\x55\xaa\xbb\xcc\xdd\xee\xff"
    eth += struct.pack("!HH", ETHERTYPE_8021AD, 200)
    eth += struct.pack("!HH", ETHERTYPE_8021Q, 10)
    eth += struct.pack("!H", ETHERTYPE_IPV4)
    eth += ip

    env = unwrap_dns_payload(eth)
    assert env is not None
    assert env.vlan_tags == [200, 10]
    assert env.src_ip == "192.168.10.1"
    assert env.payload == dns_wire


def test_unwrap_ipv6_udp_dns():
    dns_wire = b"\xde\xad\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    udp = _build_udp(53535, 53, dns_wire)
    ip6 = _build_ipv6("2001:db8::1", "2001:4860:4860::8888", IPPROTO_UDP, udp)
    eth = _build_ethernet(ETHERTYPE_IPV6) + ip6

    env = unwrap_dns_payload(eth)
    assert env is not None
    assert env.network_proto == "ipv6"
    assert env.src_ip == "2001:db8::1"
    assert env.dst_ip == "2001:4860:4860::8888"
    assert env.payload == dns_wire


def test_unwrap_ipv6_hop_by_hop_extension():
    dns_wire = b"\xbe\xef\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    udp = _build_udp(53535, 53, dns_wire)
    # Hop-by-hop extension header (next_header=0, length=(0+1)*8 = 8 bytes)
    # First byte: next header (IPPROTO_UDP=17), second byte: len (0)
    hbh = struct.pack("!BB6s", IPPROTO_UDP, 0, b"\x00" * 6)
    ip6 = _build_ipv6("2001:db8::2", "2001:4860:4860::8844", 0, hbh + udp)
    eth = _build_ethernet(ETHERTYPE_IPV6) + ip6

    env = unwrap_dns_payload(eth)
    assert env is not None
    assert env.network_proto == "ipv6"
    assert env.transport_proto == "udp"
    assert env.payload == dns_wire


def test_unwrap_tcp_dns_framing():
    dns_wire = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    tcp = _build_tcp(50000, 53, dns_wire, prefix_len=True)
    ip = _build_ipv4("10.1.1.1", "10.1.1.254", IPPROTO_TCP, tcp)
    eth = _build_ethernet(ETHERTYPE_IPV4) + ip

    env = unwrap_dns_payload(eth)
    assert env is not None
    assert env.transport_proto == "tcp"
    assert env.payload == dns_wire


def test_unwrap_ipv4_non_initial_fragment():
    # Fragment offset > 0 (e.g. offset 1480 = 185 blocks of 8)
    dummy_payload = b"\x00" * 32
    ip = _build_ipv4("192.168.1.10", "8.8.8.8", IPPROTO_UDP, dummy_payload, frag_offset=1480)
    eth = _build_ethernet(ETHERTYPE_IPV4) + ip

    env = unwrap_dns_payload(eth)
    assert env is not None
    assert env.is_fragment is True
    assert env.payload == b""


def test_unwrap_raw_ip_packet():
    dns_wire = b"\xcc\xdd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    udp = _build_udp(51234, 53, dns_wire)
    ip = _build_ipv4("172.16.0.5", "172.16.0.1", IPPROTO_UDP, udp)

    env = unwrap_dns_payload(ip)
    assert env is not None
    assert env.link_type == "raw_ip"
    assert env.src_ip == "172.16.0.5"
    assert env.payload == dns_wire


def test_filter_non_dns_traffic():
    # HTTP port 80
    udp = _build_udp(12345, 80, b"GET / HTTP/1.1\r\n\r\n")
    ip = _build_ipv4("192.168.1.2", "93.184.216.34", IPPROTO_UDP, udp)
    eth = _build_ethernet(ETHERTYPE_IPV4) + ip

    assert unwrap_dns_payload(eth, dns_only=True) is None
    env = unwrap_dns_payload(eth, dns_only=False)
    assert env is not None
    assert env.dst_port == 80
    assert env.is_dns is False


def test_truncated_buffer_handling():
    assert unwrap_dns_payload(b"") is None
    assert unwrap_dns_payload(b"\x00" * 10) is None
    # Truncated IPv4
    assert unwrap_dns_payload(b"\x00" * 14 + b"\x45\x00") is None
