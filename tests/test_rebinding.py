"""Deterministic unit tests for dnswatch DNS rebinding anomaly detector."""

from __future__ import annotations

from dnswatch.constants import (
    CLASS_IN,
    RCODE_NOERROR,
    TYPE_A,
)
from dnswatch.models import DNSHeader, DNSPacket, DNSQuestion, DNSResourceRecord
from dnswatch.rebinding import classify_private_ip, detect_dns_rebinding, is_local_domain


def make_packet_with_answer(domain: str, ip: str, rtype: int = TYPE_A) -> DNSPacket:
    header = DNSHeader(
        txid=0x1234,
        qr="response",
        opcode=0,
        aa=False,
        tc=False,
        rd=True,
        ra=True,
        z=0,
        rcode="NOERROR",
        rcode_num=RCODE_NOERROR,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
    )
    question = DNSQuestion(
        name=domain,
        qtype=rtype,
        qtype_name="A" if rtype == TYPE_A else "AAAA",
        qclass=CLASS_IN,
        qclass_name="IN",
    )
    answer = DNSResourceRecord(
        name=domain,
        rtype=rtype,
        rtype_name="A" if rtype == TYPE_A else "AAAA",
        rclass=CLASS_IN,
        rclass_name="IN",
        ttl=300,
        rdlength=4 if rtype == TYPE_A else 16,
        rdata=ip,
    )
    return DNSPacket(
        header=header,
        questions=[question],
        answers=[answer],
        authorities=[],
        additionals=[],
    )


def test_classify_private_ip() -> None:
    assert classify_private_ip("127.0.0.1") == "loopback"
    assert classify_private_ip("10.0.0.1") == "rfc1918_private"
    assert classify_private_ip("172.16.5.1") == "rfc1918_private"
    assert classify_private_ip("192.168.1.1") == "rfc1918_private"
    assert classify_private_ip("169.254.10.20") == "link_local"
    assert classify_private_ip("100.64.0.1") == "cgnat_shared"
    assert classify_private_ip("::1") == "loopback"
    assert classify_private_ip("fe80::1") == "link_local"
    assert classify_private_ip("fc00::1") == "rfc1918_private"
    assert classify_private_ip("8.8.8.8") is None
    assert classify_private_ip("1.1.1.1") is None
    assert classify_private_ip("invalid-ip") is None


def test_is_local_domain() -> None:
    assert is_local_domain("localhost") is True
    assert is_local_domain("router.local") is True
    assert is_local_domain("nas.lan") is True
    assert is_local_domain("service.internal") is True
    assert is_local_domain("device.home.arpa") is True
    assert is_local_domain("public-domain.com") is False
    assert is_local_domain("sub.attacker.net") is False


def test_detect_dns_rebinding_alerts() -> None:
    # Public domain resolving to loopback
    pkt1 = make_packet_with_answer("attacker.com", "127.0.0.1")
    alerts1 = detect_dns_rebinding(pkt1)
    assert len(alerts1) == 1
    assert alerts1[0].domain == "attacker.com"
    assert alerts1[0].ip == "127.0.0.1"
    assert alerts1[0].range_category == "loopback"

    # Public domain resolving to RFC 1918
    pkt2 = make_packet_with_answer("c2.evil.org", "192.168.1.100")
    alerts2 = detect_dns_rebinding(pkt2)
    assert len(alerts2) == 1
    assert alerts2[0].range_category == "rfc1918_private"

    # Benign public domain resolving to public IP
    pkt3 = make_packet_with_answer("google.com", "142.250.190.46")
    alerts3 = detect_dns_rebinding(pkt3)
    assert len(alerts3) == 0

    # Legitimate local domain resolving to private IP
    pkt4 = make_packet_with_answer("gateway.local", "192.168.1.1")
    alerts4 = detect_dns_rebinding(pkt4)
    assert len(alerts4) == 0


def test_detect_dns_rebinding_custom_allowlist() -> None:
    pkt = make_packet_with_answer("corp.customportal.com", "10.50.0.1")
    # Without allowlist -> flagged
    assert len(detect_dns_rebinding(pkt)) == 1

    # With custom allowlist -> benign
    assert len(detect_dns_rebinding(pkt, allow_custom_domains={"corp.customportal.com"})) == 0
