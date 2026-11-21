"""DNS Rebinding attack detector (SSRF / Intranet traversal)."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass

from dnswatch.constants import TYPE_A, TYPE_AAAA
from dnswatch.models import DNSPacket

# Legitimate local/internal domain suffixes that are expected to resolve to private IPs
BENIGN_LOCAL_SUFFIXES: tuple[str, ...] = (
    ".local",
    ".lan",
    ".internal",
    ".home.arpa",
    ".corp",
    ".intranet",
    ".test",
    ".example",
    ".invalid",
    "localhost",
    ".in-addr.arpa",
    ".ip6.arpa",
)

CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")


@dataclass(frozen=True)
class RebindingAlert:
    """Security alert raised when a public domain resolves to a restricted/private IP."""

    domain: str
    ip: str
    record_type: str
    range_category: str
    timestamp: float


def is_local_domain(domain: str) -> bool:
    """Return True if domain belongs to a standard reserved local/internal domain namespace."""
    clean = domain.strip().lower().rstrip(".")
    if clean == "localhost":
        return True
    return any(clean.endswith(suffix) for suffix in BENIGN_LOCAL_SUFFIXES)


def classify_private_ip(ip_str: str) -> str | None:
    """Classify an IP if it belongs to a private, loopback, link-local, or restricted range."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return None

    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link_local"
    if ip.is_private:
        return "rfc1918_private"
    if ip.version == 4 and ip in CGNAT_NETWORK:
        return "cgnat_shared"
    if ip.is_reserved or ip.is_unspecified:
        return "reserved"

    return None


def detect_dns_rebinding(
    packet: DNSPacket,
    timestamp: float | None = None,
    allow_custom_domains: set[str] | None = None,
) -> list[RebindingAlert]:
    """Inspect answer resource records in a DNS packet for DNS rebinding anomalies.

    Flags public domain names that return private, loopback, or link-local IP addresses,
    which is characteristic of DNS rebinding attacks targeting local host services.
    """
    alerts: list[RebindingAlert] = []
    ts = timestamp if timestamp is not None else time.time()
    custom_allow = {d.lower().rstrip(".") for d in (allow_custom_domains or set())}

    for answer in packet.answers:
        if answer.rtype not in (TYPE_A, TYPE_AAAA):
            continue
        if not isinstance(answer.rdata, str):
            continue

        domain = answer.name.strip().lower().rstrip(".")
        if is_local_domain(domain) or domain in custom_allow:
            continue

        category = classify_private_ip(answer.rdata)
        if category is not None:
            alerts.append(
                RebindingAlert(
                    domain=answer.name,
                    ip=answer.rdata,
                    record_type=answer.rtype_name,
                    range_category=category,
                    timestamp=ts,
                )
            )

    return alerts
