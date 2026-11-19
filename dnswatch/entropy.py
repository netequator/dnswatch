"""Shannon entropy analysis and covert DNS tunneling detection.

Implements mathematical Shannon entropy computation over individual domain labels
and multi-label concatenated prefixes (RFC 1035 §2.3.4) to detect covert DNS
tunneling utilities (such as iodine, dnscat2, and algorithmic DGA exfiltration).
"""

from __future__ import annotations

import collections
import math
from dataclasses import dataclass

# Detection Thresholds
DEFAULT_ENTROPY_THRESHOLD = 3.75
DEFAULT_MIN_LABEL_LEN = 20
DEFAULT_MIN_PREFIX_LEN = 32


@dataclass(frozen=True)
class DomainEntropyResult:
    """Structured result of entropy and tunneling analysis for a domain name."""

    domain: str
    is_suspicious: bool
    anomaly_type: str | None  # "high_entropy_label", "high_entropy_chunked_prefix", or None
    max_label_entropy: float
    highest_entropy_label: str
    prefix_entropy: float
    prefix_length: int


def shannon_entropy(s: str) -> float:
    """Compute mathematical Shannon entropy: H(X) = -sum(p_i * log2(p_i)).

    Args:
        s: Input ASCII or normalized string.

    Returns:
        Entropy value in bits, ranging from 0.0 to log2(len(charset)).
    """
    if not s:
        return 0.0

    length = len(s)
    counts = collections.Counter(s.lower())
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def analyze_domain(
    domain: str,
    label_len_threshold: int = DEFAULT_MIN_LABEL_LEN,
    prefix_len_threshold: int = DEFAULT_MIN_PREFIX_LEN,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
) -> DomainEntropyResult:
    """Analyze a domain name for DNS tunneling indicators and high entropy.

    Checks:
    1. Single-label trigger: any subdomain label with length >= label_len_threshold
       and entropy >= entropy_threshold.
    2. Multi-label chunked prefix trigger: concatenated subdomain prefix with
       length >= prefix_len_threshold and entropy >= entropy_threshold.

    Args:
        domain: Domain name (e.g., "a1b2c3...z9.tunnel.example.com").
        label_len_threshold: Minimum label length for single-label test (default: 20).
        prefix_len_threshold: Minimum combined prefix length for chunked test (default: 32).
        entropy_threshold: Shannon entropy threshold in bits (default: 3.75).

    Returns:
        DomainEntropyResult detailing detection outcome and metrics.
    """
    cleaned = domain.rstrip(".").lower()
    labels = [lbl for lbl in cleaned.split(".") if lbl]

    if not labels:
        return DomainEntropyResult(
            domain=domain,
            is_suspicious=False,
            anomaly_type=None,
            max_label_entropy=0.0,
            highest_entropy_label="",
            prefix_entropy=0.0,
            prefix_length=0,
        )

    max_entropy = 0.0
    highest_label = ""
    is_suspicious = False
    anomaly_type = None

    # Check individual labels
    for lbl in labels:
        ent = shannon_entropy(lbl)
        if ent > max_entropy:
            max_entropy = ent
            highest_label = lbl

        if len(lbl) >= label_len_threshold and ent >= entropy_threshold:
            is_suspicious = True
            anomaly_type = "high_entropy_label"

    # Check concatenated multi-label prefix (all labels excluding 2LD + TLD)
    prefix_entropy = 0.0
    prefix_len = 0
    if len(labels) > 2 and not is_suspicious:
        subdomain_labels = labels[:-2]
        prefix = "".join(subdomain_labels)
        prefix_len = len(prefix)
        prefix_entropy = shannon_entropy(prefix)

        if prefix_len >= prefix_len_threshold and prefix_entropy >= entropy_threshold:
            is_suspicious = True
            anomaly_type = "high_entropy_chunked_prefix"

    return DomainEntropyResult(
        domain=domain,
        is_suspicious=is_suspicious,
        anomaly_type=anomaly_type,
        max_label_entropy=max_entropy,
        highest_entropy_label=highest_label,
        prefix_entropy=prefix_entropy,
        prefix_length=prefix_len,
    )
