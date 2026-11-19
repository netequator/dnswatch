"""Unit tests for Shannon entropy computation and DNS tunneling detection."""

import math

from dnswatch.entropy import analyze_domain, shannon_entropy


def test_shannon_entropy_known_values():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("a") == 0.0
    assert shannon_entropy("aaaa") == 0.0

    # Two equally frequent characters: H = -2 * (0.5 * log2(0.5)) = 1.0
    assert math.isclose(shannon_entropy("ab"), 1.0, rel_tol=1e-3)
    assert math.isclose(shannon_entropy("abababab"), 1.0, rel_tol=1e-3)

    # 4 distinct characters equally distributed: H = log2(4) = 2.0
    assert math.isclose(shannon_entropy("abcd"), 2.0, rel_tol=1e-3)


def test_normal_domains_not_suspicious():
    normal_domains = [
        "google.com",
        "api.github.com",
        "cloudflare.net",
        "static.example.org",
        "cdn.somedomain.co.uk",
        "mail.corp.internal",
    ]
    for d in normal_domains:
        res = analyze_domain(d)
        assert res.is_suspicious is False
        assert res.anomaly_type is None


def test_single_label_tunneling_detection():
    # Base32 / hex random high entropy label >= 20 characters
    # e.g. 32-char high-entropy hash label
    high_entropy_label = "v8k9w2x4m1n7q5p3r6t0y8z1b4c7d2e9"
    domain = f"{high_entropy_label}.tunnel.evil.com"

    res = analyze_domain(domain)
    assert res.is_suspicious is True
    assert res.anomaly_type == "high_entropy_label"
    assert res.highest_entropy_label == high_entropy_label
    assert res.max_label_entropy >= 3.75


def test_chunked_multi_label_tunneling_detection():
    # Iodine-style chunked subdomain prefix where individual labels are < 20 chars,
    # but the combined prefix >= 32 chars with entropy >= 3.75
    # e.g. 3 chunked labels of 12 chars each = 36 chars prefix
    lbl1 = "x9k2m4p8q1w3"  # 12 chars
    lbl2 = "r5t7y0z2b6c1"  # 12 chars
    lbl3 = "d4e8f3g7h1j5"  # 12 chars
    domain = f"{lbl1}.{lbl2}.{lbl3}.corp.com"

    res = analyze_domain(domain)
    assert res.is_suspicious is True
    assert res.anomaly_type == "high_entropy_chunked_prefix"
    assert res.prefix_length == 36
    assert res.prefix_entropy >= 3.75


def test_empty_and_root_domain_handling():
    res = analyze_domain("")
    assert res.is_suspicious is False
    assert res.max_label_entropy == 0.0

    res_root = analyze_domain(".")
    assert res_root.is_suspicious is False
