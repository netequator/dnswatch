"""Unit tests for sliding-window NXDOMAIN burst tracker."""

from dnswatch.tracker import NXDOMAINTracker


def test_tracker_no_alert_under_threshold():
    tracker = NXDOMAINTracker(window_sec=60.0, min_queries=10, min_nxdomain=5, ratio_threshold=0.5)

    # 4 NXDOMAIN queries (under min_nxdomain=5)
    for i in range(4):
        anomaly = tracker.record_query("192.168.1.50", "NXDOMAIN", now=100.0 + i)
        assert anomaly is None

    # Add 5 NOERROR queries (total 9 queries, under min_queries=10)
    for i in range(5):
        anomaly = tracker.record_query("192.168.1.50", "NOERROR", now=110.0 + i)
        assert anomaly is None


def test_tracker_burst_detection():
    tracker = NXDOMAINTracker(window_sec=60.0, min_queries=10, min_nxdomain=5, ratio_threshold=0.5)

    # 7 NXDOMAIN and 3 NOERROR queries (total 10, 70% NXDOMAIN)
    now = 100.0
    for _ in range(3):
        tracker.record_query("10.0.0.99", "NOERROR", now=now)
        now += 1.0

    anomaly = None
    for _ in range(7):
        anomaly = tracker.record_query("10.0.0.99", "NXDOMAIN", now=now)
        now += 1.0

    assert anomaly is not None
    assert anomaly.client_ip == "10.0.0.99"
    assert anomaly.total_queries == 10
    assert anomaly.nxdomain_count == 7
    assert anomaly.nxdomain_ratio == 0.7


def test_tracker_sliding_window_expiry():
    tracker = NXDOMAINTracker(window_sec=30.0, min_queries=5, min_nxdomain=3, ratio_threshold=0.5)

    # Record 4 NXDOMAIN at t = 10.0
    for _ in range(4):
        tracker.record_query("172.16.1.1", "NXDOMAIN", now=10.0)

    # Advance time to t = 50.0 (40 seconds later, past window_sec=30)
    # The initial 4 queries should have expired from the sliding window
    anomaly = tracker.record_query("172.16.1.1", "NOERROR", now=50.0)
    assert anomaly is None

    # History now only has 1 event
    tracker.prune_stale(now=50.0)
    assert len(tracker._history["172.16.1.1"]) == 1

    # Advance to t = 90.0 and prune
    tracker.prune_stale(now=90.0)
    assert "172.16.1.1" not in tracker._history
