"""
test_detector.py
----------------
Unit tests for the detection engine (nids/detector.py).

WHY THESE EXIST:
    These prove each rule fires exactly when it should and stays silent when it
    should not - without a network, Npcap, or Administrator rights. They run in
    well under a second, so you can run them after every change.

RUN:
    pytest                       # all tests
    pytest tests/test_detector.py -v   # just these, verbose
"""

from __future__ import annotations

import pytest

from nids.detector import (
    AttackType,
    DetectionSettings,
    IntrusionDetector,
    SlidingWindowCounter,
    SlidingWindowDistinctCounter,
)
from nids.sniffer import PacketInfo


# ----------------------------------------------------------------------
# Test helpers / fixtures
# ----------------------------------------------------------------------
def make_packet(timestamp: float, source_ip: str = "10.0.0.5", **overrides: object) -> PacketInfo:
    """Build a fake PacketInfo (a TCP SYN to port 80 by default) for tests."""
    fields: dict[str, object] = {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": "10.0.0.1",
        "protocol": "TCP",
        "source_port": 50000,
        "destination_port": 80,
        "tcp_flags": "S",
        "icmp_type": None,
        "size_bytes": 60,
    }
    fields.update(overrides)
    return PacketInfo(**fields)  # type: ignore[arg-type]


@pytest.fixture
def small_settings() -> DetectionSettings:
    """Tiny thresholds so tests need only a handful of packets to trigger a rule."""
    return DetectionSettings(
        port_scan_distinct_port_limit=3,
        port_scan_window_seconds=10.0,
        syn_flood_packet_limit=5,
        syn_flood_window_seconds=5.0,
        icmp_flood_packet_limit=4,
        icmp_flood_window_seconds=5.0,
    )


@pytest.fixture
def detector(small_settings: DetectionSettings) -> IntrusionDetector:
    """A detector with small thresholds and one blacklisted IP."""
    return IntrusionDetector(blacklisted_ips={"203.0.113.77"}, settings=small_settings)


def collect_attack_types(detector: IntrusionDetector, packets: list[PacketInfo]) -> set[AttackType]:
    """Feed packets through the detector and return the set of attack types raised."""
    attack_types: set[AttackType] = set()
    for packet in packets:
        for alert in detector.inspect(packet):
            attack_types.add(alert.attack_type)
    return attack_types


# ----------------------------------------------------------------------
# SlidingWindowCounter
# ----------------------------------------------------------------------
class TestSlidingWindowCounter:
    """Tests for the plain event counter."""

    def test_counts_events_in_window(self) -> None:
        counter = SlidingWindowCounter(window_seconds=5.0)
        assert counter.add_event("a", 1.0) == 1
        assert counter.add_event("a", 2.0) == 2
        assert counter.add_event("a", 3.0) == 3

    def test_old_events_expire(self) -> None:
        counter = SlidingWindowCounter(window_seconds=5.0)
        counter.add_event("a", 1.0)
        counter.add_event("a", 2.0)
        # At t=7.0 the cutoff is 2.0, so the event at 1.0 (and 2.0) expires.
        assert counter.add_event("a", 7.0) == 1

    def test_keys_are_independent(self) -> None:
        counter = SlidingWindowCounter(window_seconds=5.0)
        counter.add_event("a", 1.0)
        assert counter.add_event("b", 1.0) == 1  # key "b" unaffected by "a"

    def test_purge_removes_stale_keys(self) -> None:
        counter = SlidingWindowCounter(window_seconds=5.0)
        counter.add_event("a", 1.0)
        assert counter.tracked_key_count() == 1
        counter.purge_stale_keys(now=100.0)  # far past the window
        assert counter.tracked_key_count() == 0

    def test_zero_window_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            SlidingWindowCounter(window_seconds=0)


# ----------------------------------------------------------------------
# SlidingWindowDistinctCounter
# ----------------------------------------------------------------------
class TestSlidingWindowDistinctCounter:
    """Tests for the distinct-value counter used by the port-scan rule."""

    def test_counts_distinct_values(self) -> None:
        counter = SlidingWindowDistinctCounter(window_seconds=10.0)
        assert counter.add_event("ip", 1.0, value=80) == 1
        assert counter.add_event("ip", 2.0, value=443) == 2
        # Repeating port 80 does NOT increase the distinct count.
        assert counter.add_event("ip", 3.0, value=80) == 2

    def test_distinct_count_drops_as_values_expire(self) -> None:
        counter = SlidingWindowDistinctCounter(window_seconds=5.0)
        counter.add_event("ip", 1.0, value=80)
        counter.add_event("ip", 2.0, value=443)
        # At t=6.5 the cutoff is 1.5, so port 80 (t=1.0) expires; 443 remains.
        # Adding port 22 gives 2 distinct ports: 443 and 22.
        assert counter.add_event("ip", 6.5, value=22) == 2


# ----------------------------------------------------------------------
# Rule 1: Port Scan
# ----------------------------------------------------------------------
class TestPortScanRule:
    """One IP touching too many different ports should trigger a Port Scan."""

    def test_scan_triggers_alert(self, detector: IntrusionDetector) -> None:
        # limit is 3, so the 4th distinct port fires.
        packets = [make_packet(1.0 + i, destination_port=1000 + i) for i in range(4)]
        assert AttackType.PORT_SCAN in collect_attack_types(detector, packets)

    def test_few_ports_do_not_trigger(self, detector: IntrusionDetector) -> None:
        # Only 2 distinct ports, under the limit of 3.
        packets = [make_packet(1.0, destination_port=80), make_packet(2.0, destination_port=443)]
        assert AttackType.PORT_SCAN not in collect_attack_types(detector, packets)

    def test_same_port_repeated_is_not_a_scan(self, detector: IntrusionDetector) -> None:
        # 10 SYNs but all to the SAME port: that is a flood pattern, not a scan.
        packets = [make_packet(1.0 + i * 0.1, destination_port=80) for i in range(10)]
        assert AttackType.PORT_SCAN not in collect_attack_types(detector, packets)


# ----------------------------------------------------------------------
# Rule 2: SYN Flood
# ----------------------------------------------------------------------
class TestSynFloodRule:
    """Too many SYNs to the SAME port should trigger a SYN Flood."""

    def test_flood_triggers_alert(self, detector: IntrusionDetector) -> None:
        # limit is 5, so the 6th SYN to port 80 fires.
        packets = [make_packet(1.0 + i * 0.1, destination_port=80) for i in range(6)]
        assert AttackType.SYN_FLOOD in collect_attack_types(detector, packets)

    def test_syn_ack_is_not_counted(self, detector: IntrusionDetector) -> None:
        # SYN-ACK ("SA") packets are server REPLIES, not connection attempts.
        packets = [make_packet(1.0 + i * 0.1, tcp_flags="SA", destination_port=80) for i in range(10)]
        assert AttackType.SYN_FLOOD not in collect_attack_types(detector, packets)

    def test_a_port_scan_does_not_also_flag_syn_flood(self, detector: IntrusionDetector) -> None:
        # 10 SYNs to 10 DIFFERENT ports: a scan, but NOT a flood of any one port.
        packets = [make_packet(1.0 + i * 0.1, destination_port=1000 + i) for i in range(10)]
        detected = collect_attack_types(detector, packets)
        assert AttackType.PORT_SCAN in detected
        assert AttackType.SYN_FLOOD not in detected


# ----------------------------------------------------------------------
# Rule 3: ICMP Flood
# ----------------------------------------------------------------------
class TestIcmpFloodRule:
    """Too many ping requests should trigger an ICMP Flood."""

    def _ping(self, timestamp: float, source_ip: str = "10.0.0.5") -> PacketInfo:
        return make_packet(
            timestamp, source_ip=source_ip, protocol="ICMP",
            source_port=None, destination_port=None, tcp_flags="", icmp_type=8,
        )

    def test_ping_flood_triggers_alert(self, detector: IntrusionDetector) -> None:
        # limit is 4, so the 5th ping fires.
        packets = [self._ping(1.0 + i * 0.1) for i in range(5)]
        assert AttackType.ICMP_FLOOD in collect_attack_types(detector, packets)

    def test_echo_reply_is_not_counted(self, detector: IntrusionDetector) -> None:
        # icmp_type 0 is an echo REPLY, not a request; it must not count.
        packets = [make_packet(1.0 + i * 0.1, protocol="ICMP", source_port=None,
                               destination_port=None, tcp_flags="", icmp_type=0)
                   for i in range(10)]
        assert AttackType.ICMP_FLOOD not in collect_attack_types(detector, packets)


# ----------------------------------------------------------------------
# Rule 4: Blacklisted IP
# ----------------------------------------------------------------------
class TestBlacklistRule:
    """Any packet from a blacklisted IP should trigger immediately."""

    def test_blacklisted_ip_triggers_on_first_packet(self, detector: IntrusionDetector) -> None:
        packets = [make_packet(1.0, source_ip="203.0.113.77", protocol="UDP", tcp_flags="")]
        assert AttackType.BLACKLISTED_IP in collect_attack_types(detector, packets)

    def test_non_blacklisted_ip_is_fine(self, detector: IntrusionDetector) -> None:
        packets = [make_packet(1.0, source_ip="8.8.8.8", protocol="UDP", tcp_flags="")]
        assert AttackType.BLACKLISTED_IP not in collect_attack_types(detector, packets)


# ----------------------------------------------------------------------
# Whole-detector behaviour
# ----------------------------------------------------------------------
class TestDetectorOverall:
    """Tests across all rules together."""

    def test_normal_traffic_raises_nothing(self, detector: IntrusionDetector) -> None:
        # Alternating web traffic to 2 ports from a normal IP: no alerts.
        packets = [make_packet(1.0 + i, destination_port=443 if i % 2 else 80) for i in range(3)]
        assert collect_attack_types(detector, packets) == set()

    def test_packets_inspected_counter(self, detector: IntrusionDetector) -> None:
        for i in range(7):
            detector.inspect(make_packet(1.0 + i))
        assert detector.packets_inspected == 7

    def test_alert_contains_useful_fields(self, detector: IntrusionDetector) -> None:
        packets = [make_packet(1.0 + i, destination_port=1000 + i) for i in range(4)]
        alerts = [a for p in packets for a in detector.inspect(p)]
        assert alerts  # at least one fired
        first = alerts[0]
        assert first.source_ip == "10.0.0.5"
        assert first.description  # non-empty explanation
        assert str(first.attack_type) == "Port Scan"
