"""
detector.py
-----------
Detection engine of the NIDS: decides whether traffic looks like an attack.

RESPONSIBILITY (Single Responsibility Principle):
    Receive one PacketInfo at a time, update short-term counters, and return
    a list of Alert objects for every rule the packet breaks.

    This module does NOT capture packets (sniffer.py does that) and does NOT
    print or save alerts (alert_manager.py does that in Module 4).
    It never imports Scapy at runtime, so it can be tested with fake packets.

THE 4 RULES:
    1. Port Scan      - one source IP tries too many DIFFERENT ports quickly.
    2. SYN Flood      - one source IP sends too many SYNs to the SAME port quickly.
    3. ICMP Flood     - one source IP sends too many pings quickly.
    4. Blacklisted IP - any packet from an IP listed in data/blacklist.txt.

SELF-TEST (no admin rights or network needed), from the project root:
    python -m nids.detector
"""

from __future__ import annotations

import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Callable, Optional

from nids import config

# TYPE_CHECKING is False when the program actually runs, so this import only
# exists for type hints / VS Code autocomplete. Result: detector.py does not
# load Scapy at runtime, keeping it independent of the capture library.
if TYPE_CHECKING:
    from nids.sniffer import PacketInfo

# ICMP type number of an "echo request", i.e. what the ping command sends.
ICMP_ECHO_REQUEST_TYPE: int = 8

# How often (in seconds of packet time) we delete counters for IPs that went quiet.
STALE_DATA_PURGE_INTERVAL_SECONDS: float = 60.0


class AttackType(StrEnum):
    """
    The kinds of attack this NIDS can detect.

    StrEnum members behave like normal strings ("Port Scan"), so they can be
    written straight into CSV files, but typos like "Port Scna" become errors
    instead of silent bugs.
    """

    PORT_SCAN = "Port Scan"
    SYN_FLOOD = "SYN Flood"
    ICMP_FLOOD = "ICMP Flood"
    BLACKLISTED_IP = "Blacklisted IP"


class Severity(StrEnum):
    """How serious an alert is. Used for colours in the console and dashboard."""

    MEDIUM = "MEDIUM"  # reconnaissance or nuisance traffic (scans, ping floods)
    HIGH = "HIGH"      # likely denial-of-service or known-bad source


@dataclass(frozen=True)
class Alert:
    """One detected suspicious event. Immutable, like PacketInfo."""

    timestamp: float         # when the triggering packet was captured (epoch seconds)
    attack_type: AttackType  # which rule fired
    severity: Severity       # how serious it is
    source_ip: str           # suspected attacker
    destination_ip: str      # target
    description: str         # human-readable explanation with numbers


@dataclass(frozen=True)
class DetectionSettings:
    """
    All thresholds the detector uses, bundled in one object.

    Defaults come from config.py. Tests can pass different values, e.g.
    DetectionSettings(port_scan_distinct_port_limit=3), without editing config.
    This is called "dependency injection": the detector receives its settings
    instead of reaching out to grab them itself.
    """

    port_scan_distinct_port_limit: int = config.PORT_SCAN_DISTINCT_PORT_LIMIT
    port_scan_window_seconds: float = config.PORT_SCAN_WINDOW_SECONDS
    syn_flood_packet_limit: int = config.SYN_FLOOD_PACKET_LIMIT
    syn_flood_window_seconds: float = config.SYN_FLOOD_WINDOW_SECONDS
    icmp_flood_packet_limit: int = config.ICMP_FLOOD_PACKET_LIMIT
    icmp_flood_window_seconds: float = config.ICMP_FLOOD_WINDOW_SECONDS


class SlidingWindowCounter:
    """
    Counts how many events each key (e.g. each IP) had in the last N seconds.

    For every key we keep a deque (double-ended queue) of event timestamps,
    oldest on the left. New events are appended on the right; events older
    than the window fall off the left. The deque length is the count.
    """

    def __init__(self, window_seconds: float) -> None:
        """Create a counter whose window is `window_seconds` long."""
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than 0")
        self.window_seconds = window_seconds
        # defaultdict(deque): looking up a new key automatically creates an empty deque.
        self._timestamps_by_key: dict[str, deque[float]] = defaultdict(deque)

    def add_event(self, key: str, timestamp: float) -> int:
        """Record one event for `key` and return how many events it has inside the window."""
        timestamps = self._timestamps_by_key[key]
        timestamps.append(timestamp)
        self._evict_expired(timestamps, now=timestamp)
        return len(timestamps)

    def _evict_expired(self, timestamps: deque[float], now: float) -> None:
        """Drop timestamps that are older than the window, starting from the oldest."""
        cutoff = now - self.window_seconds
        # The deque is in time order, so we only ever need to look at the left end.
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()  # O(1) for a deque (a list would be O(n))

    def purge_stale_keys(self, now: float) -> None:
        """Delete keys whose events have all expired, so memory doesn't grow forever."""
        # list(...) copies the keys, because we can't delete from a dict while looping over it.
        for key in list(self._timestamps_by_key):
            timestamps = self._timestamps_by_key[key]
            self._evict_expired(timestamps, now)
            if not timestamps:
                del self._timestamps_by_key[key]

    def tracked_key_count(self) -> int:
        """Return how many keys currently hold data (useful for tests and debugging)."""
        return len(self._timestamps_by_key)


class SlidingWindowDistinctCounter:
    """
    Counts how many DIFFERENT values each key had in the last N seconds.

    Used for port scans: key = source IP, value = destination port.
    Besides the deque of (timestamp, value) pairs, we keep a Counter of how
    often each value appears in the window. The number of entries in that
    Counter is the number of distinct values, available in O(1) time.
    """

    def __init__(self, window_seconds: float) -> None:
        """Create a distinct-value counter whose window is `window_seconds` long."""
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than 0")
        self.window_seconds = window_seconds
        self._events_by_key: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._value_counts_by_key: dict[str, Counter[int]] = defaultdict(Counter)

    def add_event(self, key: str, timestamp: float, value: int) -> int:
        """Record `value` for `key` and return how many distinct values it has inside the window."""
        events = self._events_by_key[key]
        value_counts = self._value_counts_by_key[key]

        events.append((timestamp, value))
        value_counts[value] += 1

        self._evict_expired(events, value_counts, now=timestamp)
        return len(value_counts)

    def _evict_expired(
        self, events: deque[tuple[float, int]], value_counts: Counter[int], now: float
    ) -> None:
        """Drop expired events and keep the per-value Counter in sync."""
        cutoff = now - self.window_seconds
        while events and events[0][0] <= cutoff:
            _, expired_value = events.popleft()
            value_counts[expired_value] -= 1
            if value_counts[expired_value] == 0:
                del value_counts[expired_value]  # value no longer in the window

    def purge_stale_keys(self, now: float) -> None:
        """Delete keys whose events have all expired."""
        for key in list(self._events_by_key):
            events = self._events_by_key[key]
            self._evict_expired(events, self._value_counts_by_key[key], now)
            if not events:
                del self._events_by_key[key]
                del self._value_counts_by_key[key]

    def tracked_key_count(self) -> int:
        """Return how many keys currently hold data."""
        return len(self._events_by_key)


class IntrusionDetector:
    """
    Applies all 4 detection rules to each packet.

    Usage:
        detector = IntrusionDetector(blacklisted_ips=config.load_blacklist())
        alerts = detector.inspect(packet_info)   # list, usually empty
    """

    def __init__(
        self,
        blacklisted_ips: Optional[set[str]] = None,
        settings: Optional[DetectionSettings] = None,
    ) -> None:
        """Set up the rule trackers. Both arguments are optional for easy testing."""
        self.settings = settings or DetectionSettings()
        # frozenset = read-only set: the blacklist can't be changed by accident at runtime.
        self.blacklisted_ips: frozenset[str] = frozenset(blacklisted_ips or ())

        self._port_scan_tracker = SlidingWindowDistinctCounter(self.settings.port_scan_window_seconds)
        self._syn_flood_tracker = SlidingWindowCounter(self.settings.syn_flood_window_seconds)
        self._icmp_flood_tracker = SlidingWindowCounter(self.settings.icmp_flood_window_seconds)

        self._last_purge_timestamp: Optional[float] = None
        self.packets_inspected: int = 0  # simple statistic shown later on shutdown

        # The list of rule methods. Adding a 5th rule = write one method + add it here.
        self._rules: tuple[Callable[[PacketInfo], Optional[Alert]], ...] = (
            self._check_blacklist,
            self._check_port_scan,
            self._check_syn_flood,
            self._check_icmp_flood,
        )

    def inspect(self, packet: PacketInfo) -> list[Alert]:
        """Run every rule against one packet and return the alerts it triggered."""
        self.packets_inspected += 1

        alerts: list[Alert] = []
        for rule in self._rules:
            alert = rule(packet)
            if alert is not None:
                alerts.append(alert)

        self._purge_stale_data_if_due(packet.timestamp)
        return alerts

    # ------------------------------------------------------------------
    # Helper checks
    # ------------------------------------------------------------------
    @staticmethod
    def _is_connection_attempt(packet: PacketInfo) -> bool:
        """
        True if the packet is a TCP SYN without ACK, i.e. the FIRST step of
        the 3-way handshake ("I want to connect").

        We check `"S" in flags and "A" not in flags` instead of `flags == "S"`
        because some SYNs carry extra flags (e.g. "SEC" for ECN), and SYN-ACK
        replies ("SA") must NOT be counted as connection attempts.
        """
        return (
            packet.protocol == "TCP"
            and "S" in packet.tcp_flags
            and "A" not in packet.tcp_flags
        )

    # ------------------------------------------------------------------
    # Rule 4: Blacklisted IP  (signature-based)
    # ------------------------------------------------------------------
    def _check_blacklist(self, packet: PacketInfo) -> Optional[Alert]:
        """Alert if the packet's source IP is on the blacklist."""
        if packet.source_ip not in self.blacklisted_ips:  # O(1) set lookup
            return None
        return Alert(
            timestamp=packet.timestamp,
            attack_type=AttackType.BLACKLISTED_IP,
            severity=Severity.HIGH,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            description=(
                f"Traffic from blacklisted IP {packet.source_ip} "
                f"to {packet.destination_ip} ({packet.protocol})"
            ),
        )

    # ------------------------------------------------------------------
    # Rule 1: Port Scan  (threshold-based)
    # ------------------------------------------------------------------
    def _check_port_scan(self, packet: PacketInfo) -> Optional[Alert]:
        """Alert if one source IP tries too many different ports within the window."""
        if not self._is_connection_attempt(packet) or packet.destination_port is None:
            return None

        distinct_port_count = self._port_scan_tracker.add_event(
            key=packet.source_ip,
            timestamp=packet.timestamp,
            value=packet.destination_port,
        )
        limit = self.settings.port_scan_distinct_port_limit
        if distinct_port_count <= limit:
            return None

        return Alert(
            timestamp=packet.timestamp,
            attack_type=AttackType.PORT_SCAN,
            severity=Severity.MEDIUM,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            description=(
                f"{packet.source_ip} tried {distinct_port_count} different ports in the last "
                f"{self.settings.port_scan_window_seconds:g}s (limit {limit})"
            ),
        )

    # ------------------------------------------------------------------
    # Rule 2: SYN Flood  (threshold-based)
    # ------------------------------------------------------------------
    def _check_syn_flood(self, packet: PacketInfo) -> Optional[Alert]:
        """Alert if one source IP sends too many SYNs to the SAME destination port."""
        if not self._is_connection_attempt(packet):
            return None

        # Key includes the target port, so a port scan (many ports, 1 SYN each)
        # does NOT also trigger this rule. Flood = hammering ONE service.
        flood_key = f"{packet.source_ip}->{packet.destination_ip}:{packet.destination_port}"
        syn_count = self._syn_flood_tracker.add_event(flood_key, packet.timestamp)
        limit = self.settings.syn_flood_packet_limit
        if syn_count <= limit:
            return None

        return Alert(
            timestamp=packet.timestamp,
            attack_type=AttackType.SYN_FLOOD,
            severity=Severity.HIGH,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            description=(
                f"{packet.source_ip} sent {syn_count} SYN packets to "
                f"{packet.destination_ip}:{packet.destination_port} in the last "
                f"{self.settings.syn_flood_window_seconds:g}s (limit {limit})"
            ),
        )

    # ------------------------------------------------------------------
    # Rule 3: ICMP Flood  (threshold-based)
    # ------------------------------------------------------------------
    def _check_icmp_flood(self, packet: PacketInfo) -> Optional[Alert]:
        """Alert if one source IP sends too many ping (echo request) packets."""
        if packet.protocol != "ICMP" or packet.icmp_type != ICMP_ECHO_REQUEST_TYPE:
            return None

        ping_count = self._icmp_flood_tracker.add_event(packet.source_ip, packet.timestamp)
        limit = self.settings.icmp_flood_packet_limit
        if ping_count <= limit:
            return None

        return Alert(
            timestamp=packet.timestamp,
            attack_type=AttackType.ICMP_FLOOD,
            severity=Severity.MEDIUM,
            source_ip=packet.source_ip,
            destination_ip=packet.destination_ip,
            description=(
                f"{packet.source_ip} sent {ping_count} ping requests in the last "
                f"{self.settings.icmp_flood_window_seconds:g}s (limit {limit})"
            ),
        )

    # ------------------------------------------------------------------
    # Memory housekeeping
    # ------------------------------------------------------------------
    def _purge_stale_data_if_due(self, now: float) -> None:
        """Every STALE_DATA_PURGE_INTERVAL_SECONDS, drop counters for IPs that went quiet."""
        if self._last_purge_timestamp is None:
            self._last_purge_timestamp = now
            return
        if now - self._last_purge_timestamp < STALE_DATA_PURGE_INTERVAL_SECONDS:
            return

        self._port_scan_tracker.purge_stale_keys(now)
        self._syn_flood_tracker.purge_stale_keys(now)
        self._icmp_flood_tracker.purge_stale_keys(now)
        self._last_purge_timestamp = now


# ======================================================================
# SELF-TEST DEMO  (python -m nids.detector)
# ======================================================================
def _run_self_test_demo() -> int:
    """
    Feed fake packets for 5 scenarios into a fresh detector and check that
    exactly the expected attack types are detected. Returns an exit code.
    """
    # Imported here (not at the top) because only the demo needs to BUILD packets.
    from nids.sniffer import PacketInfo

    def make_packet(timestamp: float, source_ip: str, **overrides: object) -> PacketInfo:
        """Build a fake PacketInfo with sensible defaults (a TCP SYN to port 80)."""
        packet_fields: dict[str, object] = {
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
        packet_fields.update(overrides)
        return PacketInfo(**packet_fields)  # type: ignore[arg-type]

    base_time = time.time()
    detector = IntrusionDetector(blacklisted_ips={"203.0.113.77"})

    # Each scenario: (name, packets, expected attack types).
    # Scenarios are 100 s apart and use different IPs so they don't affect each other.
    scenarios: list[tuple[str, list[PacketInfo], set[AttackType]]] = [
        (
            "Normal browsing",
            [make_packet(base_time + second, "10.0.0.5",
                         destination_port=443 if second % 2 else 80)
             for second in range(10)],
            set(),
        ),
        (
            "Port scan (20 ports)",
            [make_packet(base_time + 100 + index * 0.05, "10.0.0.66",
                         destination_port=20 + index)
             for index in range(20)],
            {AttackType.PORT_SCAN},
        ),
        (
            "SYN flood (150 SYNs)",
            [make_packet(base_time + 200 + index * 0.01, "10.0.0.77")
             for index in range(150)],
            {AttackType.SYN_FLOOD},
        ),
        (
            "ICMP flood (60 pings)",
            [make_packet(base_time + 300 + index * 0.02, "10.0.0.88",
                         protocol="ICMP", source_port=None, destination_port=None,
                         tcp_flags="", icmp_type=ICMP_ECHO_REQUEST_TYPE)
             for index in range(60)],
            {AttackType.ICMP_FLOOD},
        ),
        (
            "Blacklisted source",
            [make_packet(base_time + 400, "203.0.113.77",
                         protocol="UDP", destination_port=53, tcp_flags="")],
            {AttackType.BLACKLISTED_IP},
        ),
    ]

    print("=== Detection engine self-test (fake packets, no network needed) ===\n")
    all_passed = True

    for scenario_name, packets, expected_types in scenarios:
        scenario_alerts: list[Alert] = []
        for packet in packets:
            scenario_alerts.extend(detector.inspect(packet))

        detected_types = {alert.attack_type for alert in scenario_alerts}
        passed = detected_types == expected_types
        all_passed = all_passed and passed

        expected_text = ", ".join(sorted(expected_types)) or "none"
        detected_text = ", ".join(sorted(detected_types)) or "none"
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {scenario_name:<22} expected: {expected_text:<15} "
              f"got: {detected_text} ({len(scenario_alerts)} alerts)")
        if scenario_alerts:
            print(f"       first alert -> {scenario_alerts[0].description}")

    print(f"\nPackets inspected: {detector.packets_inspected}")
    print("RESULT:", "ALL SCENARIOS PASSED" if all_passed else "SOME SCENARIOS FAILED")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(_run_self_test_demo())
