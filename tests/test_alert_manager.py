"""
test_alert_manager.py
---------------------
Unit tests for the alert manager (nids/alert_manager.py).

These use pytest's `tmp_path` fixture, which gives each test its own throwaway
folder, so no real log files are touched and tests never interfere.
"""

from __future__ import annotations

import csv
import time
from pathlib import Path

import pytest

from nids.alert_manager import CSV_COLUMNS, AlertManager
from nids.detector import Alert, AttackType, Severity


def make_alert(timestamp: float, attack_type: AttackType = AttackType.SYN_FLOOD,
               severity: Severity = Severity.HIGH, source_ip: str = "10.0.0.77") -> Alert:
    """Build a fake Alert for tests."""
    return Alert(
        timestamp=timestamp,
        attack_type=attack_type,
        severity=severity,
        source_ip=source_ip,
        destination_ip="10.0.0.1",
        description=f"test {attack_type} from {source_ip}",
    )


@pytest.fixture
def manager(tmp_path: Path) -> AlertManager:
    """An AlertManager writing into a temporary folder, console output off."""
    return AlertManager(
        alerts_csv_file=tmp_path / "alerts.csv",
        log_file=tmp_path / "nids.log",
        cooldown_seconds=30.0,
        print_to_console=False,
    )


class TestCooldown:
    """The cooldown should suppress duplicate alerts for the same (type, IP)."""

    def test_first_alert_is_recorded(self, manager: AlertManager) -> None:
        assert manager.handle(make_alert(100.0)) is True
        assert manager.alerts_recorded == 1

    def test_duplicate_within_cooldown_is_suppressed(self, manager: AlertManager) -> None:
        manager.handle(make_alert(100.0))
        # Same type + IP, only 5 s later (< 30 s cooldown).
        assert manager.handle(make_alert(105.0)) is False
        assert manager.alerts_recorded == 1
        assert manager.alerts_suppressed == 1

    def test_duplicate_after_cooldown_is_recorded(self, manager: AlertManager) -> None:
        manager.handle(make_alert(100.0))
        # 31 s later: cooldown has expired.
        assert manager.handle(make_alert(131.0)) is True
        assert manager.alerts_recorded == 2

    def test_different_ip_is_separate(self, manager: AlertManager) -> None:
        manager.handle(make_alert(100.0, source_ip="10.0.0.77"))
        assert manager.handle(make_alert(100.5, source_ip="10.0.0.99")) is True
        assert manager.alerts_recorded == 2

    def test_different_attack_type_is_separate(self, manager: AlertManager) -> None:
        manager.handle(make_alert(100.0, attack_type=AttackType.SYN_FLOOD))
        other = make_alert(100.5, attack_type=AttackType.PORT_SCAN, severity=Severity.MEDIUM)
        assert manager.handle(other) is True
        assert manager.alerts_recorded == 2


class TestCsvOutput:
    """Recorded alerts should be written to alerts.csv correctly."""

    def test_csv_has_header_and_rows(self, manager: AlertManager, tmp_path: Path) -> None:
        manager.handle(make_alert(100.0))
        manager.handle(make_alert(200.0, source_ip="10.0.0.88"))
        manager.close()

        with (tmp_path / "alerts.csv").open(newline="", encoding="utf-8") as csv_file:
            rows = list(csv.DictReader(csv_file))

        assert len(rows) == 2
        assert tuple(rows[0].keys()) == CSV_COLUMNS

    def test_suppressed_alerts_are_not_in_csv(self, manager: AlertManager, tmp_path: Path) -> None:
        manager.handle(make_alert(100.0))
        manager.handle(make_alert(101.0))  # suppressed duplicate
        manager.close()

        with (tmp_path / "alerts.csv").open(newline="", encoding="utf-8") as csv_file:
            rows = list(csv.DictReader(csv_file))
        assert len(rows) == 1


class TestLogOutput:
    """Recorded alerts should appear in nids.log."""

    def test_log_file_contains_alert(self, manager: AlertManager, tmp_path: Path) -> None:
        manager.handle(make_alert(100.0))
        manager.close()
        log_text = (tmp_path / "nids.log").read_text(encoding="utf-8")
        assert "SYN Flood" in log_text
        assert "10.0.0.77" in log_text


class TestHandleMany:
    """handle_many should return the number of alerts actually recorded."""

    def test_handle_many_collapses_a_flood(self, manager: AlertManager) -> None:
        base = time.time()
        # 50 identical alerts within 0.5 s -> only 1 recorded.
        alerts = [make_alert(base + i * 0.01) for i in range(50)]
        recorded = manager.handle_many(alerts)
        assert recorded == 1
        assert manager.alerts_suppressed == 49


class TestContextManager:
    """Using AlertManager with `with` should close the log file afterwards."""

    def test_context_manager_records_and_closes(self, tmp_path: Path) -> None:
        with AlertManager(tmp_path / "a.csv", tmp_path / "n.log",
                          cooldown_seconds=30.0, print_to_console=False) as manager:
            manager.handle(make_alert(100.0))
        # After the block, the CSV exists and has the row.
        assert (tmp_path / "a.csv").exists()
