"""
test_config_and_dashboard.py
----------------------------
Unit tests for config.py (blacklist loading) and the dashboard's pure data
functions (dashboard/app.py). No Streamlit UI is launched.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

from nids import config

# Make the dashboard importable (it lives outside the nids package).
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from dashboard import app as dashboard  # noqa: E402


# ----------------------------------------------------------------------
# config.load_blacklist
# ----------------------------------------------------------------------
class TestLoadBlacklist:
    """The blacklist loader should parse valid IPs and skip junk."""

    def test_loads_valid_ips(self, tmp_path: Path) -> None:
        blacklist = tmp_path / "blacklist.txt"
        blacklist.write_text("192.0.2.1\n203.0.113.5\n", encoding="utf-8")
        result = config.load_blacklist(blacklist)
        assert result == {"192.0.2.1", "203.0.113.5"}

    def test_ignores_comments_and_blanks(self, tmp_path: Path) -> None:
        blacklist = tmp_path / "blacklist.txt"
        blacklist.write_text("# a comment\n\n192.0.2.1  # inline\n", encoding="utf-8")
        assert config.load_blacklist(blacklist) == {"192.0.2.1"}

    def test_skips_invalid_ips(self, tmp_path: Path) -> None:
        blacklist = tmp_path / "blacklist.txt"
        blacklist.write_text("192.0.2.1\n999.999.999.999\nnot-an-ip\n", encoding="utf-8")
        assert config.load_blacklist(blacklist) == {"192.0.2.1"}

    def test_missing_file_returns_empty_set(self, tmp_path: Path) -> None:
        assert config.load_blacklist(tmp_path / "nope.txt") == set()


# ----------------------------------------------------------------------
# Dashboard data functions
# ----------------------------------------------------------------------
SAMPLE_CSV = (
    "timestamp,attack_type,severity,source_ip,destination_ip,description\n"
    "2026-10-07 10:40:01,Port Scan,MEDIUM,127.0.0.1,127.0.0.1,tried 16 ports\n"
    "2026-10-07 10:40:35,SYN Flood,HIGH,127.0.0.1,127.0.0.1,sent 101 SYNs\n"
    "2026-10-07 10:41:08,SYN Flood,HIGH,10.0.0.99,10.0.0.1,sent 140 SYNs\n"
    "2026-10-07 10:41:20,Blacklisted IP,HIGH,203.0.113.77,127.0.0.1,blacklisted\n"
)


@pytest.fixture
def sample_csv(tmp_path: Path) -> Path:
    """Write a small sample alerts.csv and return its path."""
    csv_path = tmp_path / "alerts.csv"
    csv_path.write_text(SAMPLE_CSV, encoding="utf-8")
    return csv_path


class TestLoadAlerts:
    """load_alerts should read, parse and sort the CSV defensively."""

    def test_loads_all_rows(self, sample_csv: Path) -> None:
        table = dashboard.load_alerts(sample_csv)
        assert len(table) == 4

    def test_sorted_newest_first(self, sample_csv: Path) -> None:
        table = dashboard.load_alerts(sample_csv)
        assert str(table.iloc[0]["attack_type"]) == "Blacklisted IP"  # latest timestamp

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        table = dashboard.load_alerts(tmp_path / "nope.csv")
        assert table.empty
        assert list(table.columns) == list(dashboard.EXPECTED_COLUMNS)


class TestSummarise:
    """summarise_alerts should compute the headline numbers correctly."""

    def test_summary_numbers(self, sample_csv: Path) -> None:
        summary = dashboard.summarise_alerts(dashboard.load_alerts(sample_csv))
        assert summary.total_alerts == 4
        assert summary.high_severity == 3
        assert summary.unique_source_ips == 3
        assert summary.most_common_attack == "SYN Flood"

    def test_empty_summary(self) -> None:
        empty = pd.DataFrame(columns=list(dashboard.EXPECTED_COLUMNS))
        summary = dashboard.summarise_alerts(empty)
        assert summary.total_alerts == 0
        assert summary.most_common_attack == "-"


class TestFilterAndCount:
    """filter_alerts and the count helpers should behave as expected."""

    def test_filter_by_severity(self, sample_csv: Path) -> None:
        table = dashboard.load_alerts(sample_csv)
        high_only = dashboard.filter_alerts(table, severities=["HIGH"])
        assert len(high_only) == 3

    def test_filter_by_attack_type(self, sample_csv: Path) -> None:
        table = dashboard.load_alerts(sample_csv)
        syn_only = dashboard.filter_alerts(table, attack_types=["SYN Flood"])
        assert len(syn_only) == 2

    def test_count_by_column(self, sample_csv: Path) -> None:
        table = dashboard.load_alerts(sample_csv)
        counts = dashboard.count_by_column(table, "attack_type")
        syn_row = counts[counts["attack_type"] == "SYN Flood"]
        assert int(syn_row["count"].iloc[0]) == 2

    def test_top_source_ips(self, sample_csv: Path) -> None:
        table = dashboard.load_alerts(sample_csv)
        top = dashboard.top_source_ips(table)
        assert str(top.iloc[0]["source_ip"]) == "127.0.0.1"  # appears twice
        assert int(top.iloc[0]["count"]) == 2
