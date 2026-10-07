"""
dashboard/app.py
----------------
A web dashboard that turns logs/alerts.csv into a live visual report.

WHY STREAMLIT:
    Streamlit converts a plain Python script into a web app. We get tables,
    charts, filters and auto-refresh WITHOUT writing any HTML, CSS or
    JavaScript. For a beginner project this is far less code than Flask + a
    frontend.

RUN IT (a NORMAL Anaconda Prompt is fine; the dashboard only READS a file,
so it does NOT need Administrator rights), from the project root:
    streamlit run dashboard/app.py

Then open the URL it prints (usually http://localhost:8501) in your browser.

DESIGN NOTE:
    All data crunching lives in small, pure functions (load_alerts,
    summarise_alerts, ...) that take data in and return data out. They are
    unit-tested in tests/test_dashboard.py. Only render_dashboard() touches
    Streamlit. This keeps the logic testable and the Streamlit code thin.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

# Allow "from nids import config" to work when Streamlit runs this file directly.
# Streamlit does not run the file as part of a package, so the project root is
# not on the import path by default; we add it here.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from nids import config  # noqa: E402  (import after sys.path tweak, on purpose)

# The exact columns we expect in alerts.csv (must match alert_manager.CSV_COLUMNS).
EXPECTED_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "attack_type",
    "severity",
    "source_ip",
    "destination_ip",
    "description",
)


@dataclass(frozen=True)
class AlertSummary:
    """A small bundle of headline numbers shown in the dashboard's metric cards."""

    total_alerts: int
    high_severity: int
    unique_source_ips: int
    most_common_attack: str


def load_alerts(csv_file: Path = config.ALERTS_CSV_FILE) -> pd.DataFrame:
    """
    Read alerts.csv into a pandas DataFrame (a table in memory).

    Returns an EMPTY DataFrame (with the right columns) if the file is missing
    or empty, so the rest of the code can treat "no data yet" like any other
    case instead of crashing.
    """
    empty_table = pd.DataFrame(columns=list(EXPECTED_COLUMNS))

    if not csv_file.exists() or csv_file.stat().st_size == 0:
        return empty_table

    try:
        alerts_table = pd.read_csv(csv_file)
    except pd.errors.EmptyDataError:
        # File had a header but no rows, or was mid-write when we read it.
        return empty_table

    # Guard against a malformed file: only keep rows if all expected columns exist.
    if not set(EXPECTED_COLUMNS).issubset(alerts_table.columns):
        return empty_table

    # Convert the timestamp text into real datetime objects so we can sort and
    # chart by time. errors="coerce" turns any unparseable value into NaT
    # (Not a Time) instead of raising, and we then drop those rows.
    alerts_table["timestamp"] = pd.to_datetime(alerts_table["timestamp"], errors="coerce")
    alerts_table = alerts_table.dropna(subset=["timestamp"])

    # Newest alerts first.
    return alerts_table.sort_values("timestamp", ascending=False).reset_index(drop=True)


def summarise_alerts(alerts_table: pd.DataFrame) -> AlertSummary:
    """Compute the headline numbers for the metric cards from the alerts table."""
    if alerts_table.empty:
        return AlertSummary(0, 0, 0, "-")

    total_alerts = len(alerts_table)
    high_severity = int((alerts_table["severity"] == "HIGH").sum())
    unique_source_ips = int(alerts_table["source_ip"].nunique())

    # value_counts() sorts attack types by frequency; idxmax() gives the top one.
    most_common_attack = str(alerts_table["attack_type"].value_counts().idxmax())

    return AlertSummary(total_alerts, high_severity, unique_source_ips, most_common_attack)


def count_by_column(alerts_table: pd.DataFrame, column_name: str) -> pd.DataFrame:
    """
    Count how many alerts fall into each value of a column, for bar charts.

    Example: count_by_column(table, "attack_type") ->
        attack_type | count
        SYN Flood   |   5
        Port Scan   |   2
    """
    if alerts_table.empty:
        return pd.DataFrame(columns=[column_name, "count"])

    counts = (
        alerts_table[column_name]
        .value_counts()
        .rename_axis(column_name)   # name the index column
        .reset_index(name="count")  # turn the Series into a 2-column table
    )
    return counts


def top_source_ips(alerts_table: pd.DataFrame, limit: int = 10) -> pd.DataFrame:
    """Return the busiest attacker IPs and how many alerts each one caused."""
    if alerts_table.empty:
        return pd.DataFrame(columns=["source_ip", "count"])

    return (
        alerts_table["source_ip"]
        .value_counts()
        .head(limit)
        .rename_axis("source_ip")
        .reset_index(name="count")
    )


def filter_alerts(
    alerts_table: pd.DataFrame,
    attack_types: list[str] | None = None,
    severities: list[str] | None = None,
) -> pd.DataFrame:
    """
    Return only the rows matching the chosen attack types and severities.

    An empty or None filter means "no filtering on that field" (show all).
    """
    filtered = alerts_table
    if attack_types:
        filtered = filtered[filtered["attack_type"].isin(attack_types)]
    if severities:
        filtered = filtered[filtered["severity"].isin(severities)]
    return filtered


# ======================================================================
# Streamlit UI  (only this part imports / uses streamlit)
# ======================================================================
def render_dashboard() -> None:
    """Draw the whole dashboard. Called once per page refresh by Streamlit."""
    import streamlit as st  # imported here so the pure functions above need no Streamlit

    # ---- Page configuration (must be the first Streamlit call) ----
    st.set_page_config(page_title="NIDS Dashboard", page_icon="🛡️", layout="wide")

    st.title("🛡️ Network Intrusion Detection System - Dashboard")
    st.caption(f"Reading alerts from: {config.ALERTS_CSV_FILE}")

    # ---- Sidebar controls ----
    st.sidebar.header("Controls")
    auto_refresh = st.sidebar.checkbox("Auto-refresh every 5 seconds", value=False)
    if st.sidebar.button("Refresh now"):
        st.rerun()  # redraw immediately

    # Load the data fresh on every render, so new alerts appear on refresh.
    alerts_table = load_alerts()

    if alerts_table.empty:
        st.info(
            "No alerts recorded yet. Start the NIDS and run the attack simulator:\n\n"
            "1. `python -m nids.main --iface loopback` (as Administrator)\n"
            "2. `python -m scripts.attack_simulator all` (as Administrator)"
        )
        _maybe_auto_refresh(auto_refresh)
        return

    # ---- Sidebar filters (built from the data that actually exists) ----
    available_attacks = sorted(alerts_table["attack_type"].unique())
    available_severities = sorted(alerts_table["severity"].unique())
    chosen_attacks = st.sidebar.multiselect("Attack type", available_attacks, default=available_attacks)
    chosen_severities = st.sidebar.multiselect("Severity", available_severities, default=available_severities)

    visible_table = filter_alerts(alerts_table, chosen_attacks, chosen_severities)

    # ---- Metric cards ----
    summary = summarise_alerts(visible_table)
    column1, column2, column3, column4 = st.columns(4)
    column1.metric("Total alerts", summary.total_alerts)
    column2.metric("HIGH severity", summary.high_severity)
    column3.metric("Unique attacker IPs", summary.unique_source_ips)
    column4.metric("Most common attack", summary.most_common_attack)

    st.divider()

    # ---- Charts side by side ----
    left_chart, right_chart = st.columns(2)
    with left_chart:
        st.subheader("Alerts by attack type")
        attack_counts = count_by_column(visible_table, "attack_type")
        if not attack_counts.empty:
            # set_index makes the attack type the x-axis label of the bar chart.
            st.bar_chart(attack_counts.set_index("attack_type"))
    with right_chart:
        st.subheader("Top attacker IPs")
        ip_counts = top_source_ips(visible_table)
        if not ip_counts.empty:
            st.bar_chart(ip_counts.set_index("source_ip"))

    st.divider()

    # ---- Alerts over time ----
    st.subheader("Alerts over time")
    # Group alerts into 10-second buckets and count each bucket.
    over_time = (
        visible_table.set_index("timestamp")
        .resample("10s")       # one point per 10-second interval
        .size()                # number of alerts in each interval
        .rename("alerts")
    )
    if not over_time.empty:
        st.line_chart(over_time)

    st.divider()

    # ---- Full table (newest first), coloured by severity ----
    st.subheader(f"All alerts ({len(visible_table)} shown)")

    def _highlight_high(row: pd.Series) -> list[str]:
        """Give HIGH-severity rows a light-red background."""
        colour = "background-color: #ffe0e0" if row["severity"] == "HIGH" else ""
        return [colour] * len(row)

    st.dataframe(
        visible_table.style.apply(_highlight_high, axis=1),
        width="stretch",
        hide_index=True,
    )

    # ---- Download button ----
    st.download_button(
        "Download filtered alerts as CSV",
        data=visible_table.to_csv(index=False).encode("utf-8"),
        file_name="filtered_alerts.csv",
        mime="text/csv",
    )

    _maybe_auto_refresh(auto_refresh)


def _maybe_auto_refresh(enabled: bool) -> None:
    """If auto-refresh is on, wait 5 seconds and re-run the script."""
    if not enabled:
        return
    import time
    import streamlit as st

    time.sleep(5)
    st.rerun()


# Streamlit executes the whole file top to bottom on every run. We only draw
# the UI when Streamlit is actually running the app, detected via its runtime.
# This lets tests `import dashboard.app` to use the pure functions above
# WITHOUT launching (or needing) the Streamlit UI.
def _is_running_inside_streamlit() -> bool:
    """True only when this file is being served by `streamlit run`."""
    try:
        from streamlit.runtime import exists

        return exists()
    except Exception:  # noqa: BLE001 - if Streamlit isn't installed, we're not in it
        return False


if _is_running_inside_streamlit():
    render_dashboard()
