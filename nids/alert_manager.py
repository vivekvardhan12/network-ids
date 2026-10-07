"""
alert_manager.py
----------------
Alert handling layer of the NIDS.

RESPONSIBILITY (Single Responsibility Principle):
    Receive Alert objects from the detector and:
      1. Suppress duplicates using a cooldown per (attack type, source IP).
      2. Print new alerts to the console in colour (red = HIGH, yellow = MEDIUM).
      3. Write them to logs/nids.log (human-readable, auto-rotating).
      4. Append them to logs/alerts.csv (machine-readable, used by the dashboard).

    It does NOT decide what is an attack (detector.py) or capture packets (sniffer.py).

SELF-TEST (no admin rights or network needed), from the project root:
    python -m nids.alert_manager
"""

from __future__ import annotations

import csv                                        # writes alerts.csv safely (quoting, commas)
import logging                                    # standard logging framework
import sys
import tempfile                                   # temporary folder for the self-test
import time
from collections import Counter
from datetime import datetime
from logging.handlers import RotatingFileHandler  # log file that rolls over when it gets big
from pathlib import Path
from types import TracebackType
from typing import Iterable, Optional

# colorama makes ANSI colour codes work in the classic Windows console.
from colorama import Fore, Style, just_fix_windows_console

from nids import config
from nids.detector import Alert, AttackType, Severity

# Column order of alerts.csv. The dashboard (Module 7) relies on these names.
CSV_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "attack_type",
    "severity",
    "source_ip",
    "destination_ip",
    "description",
)

# Log rotation: when nids.log reaches ~1 MB it is renamed to nids.log.1 and a
# fresh file starts. At most 3 old files are kept, so logs can never fill the disk.
LOG_MAX_BYTES: int = 1_000_000
LOG_BACKUP_COUNT: int = 3

# Safety limit for the cooldown dictionary (protects memory during huge attacks
# from thousands of different IPs).
MAX_TRACKED_COOLDOWN_KEYS: int = 10_000

# Map our severities onto standard logging levels.
SEVERITY_TO_LOG_LEVEL: dict[Severity, int] = {
    Severity.MEDIUM: logging.WARNING,
    Severity.HIGH: logging.ERROR,
}

# Map our severities onto console colours.
SEVERITY_TO_COLOUR: dict[Severity, str] = {
    Severity.MEDIUM: Fore.YELLOW,
    Severity.HIGH: Fore.RED,
}

LOGGER_NAME: str = "nids.alerts"


def format_timestamp(epoch_seconds: float) -> str:
    """Convert epoch seconds to local time text like '2026-10-08 10:15:02'."""
    return datetime.fromtimestamp(epoch_seconds).strftime("%Y-%m-%d %H:%M:%S")


def build_file_logger(log_file: Path) -> logging.Logger:
    """
    Create (or re-create) the NIDS file logger.

    Any handlers left over from an earlier AlertManager are removed first,
    so lines are never written twice. Only one AlertManager should be active
    at a time in a process.
    """
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False  # don't also send our lines to Python's root logger

    for old_handler in list(logger.handlers):
        logger.removeHandler(old_handler)
        old_handler.close()

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    # Example line: 2026-10-08 10:15:02 | ERROR    | SYN Flood | HIGH | 10.0.0.77 -> 10.0.0.1 | ...
    file_handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.addHandler(file_handler)
    return logger


class AlertManager:
    """
    Deduplicates alerts and records them to console, log file and CSV.

    Usage:
        with AlertManager() as alert_manager:
            alert_manager.handle(alert)

    The `with` block guarantees the log file is closed properly at the end.
    """

    def __init__(
        self,
        alerts_csv_file: Path = config.ALERTS_CSV_FILE,
        log_file: Path = config.LOG_FILE,
        cooldown_seconds: float = config.ALERT_COOLDOWN_SECONDS,
        print_to_console: bool = True,
        use_colours: bool = True,
    ) -> None:
        """Prepare output files, the logger and the cooldown memory."""
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds cannot be negative")

        self.alerts_csv_file = Path(alerts_csv_file)
        self.log_file = Path(log_file)
        self.cooldown_seconds = cooldown_seconds
        self.print_to_console = print_to_console
        # Only colour real terminals; if output is redirected to a file, colour codes are junk.
        self.use_colours = use_colours and sys.stdout.isatty()

        # Make sure the logs/ folder exists before anything tries to write there.
        self.alerts_csv_file.parent.mkdir(parents=True, exist_ok=True)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        if self.use_colours:
            just_fix_windows_console()  # enables colour support on older Windows consoles

        self._logger = build_file_logger(self.log_file)

        # (attack type, source IP) -> timestamp of the last alert we RECORDED for that pair.
        self._last_recorded_time: dict[tuple[AttackType, str], float] = {}

        # Statistics for the shutdown summary.
        self.alerts_recorded: int = 0
        self.alerts_suppressed: int = 0
        self.recorded_by_type: Counter[AttackType] = Counter()

    # ------------------------------------------------------------------
    # Context manager support:  with AlertManager() as manager: ...
    # ------------------------------------------------------------------
    def __enter__(self) -> AlertManager:
        """Called at the start of a `with` block; returns the manager itself."""
        return self

    def __exit__(
        self,
        exception_type: Optional[type[BaseException]],
        exception: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        """Called when the `with` block ends, even after an error: close files."""
        self.close()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def handle(self, alert: Alert) -> bool:
        """
        Process one alert.

        Returns:
            True  if the alert was new and got recorded,
            False if it was a duplicate inside the cooldown and was suppressed.
        """
        if self._is_in_cooldown(alert):
            self.alerts_suppressed += 1
            return False

        self._last_recorded_time[(alert.attack_type, alert.source_ip)] = alert.timestamp
        self._purge_old_cooldowns_if_needed(alert.timestamp)

        self.alerts_recorded += 1
        self.recorded_by_type[alert.attack_type] += 1

        self._print_alert(alert)
        self._write_log(alert)
        self._append_csv(alert)
        return True

    def handle_many(self, alerts: Iterable[Alert]) -> int:
        """Process several alerts; return how many were actually recorded."""
        return sum(1 for alert in alerts if self.handle(alert))

    def log_info(self, message: str) -> None:
        """Record a normal (non-alert) event such as 'NIDS started' in log and console."""
        self._logger.info(message)
        if self.print_to_console:
            print(f"[nids] {message}", flush=True)

    def summary_lines(self) -> list[str]:
        """Build human-readable summary lines about everything handled so far."""
        lines = [
            f"Alerts recorded   : {self.alerts_recorded}",
            f"Alerts suppressed : {self.alerts_suppressed} (duplicates inside the cooldown)",
        ]
        for attack_type, count in self.recorded_by_type.most_common():
            lines.append(f"  - {attack_type}: {count}")
        return lines

    def print_summary(self) -> None:
        """Write the summary to the console and the log file."""
        for line in self.summary_lines():
            self.log_info(line)

    def close(self) -> None:
        """Flush and close the log file (important on Windows, where open files are locked)."""
        for handler in list(self._logger.handlers):
            handler.flush()
            handler.close()
            self._logger.removeHandler(handler)

    # ------------------------------------------------------------------
    # Cooldown logic
    # ------------------------------------------------------------------
    def _is_in_cooldown(self, alert: Alert) -> bool:
        """True if the same attack from the same IP was recorded less than cooldown_seconds ago."""
        last_time = self._last_recorded_time.get((alert.attack_type, alert.source_ip))
        if last_time is None:
            return False
        return (alert.timestamp - last_time) < self.cooldown_seconds

    def _purge_old_cooldowns_if_needed(self, now: float) -> None:
        """If the cooldown dict gets very large, drop entries whose cooldown has expired."""
        if len(self._last_recorded_time) <= MAX_TRACKED_COOLDOWN_KEYS:
            return
        self._last_recorded_time = {
            key: recorded_time
            for key, recorded_time in self._last_recorded_time.items()
            if now - recorded_time < self.cooldown_seconds
        }

    # ------------------------------------------------------------------
    # Output channels
    # ------------------------------------------------------------------
    def _print_alert(self, alert: Alert) -> None:
        """Print one alert line, coloured by severity when the terminal supports it."""
        if not self.print_to_console:
            return
        clock_time = datetime.fromtimestamp(alert.timestamp).strftime("%H:%M:%S")
        line = f"[ALERT] {clock_time} [{alert.severity}] {alert.attack_type}: {alert.description}"
        if self.use_colours:
            line = f"{SEVERITY_TO_COLOUR[alert.severity]}{Style.BRIGHT}{line}{Style.RESET_ALL}"
        print(line, flush=True)  # flush=True shows it immediately, no buffering delay

    def _write_log(self, alert: Alert) -> None:
        """Write one alert line to nids.log at a level matching its severity."""
        # %s placeholders: the logging module formats the text only if the line is actually written.
        self._logger.log(
            SEVERITY_TO_LOG_LEVEL[alert.severity],
            "%s | %s | %s -> %s | %s",
            alert.attack_type,
            alert.severity,
            alert.source_ip,
            alert.destination_ip,
            alert.description,
        )

    def _append_csv(self, alert: Alert) -> None:
        """Append one alert row to alerts.csv, writing the header if the file is new or empty."""
        row = {
            "timestamp": format_timestamp(alert.timestamp),
            "attack_type": str(alert.attack_type),
            "severity": str(alert.severity),
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "description": alert.description,
        }
        try:
            needs_header = (
                not self.alerts_csv_file.exists() or self.alerts_csv_file.stat().st_size == 0
            )
            # newline="" is required by the csv module to avoid blank lines on Windows.
            with self.alerts_csv_file.open("a", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
                if needs_header:
                    writer.writeheader()
                writer.writerow(row)
        except OSError as error:
            # Most common cause on Windows: alerts.csv is open in Excel, which locks it.
            # The alert is still in the console and the log, so we warn and carry on.
            warning = f"Could not write to {self.alerts_csv_file} ({error}). Is it open in Excel?"
            self._logger.error(warning)
            if self.print_to_console:
                print(f"[nids] WARNING: {warning}", flush=True)


# ======================================================================
# SELF-TEST DEMO  (python -m nids.alert_manager)
# ======================================================================
def _run_self_test_demo() -> int:
    """
    Send 53 fake alerts through an AlertManager that writes into a temporary
    folder (so your real logs stay clean) and verify the cooldown works.
    Returns an exit code (0 = all checks passed).
    """
    print("=== Alert manager self-test (temporary files, no network needed) ===\n")
    base_time = time.time()

    def make_alert(offset_seconds: float, attack_type: AttackType,
                   severity: Severity, source_ip: str) -> Alert:
        """Build a fake alert `offset_seconds` after the base time."""
        return Alert(
            timestamp=base_time + offset_seconds,
            attack_type=attack_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip="10.0.0.1",
            description=f"demo {attack_type} from {source_ip}",
        )

    # 50 identical SYN-flood alerts within 0.5 s -> expect 1 recorded, 49 suppressed.
    demo_alerts = [
        make_alert(index * 0.01, AttackType.SYN_FLOOD, Severity.HIGH, "10.0.0.77")
        for index in range(50)
    ]
    # Same IP, DIFFERENT attack type -> separate cooldown -> recorded.
    demo_alerts.append(make_alert(0.6, AttackType.PORT_SCAN, Severity.MEDIUM, "10.0.0.77"))
    # Same pair again but 31 s later (cooldown is 30 s) -> recorded again.
    demo_alerts.append(make_alert(31.0, AttackType.SYN_FLOOD, Severity.HIGH, "10.0.0.77"))
    # Different source IP -> separate cooldown -> recorded.
    demo_alerts.append(make_alert(31.5, AttackType.SYN_FLOOD, Severity.HIGH, "10.0.0.99"))

    # ignore_cleanup_errors avoids rare Windows "file in use" errors when deleting the temp folder.
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temporary_folder:
        csv_path = Path(temporary_folder) / "alerts.csv"
        log_path = Path(temporary_folder) / "nids.log"

        with AlertManager(csv_path, log_path, cooldown_seconds=30.0) as alert_manager:
            alert_manager.handle_many(demo_alerts)
            print()
            alert_manager.print_summary()
            recorded = alert_manager.alerts_recorded
            suppressed = alert_manager.alerts_suppressed

        with csv_path.open("r", newline="", encoding="utf-8") as csv_file:
            csv_rows = list(csv.DictReader(csv_file))
        alert_log_lines = [
            line for line in log_path.read_text(encoding="utf-8").splitlines() if "->" in line
        ]

        print("\n--- alerts.csv contents ---")
        print(csv_path.read_text(encoding="utf-8").strip())

    checks = [
        ("4 alerts recorded", recorded == 4),
        ("49 duplicates suppressed", suppressed == 49),
        ("4 rows in alerts.csv", len(csv_rows) == 4),
        ("4 alert lines in nids.log", len(alert_log_lines) == 4),
        ("CSV header matches CSV_COLUMNS", bool(csv_rows) and tuple(csv_rows[0].keys()) == CSV_COLUMNS),
    ]
    print("\n--- checks ---")
    for check_name, passed in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {check_name}")

    all_passed = all(passed for _, passed in checks)
    print("\nRESULT:", "ALL CHECKS PASSED" if all_passed else "SOME CHECKS FAILED")
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(_run_self_test_demo())
