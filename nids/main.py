"""
main.py
-------
Entry point of the NIDS: connects  sniffer -> detector -> alert manager.

RESPONSIBILITY:
    This file contains almost no logic of its own. Its job is "composition":
    create each component, connect them together, start capturing, and shut
    everything down cleanly when the user presses Ctrl+C.

RUN (ADMINISTRATOR Anaconda Prompt, from the project root):
    python -m nids.main                    # interface from config.py (loopback)
    python -m nids.main --iface Wi-Fi      # watch real Wi-Fi traffic
    python -m nids.main --show-packets     # also print every packet (debugging)
    python -m nids.main --help             # list all options
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Optional

from scapy.error import Scapy_Exception

from nids import __version__, config
from nids.alert_manager import AlertManager
from nids.detector import DetectionSettings, IntrusionDetector
from nids.sniffer import PacketInfo, format_packet_info, is_running_as_admin, start_sniffing

# How often (in seconds of packet time) to print a "still running" status line.
STATUS_INTERVAL_SECONDS: float = 60.0


class NidsRunner:
    """
    The glue between the components.

    Scapy calls `process_packet` for every captured packet. The runner passes
    the packet to the detector and any resulting alerts to the alert manager.
    Keeping this in a small class (instead of loose global variables) makes it
    easy to test with fake packets.
    """

    def __init__(
        self,
        detector: IntrusionDetector,
        alert_manager: AlertManager,
        show_packets: bool = False,
        status_interval_seconds: float = STATUS_INTERVAL_SECONDS,
    ) -> None:
        """Store the components this runner connects."""
        self.detector = detector
        self.alert_manager = alert_manager
        self.show_packets = show_packets
        self.status_interval_seconds = status_interval_seconds
        self._last_status_time: Optional[float] = None

    def process_packet(self, packet: PacketInfo) -> None:
        """Handle ONE packet: optionally print it, detect, record alerts, maybe print status."""
        if self.show_packets:
            print(format_packet_info(packet), flush=True)

        alerts = self.detector.inspect(packet)
        if alerts:  # most packets produce no alerts, so skip the call in that case
            self.alert_manager.handle_many(alerts)

        self._report_status_if_due(packet.timestamp)

    def _report_status_if_due(self, now: float) -> None:
        """Print a heartbeat line every status interval so you can see the NIDS is alive."""
        if self.status_interval_seconds <= 0:
            return  # status lines disabled
        if self._last_status_time is None:
            self._last_status_time = now
            return
        if now - self._last_status_time < self.status_interval_seconds:
            return

        self._last_status_time = now
        self.alert_manager.log_info(
            f"Still running: {self.detector.packets_inspected} packets inspected, "
            f"{self.alert_manager.alerts_recorded} alerts recorded"
        )


def _build_argument_parser() -> argparse.ArgumentParser:
    """Define the command-line options of the NIDS."""
    parser = argparse.ArgumentParser(
        prog="python -m nids.main",
        description="Network Intrusion Detection System - detects port scans, "
        "SYN floods, ICMP floods and blacklisted IPs.",
    )
    parser.add_argument(
        "--iface",
        default=config.INTERFACE,
        help=f"Interface to watch: 'loopback', 'Wi-Fi', or a name from conf.ifaces "
        f"(default: {config.INTERFACE!r})",
    )
    parser.add_argument(
        "--filter",
        default=config.CAPTURE_FILTER,
        help=f"BPF capture filter (default: {config.CAPTURE_FILTER!r})",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Stop after this many packets; 0 = run until Ctrl+C (default: 0)",
    )
    parser.add_argument(
        "--show-packets",
        action="store_true",  # flag with no value: present = True, absent = False
        help="Also print every captured packet (noisy; useful for debugging)",
    )
    return parser


def _print_banner(interface_name: str, capture_filter: str,
                  blacklist_size: int, settings: DetectionSettings) -> None:
    """Print a start-up summary so you can confirm the active settings at a glance."""
    print("=" * 66)
    print(f" Network Intrusion Detection System  v{__version__}")
    print("=" * 66)
    print(f" Interface      : {interface_name}")
    print(f" Capture filter : {capture_filter or '(none)'}")
    print(f" Blacklist      : {blacklist_size} IP(s) from {config.BLACKLIST_FILE.name}")
    print(" Rules:")
    print(f"   Port Scan    : > {settings.port_scan_distinct_port_limit} ports "
          f"in {settings.port_scan_window_seconds:g}s")
    print(f"   SYN Flood    : > {settings.syn_flood_packet_limit} SYNs to one port "
          f"in {settings.syn_flood_window_seconds:g}s")
    print(f"   ICMP Flood   : > {settings.icmp_flood_packet_limit} pings "
          f"in {settings.icmp_flood_window_seconds:g}s")
    print(f" Alerts saved to: {config.ALERTS_CSV_FILE}")
    print(f" Log file       : {config.LOG_FILE}")
    print("=" * 66)
    print(" Watching traffic... press Ctrl+C to stop.\n", flush=True)


def main() -> int:
    """Start the NIDS and return a process exit code (0 = clean stop, 1 = error)."""
    parser = _build_argument_parser()
    arguments = parser.parse_args()
    if arguments.count < 0:
        parser.error("--count must be 0 or a positive number")

    config.ensure_directories()

    if not is_running_as_admin():
        print("[nids] WARNING: not running as Administrator. If capture fails, "
              "reopen Anaconda Prompt with 'Run as administrator'.\n")

    # --- Build the components (composition) ---------------------------------
    blacklisted_ips = config.load_blacklist()
    settings = DetectionSettings()
    detector = IntrusionDetector(blacklisted_ips=blacklisted_ips, settings=settings)

    exit_code = 0
    start_time = time.monotonic()  # a clock that never jumps (unaffected by clock changes)

    # `with` guarantees the log file is closed even if something crashes.
    with AlertManager() as alert_manager:
        runner = NidsRunner(detector, alert_manager, show_packets=arguments.show_packets)

        _print_banner(arguments.iface, arguments.filter, len(blacklisted_ips), settings)
        alert_manager.log_info(f"NIDS v{__version__} started on {arguments.iface!r}")

        # --- Run until Ctrl+C, --count is reached, or an error occurs -------
        try:
            start_sniffing(
                packet_handler=runner.process_packet,
                interface_name=arguments.iface,
                capture_filter=arguments.filter,
                packet_count=arguments.count,
            )
        except PermissionError:
            # Must come BEFORE OSError, because PermissionError is a subclass of OSError.
            print("[nids] Permission denied. Run Anaconda Prompt as Administrator.")
            exit_code = 1
        except (OSError, ValueError, Scapy_Exception) as error:
            print(f"[nids] Could not start capture on {arguments.iface!r}: {error}")
            print('[nids] List valid interfaces with: '
                  'python -c "from scapy.all import conf; print(conf.ifaces)"')
            exit_code = 1
        except KeyboardInterrupt:
            pass  # Ctrl+C is the normal way to stop

        # --- Clean shutdown summary --------------------------------------------
        runtime_seconds = time.monotonic() - start_time
        print()
        alert_manager.log_info(
            f"NIDS stopped after {runtime_seconds:.0f}s. "
            f"Packets inspected: {detector.packets_inspected}"
        )
        alert_manager.print_summary()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
