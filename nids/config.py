"""
config.py
---------
Central configuration for the Network Intrusion Detection System (NIDS).

WHY THIS FILE EXISTS:
    Every value you might want to tweak (which network card to watch, how many
    packets count as an "attack", where log files go) lives HERE, in one place.
    Other modules import these values instead of hard-coding numbers.
    This is called "separating configuration from code".

HOW TO OVERRIDE THE INTERFACE WITHOUT EDITING THIS FILE (Anaconda Prompt):
    set NIDS_INTERFACE=Wi-Fi

QUICK CHECK (run from the project root):
    python -m nids.config
"""

from __future__ import annotations  # lets us use modern type hints such as set[str]

import ipaddress           # standard library: validates IPv4/IPv6 addresses
import os                  # standard library: reads environment variables
from pathlib import Path   # standard library: OS-independent file paths

# ======================================================================
# 1. PROJECT PATHS
# ======================================================================
# Path(__file__)            -> .../network-ids/nids/config.py
# .resolve()                -> converts it into a full absolute path
# .parent                   -> .../network-ids/nids
# .parent.parent            -> .../network-ids   (the project root)
BASE_DIR: Path = Path(__file__).resolve().parent.parent

DATA_DIR: Path = BASE_DIR / "data"   # input files we maintain (blacklist)
LOG_DIR: Path = BASE_DIR / "logs"    # output files the NIDS generates

BLACKLIST_FILE: Path = DATA_DIR / "blacklist.txt"  # one bad IP per line
ALERTS_CSV_FILE: Path = LOG_DIR / "alerts.csv"      # used in Module 4 + dashboard
LOG_FILE: Path = LOG_DIR / "nids.log"               # human-readable log (Module 4)

# ======================================================================
# 2. CAPTURE SETTINGS
# ======================================================================
# Which network interface (network card) to sniff on:
#   "loopback" -> traffic your PC sends to itself (127.0.0.1). Best for testing.
#   "Wi-Fi"    -> your real wireless traffic (use a name shown by conf.ifaces).
#   ""         -> empty string: let Scapy pick its default interface.
# os.getenv(NAME, DEFAULT) reads an environment variable, or uses DEFAULT if unset.
INTERFACE: str = os.getenv("NIDS_INTERFACE", "loopback")

# BPF (Berkeley Packet Filter) expression, applied INSIDE the Npcap driver.
# "ip" keeps only IPv4 packets, so junk (ARP, IPv6, etc.) never reaches Python.
# Filtering in the driver is much faster than filtering in Python.
CAPTURE_FILTER: str = os.getenv("NIDS_CAPTURE_FILTER", "ip")

# ======================================================================
# 3. DETECTION THRESHOLDS  (used by detector.py in Module 3)
# ======================================================================
# Rule 1 - Port Scan:
#   alert if ONE source IP touches MORE THAN this many DIFFERENT destination
#   ports inside the time window.
PORT_SCAN_DISTINCT_PORT_LIMIT: int = 15
PORT_SCAN_WINDOW_SECONDS: float = 10.0

# Rule 2 - SYN Flood:
#   alert if ONE source IP sends MORE THAN this many TCP SYN packets to the
#   SAME destination IP and port inside the time window.
#   (Counting per port keeps a port scan from also showing up as a SYN flood.)
SYN_FLOOD_PACKET_LIMIT: int = 100
SYN_FLOOD_WINDOW_SECONDS: float = 5.0

# Rule 3 - ICMP (ping) Flood:
#   alert if ONE source IP sends MORE THAN this many ICMP echo requests
#   inside the time window.
ICMP_FLOOD_PACKET_LIMIT: int = 50
ICMP_FLOOD_WINDOW_SECONDS: float = 5.0

# Rule 4 - Blacklisted IP: no threshold, a single packet is enough.

# ======================================================================
# 4. ALERT SETTINGS  (used by alert_manager.py in Module 4)
# ======================================================================
# After raising an alert for (attack type, attacker IP), stay quiet about that
# SAME pair for this many seconds. Prevents 1,000 identical alerts per attack.
ALERT_COOLDOWN_SECONDS: float = 30.0


def ensure_directories() -> None:
    """
    Create the data/ and logs/ folders if they do not exist yet.

    parents=True  -> also create any missing parent folders.
    exist_ok=True -> do NOT raise an error if the folder already exists.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def load_blacklist(file_path: Path = BLACKLIST_FILE) -> set[str]:
    """
    Read blacklisted IP addresses from a text file.

    File rules:
        - one IP address per line
        - anything after '#' is a comment and is ignored
        - blank lines are ignored
        - invalid IPs are skipped with a warning (one typo must not crash the NIDS)

    Args:
        file_path: location of the blacklist file (defaults to data/blacklist.txt).

    Returns:
        A set of normalised IP strings. We use a set (not a list) because
        "is this IP in the set?" takes O(1) time on average; a list needs O(n).
    """
    blacklisted_ips: set[str] = set()

    # A missing blacklist is not fatal: the other 3 rules still work.
    if not file_path.exists():
        print(f"[config] Blacklist not found at {file_path}. Using an empty blacklist.")
        return blacklisted_ips

    # encoding="utf-8" avoids Windows-specific encoding surprises.
    with file_path.open("r", encoding="utf-8") as blacklist_file:
        # enumerate(..., start=1) gives human-friendly line numbers for warnings.
        for line_number, raw_line in enumerate(blacklist_file, start=1):
            # Drop everything after '#', then strip spaces and the newline.
            cleaned_line = raw_line.split("#", 1)[0].strip()
            if not cleaned_line:
                continue  # blank or comment-only line

            try:
                # ip_address() raises ValueError for things like "999.1.1.1".
                validated_ip = ipaddress.ip_address(cleaned_line)
            except ValueError:
                print(f"[config] Skipping invalid IP on line {line_number}: {cleaned_line!r}")
                continue

            # str() normalises the format, e.g. IPv6 "::0001" becomes "::1".
            blacklisted_ips.add(str(validated_ip))

    return blacklisted_ips


def print_configuration_summary() -> None:
    """Print the active configuration. Handy for checking your setup quickly."""
    print("=== NIDS configuration ===")
    print(f"Project root        : {BASE_DIR}")
    print(f"Interface           : {INTERFACE or '(Scapy default)'}")
    print(f"Capture filter      : {CAPTURE_FILTER or '(none)'}")
    print(f"Blacklist file      : {BLACKLIST_FILE}")
    print(f"Alerts CSV          : {ALERTS_CSV_FILE}")
    print(f"Log file            : {LOG_FILE}")
    print(f"Port scan rule      : > {PORT_SCAN_DISTINCT_PORT_LIMIT} ports in {PORT_SCAN_WINDOW_SECONDS}s")
    print(f"SYN flood rule      : > {SYN_FLOOD_PACKET_LIMIT} SYNs in {SYN_FLOOD_WINDOW_SECONDS}s")
    print(f"ICMP flood rule     : > {ICMP_FLOOD_PACKET_LIMIT} pings in {ICMP_FLOOD_WINDOW_SECONDS}s")
    print(f"Alert cooldown      : {ALERT_COOLDOWN_SECONDS}s")
    loaded_ips = load_blacklist()
    print(f"Blacklisted IPs     : {len(loaded_ips)} -> {sorted(loaded_ips)}")


# This block runs ONLY when you execute the file directly
# (python -m nids.config), not when another module imports it.
if __name__ == "__main__":
    ensure_directories()
    print_configuration_summary()
