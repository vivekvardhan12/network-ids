"""
attack_simulator.py
-------------------
A SAFE testing tool that generates the four attack patterns the NIDS detects,
so you can confirm every rule fires without needing a second computer or any
real victim.

  python -m scripts.attack_simulator portscan
  python -m scripts.attack_simulator synflood
  python -m scripts.attack_simulator icmpflood
  python -m scripts.attack_simulator blacklist
  python -m scripts.attack_simulator all

HOW TO USE IT:
    1. Terminal 1 (ADMINISTRATOR):  python -m nids.main --iface loopback
    2. Terminal 2 (ADMINISTRATOR):  python -m scripts.attack_simulator all
    Watch the alerts appear in terminal 1.

=====================  SAFETY AND ETHICS  =====================
    * By default every attack targets 127.0.0.1 (THIS computer only).
      Loopback traffic never leaves your machine.
    * The script HARD-BLOCKS any target that is not a loopback address,
      unless you pass --i-own-this-target. Scanning or flooding a machine
      you do not own is illegal (in India, the IT Act 2000, sections 43 & 66).
    * These are low-rate simulations meant to cross detection thresholds,
      NOT real denial-of-service tools.
===============================================================

Sending crafted TCP/ICMP packets needs Administrator (Windows) / root rights,
the same as the sniffer.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import sys
import time

# We import specific Scapy pieces (not "import *") so it is clear what we use:
#   IP   - build the IPv4 layer          send - transmit packets
#   TCP  - build the TCP layer           RandShort - a random source port
#   ICMP - build a ping packet           conf - Scapy global settings
from scapy.all import ICMP, IP, TCP, RandShort, conf, send  # type: ignore[attr-defined]

from nids import config

# Default victim: this machine. Loopback traffic stays inside the computer.
DEFAULT_TARGET_IP: str = "127.0.0.1"

# Slightly exceed each rule's threshold so detection is reliable but quick.
# Thresholds are read from config so the two files can never drift apart.
PORT_SCAN_PORT_COUNT: int = config.PORT_SCAN_DISTINCT_PORT_LIMIT + 10   # default 25
SYN_FLOOD_PACKET_COUNT: int = config.SYN_FLOOD_PACKET_LIMIT + 40        # default 140
ICMP_FLOOD_PACKET_COUNT: int = config.ICMP_FLOOD_PACKET_LIMIT + 20      # default 70

# A spoofed source IP for the blacklist test. It is an RFC 5737 documentation
# address that is also listed in data/blacklist.txt, so no real host is affected.
BLACKLIST_TEST_SOURCE_IP: str = "203.0.113.77"


def is_loopback_address(ip_text: str) -> bool:
    """Return True if ip_text is a loopback address such as 127.0.0.1 or ::1."""
    try:
        return ipaddress.ip_address(ip_text).is_loopback
    except ValueError:
        return False


def simulate_port_scan(target_ip: str, port_count: int = PORT_SCAN_PORT_COUNT) -> None:
    """
    Rule 1: send ONE SYN each to many DIFFERENT ports on the target.

    This is exactly what a TCP "SYN scan" does: knock on many doors once each
    to see which services answer.
    """
    print(f"[portscan] Sending 1 SYN to each of {port_count} ports on {target_ip} ...")
    for port_number in range(1, port_count + 1):
        # IP(dst=...) / TCP(...) stacks a TCP layer on an IP layer ('/' = "on top of").
        # sport=RandShort() uses a random source port, like a real client.
        # flags="S" marks it as a SYN (connection request).
        packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port_number, flags="S")
        send(packet, verbose=False)   # verbose=False hides Scapy's own "Sent 1 packet" line
        time.sleep(0.02)              # 20 ms gap keeps all ports inside the 10 s window
    print("[portscan] Done. Expect a 'Port Scan' alert.")


def simulate_syn_flood(target_ip: str, packet_count: int = SYN_FLOOD_PACKET_COUNT) -> None:
    """
    Rule 2: send MANY SYNs to the SAME port (80), never completing the handshake.

    A real SYN flood also spoofs the source IP so replies go nowhere, leaving
    the target holding half-open connections. We keep the real source so the
    test stays harmless, but the SYN rate is what the rule detects.
    """
    target_port = 80
    print(f"[synflood] Sending {packet_count} SYNs to {target_ip}:{target_port} ...")
    for _ in range(packet_count):
        packet = IP(dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
        send(packet, verbose=False)
        time.sleep(0.005)  # ~200 packets/s: well inside the 5 s window, easy on the CPU
    print("[synflood] Done. Expect a 'SYN Flood' alert.")


def simulate_icmp_flood(target_ip: str, packet_count: int = ICMP_FLOOD_PACKET_COUNT) -> None:
    """
    Rule 3: send many ICMP echo requests (pings) quickly.

    ICMP() defaults to type 8 (echo request), the same thing the ping command
    sends. Doing it in a tight loop simulates a ping flood.
    """
    print(f"[icmpflood] Sending {packet_count} ping requests to {target_ip} ...")
    for _ in range(packet_count):
        packet = IP(dst=target_ip) / ICMP()  # ICMP() = echo request by default
        send(packet, verbose=False)
        time.sleep(0.01)  # 100 pings/s, comfortably over 50 in 5 s
    print("[icmpflood] Done. Expect an 'ICMP Flood' alert.")


def simulate_blacklisted_traffic(target_ip: str) -> None:
    """
    Rule 4: send a packet whose SOURCE IP is a blacklisted address.

    src= sets a FAKE (spoofed) source address. On loopback this is fine for a
    test. We send a few packets because the OS may not deliver crafted spoofed
    packets as reliably as normal ones.
    """
    print(f"[blacklist] Sending packets that appear to come from {BLACKLIST_TEST_SOURCE_IP} ...")
    for _ in range(5):
        packet = IP(src=BLACKLIST_TEST_SOURCE_IP, dst=target_ip) / TCP(dport=80, flags="S")
        send(packet, verbose=False)
        time.sleep(0.05)
    print("[blacklist] Done. Expect a 'Blacklisted IP' alert "
          f"(ensure {BLACKLIST_TEST_SOURCE_IP} is in {config.BLACKLIST_FILE.name}).")


# Maps each command-line choice to the function that runs it.
SIMULATIONS = {
    "portscan": simulate_port_scan,
    "synflood": simulate_syn_flood,
    "icmpflood": simulate_icmp_flood,
    "blacklist": simulate_blacklisted_traffic,
}


def run_all(target_ip: str) -> None:
    """Run all four simulations one after another, pausing between them."""
    ordered_attacks = ["portscan", "synflood", "icmpflood", "blacklist"]
    for index, attack_name in enumerate(ordered_attacks):
        SIMULATIONS[attack_name](target_ip)
        if index < len(ordered_attacks) - 1:
            # Pause longer than the alert cooldown so each attack is reported on its own.
            pause = config.ALERT_COOLDOWN_SECONDS + 2
            print(f"--- waiting {pause:g}s so the next alert is not suppressed ---\n")
            time.sleep(pause)


def _build_argument_parser() -> argparse.ArgumentParser:
    """Define the simulator's command-line options."""
    parser = argparse.ArgumentParser(
        prog="python -m scripts.attack_simulator",
        description="Safely generate attacks against THIS machine to test the NIDS.",
    )
    parser.add_argument(
        "attack",
        choices=[*SIMULATIONS.keys(), "all"],
        help="Which attack to simulate",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET_IP,
        help=f"Target IP (default: {DEFAULT_TARGET_IP}; only loopback is allowed by default)",
    )
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="Required confirmation to target a NON-loopback IP you own. Use responsibly.",
    )
    return parser


def main() -> int:
    """Validate the target, enforce the safety rule, then run the chosen attack."""
    parser = _build_argument_parser()
    arguments = parser.parse_args()

    # Reject a target that is not a valid IP address at all.
    try:
        ipaddress.ip_address(arguments.target)
    except ValueError:
        parser.error(f"{arguments.target!r} is not a valid IP address")

    # SAFETY GATE: block non-loopback targets unless the user explicitly confirms ownership.
    if not is_loopback_address(arguments.target) and not arguments.i_own_this_target:
        print(f"[safety] Refusing to target {arguments.target} because it is not a loopback "
              "address.\n[safety] Attacking a machine you do not own is illegal. If you own "
              "this host\n[safety] and have permission, re-run with --i-own-this-target.")
        return 2

    # Scapy picks the right interface automatically for 127.0.0.1 (the loopback one).
    conf.verb = 0  # silence Scapy's global logging

    print(f"Target: {arguments.target}  |  Attack: {arguments.attack}\n")
    start_time = time.monotonic()

    try:
        if arguments.attack == "all":
            run_all(arguments.target)
        else:
            SIMULATIONS[arguments.attack](arguments.target)
    except PermissionError:
        print("[simulator] Permission denied. Run Anaconda Prompt as Administrator.")
        return 1
    except OSError as error:
        print(f"[simulator] Could not send packets: {error}")
        return 1
    except KeyboardInterrupt:
        print("\n[simulator] Stopped by user.")
        return 0

    print(f"\nFinished in {time.monotonic() - start_time:.1f}s. "
          "Check terminal 1 (and logs/alerts.csv) for the alerts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
