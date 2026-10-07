"""
sniffer.py
----------
Packet capture layer of the NIDS.

RESPONSIBILITY (Single Responsibility Principle):
    1. Capture raw packets from a network interface using Scapy + Npcap.
    2. Convert each raw Scapy packet into a small, clean PacketInfo object
       holding ONLY the fields the detection engine needs.
    3. Pass each PacketInfo to a callback function supplied by the caller.

    This module does NOT decide whether a packet is malicious. That is the
    detector's job (Module 3). Keeping them separate means we can test the
    detector with fake packets, without needing a real network.

RUN ON ITS OWN (from the project root, in an ADMINISTRATOR Anaconda Prompt):
    python -m nids.sniffer --iface loopback --count 20
"""

from __future__ import annotations

import argparse                     # parses command-line options like --iface
import ctypes                       # lets Python call a Windows API (admin check)
import os                           # OS name / user id
import sys                          # exit codes
from dataclasses import dataclass   # auto-generates __init__, __repr__, etc.
from datetime import datetime       # converts timestamps to readable time
from typing import Callable, Optional

# scapy.all loads every protocol layer AND the Windows/Npcap integration.
from scapy.all import ICMP, IP, TCP, UDP, conf, sniff  # type: ignore[attr-defined]
from scapy.error import Scapy_Exception
from scapy.packet import Packet

from nids import config


@dataclass(frozen=True)
class PacketInfo:
    """
    A simplified, read-only summary of one captured packet.

    frozen=True makes the object immutable: once created, its fields cannot be
    changed. That prevents bugs where one module accidentally edits data that
    another module is still using.
    """

    timestamp: float                 # seconds since 1 Jan 1970 (Unix epoch time)
    source_ip: str                   # who SENT the packet (the possible attacker)
    destination_ip: str              # who RECEIVES it
    protocol: str                    # "TCP", "UDP", "ICMP" or "OTHER"
    source_port: Optional[int]       # None for ICMP / OTHER (they have no ports)
    destination_port: Optional[int]  # None for ICMP / OTHER
    tcp_flags: str                   # e.g. "S" = SYN, "SA" = SYN+ACK; "" if not TCP
    icmp_type: Optional[int]         # 8 = echo request (ping), 0 = echo reply
    size_bytes: int                  # total packet length


# Type alias meaning: "a function that receives a PacketInfo and returns nothing".
PacketHandler = Callable[[PacketInfo], None]


def is_running_as_admin() -> bool:
    """
    Return True if this process has Administrator (Windows) or root (Linux/Mac) rights.

    Reading every packet on a network card is powerful and privacy-sensitive,
    so operating systems usually require elevated rights for it.
    """
    try:
        if os.name == "nt":  # "nt" means Windows
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0  # on Linux/Mac, root has user id 0
    except (AttributeError, OSError):
        # If the check itself fails, report "not admin"; capture will give a clear error later.
        return False


def resolve_interface(interface_name: str) -> Optional[str]:
    """
    Translate the friendly interface name from config into what Scapy expects.

    - "loopback" -> Scapy's own loopback adapter name. It differs between
                    operating systems and Npcap versions, so we ask Scapy
                    instead of hard-coding it.
    - ""         -> None, meaning "use Scapy's default interface".
    - otherwise  -> returned unchanged (for example "Wi-Fi").
    """
    cleaned_name = interface_name.strip()
    if cleaned_name.lower() == "loopback":
        return conf.loopback_name
    if cleaned_name == "":
        return None
    return cleaned_name


def parse_packet(raw_packet: Packet) -> Optional[PacketInfo]:
    """
    Convert a raw Scapy packet into a PacketInfo.

    Returns None for packets without an IPv4 layer, because all our
    detection rules are based on source IP addresses.
    """
    if not raw_packet.haslayer(IP):
        return None

    ip_layer = raw_packet[IP]

    # Defaults for fields that only some protocols have.
    protocol = "OTHER"
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    tcp_flags = ""
    icmp_type: Optional[int] = None

    if raw_packet.haslayer(TCP):
        tcp_layer = raw_packet[TCP]
        protocol = "TCP"
        source_port = int(tcp_layer.sport)
        destination_port = int(tcp_layer.dport)
        tcp_flags = str(tcp_layer.flags)  # Scapy shows flags as letters, e.g. "S", "SA", "PA"
    elif raw_packet.haslayer(UDP):
        udp_layer = raw_packet[UDP]
        protocol = "UDP"
        source_port = int(udp_layer.sport)
        destination_port = int(udp_layer.dport)
    elif raw_packet.haslayer(ICMP):
        protocol = "ICMP"
        icmp_type = int(raw_packet[ICMP].type)

    return PacketInfo(
        timestamp=float(raw_packet.time),  # capture time recorded by Npcap
        source_ip=str(ip_layer.src),
        destination_ip=str(ip_layer.dst),
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        tcp_flags=tcp_flags,
        icmp_type=icmp_type,
        size_bytes=len(raw_packet),
    )


def format_packet_info(packet_info: PacketInfo) -> str:
    """Build a one-line, human-readable description of a packet for the console."""
    readable_time = datetime.fromtimestamp(packet_info.timestamp).strftime("%H:%M:%S")

    # TCP/UDP show ip:port; ICMP has no ports, so show only IPs.
    if packet_info.protocol in ("TCP", "UDP"):
        route = (
            f"{packet_info.source_ip}:{packet_info.source_port} -> "
            f"{packet_info.destination_ip}:{packet_info.destination_port}"
        )
    else:
        route = f"{packet_info.source_ip} -> {packet_info.destination_ip}"

    details = ""
    if packet_info.protocol == "TCP":
        details = f"flags={packet_info.tcp_flags}"
    elif packet_info.protocol == "ICMP":
        details = f"type={packet_info.icmp_type}"

    # :<5 / :<45 / :<10 pad the text so columns line up neatly.
    return (
        f"[{readable_time}] {packet_info.protocol:<5} {route:<45} "
        f"{details:<10} {packet_info.size_bytes} bytes"
    )


def start_sniffing(
    packet_handler: PacketHandler,
    interface_name: str = config.INTERFACE,
    capture_filter: str = config.CAPTURE_FILTER,
    packet_count: int = 0,
) -> None:
    """
    Capture packets and call packet_handler(packet_info) for every IPv4 packet.

    Args:
        packet_handler: function to run for each parsed packet (the "callback").
        interface_name: friendly interface name ("loopback", "Wi-Fi", or "").
        capture_filter: BPF filter expression; empty string means no filter.
        packet_count:   stop after this many packets; 0 = run until Ctrl+C.

    This call BLOCKS: it does not return until capture stops.
    """
    scapy_interface = resolve_interface(interface_name)

    def _on_raw_packet(raw_packet: Packet) -> None:
        """Inner callback that Scapy runs for EVERY captured packet."""
        try:
            packet_info = parse_packet(raw_packet)
            if packet_info is not None:
                packet_handler(packet_info)
        except Exception as error:  # noqa: BLE001 - deliberate safety net
            # One weird packet must never crash a security tool that runs 24/7.
            print(f"[sniffer] Skipped a packet that could not be processed: {error}")

    sniff(
        iface=scapy_interface,
        filter=capture_filter or None,  # empty string -> None (no filter)
        prn=_on_raw_packet,             # "prn" = function to call per packet
        store=False,                    # do NOT keep packets in RAM (avoids memory growth)
        count=packet_count,             # 0 means unlimited
    )


def _build_argument_parser() -> argparse.ArgumentParser:
    """Define the command-line options for running this file on its own."""
    parser = argparse.ArgumentParser(
        description="Print live packets to the console (Module 2 test tool)."
    )
    parser.add_argument(
        "--iface",
        default=config.INTERFACE,
        help="Interface to sniff: 'loopback', 'Wi-Fi', or a name from conf.ifaces "
        f"(default: {config.INTERFACE!r})",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture, 0 = until Ctrl+C (default: 0)",
    )
    parser.add_argument(
        "--filter",
        default=config.CAPTURE_FILTER,
        help=f"BPF capture filter (default: {config.CAPTURE_FILTER!r})",
    )
    return parser


def _print_packet(packet_info: PacketInfo) -> None:
    """Simple packet handler used for testing: print each packet on one line."""
    print(format_packet_info(packet_info))


def main() -> int:
    """Entry point for `python -m nids.sniffer`. Returns a process exit code."""
    parser = _build_argument_parser()
    arguments = parser.parse_args()

    if arguments.count < 0:
        parser.error("--count must be 0 or a positive number")  # prints the message and exits

    if not is_running_as_admin():
        print(
            "[sniffer] WARNING: not running as Administrator. If capture fails, "
            "reopen Anaconda Prompt with 'Run as administrator'."
        )

    print(
        f"[sniffer] Listening on {arguments.iface!r} with filter {arguments.filter!r}. "
        "Press Ctrl+C to stop."
    )

    try:
        start_sniffing(_print_packet, arguments.iface, arguments.filter, arguments.count)
    except PermissionError:
        print("[sniffer] Permission denied. Run Anaconda Prompt as Administrator.")
        return 1
    except (OSError, ValueError, Scapy_Exception) as error:
        print(f"[sniffer] Could not start capture on {arguments.iface!r}: {error}")
        print('[sniffer] List valid interfaces with: python -c "from scapy.all import conf; print(conf.ifaces)"')
        return 1
    except KeyboardInterrupt:
        pass  # Ctrl+C is the normal way to stop; not an error

    print("\n[sniffer] Capture stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
