"""
nids package
------------
Network Intrusion Detection System (NIDS) - a beginner-friendly CNS project.

This file marks the `nids/` folder as a Python *package*, which lets other
files write imports like:

    from nids import config
    from nids.sniffer import start_sniffing

Modules inside this package:
    config.py         -> all settings (interface, thresholds, file paths)
    sniffer.py        -> captures packets and converts them to PacketInfo objects
    detector.py       -> detection rules (Module 3)
    alert_manager.py  -> prints / saves alerts (Module 4)
    main.py           -> entry point that connects everything (Module 5)
"""

# Single source of truth for the project version. Shown in logs and the README.
__version__ = "0.1.0"
