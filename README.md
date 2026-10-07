# 🛡️ Network Intrusion Detection System (NIDS)

A beginner-friendly, signature- and anomaly-based **Network Intrusion Detection
System** written in Python. It sniffs live network traffic, detects four common
attack patterns using explainable rules, records every alert, and visualises
them on a live web dashboard.

Built as a Cryptography & Network Security (CNS) course project.

---

## ✨ Features

- **Live packet capture** on any interface (Wi-Fi or loopback) using Scapy.
- **Four detection rules:**
  - **Port Scan** – one IP probing many different ports (anomaly / threshold).
  - **SYN Flood** – one IP flooding a single port with TCP SYNs (anomaly).
  - **ICMP Flood** – one IP sending too many pings (anomaly).
  - **Blacklisted IP** – traffic from a known-bad IP (signature).
- **Smart alerting** – coloured console output, a rotating log file, and a CSV
  log, with a per-attack **cooldown** that stops alert spam.
- **Live web dashboard** – metric cards, charts, filters, and CSV export (Streamlit).
- **Safe attack simulator** – reproduce all four attacks against your own
  machine to test the system, with a built-in safety gate.
- **43 automated tests** covering every rule and edge case (pytest).

---

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.13 (Anaconda) |
| Packet capture | Scapy + Npcap (Windows) / libpcap (Linux/macOS) |
| Dashboard | Streamlit + pandas |
| Console colour | colorama |
| Testing | pytest |
| Version control | Git + GitHub |

---

## 🏗️ Architecture

```
Network card ──Npcap──▶ Sniffer ──PacketInfo──▶ Detector ──Alert──▶ Alert Manager
 (Wi-Fi/loopback)       (Scapy)                 (4 rules)           │
                                                                    ├─▶ Console (coloured)
                                                                    ├─▶ logs/nids.log
                                                                    └─▶ logs/alerts.csv ──▶ Dashboard (browser)
```

Each component has a single responsibility and does not depend on the internals
of the others, so any part can be tested or replaced on its own.

---

## 📁 Folder Structure

```
network-ids/
├── nids/                      # core package
│   ├── __init__.py
│   ├── config.py              # all settings & thresholds (one place to tune)
│   ├── sniffer.py             # captures packets -> PacketInfo
│   ├── detector.py            # the 4 detection rules + sliding windows
│   ├── alert_manager.py       # cooldown, console, log file, CSV
│   └── main.py                # entry point; wires everything together
├── dashboard/
│   └── app.py                 # Streamlit dashboard (reads alerts.csv)
├── scripts/
│   ├── __init__.py
│   └── attack_simulator.py    # safe attack generator for testing
├── data/
│   └── blacklist.txt          # one bad IP per line
├── logs/                      # alerts.csv + nids.log created here (git-ignored)
├── tests/                     # pytest suite (43 tests)
├── requirements.txt
├── pytest.ini
├── .gitignore
└── README.md
```

---

## ✅ Prerequisites

- **Windows 10/11** (Linux/macOS work too; use `sudo` instead of Administrator).
- **Anaconda** (Python 3.13): https://www.anaconda.com/download
- **Npcap** (Windows packet driver): https://npcap.com/#download
  Install with **"Support loopback traffic"** and **WinPcap-compatible mode** ticked.
- **Nmap** (for testing port scans): https://nmap.org/download.html
- **Wireshark** (optional, to cross-check packets): https://www.wireshark.org/download.html

> ⚠️ Packet capture needs **Administrator** (Windows) or **root** (Linux/macOS) rights.

---

## 🚀 Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/network-ids.git
cd network-ids

# 2. Create and activate the environment
conda create -n nids python=3.13 -y
conda activate nids

# 3. Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Usage

Open **Anaconda Prompt as Administrator** for anything that captures or sends packets.

```bash
# Start the NIDS (watches loopback by default)
python -m nids.main --iface loopback

# ...or watch real Wi-Fi traffic
python -m nids.main --iface Wi-Fi
```

In a **second** Administrator prompt, generate test attacks against your own machine:

```bash
python -m scripts.attack_simulator all        # run all four, one by one
python -m scripts.attack_simulator portscan   # or just one
```

Launch the dashboard (a normal prompt is fine – it only reads a file):

```bash
streamlit run dashboard/app.py
# then open http://localhost:8501
```

---

## 🖼️ Screenshots

> _Add screenshots here after your first run:_
> - `docs/screenshot-console.png` – coloured alerts in the terminal
> - `docs/screenshot-dashboard.png` – the Streamlit dashboard

---

## ⚙️ Configuration

All settings live in `nids/config.py`:

| Setting | Default | Meaning |
|---|---|---|
| `PORT_SCAN_DISTINCT_PORT_LIMIT` | 15 | ports in the window before a scan alert |
| `SYN_FLOOD_PACKET_LIMIT` | 100 | SYNs to one port before a flood alert |
| `ICMP_FLOOD_PACKET_LIMIT` | 50 | pings in the window before a flood alert |
| `ALERT_COOLDOWN_SECONDS` | 30 | quiet period per (attack, IP) after an alert |

You can also override the interface without editing code:

```bash
set NIDS_INTERFACE=Wi-Fi        # Windows
export NIDS_INTERFACE=eth0      # Linux/macOS
```

The blacklist is `data/blacklist.txt` (one IP per line, `#` for comments).

---

## 🧪 Testing

```bash
pytest                      # run all 43 tests
pytest -v                   # verbose
pytest tests/test_detector.py   # one file
```

Tests need no network, no Npcap and no Administrator rights.

---

## 🩹 Troubleshooting

| Problem | Fix |
|---|---|
| `No module named 'nids'` | Run from the project root with `python -m nids.main`. |
| `winpcap is not installed` | Reinstall Npcap (as admin) with WinPcap-compatible mode. |
| No alerts on loopback | Reinstall Npcap with "Support loopback traffic" ticked. |
| `'streamlit' is not recognized` | `conda activate nids`, then `streamlit run dashboard/app.py`. |
| `Could not write to alerts.csv` | Close the file if it is open in Excel. |

---

## 🗺️ Deployment

A sniffer must run on the machine whose traffic it watches, so this tool runs
**locally** rather than on a cloud host. The code is version-controlled on
GitHub; see the installation steps to run it on any machine.

---

## 🔮 Future Enhancements

- Machine-learning detection trained on the NSL-KDD dataset.
- Detection of slow/stealth scans and distributed (multi-source) floods.
- Store alerts in SQLite instead of CSV for larger histories.
- Email/Telegram notifications for HIGH-severity alerts.
- Optional blocking (turn the IDS into an IPS) via firewall rules.

---

## ⚖️ Ethics & Legal

This project is for **education and authorised testing only**. Scanning or
flooding systems you do not own is illegal (in India, the IT Act 2000,
sections 43 & 66). The attack simulator targets `127.0.0.1` by default and
refuses other targets unless you explicitly confirm ownership.

---

## 📜 License

Released under the MIT License. See `LICENSE`.

---

## 🙏 Acknowledgements

- [Scapy](https://scapy.net/) for packet capture and crafting.
- [Streamlit](https://streamlit.io/) for the dashboard.
- [Npcap](https://npcap.com/) for Windows packet capture.
