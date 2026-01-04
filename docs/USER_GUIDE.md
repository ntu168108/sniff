# SNIFF - User Guide & Documentation

![SNIFF Banner](https://img.shields.io/badge/SNIFF-Packet_Capture_Tool-blue?style=for-the-badge)

**Complete guide for installing and using SNIFF Network Packet Capture Tool**

---

## 📖 Table of Contents

1. [Installation](#-installation)
2. [Quick Start](#-quick-start)
3. [Usage Modes](#-usage-modes)
4. [Command-Line Options](#-command-line-options)
5. [Interactive Menu](#-interactive-menu)
6. [Daemon Mode](#-daemon-mode)
7. [Advanced Usage](#-advanced-usage)
8. [Output Files](#-output-files)
9. [Troubleshooting](#-troubleshooting)
10. [Uninstall](#-uninstall)

---

## 🚀 Installation

### One-Line Install (Recommended)

Install everything (Python + dependencies + SNIFF) with one command:

```bash
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/install.sh | sudo bash
```

**What this does:**
- ✅ Detects your OS (Ubuntu, Debian, CentOS, Fedora)
- ✅ Installs Python 3.8+ if not present
- ✅ Installs pip3 if needed
- ✅ Installs scapy library
- ✅ Installs SNIFF
- ✅ Optionally sets up systemd service

**Requirements:**
- Linux OS (Ubuntu, Debian, CentOS, Fedora)
- Root/sudo access
- Internet connection

---

## ⚡ Quick Start

After installation, run SNIFF in interactive mode:

```bash
sudo sniff
```

You'll see a menu like this:

```
╔═══════════════════════════════════════╗
║           SNIFF v1.0.0                ║
║   Network Packet Capture Tool         ║
╚═══════════════════════════════════════╝

Main Menu:
  [1] Quick Capture    - Start capturing on an interface
  [2] Advanced Capture - Custom settings and filters
  [3] Open PCAP File   - Browse captured packets
  [4] Settings         - Configure defaults
  [Q] Quit

Select option [1-4, Q]:
```

**For quick capture:**
1. Press `1` for Quick Capture
2. Select network interface (e.g., eth0, wlan0)
3. Press Enter to start capturing
4. You'll see packets in real-time!

**Stop capture:**
- Press `S` to save and exit
- Press `Q` to quit without saving
- Press `SPACE` to pause/resume

---

## 🎯 Usage Modes

SNIFF has 3 main modes:

### 1. Interactive Menu Mode

```bash
sudo sniff
```

**Best for:** First-time users, exploring options

**Features:**
- Easy-to-use menu interface
- Quick capture setup
- Advanced configuration wizard
- Browse existing PCAP files
- View packet details

### 2. Command-Line Mode

```bash
# Basic capture on specific interface
sudo sniff -i eth0

# With BPF filter
sudo sniff -i eth0 -f "tcp port 80"

# With custom buffer size
sudo sniff -i eth0 -b fast

# Custom output directory
sudo sniff -i eth0 -o /data/captures
```

**Best for:** Automation, scripts, quick captures

### 3. Daemon Mode

```bash
# Start as background daemon
sudo sniff -i eth0 -d

# Check status
sudo sniff --status

# Stop daemon
sudo sniff --stop
```

**Best for:** 24/7 monitoring, production environments

---

## 📋 Command-Line Options

### Basic Options

```bash
sniff [OPTIONS]

Required:
  -i, --interface INTERFACE    Network interface to capture on
                               Example: eth0, wlan0, ens33

Optional:
  -f, --filter FILTER          BPF filter expression
                               Example: "tcp port 80"
                                        "host 192.168.1.1"
                                        "not port 22"

  -s, --snaplen SIZE          Max bytes per packet (default: 65535)
                               Example: -s 1500

  -p, --no-promisc            Disable promiscuous mode
                               (only capture packets for this host)

  -b, --buffer PROFILE        Buffer size profile
                               Options: low, balanced, fast, max
                               Default: balanced

  -o, --output DIR            Output directory
                               Default: ./sniff_data

  -r, --retention DAYS        Keep files for N days (default: 7)
                               Example: -r 30

Daemon Mode:
  -d, --daemon                Run as background daemon
  --status                    Show daemon status
  --stop                      Stop daemon

Utility:
  --list-interfaces           Show available network interfaces
  -h, --help                  Show help message
```

### Buffer Profiles

Choose based on your network speed and available memory:

| Profile | Buffer Size | Queue Size | Best For |
|---------|-------------|------------|----------|
| `low` | 1 MB | 100 | Low-traffic, limited RAM |
| `balanced` | 4 MB | 500 | Normal usage (default) |
| `fast` | 16 MB | 2000 | High-traffic networks |
| `max` | 64 MB | 10000 | Enterprise, high-speed capture |

---

## 🖥️ Interactive Menu

### Quick Capture

1. Run `sudo sniff`
2. Select `[1] Quick Capture`
3. Choose interface from list
4. Capture starts immediately!

**Real-time display:**
```
╔══════════════════════════════════════════════════════════════╗
║ SNIFF - Capturing on eth0                     [SPACE] Pause  ║
╠══════════════════════════════════════════════════════════════╣
║ Stats: 1,234 pkts | 567 KB | 45 pps | 0 drops    [Q] Quit   ║
║ File: eth0_2026-01-04_22.pcap                   [S] Save     ║
╠══════════════════════════════════════════════════════════════╣
  #    Time      Src IP:Port          Dst IP:Port         Proto
  1    0.000     192.168.1.100:52341  1.1.1.1:443        TCP
  2    0.001     1.1.1.1:443          192.168.1.100:52341 TCP
  3    0.015     192.168.1.100:52341  1.1.1.1:443        TCP
  ...
```

**Controls:**
- `SPACE` - Pause/Resume capture
- `Q` - Quit without saving
- `S` - Save and exit
- `↑/↓` - Scroll packet list
- `Enter` - View packet details

### Advanced Capture

For custom configuration:

1. Select `[2] Advanced Capture`
2. Configure settings:
   - Interface
   - BPF filter (optional)
   - Snaplen
   - Buffer profile
   - Output directory
   - Retention days
   - Enable analysis modules
3. Start capture

**Example Advanced Setup:**
```
Interface: eth0
BPF Filter: tcp port 80 or tcp port 443
Snaplen: 65535
Buffer: fast
Output: /data/web-traffic
Retention: 30 days
Modules: [x] dummy (protocol analysis)
```

### Browse PCAP Files

1. Select `[3] Open PCAP File`
2. See list of captured files (newest first)
3. Select file to view
4. Browse packets and view details

---

## 🔧 Daemon Mode

### Setup as Systemd Service

During installation, the script asks if you want to setup systemd service.

Or install manually:

```bash
# Install service with auto-installer
sudo ./install-service.sh eth0

# Or use the install.sh and choose service setup
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/install.sh | sudo bash
# Then answer 'y' when asked about systemd service
```

### Service Management

```bash
# Start service
sudo systemctl start sniff

# Stop service
sudo systemctl stop sniff

# Restart service
sudo systemctl restart sniff

# Check status
sudo systemctl status sniff

# View logs (real-time)
sudo journalctl -u sniff -f

# View logs (last 100 lines)
sudo journalctl -u sniff -n 100

# Enable auto-start on boot
sudo systemctl enable sniff

# Disable auto-start
sudo systemctl disable sniff
```

### Daemon CLI Mode

Alternative to systemd service:

```bash
# Start daemon
sudo sniff -i eth0 -d

# Check if running
sudo sniff --status
# Output:
# SNIFF Daemon Status
# ------------------------------
# Status: Running
# PID:    12345
# Log:    /tmp/sniff.log

# Stop daemon
sudo sniff --stop
```

---

## 🎓 Advanced Usage

### BPF Filters Examples

Capture only specific traffic:

```bash
# HTTP traffic only
sudo sniff -i eth0 -f "tcp port 80"

# HTTPS traffic
sudo sniff -i eth0 -f "tcp port 443"

# DNS traffic
sudo sniff -i eth0 -f "udp port 53"

# Traffic from specific host
sudo sniff -i eth0 -f "host 192.168.1.100"

# Traffic to specific network
sudo sniff -i eth0 -f "dst net 10.0.0.0/8"

# Exclude SSH traffic
sudo sniff -i eth0 -f "not port 22"

# Multiple conditions (HTTP or HTTPS)
sudo sniff -i eth0 -f "tcp port 80 or tcp port 443"

# TCP SYN packets only
sudo sniff -i eth0 -f "tcp[tcpflags] & tcp-syn != 0"

# ICMP packets
sudo sniff -i eth0 -f "icmp"

# Large packets only (> 1000 bytes)
sudo sniff -i eth0 -f "greater 1000"
```

### Custom Output Directory

```bash
# Store in specific location
sudo sniff -i eth0 -o /data/network-captures

# Organized by purpose
sudo sniff -i eth0 -o /var/log/sniff/web-traffic -f "port 80 or port 443"
sudo sniff -i eth0 -o /var/log/sniff/dns-traffic -f "port 53"
```

### File Retention

```bash
# Keep files for 30 days
sudo sniff -i eth0 -r 30

# Keep files for 1 year
sudo sniff -i eth0 -r 365

# Keep forever (set to very high number)
sudo sniff -i eth0 -r 9999
```

### High-Performance Capture

For gigabit networks:

```bash
sudo sniff -i eth0 -b max -s 1500 -f "not port 22"
```

Explanation:
- `-b max` - Maximum buffer (64MB, 10K queue)
- `-s 1500` - Snaplen 1500 (don't need full packet for analysis)
- `-f "not port 22"` - Skip SSH to reduce volume

---

## 📁 Output Files

### Directory Structure

Default location: `./sniff_data/`

```
sniff_data/
├── raw/                           # Raw PCAP files
│   └── 2026-01-04/
│       ├── eth0_2026-01-04_00.pcap  # 00:00-00:59
│       ├── eth0_2026-01-04_01.pcap  # 01:00-01:59
│       ├── eth0_2026-01-04_22.pcap  # 22:00-22:59
│       └── ...
└── modules/                       # Analysis results
    └── dummy/                     # Module name
        └── 2026-01-04/
            ├── eth0_2026-01-04_22.summary.json
            └── eth0_2026-01-04_22.index.jsonl
```

### PCAP Files

- **Format:** Standard PCAP format (readable by Wireshark, tcpdump)
- **Naming:** `{interface}_{date}_{hour}.pcap`
- **Rotation:** Automatic hourly rotation
- **Retention:** Auto-delete after configured days

**Open with Wireshark:**
```bash
wireshark sniff_data/raw/2026-01-04/eth0_2026-01-04_22.pcap
```

**Analyze with tcpdump:**
```bash
tcpdump -r sniff_data/raw/2026-01-04/eth0_2026-01-04_22.pcap
```

### Module Output

Analysis modules generate:

**Summary JSON (`*.summary.json`):**
```json
{
  "module_name": "dummy",
  "interface": "eth0",
  "time_window": "2026-01-04_22",
  "total_packets": 10000,
  "total_hits": 5,
  "labels": {
    "port-scan": 2,
    "high-rate-source": 3
  },
  "top_sources": [
    ["192.168.1.100", 5000],
    ["192.168.1.101", 3000]
  ]
}
```

**Detection Index (`*.index.jsonl`):**
```json
{"stt": 1234, "ts_sec": 1704394800, "label": "port-scan", "src": "192.168.1.100", "unique_ports": 50}
{"stt": 5678, "ts_sec": 1704394900, "label": "high-rate-source", "src": "10.0.0.5", "packet_count": 5000}
```

---

## 🐛 Troubleshooting

### "Permission denied" Error

**Problem:** Running without sudo

**Solution:**
```bash
# Always use sudo for packet capture
sudo sniff -i eth0
```

### "Interface not found" Error

**Problem:** Invalid interface name

**Solution:**
```bash
# List available interfaces
sudo sniff --list-interfaces

# Or use system command
ip link show
```

Output example:
```
Available Interfaces:
  - eth0
  - wlan0
  - lo
```

### "Scapy not found" Error

**Problem:** Scapy not installed

**Solution:**
```bash
# Install manually
sudo pip3 install scapy>=2.5.0

# Or reinstall SNIFF (includes dependencies)
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/install.sh | sudo bash
```

### "Cannot capture packets" / 0 packets captured

**Possible causes:**

1. **Wrong interface:** Check with `ip link show`
2. **No traffic:** Use `ping` to generate traffic
3. **Firewall blocking:** Check iptables/firewalld
4. **BPF filter too restrictive:** Try without `-f` filter first

**Debug:**
```bash
# Test with tcpdump (should work if system is OK)
sudo tcpdump -i eth0 -c 10

# If tcpdump works but SNIFF doesn't, report issue on GitHub
```

### High CPU Usage

**Solution:** Use smaller buffer profile or BPF filter

```bash
# Reduce buffer
sudo sniff -i eth0 -b low

# Filter specific traffic only
sudo sniff -i eth0 -f "host 192.168.1.100"
```

### Disk Full

**Problem:** Too many PCAP files

**Solution:**
```bash
# Reduce retention days
sudo sniff -i eth0 -r 1

# Or manually clean old files
rm -rf sniff_data/raw/2026-01-01/
```

---

## 🗑️ Uninstall

### Complete Uninstall

```bash
# One-line uninstall
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/uninstall.sh | sudo bash
```

This removes:
- ✅ SNIFF package
- ✅ Systemd service
- ✅ Service files

**Note:** Captured data (`sniff_data/`) is NOT deleted automatically.

### Manual Uninstall

```bash
# Stop and disable service
sudo systemctl stop sniff
sudo systemctl disable sniff

# Remove service file
sudo rm /etc/systemd/system/sniff.service
sudo systemctl daemon-reload

# Uninstall package
sudo pip3 uninstall -y sniff-pcap

# Remove captured data (optional)
rm -rf ./sniff_data
```

---

## 📚 Additional Resources

### Example Use Cases

**1. Monitor Web Traffic**
```bash
sudo sniff -i eth0 -f "port 80 or port 443" -o /var/log/web-traffic -r 30
```

**2. Capture DNS Queries**
```bash
sudo sniff -i eth0 -f "port 53" -o /var/log/dns-queries
```

**3. Debug Specific Host**
```bash
sudo sniff -i eth0 -f "host 192.168.1.100"
```

**4. Production Monitoring (24/7)**
```bash
# Setup as service
sudo ./install-service.sh eth0

# Or manual daemon
sudo sniff -i eth0 -d -b fast -r 90
```

### Getting Help

```bash
# Built-in help
sudo sniff --help

# GitHub Issues
https://github.com/ntu168108/sniff/issues

# View version
pip3 show sniff-pcap
```

---

## ✅ Quick Reference Card

```bash
# Installation
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/install.sh | sudo bash

# Interactive Mode
sudo sniff

# Quick Capture
sudo sniff -i eth0

# With Filter
sudo sniff -i eth0 -f "tcp port 80"

# Daemon Mode
sudo sniff -i eth0 -d
sudo sniff --status
sudo sniff --stop

# Systemd Service
sudo systemctl start sniff
sudo systemctl status sniff
sudo journalctl -u sniff -f

# List Interfaces
sudo sniff --list-interfaces

# Uninstall
curl -sSL https://raw.githubusercontent.com/ntu168108/sniff/main/uninstall.sh | sudo bash
```

---

**Version:** 1.0.0  
**Last Updated:** 2026-01-04  
**License:** MIT
