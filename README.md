# SNIFF - Network Packet Capture Tool

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)

A powerful, modular network packet capture tool for Linux with real-time TUI and extensible analysis modules.

## ✨ Features

- 🎯 **Real-time Packet Capture** - High-performance capture using Scapy/libpcap
- 📊 **Interactive TUI** - Beautiful text-based user interface for live packet monitoring
- 🔄 **Hourly Rotation** - Automatic PCAP file rotation with configurable retention
- 🔌 **Plugin System** - Extensible module architecture for custom packet analysis
- ⚙️ **Daemon Mode** - Run as systemd service for 24/7 monitoring
- 🎨 **Advanced Decoder** - Built-in support for Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP
- ⏸️ **Pause/Resume** - Control capture on the fly without losing data
- 📝 **BPF Filters** - Berkeley Packet Filter support for targeted capture

## ⚡ Quick Install (One Command)

```bash
# Install everything automatically (Python + SNIFF)
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sniff/main/install.sh | sudo bash
```

That's it! Then run:
```bash
sudo sniff
```

## 🚀 Quick Start

### Requirements

- Linux OS (tested on Ubuntu 20.04+, Debian 11+)
- Python 3.8 or higher
- Root/sudo privileges (required for packet capture)

### Installation

**Method 1: Automatic Install (Recommended) ⭐**

One command installs Python, dependencies, and SNIFF:

```bash
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sniff/main/install.sh | sudo bash
```

**Method 2: Manual Install with pip**

```bash
# Install from GitHub repo
sudo pip3 install git+https://github.com/YOUR_USERNAME/sniff.git
```

**Method 3: Clone and Install**

### Basic Usage

```bash
# Interactive menu mode
sudo sniff

# Quick capture on specific interface
sudo sniff -i eth0

# Capture with BPF filter
sudo sniff -i eth0 -f "tcp port 80"

# Run as daemon
sudo sniff -i eth0 -d

# Check daemon status
sudo sniff --status

# Stop daemon
sudo sniff --stop

# List available interfaces
sudo sniff --list-interfaces
```

## 📖 Usage Examples

### Interactive Mode

The easiest way to use SNIFF is the interactive menu:

```bash
sudo sniff
```

This will show you:
- Quick capture on any interface
- Advanced capture with custom settings
- Browse captured PCAP files
- Configure settings

### Command Line Options

```bash
sniff [-h] [-i INTERFACE] [-f FILTER] [-s SNAPLEN] [-p] 
      [-b {low,balanced,fast,max}] [-o OUTPUT] [-r RETENTION]
      [-d] [--status] [--stop] [--list-interfaces]

Options:
  -i, --interface INTERFACE  Network interface to capture on
  -f, --filter FILTER        BPF filter (e.g., "tcp port 80")
  -s, --snaplen SNAPLEN      Capture length (default: 65535)
  -p, --no-promisc          Disable promiscuous mode
  -b, --buffer PROFILE      Buffer profile: low, balanced, fast, max
  -o, --output OUTPUT       Output directory (default: ./sniff_data)
  -r, --retention DAYS      Days to keep files (default: 7)
  -d, --daemon              Run as daemon (background)
  --status                  Show daemon status
  --stop                    Stop daemon
  --list-interfaces         List available interfaces
```

### Install as Systemd Service

For production 24/7 monitoring:

```bash
# Use the provided installer
sudo ./install-service.sh eth0

# Or manually:
sudo cp sniff.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable sniff
sudo systemctl start sniff

# Check status
sudo systemctl status sniff

# View logs
sudo journalctl -u sniff -f
```

## 📁 Project Structure

```
sniff/
├── core/               # Core capture engine
│   ├── capture.py     # Packet capture with Scapy
│   ├── decoder.py     # Packet decoder
│   ├── pcap_writer.py # PCAP file I/O
│   ├── rotator.py     # Hourly file rotation
│   └── constants.py   # Constants and configs
├── modules/           # Analysis modules
│   ├── base.py        # Module base class
│   ├── runner.py      # Module executor
│   └── dummy/         # Example module
├── ui/                # Text UI
│   ├── menu.py        # Main menu
│   ├── list_view.py   # Packet list view
│   ├── detail_view.py # Packet detail view
│   └── colors.py      # Terminal colors
├── sniff.py           # Main entry point
├── setup.py           # Package setup
└── requirements.txt   # Dependencies
```

## 🔌 Plugin Development

Create custom analysis modules easily:

```python
from modules.base import BaseModule, Summary, Detection

class MyModule(BaseModule):
    @property
    def name(self) -> str:
        return "my_module"
    
    def analyze(self, pcap_path, output_dir, interface, time_window) -> Summary:
        # Your analysis logic here
        detections = []
        # ... analyze packets ...
        
        summary = Summary(
            module_name=self.name,
            total_hits=len(detections),
            # ...
        )
        
        self.write_output(output_dir, interface, time_window, summary, detections)
        return summary
```

## 📊 Data Storage

By default, SNIFF stores data in `./sniff_data/`:

```
sniff_data/
├── raw/                    # Raw PCAP files
│   └── YYYY-MM-DD/
│       └── interface_YYYY-MM-DD_HH.pcap
└── modules/                # Analysis results
    └── module_name/
        └── YYYY-MM-DD/
            ├── interface_YYYY-MM-DD_HH.summary.json
            └── interface_YYYY-MM-DD_HH.index.jsonl
```

## 🛠️ Configuration

### Buffer Profiles

- `low` - Minimal memory usage (1MB buffer, 100 queue)
- `balanced` - Default (4MB buffer, 500 queue)
- `fast` - High performance (16MB buffer, 2000 queue)
- `max` - Maximum throughput (64MB buffer, 10000 queue)

### File Retention

Configure automatic cleanup of old files:

```bash
sudo sniff -i eth0 -r 30  # Keep files for 30 days
```

## 🔒 Security Considerations

- SNIFF requires root privileges for raw socket access
- Systemd service includes security hardening (`ProtectSystem`, `ProtectHome`)
- BPF filters help reduce attack surface
- Captured data may contain sensitive information - secure appropriately

## 🐛 Troubleshooting

### Permission Denied

```bash
# Ensure you're running with sudo
sudo sniff -i eth0
```

### Interface Not Found

```bash
# List available interfaces
sudo sniff --list-interfaces

# Check interface is up
ip link show
```

### Scapy Import Error

```bash
# Install Scapy
sudo pip3 install scapy>=2.5.0
```

## 📝 License

MIT License - see LICENSE file for details

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 👨‍💻 Author

Created by Tu

## 🙏 Acknowledgments

- Built with [Scapy](https://scapy.net/) - powerful packet manipulation library
- Inspired by tcpdump, Wireshark, and other network analysis tools
