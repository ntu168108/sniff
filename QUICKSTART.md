# SNIFF - Quick Start Guide

**Get started with SNIFF in 2 minutes!**

---

## 📦 Installation (30 seconds)

Run this ONE command:

```bash
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sniff/main/install.sh | sudo bash
```

**That's it!** The script automatically installs:
- ✅ Python 3.8+
- ✅ pip3
- ✅ scapy
- ✅ SNIFF

---

## ⚡ Quick Start (1 minute)

### Option 1: Interactive Menu (Easiest)

```bash
sudo sniff
```

Then:
1. Press `1` for Quick Capture
2. Select your network interface (e.g., `eth0`)
3. Watch packets flow in real-time! 🎉

**Controls:**
- `SPACE` - Pause/Resume
- `S` - Save and exit
- `Q` - Quit

### Option 2: Command Line (Fast)

```bash
# Capture on eth0
sudo sniff -i eth0

# Capture HTTP traffic only
sudo sniff -i eth0 -f "tcp port 80"

# Run as background daemon
sudo sniff -i eth0 -d
```

---

## 🎯 Common Use Cases

### Monitor All Traffic
```bash
sudo sniff -i eth0
```

### Monitor Web Traffic (HTTP/HTTPS)
```bash
sudo sniff -i eth0 -f "port 80 or port 443"
```

### Monitor Specific Host
```bash
sudo sniff -i eth0 -f "host 192.168.1.100"
```

### 24/7 Background Monitoring
```bash
sudo sniff -i eth0 -d
```

Check status:
```bash
sudo sniff --status
```

Stop:
```bash
sudo sniff --stop
```

---

## 📁 Where Are My Files?

Default location: `./sniff_data/raw/`

```
sniff_data/
└── raw/
    └── 2026-01-04/
        ├── eth0_2026-01-04_00.pcap  
        ├── eth0_2026-01-04_01.pcap
        └── ...
```

**Open with Wireshark:**
```bash
wireshark sniff_data/raw/2026-01-04/eth0_2026-01-04_22.pcap
```

---

## 🛠️ Need Help?

### List Network Interfaces
```bash
sudo sniff --list-interfaces
```

### View All Options
```bash
sudo sniff --help
```

### Read Full Documentation
See [USER_GUIDE.md](USER_GUIDE.md) for complete documentation.

---

## 🗑️ Uninstall

```bash
curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sniff/main/uninstall.sh | sudo bash
```

---

**That's it! Happy packet capturing! 🚀**
