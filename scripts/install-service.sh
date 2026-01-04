#!/bin/bash
#
# SNIFF Service Installer
# Install SNIFF as a systemd service
#
# Usage:
#   sudo ./install-service.sh INTERFACE
#   sudo ./install-service.sh eth0
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Config
INSTALL_DIR="/opt/sniff"
SERVICE_FILE="/etc/systemd/system/sniff.service"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo $0 INTERFACE"
    exit 1
fi

# Check interface argument
if [[ -z "$1" ]]; then
    echo -e "${YELLOW}Usage: sudo $0 INTERFACE${NC}"
    echo ""
    echo "Available interfaces:"
    ip -o link show | awk -F': ' '{print "  - " $2}'
    echo ""
    exit 1
fi

INTERFACE="$1"

# Validate interface
if ! ip link show "$INTERFACE" &>/dev/null; then
    echo -e "${RED}Error: Interface '$INTERFACE' not found${NC}"
    echo ""
    echo "Available interfaces:"
    ip -o link show | awk -F': ' '{print "  - " $2}'
    exit 1
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  SNIFF Service Installer${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Step 1: Install to /opt/sniff
echo -e "${YELLOW}[1/5] Installing files to $INSTALL_DIR...${NC}"
mkdir -p "$INSTALL_DIR"
cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/sniff.py"
echo -e "${GREEN}  Done${NC}"

# Step 2: Create data directory
echo -e "${YELLOW}[2/5] Creating data directory...${NC}"
mkdir -p "$INSTALL_DIR/sniff_data/raw"
mkdir -p "$INSTALL_DIR/sniff_data/modules"
chmod -R 755 "$INSTALL_DIR/sniff_data"
echo -e "${GREEN}  Done${NC}"

# Step 3: Install Python dependencies
echo -e "${YELLOW}[3/5] Installing Python dependencies...${NC}"
if command -v pip3 &>/dev/null; then
    pip3 install -r "$INSTALL_DIR/requirements.txt" --quiet
    echo -e "${GREEN}  Done${NC}"
else
    echo -e "${YELLOW}  Warning: pip3 not found, please install manually:${NC}"
    echo "    pip3 install scapy"
fi

# Step 4: Install systemd service
echo -e "${YELLOW}[4/5] Installing systemd service...${NC}"

# Create service file with actual interface
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=SNIFF Packet Capture Service - $INTERFACE
Documentation=https://github.com/your-repo/sniff
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/sniff.py -i $INTERFACE
ExecStop=/usr/bin/python3 $INSTALL_DIR/sniff.py --stop
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Environment
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo -e "${GREEN}  Done${NC}"

# Step 5: Enable and start service
echo -e "${YELLOW}[5/5] Enabling service...${NC}"
systemctl enable sniff
echo -e "${GREEN}  Done${NC}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Service commands:"
echo "  sudo systemctl start sniff    # Start capture"
echo "  sudo systemctl stop sniff     # Stop capture"
echo "  sudo systemctl status sniff   # Check status"
echo "  sudo journalctl -u sniff -f   # View logs"
echo ""
echo "Manual commands:"
echo "  sudo python3 $INSTALL_DIR/sniff.py             # Interactive mode"
echo "  sudo python3 $INSTALL_DIR/sniff.py -i $INTERFACE   # Quick capture"
echo ""
echo "Data directory: $INSTALL_DIR/sniff_data"
echo ""

# Ask to start
read -p "Start service now? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    systemctl start sniff
    echo -e "${GREEN}Service started!${NC}"
    systemctl status sniff --no-pager
fi

