#!/bin/bash
#
# SNIFF Auto-Installer
# One-line install: curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sniff/main/install.sh | sudo bash
#
# This script will:
# - Install Python 3.8+ if needed
# - Install pip3 if needed
# - Install scapy
# - Install SNIFF
# - Setup systemd service (optional)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════╗"
echo "║   SNIFF Auto-Installer v0.0.1         ║"
echo "║   Network Packet Capture Tool         ║"
echo "╚═══════════════════════════════════════╝"
echo -e "${NC}"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/sniff/main/install.sh | sudo bash"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}Cannot detect OS${NC}"
    exit 1
fi

echo -e "${BLUE}[1/5] Detecting system...${NC}"
echo "  OS: $PRETTY_NAME"
echo ""

# Update package list
echo -e "${BLUE}[2/5] Updating package list...${NC}"
case $OS in
    ubuntu|debian)
        apt-get update -qq
        ;;
    centos|rhel|fedora)
        yum check-update -q || true
        ;;
    *)
        echo -e "${YELLOW}Warning: Unsupported OS, trying anyway...${NC}"
        ;;
esac
echo -e "${GREEN}  Done${NC}"
echo ""

# Install Python 3.8+
echo -e "${BLUE}[3/5] Checking Python installation...${NC}"
PYTHON_CMD=""

# Try to find Python 3.8+
for py in python3.11 python3.10 python3.9 python3.8 python3; do
    if command -v $py &> /dev/null; then
        PY_VERSION=$($py --version 2>&1 | awk '{print $2}')
        PY_MAJOR=$(echo $PY_VERSION | cut -d. -f1)
        PY_MINOR=$(echo $PY_VERSION | cut -d. -f2)
        
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 8 ]; then
            PYTHON_CMD=$py
            echo -e "${GREEN}  Found: $py ($PY_VERSION)${NC}"
            break
        fi
    fi
done

# Install Python if not found
if [ -z "$PYTHON_CMD" ]; then
    echo -e "${YELLOW}  Python 3.8+ not found, installing...${NC}"
    
    case $OS in
        ubuntu|debian)
            apt-get install -y python3 python3-pip -qq
            PYTHON_CMD=python3
            ;;
        centos|rhel|fedora)
            yum install -y python3 python3-pip -q
            PYTHON_CMD=python3
            ;;
        *)
            echo -e "${RED}Cannot install Python automatically${NC}"
            exit 1
            ;;
    esac
    
    echo -e "${GREEN}  Installed: python3${NC}"
fi
echo ""

# Install pip3
echo -e "${BLUE}[4/5] Checking pip installation...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}  pip3 not found, installing...${NC}"
    
    case $OS in
        ubuntu|debian)
            apt-get install -y python3-pip -qq
            ;;
        centos|rhel|fedora)
            yum install -y python3-pip -q
            ;;
    esac
    
    echo -e "${GREEN}  Installed: pip3${NC}"
else
    echo -e "${GREEN}  Found: pip3${NC}"
fi
echo ""

# Install SNIFF
echo -e "${BLUE}[5/5] Installing SNIFF...${NC}"

# Determine installation method
GITHUB_REPO="ntu168108/sniff"
INSTALL_METHOD="github"

if [ "$INSTALL_METHOD" = "github" ]; then
    echo "  Installing from GitHub..."
    pip3 install --quiet git+https://github.com/$GITHUB_REPO.git
else
    # Alternative: download and install locally
    echo "  Downloading latest release..."
    TEMP_DIR=$(mktemp -d)
    cd $TEMP_DIR
    
    # Clone repo
    git clone https://github.com/$GITHUB_REPO.git || {
        echo -e "${RED}Failed to clone repository${NC}"
        exit 1
    }
    
    cd sniff
    pip3 install --quiet .
    
    # Cleanup
    cd /
    rm -rf $TEMP_DIR
fi

echo -e "${GREEN}  Done${NC}"
echo ""

# Verify installation
if command -v sniff &> /dev/null; then
    echo -e "${GREEN}╔═══════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   Installation Successful! ✓          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════╝${NC}"
    echo ""
    echo "Run SNIFF with:"
    echo -e "  ${YELLOW}sudo sniff${NC}                    # Interactive mode"
    echo -e "  ${YELLOW}sudo sniff -i eth0${NC}            # Quick capture"
    echo -e "  ${YELLOW}sudo sniff --help${NC}             # Show help"
    echo ""
    
    # Ask about systemd service
    if command -v systemctl &> /dev/null; then
        echo -e "${BLUE}Would you like to setup SNIFF as a systemd service? [y/N]${NC}"
        read -r -n 1 SETUP_SERVICE
        echo ""
        
        if [[ $SETUP_SERVICE =~ ^[Yy]$ ]]; then
            echo ""
            echo -e "${BLUE}Installing systemd service...${NC}"
            
            # List interfaces
            echo "Available network interfaces:"
            ip -o link show | awk -F': ' '{print "  - " $2}'
            echo ""
            echo -e "${BLUE}Enter interface name (e.g., eth0):${NC}"
            read -r INTERFACE
            
            if [ -z "$INTERFACE" ]; then
                echo -e "${YELLOW}No interface provided, skipping service setup${NC}"
            else
                # Create service file
                cat > /etc/systemd/system/sniff.service <<EOF
[Unit]
Description=SNIFF Packet Capture Service - $INTERFACE
After=network.target

[Service]
Type=simple
User=root
ExecStart=$(which sniff) -i $INTERFACE
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

                # Enable and start
                systemctl daemon-reload
                systemctl enable sniff
                
                echo ""
                echo -e "${BLUE}Start service now? [y/N]${NC}"
                read -r -n 1 START_NOW
                echo ""
                
                if [[ $START_NOW =~ ^[Yy]$ ]]; then
                    systemctl start sniff
                    echo -e "${GREEN}Service started!${NC}"
                    systemctl status sniff --no-pager
                else
                    echo "Service installed but not started."
                    echo "Start with: sudo systemctl start sniff"
                fi
                
                echo ""
                echo "Service commands:"
                echo "  sudo systemctl start sniff     # Start"
                echo "  sudo systemctl stop sniff      # Stop"
                echo "  sudo systemctl status sniff    # Status"
                echo "  sudo journalctl -u sniff -f    # Logs"
            fi
        fi
    fi
else
    echo -e "${RED}Installation failed!${NC}"
    echo "Please check the error messages above."
    exit 1
fi

echo ""
echo -e "${GREEN}Thank you for using SNIFF! 🚀${NC}"
echo ""
