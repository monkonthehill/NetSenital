#!/usr/bin/env bash
# ==============================================================================
# NetSentinel - Automated Installer for Linux
# Repository: https://github.com/monkonthehill/NetSenital
# ==============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}        NetSentinel NIDS - Linux Installation & Setup           ${NC}"
echo -e "${BLUE}        Repository: https://github.com/monkonthehill/NetSenital  ${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""

# 1. Check Root / Sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}[!] Warning: Not running as root. Sudo will be used for package installs.${NC}"
    SUDO="sudo"
else
    SUDO=""
fi

# 2. Detect Package Manager and Install Dependencies
echo -e "${GREEN}[1/5] Detecting package manager and installing core dependencies...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    echo -e "      Detected Debian / Ubuntu (apt)"
    $SUDO apt-get update -qq
    $SUDO apt-get install -y -qq build-essential g++ make libpcap-dev python3 python3-pip python3-venv
elif command -v dnf >/dev/null 2>&1; then
    echo -e "      Detected Fedora / RHEL (dnf)"
    $SUDO dnf install -y gcc-c++ make libpcap-devel python3 python3-pip
elif command -v pacman >/dev/null 2>&1; then
    echo -e "      Detected Arch Linux (pacman)"
    $SUDO pacman -Sy --noconfirm base-devel gcc make libpcap python python-pip
elif command -v zypper >/dev/null 2>&1; then
    echo -e "      Detected openSUSE (zypper)"
    $SUDO zypper install -y gcc-c++ make libpcap-devel python3 python3-pip
else
    echo -e "${YELLOW}[!] Unknown package manager. Please ensure g++, make, libpcap-dev, and python3-pip are installed manually.${NC}"
fi

# 3. Install Python Dependencies
echo -e "${GREEN}[2/5] Installing Python dependencies from requirements.txt...${NC}"
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt || true
else
    echo -e "${YELLOW}[!] requirements.txt not found, skipping pip install.${NC}"
fi

# 4. Compile NetSentinel Core
echo -e "${GREEN}[3/5] Compiling NetSentinel C++20 engine...${NC}"
make build

# 5. Set Packet Capture Capabilities
echo -e "${GREEN}[4/5] Configuring raw socket packet capture capabilities...${NC}"
if command -v setcap >/dev/null 2>&1 && [ -f "./netsentinel" ]; then
    $SUDO setcap cap_net_raw=ep ./netsentinel 2>/dev/null || true
    echo -e "      CAP_NET_RAW capability applied to ./netsentinel"
fi

# 6. Run Verification Tests
echo -e "${GREEN}[5/5] Running verification test suite...${NC}"
make test

echo ""
echo -e "${BLUE}================================================================${NC}"
echo -e "${GREEN}✓ NetSentinel installation completed successfully!${NC}"
echo -e "${BLUE}================================================================${NC}"
echo -e "To start the Web Command & Control Dashboard:"
echo -e "   ${YELLOW}./run.sh${NC}   or   ${YELLOW}make run${NC}"
echo ""
echo -e "To run standalone CLI capture:"
echo -e "   ${YELLOW}sudo ./netsentinel <interface>${NC}  (e.g., sudo ./netsentinel eth0)"
echo -e "${BLUE}================================================================${NC}"
