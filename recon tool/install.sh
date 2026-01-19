#!/bin/bash
# install.sh - Installation script for Reconstack

echo "[*] Installing Reconstack dependencies..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[!] Please run as root (use sudo)"
    exit 1
fi

# Update and install system packages
echo "[*] Updating package lists and installing system dependencies..."
apt update
apt install -y \
    python3-pip \
    python3-venv \
    git \
    jq \
    curl \
    dnsutils \
    nmap \
    sublist3r \
    amass \
    gobuster \
    dirsearch \
    dnsx \
    httpx

# Install Python packages
echo "[*] Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

# Make scripts executable
chmod +x reconstack.sh
chmod +x install.sh

echo -e "\n[+] Installation complete!"
echo "[*] To get started, run: ./reconstack.sh -h"
echo "[*] Make sure to activate the virtual environment first: source venv/bin/activate"
