#!/bin/bash
# RTR2-CTF Setup Script
# Rise The Ranger 2 - Digital Forensics CTF Toolkit

echo "=============================================="
echo "  RTR2-CTF Toolkit Setup"
echo "  Rise The Ranger 2 - Satsiber TNI 2026"
echo "=============================================="

echo ""
echo "[*] Checking Python..."
if command -v python3 &> /dev/null; then
    echo "    Python3: $(python3 --version)"
else
    echo "    Python3 NOT FOUND - please install Python 3.6+"
    exit 1
fi

echo ""
echo "[*] Installing Python packages..."
pip3 install --quiet pillow pypng 2>/dev/null
echo "    pillow, pypng: OK"

pip3 install --quiet volatility3 2>/dev/null && echo "    volatility3: OK" || echo "    volatility3: optional"

echo ""
echo "[*] Installing system packages..."
install_pkg() {
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y "$1" 2>/dev/null && echo "    $1: OK" || echo "    $1: optional"
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm "$1" 2>/dev/null && echo "    $1: OK" || echo "    $1: optional"
    fi
}

install_pkg "wireshark-common tshark"
install_pkg "foremost"
install_pkg "binwalk"
install_pkg "exiftool"
install_pkg "sleuthkit"
install_pkg "steghide"
install_pkg "testdisk"
install_pkg "yara"

echo ""
echo "[*] Installing zsteg (Ruby)..."
if command -v gem &> /dev/null; then
    gem install zsteg 2>/dev/null && echo "    zsteg: OK" || echo "    zsteg: optional (gem install zsteg)"
fi

echo ""
echo "[*] Testing main tool..."
if python3 rtr2_ctf.py info > /dev/null 2>&1; then
    echo "    rtr2_ctf.py: OK"
else
    echo "    rtr2_ctf.py: ERROR"
fi

echo ""
echo "[*] Available commands:"
echo "    python3 rtr2_ctf.py --help"
echo "    ./rtr2 info"
echo ""
echo "[*] Quick start:"
echo "    ./rtr2 auto evidence.bin"
echo "    ./rtr2 hash evidence.bin"
echo "    ./rtr2 pcap-creds capture.pcap"
echo ""
echo "=============================================="
echo "  Setup complete! Good luck di RTR2 2026!  "
echo "=============================================="
