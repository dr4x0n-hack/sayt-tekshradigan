#!/bin/bash
# install_pentest_tool.sh

echo "Kali Linux Pentest Tool - Auto Installer"
echo "========================================"

# Update system
echo "[1] Tizim yangilanmoqda..."
sudo apt update && sudo apt upgrade -y

# Install dependencies
echo "[2] Asosiy kutubxonalar o'rnatilmoqda..."
sudo apt install -y \
    python3 \
    python3-pip \
    python3-tk \
    nmap \
    whois \
    dnsutils

# Install Python packages
echo "[3] Python kutubxonalari o'rnatilmoqda..."
sudo pip3 install \
    requests \
    python-nmap \
    python-whois \
    dnspython \
    Pillow

# Download tool
echo "[4] Dastur yuklanmoqda..."
wget https://raw.githubusercontent.com/sizning-repo/kali-pentest-gui/main/kali_pentest_gui.py -O kali_pentest.py

# Make executable
chmod +x kali_pentest.py

echo ""
echo "✅ O'rnatish muvaffaqiyatli yakunlandi!"
echo "🖥️  Dasturni ishga tushirish: ./kali_pentest.py"
echo ""
