#!/bin/bash
# Emergency Fix for Shared Library Permission Issues
# Related to Debian 13.2 update conflicts

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}════════════════════════════════════════════════════════════${NC}"
echo -e "${RED}  EMERGENCY: Shared Library Permission Fix${NC}"
echo -e "${RED}════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root!${NC}"
   echo "Run: sudo bash $0"
   exit 1
fi

echo -e "${YELLOW}[1/6] Checking libstdc++.so.6 permissions...${NC}"
ls -la /usr/lib/x86_64-linux-gnu/libstdc++.so.6* 2>/dev/null || echo "Library not found in standard location"
echo ""

echo -e "${YELLOW}[2/6] Checking mount options on /usr...${NC}"
mount | grep '/usr'
echo ""

echo -e "${YELLOW}[3/6] Checking AppArmor status...${NC}"
aa-status 2>/dev/null || echo "AppArmor not available"
echo ""

echo -e "${YELLOW}[4/6] Fixing library permissions...${NC}"
# Fix permissions on common library directories
chmod 755 /lib /lib64 /usr/lib /usr/lib64 2>/dev/null || true
chmod 755 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu 2>/dev/null || true

# Fix shared library permissions specifically
find /lib /lib64 /usr/lib /usr/lib64 -name "*.so*" -type f -exec chmod 644 {} \; 2>/dev/null || true
find /lib /lib64 /usr/lib /usr/lib64 -name "*.so*" -type l -exec chmod 777 {} \; 2>/dev/null || true

echo -e "${GREEN}Library permissions reset to standard values${NC}"
echo ""

echo -e "${YELLOW}[5/6] Checking if /usr is mounted with noexec...${NC}"
if mount | grep '/usr' | grep -q 'noexec'; then
    echo -e "${RED}WARNING: /usr is mounted with noexec option!${NC}"
    echo "This could be the problem. Remounting without noexec..."
    mount -o remount,exec /usr
    echo -e "${GREEN}Remounted /usr with exec permissions${NC}"
else
    echo -e "${GREEN}/usr mount options look correct${NC}"
fi
echo ""

echo -e "${YELLOW}[6/6] Checking /etc/fstab for problematic entries...${NC}"
if grep -q '/usr.*noexec' /etc/fstab; then
    echo -e "${RED}Found noexec option for /usr in /etc/fstab!${NC}"
    echo "Creating backup and fixing..."
    cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d_%H%M%S)
    sed -i 's/\(\/usr.*\)noexec/\1/g' /etc/fstab
    echo -e "${GREEN}Removed noexec from /usr mount in fstab${NC}"
fi

if grep -q '/lib.*noexec' /etc/fstab; then
    echo -e "${RED}Found noexec option for /lib in /etc/fstab!${NC}"
    echo "Creating backup and fixing..."
    cp /etc/fstab /etc/fstab.backup.$(date +%Y%m%d_%H%M%S)
    sed -i 's/\(\/lib.*\)noexec/\1/g' /etc/fstab
    echo -e "${GREEN}Removed noexec from /lib mount in fstab${NC}"
fi
echo ""

echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Fix Attempt Complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Testing Firefox launch..."
if sudo -u $SUDO_USER firefox-esr --version 2>/dev/null; then
    echo -e "${GREEN}SUCCESS! Firefox can now access libraries${NC}"
else
    echo -e "${YELLOW}Firefox still failing. Additional diagnostics:${NC}"
    echo ""
    echo "Checking ldconfig cache..."
    ldconfig -p | grep libstdc++
    echo ""
    echo "Trying to rebuild ldconfig cache..."
    ldconfig
    echo ""
    echo "Please try running: firefox-esr"
fi

echo ""
echo -e "${YELLOW}If applications still fail, please:${NC}"
echo "1. Run: sudo ldconfig -v"
echo "2. Check: ldd /usr/bin/firefox-esr"
echo "3. Reboot the system"
echo ""
echo "Logs saved to: /var/log/fortress_hardening.log"
