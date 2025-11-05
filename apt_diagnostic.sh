#!/bin/bash

# APT System Diagnostic Script
# Tests for common issues that cause the hardening script to hang

echo "================================"
echo "APT System Diagnostic Tool"
echo "================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
   exit 1
fi

echo "1. Checking for running APT processes..."
APT_PROCS=$(ps aux | grep -E "apt|apt-get|dpkg" | grep -v grep)
if [[ -n "$APT_PROCS" ]]; then
    echo -e "${YELLOW}[WARNING]${NC} Found running APT processes:"
    echo "$APT_PROCS"
    echo ""
    read -p "Kill these processes? (y/N): " kill_choice
    if [[ "$kill_choice" =~ ^[Yy]$ ]]; then
        killall -9 apt apt-get dpkg 2>/dev/null || true
        echo -e "${GREEN}[OK]${NC} Processes killed"
    fi
else
    echo -e "${GREEN}[OK]${NC} No APT processes running"
fi
echo ""

echo "2. Checking for APT lock files..."
LOCK_FILES=(
    "/var/lib/dpkg/lock-frontend"
    "/var/lib/dpkg/lock"
    "/var/cache/apt/archives/lock"
    "/var/lib/apt/lists/lock"
)

LOCKS_FOUND=false
for lock in "${LOCK_FILES[@]}"; do
    if [[ -f "$lock" ]]; then
        echo -e "${YELLOW}[WARNING]${NC} Found lock file: $lock"
        LOCKS_FOUND=true
    fi
done

if [[ "$LOCKS_FOUND" == true ]]; then
    read -p "Remove lock files? (y/N): " remove_choice
    if [[ "$remove_choice" =~ ^[Yy]$ ]]; then
        for lock in "${LOCK_FILES[@]}"; do
            rm -f "$lock" 2>/dev/null || true
        done
        echo -e "${GREEN}[OK]${NC} Lock files removed"
    fi
else
    echo -e "${GREEN}[OK]${NC} No lock files found"
fi
echo ""

echo "3. Checking dpkg status..."
if dpkg --audit 2>/dev/null; then
    echo -e "${GREEN}[OK]${NC} dpkg status is clean"
else
    echo -e "${YELLOW}[WARNING]${NC} dpkg found issues"
    read -p "Attempt to fix? (y/N): " fix_choice
    if [[ "$fix_choice" =~ ^[Yy]$ ]]; then
        dpkg --configure -a
        apt-get install -f -y
        echo -e "${GREEN}[OK]${NC} Attempted dpkg repair"
    fi
fi
echo ""

echo "4. Testing APT update..."
echo "Running: apt-get update (with 30 second timeout)..."
if timeout 30 apt-get update >/dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC} APT update successful"
else
    echo -e "${RED}[ERROR]${NC} APT update failed or timed out"
    echo "This might indicate network issues or repository problems"
fi
echo ""

echo "5. Checking disk space..."
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [[ $DISK_USAGE -gt 90 ]]; then
    echo -e "${RED}[ERROR]${NC} Disk usage is critical: ${DISK_USAGE}%"
    echo "Free up disk space before running the hardening script"
elif [[ $DISK_USAGE -gt 80 ]]; then
    echo -e "${YELLOW}[WARNING]${NC} Disk usage is high: ${DISK_USAGE}%"
else
    echo -e "${GREEN}[OK]${NC} Disk usage is acceptable: ${DISK_USAGE}%"
fi
echo ""

echo "6. Checking system information..."
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "OS: ${NAME} ${VERSION}"
    echo "Codename: ${VERSION_CODENAME:-unknown}"
else
    echo "OS: Unknown"
fi
echo "Kernel: $(uname -r)"
echo "Architecture: $(uname -m)"
echo ""

echo "7. Testing timeout command..."
if timeout 2 sleep 1; then
    echo -e "${GREEN}[OK]${NC} Timeout command works properly"
else
    echo -e "${RED}[ERROR]${NC} Timeout command not working"
    echo "This is required for the hardening script to work properly"
fi
echo ""

echo "================================"
echo "Diagnostic Summary"
echo "================================"

# Final recommendations
echo ""
echo "Recommendations:"
echo "1. If APT processes were found and killed, wait a moment before running the hardening script"
echo "2. If lock files were removed, you may need to run: sudo dpkg --configure -a"
echo "3. If disk space is low, free up space before proceeding"
echo "4. If APT update failed, check your network connection and repository settings"
echo ""
echo "To run the hardening script after fixing issues:"
echo "  sudo ./fixed_harden_linux.sh -v"
echo ""
echo "To skip problematic modules:"
echo "  sudo ./fixed_harden_linux.sh -v -x system_update"
