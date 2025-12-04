#!/bin/bash
# ULTRA-DIAGNOSTIC: Find the EXACT problem
# Run this and share ALL output

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG="/tmp/ultra_diagnostic_$(date +%Y%m%d_%H%M%S).log"

echo "ULTRA-DIAGNOSTIC REPORT" | tee "$LOG"
echo "======================" | tee -a "$LOG"
echo "Date: $(date)" | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Test if we're root
echo -e "${YELLOW}=== ROOT CHECK ===${NC}" | tee -a "$LOG"
if [[ $EUID -eq 0 ]]; then
    echo "✓ Running as root" | tee -a "$LOG"
else
    echo "✗ NOT running as root - some checks will fail" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Basic command test
echo -e "${YELLOW}=== BASIC COMMAND TEST ===${NC}" | tee -a "$LOG"
echo "Testing if basic commands work..." | tee -a "$LOG"
if /bin/ls /tmp >/dev/null 2>&1; then
    echo "✓ ls works" | tee -a "$LOG"
else
    echo "✗ ls FAILS" | tee -a "$LOG"
fi

if /bin/cat /etc/hostname >/dev/null 2>&1; then
    echo "✓ cat works" | tee -a "$LOG"
else
    echo "✗ cat FAILS" | tee -a "$LOG"
fi

if /bin/bash --version >/dev/null 2>&1; then
    echo "✓ bash works" | tee -a "$LOG"
else
    echo "✗ bash FAILS" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Check specific library
echo -e "${YELLOW}=== LIBSTDC++ SPECIFIC CHECK ===${NC}" | tee -a "$LOG"
LIBSTDCPP=$(find /lib /usr/lib -name "libstdc++.so.6" 2>/dev/null | head -1)
if [[ -n "$LIBSTDCPP" ]]; then
    echo "Found: $LIBSTDCPP" | tee -a "$LOG"
    ls -l "$LIBSTDCPP" | tee -a "$LOG"
    stat "$LIBSTDCPP" | tee -a "$LOG"
    echo "Can I read it as current user?" | tee -a "$LOG"
    if [[ -r "$LIBSTDCPP" ]]; then
        echo "✓ YES - Readable" | tee -a "$LOG"
    else
        echo "✗ NO - NOT readable!" | tee -a "$LOG"
    fi
    echo "Parent directory permissions:" | tee -a "$LOG"
    ls -ld "$(dirname "$LIBSTDCPP")" | tee -a "$LOG"
else
    echo "✗ libstdc++.so.6 NOT FOUND!" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Check ALL library directories
echo -e "${YELLOW}=== ALL LIBRARY DIRECTORY PERMISSIONS ===${NC}" | tee -a "$LOG"
for dir in /lib /lib64 /usr/lib /usr/lib64 /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu; do
    if [[ -d "$dir" ]]; then
        echo "Directory: $dir" | tee -a "$LOG"
        ls -ld "$dir" | tee -a "$LOG"
        stat -c "Perms: %a Owner: %U:%G" "$dir" | tee -a "$LOG"
        if [[ -r "$dir" ]] && [[ -x "$dir" ]]; then
            echo "✓ Accessible (read+exec)" | tee -a "$LOG"
        else
            echo "✗ NOT accessible!" | tee -a "$LOG"
        fi
        echo "" | tee -a "$LOG"
    fi
done

# Check ALL mounts in extreme detail
echo -e "${YELLOW}=== ALL MOUNT POINTS ===${NC}" | tee -a "$LOG"
mount | tee -a "$LOG"
echo "" | tee -a "$LOG"

echo -e "${YELLOW}=== MOUNTS WITH NOEXEC ===${NC}" | tee -a "$LOG"
if mount | grep noexec; then
    mount | grep noexec | tee -a "$LOG"
else
    echo "✓ No noexec mounts found" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Check /etc/fstab
echo -e "${YELLOW}=== /etc/fstab CONTENTS ===${NC}" | tee -a "$LOG"
if [[ -f /etc/fstab ]]; then
    cat /etc/fstab | tee -a "$LOG"
else
    echo "✗ /etc/fstab not found!" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Check ldconfig
echo -e "${YELLOW}=== LDCONFIG CHECK ===${NC}" | tee -a "$LOG"
echo "Checking if libstdc++ is in ldconfig cache..." | tee -a "$LOG"
if ldconfig -p | grep libstdc++; then
    ldconfig -p | grep libstdc++ | tee -a "$LOG"
else
    echo "✗ libstdc++ NOT in ldconfig cache!" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Try to load the library directly
echo -e "${YELLOW}=== DIRECT LIBRARY LOAD TEST ===${NC}" | tee -a "$LOG"
if [[ -n "$LIBSTDCPP" ]]; then
    echo "Attempting to directly access library file..." | tee -a "$LOG"
    if head -c 4 "$LIBSTDCPP" >/dev/null 2>&1; then
        echo "✓ Can read library file directly" | tee -a "$LOG"
    else
        echo "✗ CANNOT read library file!" | tee -a "$LOG"
        echo "Error was:" | tee -a "$LOG"
        head -c 4 "$LIBSTDCPP" 2>&1 | tee -a "$LOG"
    fi
fi
echo "" | tee -a "$LOG"

# Check AppArmor
echo -e "${YELLOW}=== APPARMOR STATUS ===${NC}" | tee -a "$LOG"
if command -v aa-status >/dev/null 2>&1; then
    aa-status 2>&1 | tee -a "$LOG"
else
    echo "AppArmor not installed" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Check for AppArmor denials
echo -e "${YELLOW}=== RECENT APPARMOR DENIALS ===${NC}" | tee -a "$LOG"
if dmesg | grep -i apparmor | grep -i denied | tail -20 >/dev/null 2>&1; then
    dmesg | grep -i apparmor | grep -i denied | tail -20 | tee -a "$LOG"
else
    echo "No AppArmor denials in dmesg" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Check SELinux
echo -e "${YELLOW}=== SELINUX CHECK ===${NC}" | tee -a "$LOG"
if command -v getenforce >/dev/null 2>&1; then
    getenforce 2>&1 | tee -a "$LOG"
    if [[ "$(getenforce 2>/dev/null)" != "Disabled" ]]; then
        echo "⚠ SELinux is active!" | tee -a "$LOG"
        ls -Z /usr/lib/x86_64-linux-gnu/libstdc++.so.6 2>&1 | tee -a "$LOG"
    fi
else
    echo "SELinux not installed" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Check ACLs
echo -e "${YELLOW}=== ACL CHECK ===${NC}" | tee -a "$LOG"
if command -v getfacl >/dev/null 2>&1; then
    echo "Checking ACLs on library directories..." | tee -a "$LOG"
    for dir in /lib /usr/lib; do
        if [[ -d "$dir" ]]; then
            echo "ACLs for $dir:" | tee -a "$LOG"
            getfacl "$dir" 2>&1 | tee -a "$LOG"
        fi
    done
else
    echo "getfacl not available" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Check namespaces
echo -e "${YELLOW}=== NAMESPACE CHECK ===${NC}" | tee -a "$LOG"
echo "Current namespaces:" | tee -a "$LOG"
ls -l /proc/$$/ns/ 2>&1 | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Try ldd on firefox
echo -e "${YELLOW}=== LDD ON FIREFOX ===${NC}" | tee -a "$LOG"
if [[ -f /usr/bin/firefox-esr ]]; then
    echo "Running ldd on firefox-esr..." | tee -a "$LOG"
    ldd /usr/bin/firefox-esr 2>&1 | tee -a "$LOG"
else
    echo "firefox-esr not found" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Try to actually run firefox
echo -e "${YELLOW}=== FIREFOX EXECUTION TEST ===${NC}" | tee -a "$LOG"
if [[ -f /usr/bin/firefox-esr ]]; then
    echo "Attempting to run firefox-esr --version..." | tee -a "$LOG"
    timeout 5 /usr/bin/firefox-esr --version 2>&1 | tee -a "$LOG"
    EXIT_CODE=$?
    echo "Exit code: $EXIT_CODE" | tee -a "$LOG"
    
    if [[ $EXIT_CODE -eq 0 ]]; then
        echo "✓ Firefox works!" | tee -a "$LOG"
    else
        echo "✗ Firefox failed with exit code $EXIT_CODE" | tee -a "$LOG"
    fi
fi
echo "" | tee -a "$LOG"

# Check strace if available
echo -e "${YELLOW}=== STRACE FIREFOX (if available) ===${NC}" | tee -a "$LOG"
if command -v strace >/dev/null 2>&1 && [[ -f /usr/bin/firefox-esr ]]; then
    echo "Running strace to see exactly what fails..." | tee -a "$LOG"
    timeout 3 strace -e trace=open,openat,access /usr/bin/firefox-esr --version 2>&1 | grep -i "libstdc\|denied\|EACCES\|EPERM" | head -20 | tee -a "$LOG"
else
    echo "strace not available or firefox not found" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Check system logs
echo -e "${YELLOW}=== RECENT PERMISSION DENIED ERRORS ===${NC}" | tee -a "$LOG"
journalctl -b | grep -i "permission denied" | tail -20 2>&1 | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Check for FORTRESS backups
echo -e "${YELLOW}=== FORTRESS BACKUPS ===${NC}" | tee -a "$LOG"
if [[ -d /root/fortress_backups_* ]]; then
    echo "Found FORTRESS backup(s):" | tee -a "$LOG"
    ls -la /root/ | grep fortress_backups | tee -a "$LOG"
    
    LATEST_BACKUP=$(ls -dt /root/fortress_backups_* | head -1)
    if [[ -n "$LATEST_BACKUP" ]]; then
        echo "Latest backup: $LATEST_BACKUP" | tee -a "$LOG"
        if [[ -f "$LATEST_BACKUP/etc/fstab" ]]; then
            echo "Backup fstab content:" | tee -a "$LOG"
            cat "$LATEST_BACKUP/etc/fstab" | tee -a "$LOG"
        fi
    fi
else
    echo "No FORTRESS backups found" | tee -a "$LOG"
fi
echo "" | tee -a "$LOG"

# Final summary
echo -e "${YELLOW}=== SUMMARY ===${NC}" | tee -a "$LOG"
echo "This diagnostic report has been saved to: $LOG" | tee -a "$LOG"
echo "" | tee -a "$LOG"
echo "Please share this ENTIRE output." | tee -a "$LOG"
echo "" | tee -a "$LOG"

# Create a copy as root-readable if we're root
if [[ $EUID -eq 0 ]]; then
    cp "$LOG" /root/ultra_diagnostic_$(date +%Y%m%d_%H%M%S).log
    echo "Also saved to /root/ for safety" | tee -a "$LOG"
fi

echo ""
echo -e "${GREEN}DIAGNOSTIC COMPLETE!${NC}"
echo -e "${GREEN}Log saved to: $LOG${NC}"
echo ""
echo "Please share ALL the output above, especially:"
echo "  1. Library directory permissions"
echo "  2. Mount output (any noexec?)"
echo "  3. ldd output for firefox"
echo "  4. strace output (if available)"
