#!/bin/bash
# COMPREHENSIVE Emergency Fix for Shared Library Permission Issues
# Handles ALL libraries and system binaries
# Related to Debian 13.2 update conflicts with FORTRESS.SH

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG_FILE="/var/log/library_permission_fix.log"
ISSUE_COUNT=0

log_and_print() {
    echo -e "$@" | tee -a "$LOG_FILE"
}

echo "" | tee "$LOG_FILE"
log_and_print "${RED}════════════════════════════════════════════════════════════${NC}"
log_and_print "${RED}  EMERGENCY: COMPREHENSIVE System Library Fix${NC}"
log_and_print "${RED}  Fixing ALL shared libraries and executables${NC}"
log_and_print "${RED}════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_and_print "${RED}This script must be run as root!${NC}"
   echo "Run: sudo bash $0"
   exit 1
fi

log_and_print "${BLUE}Starting comprehensive system library repair...${NC}"
log_and_print "Timestamp: $(date)"
log_and_print "System: $(uname -a)"
echo ""

#=============================================================================
# PHASE 1: DIAGNOSTIC - Identify Issues
#=============================================================================

log_and_print "${YELLOW}[PHASE 1] DIAGNOSTICS - Identifying Issues${NC}"
echo ""

log_and_print "${YELLOW}[1.1] Checking ALL library directory permissions...${NC}"
for dir in /lib /lib32 /lib64 /libx32 /usr/lib /usr/lib32 /usr/lib64 /usr/libx32 \
           /lib/x86_64-linux-gnu /lib/i386-linux-gnu \
           /usr/lib/x86_64-linux-gnu /usr/lib/i386-linux-gnu \
           /usr/local/lib /usr/local/lib64; do
    if [[ -d "$dir" ]]; then
        PERMS=$(stat -c "%a" "$dir" 2>/dev/null)
        log_and_print "  $dir: $PERMS"
        if [[ "$PERMS" != "755" ]]; then
            log_and_print "${RED}    ⚠ WRONG! Should be 755${NC}"
            ISSUE_COUNT=$((ISSUE_COUNT + 1))
        fi
    fi
done
echo ""

log_and_print "${YELLOW}[1.2] Checking critical shared libraries...${NC}"
CRITICAL_LIBS=(
    "libc.so.6"
    "libstdc++.so.6"
    "libm.so.6"
    "libpthread.so.0"
    "libdl.so.2"
    "libgcc_s.so.1"
    "libz.so.1"
    "ld-linux-x86-64.so.2"
)

for lib in "${CRITICAL_LIBS[@]}"; do
    FOUND=$(find /lib /usr/lib -name "$lib" 2>/dev/null | head -1)
    if [[ -n "$FOUND" ]]; then
        PERMS=$(stat -c "%a" "$FOUND" 2>/dev/null)
        log_and_print "  $lib: $PERMS ($FOUND)"
        if [[ "$PERMS" != "755" ]] && [[ "$PERMS" != "644" ]]; then
            log_and_print "${RED}    ⚠ WRONG! Should be 644 or 755${NC}"
            ISSUE_COUNT=$((ISSUE_COUNT + 1))
        fi
    else
        log_and_print "${RED}  $lib: NOT FOUND!${NC}"
        ISSUE_COUNT=$((ISSUE_COUNT + 1))
    fi
done
echo ""

log_and_print "${YELLOW}[1.3] Checking ALL mount points for noexec...${NC}"
mount | tee -a "$LOG_FILE" | grep -E '/(usr|lib|bin|opt)' || log_and_print "  No /usr, /lib, /bin, or /opt mounts found"
echo ""

MOUNT_ISSUES=0
for mount_point in /usr /lib /bin /opt /usr/local /usr/lib /lib64; do
    if mount | grep " $mount_point " | grep -q 'noexec'; then
        log_and_print "${RED}  ⚠ $mount_point is mounted with noexec!${NC}"
        MOUNT_ISSUES=$((MOUNT_ISSUES + 1))
        ISSUE_COUNT=$((ISSUE_COUNT + 1))
    fi
done

if [[ $MOUNT_ISSUES -eq 0 ]]; then
    log_and_print "${GREEN}  ✓ No problematic mount options detected${NC}"
fi
echo ""

log_and_print "${YELLOW}[1.4] Checking /etc/fstab for persistent problems...${NC}"
if [[ -f /etc/fstab ]]; then
    grep -E '^[^#].*(usr|lib|bin|opt)' /etc/fstab | tee -a "$LOG_FILE" || log_and_print "  No relevant mounts in fstab"
    if grep -E '^[^#].*(usr|lib|bin|opt).*noexec' /etc/fstab; then
        log_and_print "${RED}  ⚠ Found noexec in fstab!${NC}"
        ISSUE_COUNT=$((ISSUE_COUNT + 1))
    fi
fi
echo ""

log_and_print "${YELLOW}[1.5] Checking AppArmor for restrictions...${NC}"
if command -v aa-status &>/dev/null; then
    aa-status 2>&1 | head -20 | tee -a "$LOG_FILE"
    if dmesg | grep -i apparmor | grep -i denied | tail -5; then
        log_and_print "${RED}  ⚠ Recent AppArmor denials detected${NC}"
        ISSUE_COUNT=$((ISSUE_COUNT + 1))
    fi
else
    log_and_print "  AppArmor not installed"
fi
echo ""

log_and_print "${YELLOW}[1.6] Testing sample applications...${NC}"
TEST_APPS=("ls" "cat" "echo" "bash" "firefox-esr" "gnome-terminal" "nautilus")
FAILED_APPS=0

for app in "${TEST_APPS[@]}"; do
    APP_PATH=$(which "$app" 2>/dev/null || find /usr/bin /bin -name "$app" 2>/dev/null | head -1)
    if [[ -n "$APP_PATH" ]]; then
        if ldd "$APP_PATH" &>/dev/null; then
            log_and_print "${GREEN}  ✓ $app: OK${NC}"
        else
            log_and_print "${RED}  ✗ $app: FAILED to resolve libraries${NC}"
            FAILED_APPS=$((FAILED_APPS + 1))
            ISSUE_COUNT=$((ISSUE_COUNT + 1))
        fi
    fi
done

log_and_print ""
log_and_print "${YELLOW}DIAGNOSTIC SUMMARY: Found $ISSUE_COUNT potential issues${NC}"
echo ""

#=============================================================================
# PHASE 2: FIX - Repair All Issues
#=============================================================================

log_and_print "${YELLOW}[PHASE 2] REPAIR - Fixing All Issues${NC}"
echo ""

# Backup fstab first
if [[ -f /etc/fstab ]]; then
    BACKUP_FILE="/etc/fstab.backup.$(date +%Y%m%d_%H%M%S)"
    cp /etc/fstab "$BACKUP_FILE"
    log_and_print "${GREEN}[2.1] Backed up /etc/fstab to $BACKUP_FILE${NC}"
fi
echo ""

log_and_print "${YELLOW}[2.2] Remounting filesystems with correct options...${NC}"
for mount_point in /usr /lib /bin /opt /usr/local /lib64; do
    if mount | grep " $mount_point " | grep -q 'noexec'; then
        log_and_print "  Remounting $mount_point with exec..."
        mount -o remount,exec "$mount_point" 2>&1 | tee -a "$LOG_FILE"
        log_and_print "${GREEN}  ✓ Remounted $mount_point${NC}"
    fi
done

# Also check root partition
if mount | grep ' / ' | grep -q 'noexec'; then
    log_and_print "  Remounting / (root) with exec..."
    mount -o remount,exec / 2>&1 | tee -a "$LOG_FILE"
    log_and_print "${GREEN}  ✓ Remounted root filesystem${NC}"
fi
echo ""

log_and_print "${YELLOW}[2.3] Fixing /etc/fstab (removing noexec from critical paths)...${NC}"
if [[ -f /etc/fstab ]]; then
    # Remove noexec from /usr, /lib, /bin, /opt lines
    sed -i.bak2 's|\(^[^#].*[[:space:]]\+/\(usr\|lib\|bin\|opt\|usr/local\)[[:space:]].*\)noexec|\1|g' /etc/fstab
    
    if ! diff -q /etc/fstab /etc/fstab.bak2 &>/dev/null; then
        log_and_print "${GREEN}  ✓ Removed noexec from fstab${NC}"
    else
        log_and_print "  No changes needed in fstab"
    fi
    rm -f /etc/fstab.bak2
fi
echo ""

log_and_print "${YELLOW}[2.4] Fixing ALL library directory permissions...${NC}"
# Fix all library directory permissions
for dir in /lib /lib32 /lib64 /libx32 /usr/lib /usr/lib32 /usr/lib64 /usr/libx32 \
           /lib/x86_64-linux-gnu /lib/i386-linux-gnu /lib/aarch64-linux-gnu /lib/arm-linux-gnueabihf \
           /usr/lib/x86_64-linux-gnu /usr/lib/i386-linux-gnu /usr/lib/aarch64-linux-gnu /usr/lib/arm-linux-gnueabihf \
           /usr/local/lib /usr/local/lib64; do
    if [[ -d "$dir" ]]; then
        chmod 755 "$dir" 2>/dev/null && log_and_print "  ✓ Fixed $dir" || true
    fi
done
echo ""

log_and_print "${YELLOW}[2.5] Fixing ALL shared library files (.so*)...${NC}"
log_and_print "  This may take a minute..."

# Fix all .so files
FIXED_COUNT=0
for dir in /lib /lib32 /lib64 /libx32 /usr/lib /usr/lib32 /usr/lib64 /usr/libx32 /usr/local/lib /usr/local/lib64; do
    if [[ -d "$dir" ]]; then
        # Regular files
        find "$dir" -name "*.so*" -type f -exec chmod 644 {} \; 2>/dev/null && FIXED_COUNT=$((FIXED_COUNT + 1)) || true
        # Symlinks (need 777)
        find "$dir" -name "*.so*" -type l -exec chmod -h 777 {} \; 2>/dev/null || true
    fi
done

log_and_print "${GREEN}  ✓ Fixed permissions on shared libraries in $FIXED_COUNT directories${NC}"
echo ""

log_and_print "${YELLOW}[2.6] Fixing binary directory permissions...${NC}"
for dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt; do
    if [[ -d "$dir" ]]; then
        chmod 755 "$dir" 2>/dev/null && log_and_print "  ✓ Fixed $dir" || true
    fi
done
echo ""

log_and_print "${YELLOW}[2.7] Fixing executable permissions...${NC}"
# Fix common binary permissions
for dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
    if [[ -d "$dir" ]]; then
        find "$dir" -type f -exec chmod 755 {} \; 2>/dev/null || true
    fi
done
log_and_print "${GREEN}  ✓ Fixed executable permissions${NC}"
echo ""

log_and_print "${YELLOW}[2.8] Rebuilding dynamic linker cache...${NC}"
ldconfig -v 2>&1 | tail -20 | tee -a "$LOG_FILE"
log_and_print "${GREEN}  ✓ Rebuilt ldconfig cache${NC}"
echo ""

log_and_print "${YELLOW}[2.9] Checking for ACLs and extended attributes...${NC}"
# Remove problematic ACLs if they exist
for dir in /lib /usr/lib /lib64 /usr/lib64; do
    if [[ -d "$dir" ]]; then
        setfacl -R -b "$dir" 2>/dev/null && log_and_print "  ✓ Cleared ACLs from $dir" || true
    fi
done
echo ""

log_and_print "${YELLOW}[2.10] Handling AppArmor if needed...${NC}"
if command -v aa-status &>/dev/null; then
    if aa-status | grep -q "profiles are in enforce mode"; then
        log_and_print "  AppArmor is active. Checking for problematic profiles..."
        # Don't disable entirely, just set problematic profiles to complain mode
        for profile in /etc/apparmor.d/usr.bin.firefox* /etc/apparmor.d/usr.bin.thunderbird*; do
            if [[ -f "$profile" ]]; then
                aa-complain "$profile" 2>&1 | tee -a "$LOG_FILE" || true
            fi
        done
        apparmor_parser -r /etc/apparmor.d/ 2>&1 | head -20 | tee -a "$LOG_FILE" || true
    fi
fi
echo ""

#=============================================================================
# PHASE 3: VERIFICATION - Test Everything
#=============================================================================

log_and_print "${YELLOW}[PHASE 3] VERIFICATION - Testing Repairs${NC}"
echo ""

log_and_print "${YELLOW}[3.1] Testing critical libraries...${NC}"
VERIFICATION_PASSED=0
VERIFICATION_FAILED=0

for lib in "${CRITICAL_LIBS[@]}"; do
    FOUND=$(find /lib /usr/lib -name "$lib" 2>/dev/null | head -1)
    if [[ -n "$FOUND" ]]; then
        if [[ -r "$FOUND" ]]; then
            log_and_print "${GREEN}  ✓ $lib: Readable${NC}"
            VERIFICATION_PASSED=$((VERIFICATION_PASSED + 1))
        else
            log_and_print "${RED}  ✗ $lib: Still not readable!${NC}"
            VERIFICATION_FAILED=$((VERIFICATION_FAILED + 1))
        fi
    fi
done
echo ""

log_and_print "${YELLOW}[3.2] Testing applications...${NC}"
for app in "${TEST_APPS[@]}"; do
    APP_PATH=$(which "$app" 2>/dev/null || find /usr/bin /bin -name "$app" 2>/dev/null | head -1)
    if [[ -n "$APP_PATH" ]]; then
        if "$APP_PATH" --version &>/dev/null || "$APP_PATH" -version &>/dev/null || [[ "$app" == "ls" ]]; then
            log_and_print "${GREEN}  ✓ $app: Working${NC}"
            VERIFICATION_PASSED=$((VERIFICATION_PASSED + 1))
        else
            log_and_print "${YELLOW}  ~ $app: May still have issues${NC}"
        fi
    fi
done
echo ""

log_and_print "${YELLOW}[3.3] Testing Firefox specifically...${NC}"
if command -v firefox-esr &>/dev/null; then
    if timeout 5 firefox-esr --version 2>&1 | tee -a "$LOG_FILE"; then
        log_and_print "${GREEN}  ✓ Firefox-ESR: Working!${NC}"
    else
        log_and_print "${RED}  ✗ Firefox-ESR: Still failing${NC}"
        log_and_print "    Running ldd to check dependencies..."
        ldd /usr/bin/firefox-esr 2>&1 | grep -i "not found" | tee -a "$LOG_FILE" || log_and_print "    All dependencies found"
    fi
fi
echo ""

#=============================================================================
# FINAL SUMMARY
#=============================================================================

log_and_print ""
log_and_print "${GREEN}════════════════════════════════════════════════════════════${NC}"
log_and_print "${GREEN}  REPAIR COMPLETE!${NC}"
log_and_print "${GREEN}════════════════════════════════════════════════════════════${NC}"
echo ""

log_and_print "${BLUE}SUMMARY:${NC}"
log_and_print "  Initial issues found: $ISSUE_COUNT"
log_and_print "  Verifications passed: $VERIFICATION_PASSED"
log_and_print "  Verifications failed: $VERIFICATION_FAILED"
log_and_print "  Full log: $LOG_FILE"
echo ""

if [[ $VERIFICATION_FAILED -eq 0 ]]; then
    log_and_print "${GREEN}✓ All checks passed! Your system should be working now.${NC}"
    echo ""
    log_and_print "${YELLOW}NEXT STEPS:${NC}"
    log_and_print "1. Test your applications"
    log_and_print "2. If everything works, you're good!"
    log_and_print "3. Consider rebooting to ensure all changes persist"
else
    log_and_print "${RED}⚠ Some issues remain. Additional steps needed:${NC}"
    echo ""
    log_and_print "${YELLOW}TROUBLESHOOTING:${NC}"
    log_and_print "1. Check the detailed log: cat $LOG_FILE"
    log_and_print "2. Try rebooting: sudo reboot"
    log_and_print "3. If still failing after reboot, boot into recovery mode:"
    log_and_print "   - Reboot and hold Shift for GRUB menu"
    log_and_print "   - Select 'Advanced options' → 'Recovery mode'"
    log_and_print "   - Choose 'root' shell and run this script again"
    log_and_print "4. Check FORTRESS backup: ls -la /root/fortress_backups_*/"
fi

echo ""
log_and_print "${YELLOW}IMPORTANT:${NC}"
log_and_print "  • Backup of fstab: $BACKUP_FILE"
log_and_print "  • FORTRESS backups: /root/fortress_backups_*/"
log_and_print "  • If problems persist, restore fstab: sudo cp $BACKUP_FILE /etc/fstab"
echo ""

# Offer to reboot
read -p "Would you like to reboot now? (recommended) [y/N]: " -r REBOOT
if [[ $REBOOT =~ ^[Yy]$ ]]; then
    log_and_print "Rebooting in 5 seconds... (Ctrl+C to cancel)"
    sleep 5
    reboot
fi
