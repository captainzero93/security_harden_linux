#!/bin/bash
# FORTRESS.SH Health Verification Script v5.2
# Checks if hardening broke anything critical
#
# Author: captainzero93
# GitHub: https://github.com/captainzero93/security_harden_linux
# Run after applying FORTRESS.SH hardening to verify system health
#
# v5.2 changes:
# - Reports active SSH scanner-mode options (TCP/agent fwd, MaxSessions)
# - Checks for the kernel.yama.ptrace_scope sysctl
# - Reports if any modules were skipped due to excluded dependencies

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

PASSED=0
FAILED=0
WARNINGS=0

VERSION="5.2"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  FORTRESS.SH Health Verification v${VERSION}"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo ""

# Check if running as root (some tests need it)
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}Note: Running without root - some tests may be limited${NC}"
    echo ""
fi

#=============================================================================
# TEST 1: Basic System Commands
#=============================================================================

echo -e "${BLUE}[TEST 1] Basic System Commands${NC}"
echo "─────────────────────────────────────────────────"

if ls /tmp >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} ls command works"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}✗${NC} ls command FAILED"
    FAILED=$((FAILED + 1))
fi

if cat /etc/hostname >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} cat command works"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}✗${NC} cat command FAILED"
    FAILED=$((FAILED + 1))
fi

if echo "test" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} echo command works"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}✗${NC} echo command FAILED"
    FAILED=$((FAILED + 1))
fi

if bash --version >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} bash works"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}✗${NC} bash FAILED"
    FAILED=$((FAILED + 1))
fi

echo ""

#=============================================================================
# TEST 2: Network Connectivity
#=============================================================================

echo -e "${BLUE}[TEST 2] Network Connectivity${NC}"
echo "─────────────────────────────────────────────────"

if ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} IPv4 connectivity (ping 8.8.8.8)"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${RED}✗${NC} IPv4 connectivity FAILED"
    echo "      Hint: Check firewall rules and network configuration"
    FAILED=$((FAILED + 1))
fi

if ping -c 1 -W 3 google.com >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} DNS resolution (ping google.com)"
    PASSED=$((PASSED + 1))
else
    echo -e "  ${YELLOW}⚠${NC} DNS resolution may have issues"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

#=============================================================================
# TEST 3: Docker (if installed)
#=============================================================================

echo -e "${BLUE}[TEST 3] Docker (if installed)${NC}"
echo "─────────────────────────────────────────────────"

if command -v docker >/dev/null 2>&1; then
    echo "  Docker is installed"
    
    if docker ps >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Docker daemon is accessible"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}✗${NC} Docker daemon not accessible"
        echo "      Hint: Check if docker service is running"
        FAILED=$((FAILED + 1))
    fi
    
    # Test Docker networking
    echo "  Testing Docker container networking..."
    if docker run --rm alpine ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓${NC} Docker container networking works"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${RED}✗${NC} Docker container networking FAILED"
        echo "      Hint: Check net.ipv4.ip_forward in /etc/sysctl.d/99-fortress.conf"
        echo "      Fix: Set net.ipv4.ip_forward = 1 and run: sudo sysctl -p"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "  ${CYAN}○${NC} Docker not installed (skipped)"
fi

echo ""

#=============================================================================
# TEST 4: Browsers (if installed)
#=============================================================================

echo -e "${BLUE}[TEST 4] Web Browsers (if installed)${NC}"
echo "─────────────────────────────────────────────────"

BROWSER_FOUND=false

for browser in firefox firefox-esr chromium chromium-browser google-chrome brave-browser; do
    if command -v "$browser" >/dev/null 2>&1; then
        BROWSER_FOUND=true
        echo "  Testing $browser..."
        
        if timeout 5 "$browser" --version >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} $browser version check works"
            PASSED=$((PASSED + 1))
        else
            echo -e "  ${RED}✗${NC} $browser FAILED"
            echo "      Hint: Check /dev/shm mount options (noexec may be breaking it)"
            echo "      Check: grep /dev/shm /etc/fstab"
            echo "      Fix: Remove 'noexec' from /dev/shm mount and remount"
            FAILED=$((FAILED + 1))
        fi
    fi
done

if [[ "$BROWSER_FOUND" == "false" ]]; then
    echo -e "  ${CYAN}○${NC} No browsers detected (skipped)"
fi

echo ""

#=============================================================================
# TEST 5: SSH Service
#=============================================================================

echo -e "${BLUE}[TEST 5] SSH Service${NC}"
echo "─────────────────────────────────────────────────"

if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
    echo -e "  ${GREEN}✓${NC} SSH service is running"
    PASSED=$((PASSED + 1))
    
    # Check SSH config syntax
    if sshd -t 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} SSH configuration syntax valid"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${YELLOW}⚠${NC} SSH configuration has warnings"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "  ${CYAN}○${NC} SSH service not running (may be expected on desktop)"
fi

echo ""

#=============================================================================
# TEST 6: Firewall Status
#=============================================================================

echo -e "${BLUE}[TEST 6] Firewall Status${NC}"
echo "─────────────────────────────────────────────────"

if command -v ufw >/dev/null 2>&1; then
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "  ${GREEN}✓${NC} UFW firewall is active"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${YELLOW}⚠${NC} UFW firewall is not active"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "  ${CYAN}○${NC} UFW not installed"
fi

echo ""

#=============================================================================
# TEST 7: Critical Libraries
#=============================================================================

echo -e "${BLUE}[TEST 7] Critical Libraries${NC}"
echo "─────────────────────────────────────────────────"

CRITICAL_LIBS=("libc.so.6" "libstdc++.so.6" "libm.so.6" "libpthread.so.0" "libdl.so.2" "libgcc_s.so.1")

for lib in "${CRITICAL_LIBS[@]}"; do
    FOUND=$(find /lib /usr/lib -name "$lib" 2>/dev/null | head -1)
    if [[ -n "$FOUND" ]]; then
        if [[ -r "$FOUND" ]]; then
            echo -e "  ${GREEN}✓${NC} $lib readable"
            PASSED=$((PASSED + 1))
        else
            echo -e "  ${RED}✗${NC} $lib NOT readable"
            echo "      Fix: sudo chmod 644 $FOUND"
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} $lib not found (may be OK on some systems)"
        WARNINGS=$((WARNINGS + 1))
    fi
done

echo ""

#=============================================================================
# TEST 8: AppArmor Status
#=============================================================================

echo -e "${BLUE}[TEST 8] AppArmor Status${NC}"
echo "─────────────────────────────────────────────────"

if command -v aa-status >/dev/null 2>&1; then
    if systemctl is-active --quiet apparmor 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} AppArmor service is running"
        PASSED=$((PASSED + 1))
        
        PROFILES=$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')
        if [[ -n "$PROFILES" ]] && [[ "$PROFILES" -gt 0 ]]; then
            echo -e "  ${GREEN}✓${NC} $PROFILES profiles in enforce mode"
            PASSED=$((PASSED + 1))
        else
            echo -e "  ${YELLOW}⚠${NC} No profiles in enforce mode"
            WARNINGS=$((WARNINGS + 1))
        fi
    else
        echo -e "  ${YELLOW}⚠${NC} AppArmor service not running"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "  ${CYAN}○${NC} AppArmor not installed"
fi

echo ""

#=============================================================================
# TEST 9: Audit Daemon
#=============================================================================

echo -e "${BLUE}[TEST 9] Audit Daemon${NC}"
echo "─────────────────────────────────────────────────"

if command -v auditd >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
        echo -e "  ${GREEN}✓${NC} Audit daemon is running"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${YELLOW}⚠${NC} Audit daemon not running"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "  ${CYAN}○${NC} auditd not installed"
fi

echo ""

#=============================================================================
# TEST 10: Mount Options
#=============================================================================

echo -e "${BLUE}[TEST 10] Mount Options${NC}"
echo "─────────────────────────────────────────────────"

# Check if critical partitions have noexec (which would break things)
for mount_point in /usr /lib /lib64 /bin /sbin; do
    if mount | grep " $mount_point " | grep -q 'noexec'; then
        echo -e "  ${RED}✗${NC} $mount_point has noexec - THIS WILL BREAK THINGS"
        echo "      Fix: sudo mount -o remount,exec $mount_point"
        FAILED=$((FAILED + 1))
    fi
done

# Check /dev/shm
if mount | grep '/dev/shm' >/dev/null 2>&1; then
    SHM_OPTS=$(mount | grep '/dev/shm' | awk '{print $6}')
    if echo "$SHM_OPTS" | grep -q 'noexec'; then
        echo -e "  ${YELLOW}⚠${NC} /dev/shm has noexec (may break browsers)"
        WARNINGS=$((WARNINGS + 1))
    else
        echo -e "  ${GREEN}✓${NC} /dev/shm mount options OK for browsers"
        PASSED=$((PASSED + 1))
    fi
fi

echo ""

#=============================================================================
# TEST 11: FORTRESS Specific
#=============================================================================

echo -e "${BLUE}[TEST 11] FORTRESS Configuration${NC}"
echo "─────────────────────────────────────────────────"

if [[ -f /etc/sysctl.d/99-fortress.conf ]]; then
    echo -e "  ${GREEN}✓${NC} FORTRESS sysctl config exists"
    PASSED=$((PASSED + 1))
    
    # Check IP forwarding setting
    if grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.d/99-fortress.conf; then
        echo -e "  ${GREEN}✓${NC} IP forwarding enabled (Docker compatible)"
    else
        echo -e "  ${CYAN}○${NC} IP forwarding disabled (standard security)"
    fi
else
    echo -e "  ${YELLOW}⚠${NC} FORTRESS sysctl config not found"
    WARNINGS=$((WARNINGS + 1))
fi

if [[ -d /root/fortress_backups_* ]] 2>/dev/null; then
    BACKUP_DIR=$(ls -dt /root/fortress_backups_* 2>/dev/null | head -1)
    if [[ -n "$BACKUP_DIR" ]]; then
        echo -e "  ${GREEN}✓${NC} FORTRESS backup exists: $BACKUP_DIR"
        PASSED=$((PASSED + 1))
    fi
fi

echo ""

#=============================================================================
# TEST 12: SSH Scanner-Mode Compatibility  (v5.2)
#=============================================================================

echo -e "${BLUE}[TEST 12] SSH Configuration (v5.2)${NC}"
echo "─────────────────────────────────────────────────"

SSH_CFG="/etc/ssh/sshd_config"
if [[ -r "$SSH_CFG" ]]; then
    # Report the scanner-sensitive options exactly as sshd sees them.
    # sshd -T requires root, so fall back to grepping the file.
    ssh_report() {
        local opt="$1"
        local val
        if [[ $EUID -eq 0 ]] && command -v sshd >/dev/null 2>&1; then
            val=$(sshd -T 2>/dev/null | awk -v k="${opt,,}" 'tolower($1)==k{print $2; exit}')
        fi
        if [[ -z "${val:-}" ]]; then
            val=$(grep -iE "^[[:space:]]*${opt}[[:space:]]" "$SSH_CFG" 2>/dev/null \
                  | tail -1 | awk '{print $2}')
        fi
        echo "${val:-<default>}"
    }

    TCP_FWD=$(ssh_report AllowTcpForwarding)
    AGT_FWD=$(ssh_report AllowAgentForwarding)
    KBD_INT=$(ssh_report KbdInteractiveAuthentication)
    MAX_SES=$(ssh_report MaxSessions)
    PERM_RL=$(ssh_report PermitRootLogin)
    PW_AUTH=$(ssh_report PasswordAuthentication)

    echo "  AllowTcpForwarding       = ${TCP_FWD}"
    echo "  AllowAgentForwarding     = ${AGT_FWD}"
    echo "  KbdInteractiveAuthentication = ${KBD_INT}"
    echo "  MaxSessions              = ${MAX_SES}"
    echo "  PermitRootLogin          = ${PERM_RL}"
    echo "  PasswordAuthentication   = ${PW_AUTH}"

    # Call out the scanner-mode profile when we see it
    if [[ "${TCP_FWD,,}" == "yes" ]] && [[ "${AGT_FWD,,}" == "yes" ]]; then
        echo -e "  ${CYAN}○${NC} Looks like scanner-mode (TCP & agent forwarding enabled)."
        echo "      OK for Nessus/CIS credentialed scans; revert with --force-server if unwanted."
    fi

    # Sanity-validate the config parses
    if command -v sshd >/dev/null 2>&1; then
        if sshd -t 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} sshd_config parses cleanly"
            PASSED=$((PASSED + 1))
        else
            echo -e "  ${RED}✗${NC} sshd_config has syntax errors — 'sshd -t' failed"
            FAILED=$((FAILED + 1))
        fi
    fi
else
    echo -e "  ${CYAN}○${NC} No SSH server installed (skipped)"
fi

echo ""

#=============================================================================
# TEST 13: Sysctl kernel hardening (v5.2)
#=============================================================================

echo -e "${BLUE}[TEST 13] Kernel Sysctl Hardening${NC}"
echo "─────────────────────────────────────────────────"

check_sysctl() {
    local key="$1" want="$2"
    local have
    have=$(sysctl -n "$key" 2>/dev/null || echo "")
    if [[ -z "$have" ]]; then
        echo -e "  ${CYAN}○${NC} ${key} not present on this kernel"
        return
    fi
    if [[ "$have" == "$want" ]]; then
        echo -e "  ${GREEN}✓${NC} ${key} = ${have}"
        PASSED=$((PASSED + 1))
    else
        echo -e "  ${YELLOW}⚠${NC} ${key} = ${have} (FORTRESS default is ${want})"
        WARNINGS=$((WARNINGS + 1))
    fi
}
check_sysctl kernel.yama.ptrace_scope 1
check_sysctl kernel.kptr_restrict     2
check_sysctl kernel.dmesg_restrict    1
check_sysctl net.ipv4.tcp_syncookies  1
check_sysctl kernel.randomize_va_space 2

echo ""

#=============================================================================
# SUMMARY
#=============================================================================

echo "════════════════════════════════════════════════════════════════"
echo -e "${BLUE}VERIFICATION SUMMARY${NC}"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo -e "  ${GREEN}Passed:${NC}   $PASSED"
echo -e "  ${RED}Failed:${NC}   $FAILED"
echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
echo ""

if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  ⚠ SOME TESTS FAILED - ACTION REQUIRED${NC}"
    echo -e "${RED}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Recommended fixes:"
    echo ""
    echo "1. For library permission issues:"
    echo "   sudo ./fix_library_permissions.sh"
    echo ""
    echo "2. For Docker networking issues:"
    echo "   sudo sed -i 's/net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/' /etc/sysctl.d/99-fortress.conf"
    echo "   sudo sysctl -p /etc/sysctl.d/99-fortress.conf"
    echo ""
    echo "3. For browser issues:"
    echo "   sudo sed -i 's/nodev,nosuid,noexec/nodev,nosuid/' /etc/fstab"
    echo "   sudo mount -o remount /dev/shm"
    echo ""
    echo "4. View full diagnostic:"
    echo "   sudo ./PERM_diagnostic.sh"
    echo ""
    exit 1
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  ⚠ SOME WARNINGS - Review recommended${NC}"
    echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Warnings may indicate non-critical issues or expected configurations."
    echo "Review the warnings above and address if needed."
    echo ""
    exit 0
else
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  ✓ ALL CRITICAL TESTS PASSED!${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo "Your system appears to be functioning correctly after hardening."
    echo ""
    exit 0
fi
