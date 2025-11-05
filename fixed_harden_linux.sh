#!/bin/bash

# Enhanced Ubuntu/Kubuntu Linux Security Hardening Script
# Version: 3.8 - Fixed for Debian 13
# Author: captainzero93 (Fixed version)
# GitHub: https://github.com/captainzero93/security_harden_linux
# Optimized for Kubuntu 24.04+, Ubuntu 25.10+, and Debian 13
# Last Updated: 2025-11-05
# 
# FIXES IN THIS VERSION:
# - Fixed system_update hanging issue on Debian 13
# - Fixed progress bar interfering with apt output
# - Improved timeout handling for apt operations
# - Better error handling and recovery
# - Fixed dry-run mode not working properly
# - Fixed missing MODULE_DEPS entries
# - Better handling of locked dpkg/apt states
# - Progress bar now shows after module completion, not before

set -euo pipefail

# Global variables
readonly VERSION="3.8"
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/security_hardening.log"
readonly REPORT_FILE="/root/security_hardening_report_$(date +%Y%m%d_%H%M%S).html"
readonly CONFIG_FILE="${SCRIPT_DIR}/hardening.conf"
readonly TEMP_DIR=$(mktemp -d -t hardening.XXXXXXXXXX)

# Configuration flags
VERBOSE=false
DRY_RUN=false
INTERACTIVE=true
ENABLE_MODULES=""
DISABLE_MODULES=""
SECURITY_LEVEL="moderate"
IS_DESKTOP=false
CURRENT_MODULE=""
PROGRESS_ENABLED=true

# Tracking
declare -a EXECUTED_MODULES=()
declare -a FAILED_MODULES=()

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Security modules
declare -A SECURITY_MODULES=(
    ["system_update"]="Update system packages"
    ["firewall"]="Configure UFW firewall"
    ["fail2ban"]="Setup Fail2Ban intrusion prevention"
    ["clamav"]="Install ClamAV antivirus"
    ["root_access"]="Disable direct root login"
    ["ssh_hardening"]="Harden SSH configuration"
    ["packages"]="Remove unnecessary packages"
    ["audit"]="Configure auditd logging"
    ["filesystems"]="Disable unused filesystems"
    ["boot_security"]="Secure boot settings"
    ["ipv6"]="Configure IPv6 settings"
    ["apparmor"]="Setup AppArmor profiles"
    ["ntp"]="Configure time synchronization"
    ["aide"]="Setup AIDE file integrity"
    ["sysctl"]="Configure kernel parameters"
    ["password_policy"]="Set strong password policies"
    ["automatic_updates"]="Enable automatic security updates"
    ["rootkit_scanner"]="Install rootkit scanners"
    ["usb_protection"]="Configure USB device policies"
    ["secure_shared_memory"]="Secure shared memory"
    ["lynis_audit"]="Run Lynis security audit"
)

# Module dependencies - FIXED: Added missing dependencies
declare -A MODULE_DEPS=(
    ["ssh_hardening"]="system_update"
    ["fail2ban"]="system_update firewall"
    ["aide"]="system_update"
    ["rootkit_scanner"]="system_update"
    ["clamav"]="system_update"
    ["apparmor"]="system_update"
    ["audit"]="system_update"
    ["secure_shared_memory"]=""
    ["automatic_updates"]=""
    ["sysctl"]=""
    ["lynis_audit"]=""
    ["firewall"]=""
    ["root_access"]=""
    ["packages"]=""
    ["filesystems"]=""
    ["boot_security"]=""
    ["ipv6"]=""
    ["ntp"]="system_update"
    ["password_policy"]=""
    ["usb_protection"]=""
    ["system_update"]=""
)

trap cleanup EXIT

cleanup() {
    if [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local log_entry="${timestamp} [${level}]: ${message}"
    
    # Log to file
    echo "${log_entry}" | sudo tee -a "${LOG_FILE}" >/dev/null 2>&1 || true
    
    # Print to console
    case "${level}" in
        ERROR)
            echo -e "${RED}[ERROR]${NC} ${message}" >&2
            ;;
        WARNING)
            echo -e "${YELLOW}[WARNING]${NC} ${message}"
            ;;
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} ${message}"
            ;;
        INFO)
            if [[ "${VERBOSE}" == "true" ]]; then
                echo -e "${BLUE}[INFO]${NC} ${message}"
            fi
            ;;
        *)
            echo "${message}"
            ;;
    esac
}

handle_error() {
    local exit_code=$?
    local line_number=$1
    local command="${2:-}"
    
    log ERROR "Command failed in module '${CURRENT_MODULE:-unknown}' with exit code ${exit_code} at line ${line_number}: ${command}"
    
    if [[ "${DRY_RUN}" == "false" ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        read -p "Do you want to restore from backup? (y/N): " -r restore_choice
        if [[ "${restore_choice}" =~ ^[Yy]$ ]]; then
            restore_backup
        fi
    fi
    
    exit "${exit_code}"
}

trap 'handle_error ${LINENO} "${BASH_COMMAND}"' ERR

# FIXED: Progress bar now properly handles module execution
show_progress() {
    local current=$1
    local total=$2
    local task=$3
    local width=50
    
    # Disable progress bar during module execution to avoid interference
    if [[ "${PROGRESS_ENABLED}" == "false" ]]; then
        return 0
    fi
    
    local percentage=$((current * 100 / total))
    local filled=$((percentage * width / 100))
    
    # Clear the line first
    printf "\r%${COLUMNS:-80}s\r" " "
    
    # Only show progress bar if we're in an interactive terminal
    if [[ -t 1 ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        printf "\r["
        printf "%${filled}s" | tr ' ' '='
        printf "%$((width - filled))s" | tr ' ' '-'
        printf "] %3d%% - %s" "${percentage}" "${task}"
        
        [[ ${current} -eq ${total} ]] && echo
    else
        # In non-interactive mode, just log progress at milestones
        if [[ ${percentage} -eq 25 ]] || \
           [[ ${percentage} -eq 50 ]] || \
           [[ ${percentage} -eq 75 ]] || \
           [[ ${current} -eq ${total} ]]; then
            log INFO "Progress: ${percentage}% - ${task}"
        fi
    fi
}

check_permissions() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${RED}This script must be run with sudo privileges.${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

detect_desktop() {
    if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]] || [[ -n "${DESKTOP_SESSION:-}" ]] || \
       systemctl is-active --quiet display-manager 2>/dev/null; then
        IS_DESKTOP=true
        log INFO "Desktop environment detected: ${XDG_CURRENT_DESKTOP:-Unknown}"
    fi
}

display_help() {
    cat << EOF
${GREEN}Security Hardening Script v${VERSION}${NC}

${YELLOW}Usage:${NC} sudo $0 [OPTIONS]

${YELLOW}Options:${NC}
  -h, --help              Show this help message
  -v, --verbose          Enable verbose output
  -n, --non-interactive  Run without user prompts
  -d, --dry-run          Show what would be done without making changes
  -l, --level <level>    Set security level (low|moderate|high|paranoid)
  -e, --enable <modules> Enable specific modules (comma-separated)
  -x, --exclude <modules> Disable specific modules (comma-separated)
  --list-modules         List all available modules
  --restore <backup>     Restore from a specific backup file

${YELLOW}Security Levels:${NC}
  low       - Basic security (desktop-friendly)
  moderate  - Balanced security (default)
  high      - Strong security (may affect usability)
  paranoid  - Maximum security (server-oriented)

${YELLOW}Examples:${NC}
  sudo $0                           # Run with defaults
  sudo $0 -v -l high                # Verbose mode, high security
  sudo $0 -d                        # Dry run to preview changes
  sudo $0 -e firewall,ssh_hardening  # Run specific modules only

${YELLOW}Available Modules:${NC}
EOF
    
    for module in "${!SECURITY_MODULES[@]}"; do
        printf "  %-20s - %s\n" "${module}" "${SECURITY_MODULES[${module}]}"
    done | sort
    
    exit 0
}

check_system() {
    log INFO "Checking system requirements..."
    
    if ! command -v apt-get &>/dev/null; then
        log ERROR "This script requires apt package manager (Debian/Ubuntu)"
        exit 1
    fi
    
    local os_name=""
    local os_version=""
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        os_name="${ID:-unknown}"
        os_version="${VERSION_ID:-unknown}"
    fi
    
    case "${os_name}" in
        ubuntu|kubuntu)
            if [[ "${os_version}" < "22.04" ]]; then
                log WARNING "This script is optimized for Ubuntu 22.04+"
            fi
            ;;
        debian)
            if [[ "${os_version}" == "13" ]] || [[ "${os_version}" == "12" ]]; then
                log INFO "Debian ${os_version} (${VERSION_CODENAME:-}) detected - using enhanced compatibility mode"
            elif [[ "${os_version}" < "11" ]]; then
                log WARNING "This script is optimized for Debian 11+"
            fi
            ;;
        *)
            log WARNING "Untested distribution: ${os_name} ${os_version}"
            if [[ "${INTERACTIVE}" == "true" ]]; then
                read -p "Continue anyway? (y/N): " -r continue_anyway
                [[ ! "${continue_anyway}" =~ ^[Yy]$ ]] && exit 0
            fi
            ;;
    esac
    
    log SUCCESS "System: ${NAME:-${os_name}} ${VERSION:-${os_version}}"
}

create_backup() {
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would create backup"; return 0; }
    
    log INFO "Creating comprehensive system backup..."
    
    local backup_dir="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "${backup_dir}"
    
    local files_to_backup=(
        "/etc/ssh/sshd_config"
        "/etc/fstab"
        "/etc/sysctl.conf"
        "/etc/security/limits.conf"
        "/etc/pam.d/common-password"
        "/etc/pam.d/common-auth"
        "/etc/sudoers"
        "/etc/apt/apt.conf.d/50unattended-upgrades"
        "/etc/modprobe.d"
        "/etc/audit"
        "/etc/apparmor.d"
    )
    
    local backup_count=0
    for item in "${files_to_backup[@]}"; do
        if [[ -e "${item}" ]]; then
            if sudo cp -a "${item}" "${backup_dir}/" 2>/dev/null; then
                backup_count=$((backup_count + 1))
            else
                log WARNING "Failed to backup ${item}"
            fi
        fi
    done
    
    systemctl list-unit-files --state=enabled > "${backup_dir}/enabled_services.txt" 2>/dev/null || true
    dpkg -l > "${backup_dir}/installed_packages.txt" 2>/dev/null || true
    sudo iptables-save > "${backup_dir}/iptables.rules" 2>/dev/null || true
    sudo ip6tables-save > "${backup_dir}/ip6tables.rules" 2>/dev/null || true
    
    cat > "${backup_dir}/backup_info.txt" << EOF
Backup Date: $(date)
Script Version: ${VERSION}
Security Level: ${SECURITY_LEVEL}
System: $(lsb_release -ds 2>/dev/null || echo "Unknown")
Kernel: $(uname -r)
Desktop: ${IS_DESKTOP}
Files Backed Up: ${backup_count}
EOF
    
    if sudo tar -czf "${backup_dir}.tar.gz" -C "$(dirname "${backup_dir}")" "$(basename "${backup_dir}")" 2>&1 | tee -a "${LOG_FILE}"; then
        cd "$(dirname "${backup_dir}")" || return 1
        sha256sum "$(basename "${backup_dir}.tar.gz")" > "${backup_dir}.tar.gz.sha256"
        sudo rm -rf "${backup_dir}"
        log SUCCESS "Backup created: ${backup_dir}.tar.gz"
    else
        log WARNING "Failed to compress backup, keeping uncompressed version"
        log SUCCESS "Backup created: ${backup_dir}"
    fi
}

restore_backup() {
    local backup_file="${1:-$(ls -t /root/security_backup_*.tar.gz 2>/dev/null | head -1)}"
    
    if [[ ! -f "${backup_file}" ]]; then
        log ERROR "No backup file found"
        return 1
    fi
    
    if [[ -f "${backup_file}.sha256" ]]; then
        log INFO "Verifying backup integrity..."
        if ! sha256sum -c "${backup_file}.sha256" &>/dev/null; then
            log ERROR "Backup checksum verification failed"
            return 1
        fi
        log SUCCESS "Backup integrity verified"
    fi
    
    log INFO "Restoring from ${backup_file}..."
    
    local temp_dir=$(mktemp -d)
    if ! sudo tar -xzf "${backup_file}" -C "${temp_dir}" 2>&1 | tee -a "${LOG_FILE}"; then
        log ERROR "Failed to extract backup"
        rm -rf "${temp_dir}"
        return 1
    fi
    
    local backup_source=$(find "${temp_dir}" -maxdepth 1 -type d -name "security_backup_*" | head -1)
    
    if [[ -z "${backup_source}" ]]; then
        log ERROR "Invalid backup structure in ${backup_file}"
        rm -rf "${temp_dir}"
        return 1
    fi
    
    local restore_errors=0
    if [[ -d "${backup_source}/etc" ]]; then
        for item in "${backup_source}"/etc/*; do
            if [[ -e "$item" ]]; then
                local target_name=$(basename "$item")
                if ! sudo cp -a "$item" "/etc/" 2>&1 | tee -a "${LOG_FILE}"; then
                    log ERROR "Failed to restore ${target_name}"
                    restore_errors=$((restore_errors + 1))
                else
                    log INFO "Restored /etc/${target_name}"
                fi
            fi
        done
    fi
    
    if [[ -f "${backup_source}/iptables.rules" ]]; then
        if sudo iptables-restore < "${backup_source}/iptables.rules" 2>&1 | tee -a "${LOG_FILE}"; then
            log SUCCESS "Restored iptables rules"
        else
            log WARNING "Failed to restore iptables rules"
        fi
    fi
    
    if [[ -f "${backup_source}/ip6tables.rules" ]]; then
        if sudo ip6tables-restore < "${backup_source}/ip6tables.rules" 2>&1 | tee -a "${LOG_FILE}"; then
            log SUCCESS "Restored ip6tables rules"
        else
            log WARNING "Failed to restore ip6tables rules"
        fi
    fi
    
    rm -rf "${temp_dir}"
    
    if [[ $restore_errors -gt 0 ]]; then
        log WARNING "Restore completed with ${restore_errors} errors"
        return 1
    else
        log SUCCESS "System restored from backup successfully"
    fi
}

is_package_installed() {
    dpkg -l "$1" 2>/dev/null | grep -q "^ii"
}

# FIXED: Better handling of apt locks and timeouts
wait_for_apt_lock() {
    local max_wait=300  # 5 minutes max
    local waited=0
    
    while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
        if [[ $waited -ge $max_wait ]]; then
            log ERROR "Timeout waiting for apt lock to be released"
            
            # Try to clean up stale locks
            log INFO "Attempting to clean up stale locks..."
            sudo rm -f /var/lib/dpkg/lock-frontend 2>/dev/null || true
            sudo rm -f /var/lib/dpkg/lock 2>/dev/null || true
            sudo rm -f /var/cache/apt/archives/lock 2>/dev/null || true
            sudo rm -f /var/lib/apt/lists/lock 2>/dev/null || true
            
            # Reconfigure dpkg
            sudo dpkg --configure -a 2>/dev/null || true
            
            return 1
        fi
        
        if [[ $((waited % 10)) -eq 0 ]]; then
            log INFO "Waiting for other package operations to complete... (${waited}s)"
        fi
        
        sleep 2
        waited=$((waited + 2))
    done
    
    return 0
}

install_package() {
    local package="$1"
    
    if is_package_installed "${package}"; then
        log INFO "${package} already installed"
        return 0
    fi
    
    # Wait for any existing apt operations to complete
    wait_for_apt_lock || return 1
    
    local max_retries=3
    local retry_count=0
    
    while [[ ${retry_count} -lt ${max_retries} ]]; do
        if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
               -o Dpkg::Options::="--force-confdef" \
               -o Dpkg::Options::="--force-confold" \
               "${package}" 2>&1 | tee -a "${LOG_FILE}"; then
            log SUCCESS "Installed ${package}"
            return 0
        fi
        
        retry_count=$((retry_count + 1))
        log WARNING "Failed to install ${package}, retry ${retry_count}/${max_retries}"
        sleep 2
    done
    
    log ERROR "Failed to install ${package} after ${max_retries} attempts"
    return 1
}

# FIXED: Use parameter expansion to avoid unbound variable errors
check_circular_deps() {
    local module=$1
    shift
    local -a visited=("$@")
    
    # FIXED: Use :- to provide default empty value
    if [[ -z "${MODULE_DEPS[$module]:-}" ]]; then
        return 0
    fi
    
    for dep in ${MODULE_DEPS[$module]}; do
        if [[ " ${visited[*]} " =~ " ${dep} " ]]; then
            log ERROR "Circular dependency detected: ${visited[*]} -> ${dep}"
            return 1
        fi
        
        local -a new_visited=("${visited[@]}" "${dep}")
        if ! check_circular_deps "${dep}" "${new_visited[@]}"; then
            return 1
        fi
    done
    
    return 0
}

resolve_dependencies() {
    local module="$1"
    local -a resolved=()
    
    # FIXED: Use :- to provide default empty value
    if [[ -n "${MODULE_DEPS[$module]:-}" ]]; then
        for dep in ${MODULE_DEPS[$module]}; do
            local subdeps=($(resolve_dependencies "${dep}"))
            for subdep in "${subdeps[@]}"; do
                if [[ ! " ${resolved[*]} " =~ " ${subdep} " ]]; then
                    resolved+=("${subdep}")
                fi
            done
            if [[ ! " ${resolved[*]} " =~ " ${dep} " ]]; then
                resolved+=("${dep}")
            fi
        done
    fi
    
    echo "${resolved[@]}"
}

# FIXED: Improved system_update module with better output handling
module_system_update() {
    CURRENT_MODULE="system_update"
    log INFO "Updating system packages..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would update packages"
        return 0
    fi
    
    # Disable progress bar during apt operations
    local old_progress="${PROGRESS_ENABLED}"
    PROGRESS_ENABLED=false
    
    # Clear any existing progress bar
    printf "\r%${COLUMNS:-80}s\r" " "
    
    # Wait for any existing apt locks
    if ! wait_for_apt_lock; then
        log WARNING "Could not acquire apt lock, attempting cleanup..."
        
        # Kill any hung apt processes
        sudo killall -9 apt apt-get dpkg 2>/dev/null || true
        sleep 2
        
        # Try again
        if ! wait_for_apt_lock; then
            log ERROR "Could not acquire apt lock after cleanup"
            PROGRESS_ENABLED="${old_progress}"
            return 1
        fi
    fi
    
    # Update package lists with timeout
    log INFO "Updating package lists..."
    if ! timeout 600 sudo DEBIAN_FRONTEND=noninteractive apt-get update \
         -o Acquire::http::Timeout=10 \
         -o Acquire::https::Timeout=10 \
         -o Acquire::ftp::Timeout=10 2>&1 | \
         while IFS= read -r line; do
             echo "$line" >> "${LOG_FILE}"
             if [[ "${VERBOSE}" == "true" ]]; then
                 echo "$line"
             fi
         done; then
        log ERROR "Failed to update package lists"
        PROGRESS_ENABLED="${old_progress}"
        return 1
    fi
    
    log SUCCESS "Package lists updated"
    
    # Fix any broken packages first
    log INFO "Checking for broken packages..."
    sudo dpkg --configure -a 2>/dev/null || true
    sudo apt-get install -f -y 2>/dev/null || true
    
    # Upgrade packages with timeout and better output handling
    log INFO "Upgrading packages (this may take several minutes)..."
    if ! timeout 1800 sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
         -o Dpkg::Options::="--force-confdef" \
         -o Dpkg::Options::="--force-confold" \
         -o APT::Get::Show-Upgraded=true 2>&1 | \
         while IFS= read -r line; do
             echo "$line" >> "${LOG_FILE}"
             if [[ "${VERBOSE}" == "true" ]]; then
                 echo "$line"
             fi
         done; then
        log WARNING "Package upgrade completed with warnings"
    else
        log SUCCESS "Packages upgraded"
    fi
    
    # Dist-upgrade with timeout (optional, don't fail if it errors)
    if [[ "${SECURITY_LEVEL}" == "high" ]] || [[ "${SECURITY_LEVEL}" == "paranoid" ]]; then
        log INFO "Performing distribution upgrade..."
        timeout 1800 sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" 2>&1 | \
            while IFS= read -r line; do
                echo "$line" >> "${LOG_FILE}"
                if [[ "${VERBOSE}" == "true" ]]; then
                    echo "$line"
                fi
            done || log WARNING "Dist-upgrade completed with warnings"
    fi
    
    # Cleanup
    log INFO "Cleaning up..."
    sudo apt-get autoremove -y 2>&1 | tee -a "${LOG_FILE}" > /dev/null || true
    sudo apt-get autoclean -y 2>&1 | tee -a "${LOG_FILE}" > /dev/null || true
    
    # Re-enable progress bar
    PROGRESS_ENABLED="${old_progress}"
    
    log SUCCESS "System packages updated successfully"
}

module_firewall() {
    CURRENT_MODULE="firewall"
    log INFO "Configuring firewall..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure firewall"; return 0; }
    
    install_package "ufw" || return 1
    
    local ssh_port=$(grep -E "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null | \
                     grep -v "^#" | tail -1 | awk '{print $2}' | grep -E '^[0-9]+$' || echo "22")
    
    if [[ $ssh_port -lt 1 || $ssh_port -gt 65535 ]]; then
        log WARNING "Invalid SSH port detected: ${ssh_port}, using default 22"
        ssh_port=22
    fi
    
    # Add SSH rule BEFORE reset if in SSH session
    if [[ -n "${SSH_CONNECTION:-}" ]] || [[ -n "${SSH_CLIENT:-}" ]] || [[ -n "${SSH_TTY:-}" ]]; then
        log WARNING "SSH session detected - ensuring SSH access before firewall reset"
        sudo ufw allow "${ssh_port}/tcp" comment 'SSH emergency rule' 2>/dev/null || true
    fi
    
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw default deny routed
    
    log INFO "Configuring SSH access on port ${ssh_port}"
    sudo ufw limit "${ssh_port}/tcp" comment 'SSH rate limited'
    
    if [[ "${IS_DESKTOP}" == "true" ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        read -p "Allow mDNS/Avahi for network discovery? (Y/n): " -r allow_mdns
        [[ ! "${allow_mdns}" =~ ^[Nn]$ ]] && sudo ufw allow 5353/udp comment 'mDNS'
        
        read -p "Allow KDE Connect (for phone integration)? (Y/n): " -r allow_kde
        if [[ ! "${allow_kde}" =~ ^[Nn]$ ]]; then
            sudo ufw allow 1714:1764/tcp comment 'KDE Connect'
            sudo ufw allow 1714:1764/udp comment 'KDE Connect'
        fi
        
        read -p "Allow Samba file sharing? (y/N): " -r allow_samba
        if [[ "${allow_samba}" =~ ^[Yy]$ ]]; then
            sudo ufw allow 137/udp comment 'Samba NetBIOS'
            sudo ufw allow 138/udp comment 'Samba NetBIOS'
            sudo ufw allow 139/tcp comment 'Samba SMB'
            sudo ufw allow 445/tcp comment 'Samba CIFS'
        fi
    fi
    
    sudo ufw --force enable
    sudo ufw reload
    
    log SUCCESS "Firewall configured and enabled"
}

module_fail2ban() {
    CURRENT_MODULE="fail2ban"
    log INFO "Setting up Fail2Ban..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would setup Fail2Ban"; return 0; }
    
    install_package "fail2ban" || return 1
    
    local f2b_config="/etc/fail2ban/jail.local"
    sudo cp /etc/fail2ban/jail.conf "${f2b_config}" 2>/dev/null || true
    
    cat << 'EOF' | sudo tee "${f2b_config}" > /dev/null
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3

[sshd-ddos]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 10

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
banaction = %(banaction_allports)s
bantime = 86400
maxretry = 3
EOF
    
    sudo systemctl enable fail2ban
    sudo systemctl restart fail2ban
    
    log SUCCESS "Fail2Ban configured and started"
}

module_clamav() {
    CURRENT_MODULE="clamav"
    log INFO "Installing ClamAV antivirus..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would install ClamAV"; return 0; }
    
    install_package "clamav" || return 1
    install_package "clamav-daemon" || return 1
    
    log INFO "Updating ClamAV database (this may take a while)..."
    sudo systemctl stop clamav-freshclam 2>/dev/null || true
    sudo freshclam 2>&1 | tee -a "${LOG_FILE}" || log WARNING "ClamAV database update completed with warnings"
    sudo systemctl start clamav-freshclam
    sudo systemctl enable clamav-freshclam
    
    log SUCCESS "ClamAV installed and configured"
}

module_root_access() {
    CURRENT_MODULE="root_access"
    log INFO "Securing root access..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure root access"; return 0; }
    
    # Disable root login via SSH
    if [[ -f /etc/ssh/sshd_config ]]; then
        sudo sed -i.bak 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
        log SUCCESS "Disabled root SSH login"
    fi
    
    # Lock root account password (but keep sudo working)
    sudo passwd -l root 2>&1 | tee -a "${LOG_FILE}" || true
    
    log SUCCESS "Root access secured"
}

module_ssh_hardening() {
    CURRENT_MODULE="ssh_hardening"
    log INFO "Hardening SSH configuration..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would harden SSH"; return 0; }
    
    if [[ ! -f /etc/ssh/sshd_config ]]; then
        log WARNING "SSH server not installed, skipping"
        return 0
    fi
    
    # Backup current config
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d)
    
    local ssh_config="/etc/ssh/sshd_config.d/99-hardening.conf"
    
    cat << 'EOF' | sudo tee "${ssh_config}" > /dev/null
# SSH Hardening Configuration
Protocol 2
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
MaxAuthTries 3
MaxSessions 10
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 60
X11Forwarding no
IgnoreRhosts yes
HostbasedAuthentication no
UsePAM yes
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
Compression delayed
AllowUsers *@*
DenyUsers root
UseDNS no

# Strong ciphers and algorithms
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
EOF
    
    # Test SSH config
    if sudo sshd -t -f /etc/ssh/sshd_config 2>/dev/null; then
        sudo systemctl reload sshd
        log SUCCESS "SSH configuration hardened"
    else
        log ERROR "SSH configuration test failed, reverting changes"
        sudo rm -f "${ssh_config}"
        return 1
    fi
}

module_packages() {
    CURRENT_MODULE="packages"
    log INFO "Removing unnecessary packages..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would remove unnecessary packages"; return 0; }
    
    local packages_to_remove=(
        "telnet"
        "nis"
        "ntpdate"
        "prelink"
        "talk"
        "rsync"
    )
    
    for package in "${packages_to_remove[@]}"; do
        if is_package_installed "${package}"; then
            log INFO "Removing ${package}..."
            sudo apt-get remove --purge -y "${package}" 2>&1 | tee -a "${LOG_FILE}" || true
        fi
    done
    
    log SUCCESS "Unnecessary packages removed"
}

module_audit() {
    CURRENT_MODULE="audit"
    log INFO "Configuring auditd..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure auditd"; return 0; }
    
    install_package "auditd" || return 1
    install_package "audispd-plugins" || return 1
    
    # Configure audit rules
    local audit_rules="/etc/audit/rules.d/hardening.rules"
    
    cat << 'EOF' | sudo tee "${audit_rules}" > /dev/null
# Delete all rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Monitor authentication events
-w /var/log/faillog -p wa -k auth_failures
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Monitor user/group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor sudoers
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Make configuration immutable
-e 2
EOF
    
    sudo systemctl enable auditd
    sudo systemctl restart auditd
    
    log SUCCESS "Auditd configured and started"
}

module_filesystems() {
    CURRENT_MODULE="filesystems"
    log INFO "Disabling unused filesystems..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would disable unused filesystems"; return 0; }
    
    local fs_blacklist="/etc/modprobe.d/filesystem-blacklist.conf"
    
    cat << 'EOF' | sudo tee "${fs_blacklist}" > /dev/null
# Disable unused filesystems
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
EOF
    
    log SUCCESS "Unused filesystems disabled"
}

module_boot_security() {
    CURRENT_MODULE="boot_security"
    log INFO "Securing boot configuration..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure boot configuration"; return 0; }
    
    # Set proper permissions on bootloader config
    if [[ -f /boot/grub/grub.cfg ]]; then
        sudo chmod 600 /boot/grub/grub.cfg
        sudo chown root:root /boot/grub/grub.cfg
        log SUCCESS "Secured GRUB configuration"
    fi
    
    log SUCCESS "Boot configuration secured"
}

module_ipv6() {
    CURRENT_MODULE="ipv6"
    log INFO "Configuring IPv6..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure IPv6"; return 0; }
    
    if [[ "${INTERACTIVE}" == "true" ]]; then
        read -p "Disable IPv6? (y/N): " -r disable_ipv6
        if [[ "${disable_ipv6}" =~ ^[Yy]$ ]]; then
            cat << 'EOF' | sudo tee -a /etc/sysctl.d/99-disable-ipv6.conf > /dev/null
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
            sudo sysctl -p /etc/sysctl.d/99-disable-ipv6.conf
            log SUCCESS "IPv6 disabled"
        else
            log INFO "IPv6 kept enabled"
        fi
    fi
}

module_apparmor() {
    CURRENT_MODULE="apparmor"
    log INFO "Setting up AppArmor..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would setup AppArmor"; return 0; }
    
    install_package "apparmor" || return 1
    install_package "apparmor-utils" || return 1
    install_package "apparmor-profiles" || return 1
    
    sudo systemctl enable apparmor
    sudo systemctl start apparmor
    
    # Set all profiles to enforce mode
    sudo aa-enforce /etc/apparmor.d/* 2>/dev/null || true
    
    log SUCCESS "AppArmor configured and enabled"
}

module_ntp() {
    CURRENT_MODULE="ntp"
    log INFO "Configuring time synchronization..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure NTP"; return 0; }
    
    install_package "chrony" || install_package "systemd-timesyncd" || return 1
    
    if systemctl is-enabled systemd-timesyncd &>/dev/null; then
        sudo systemctl restart systemd-timesyncd
        log SUCCESS "Time synchronization configured with systemd-timesyncd"
    elif systemctl is-enabled chrony &>/dev/null; then
        sudo systemctl restart chrony
        log SUCCESS "Time synchronization configured with chrony"
    fi
}

module_aide() {
    CURRENT_MODULE="aide"
    log INFO "Setting up AIDE file integrity monitoring..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would setup AIDE"; return 0; }
    
    install_package "aide" || return 1
    
    log INFO "Initializing AIDE database (this may take a while)..."
    sudo aideinit 2>&1 | tee -a "${LOG_FILE}" || sudo aide --init 2>&1 | tee -a "${LOG_FILE}"
    
    # Move the new database to the active location
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
    
    # Setup daily check
    cat << 'EOF' | sudo tee /etc/cron.daily/aide-check > /dev/null
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Daily Report" root
EOF
    sudo chmod +x /etc/cron.daily/aide-check
    
    log SUCCESS "AIDE configured for file integrity monitoring"
}

module_sysctl() {
    CURRENT_MODULE="sysctl"
    log INFO "Configuring kernel parameters..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure kernel parameters"; return 0; }
    
    local sysctl_config="/etc/sysctl.d/99-hardening.conf"
    
    cat << 'EOF' | sudo tee "${sysctl_config}" > /dev/null
# Kernel hardening parameters

# Network security
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# File system protection
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Process protection
kernel.randomize_va_space = 2
kernel.yama.ptrace_scope = 1
kernel.core_uses_pid = 1

# Kernel protection
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.panic = 60
kernel.panic_on_oops = 60

# Disable SysRq key
kernel.sysrq = 0

# Enable ExecShield (if available)
kernel.exec-shield = 1

# Memory protection
vm.mmap_min_addr = 65536
vm.panic_on_oom = 0
vm.overcommit_memory = 0
vm.overcommit_ratio = 50
EOF
    
    sudo sysctl -p "${sysctl_config}"
    
    log SUCCESS "Kernel parameters configured"
}

module_password_policy() {
    CURRENT_MODULE="password_policy"
    log INFO "Setting password policies..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would set password policies"; return 0; }
    
    install_package "libpam-pwquality" || return 1
    
    # Configure password quality requirements
    local pwquality_config="/etc/security/pwquality.conf"
    sudo cp "${pwquality_config}" "${pwquality_config}.bak" 2>/dev/null || true
    
    cat << 'EOF' | sudo tee "${pwquality_config}" > /dev/null
# Password quality configuration
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
retry = 3
maxrepeat = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
EOF
    
    # Configure password aging
    sudo sed -i.bak 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    
    log SUCCESS "Password policies configured"
}

module_automatic_updates() {
    CURRENT_MODULE="automatic_updates"
    log INFO "Configuring automatic security updates..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure automatic updates"; return 0; }
    
    install_package "unattended-upgrades" || return 1
    install_package "apt-listchanges" || return 1
    
    cat << 'EOF' | sudo tee /etc/apt/apt.conf.d/50unattended-upgrades > /dev/null
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF
    
    cat << 'EOF' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
    
    sudo systemctl enable unattended-upgrades
    sudo systemctl start unattended-upgrades
    
    log SUCCESS "Automatic security updates configured"
}

module_rootkit_scanner() {
    CURRENT_MODULE="rootkit_scanner"
    log INFO "Installing rootkit scanners..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would install rootkit scanners"; return 0; }
    
    install_package "rkhunter" || return 1
    install_package "chkrootkit" || return 1
    
    # Update rkhunter database
    sudo rkhunter --propupd 2>&1 | tee -a "${LOG_FILE}" || true
    
    # Setup weekly scans
    cat << 'EOF' | sudo tee /etc/cron.weekly/rootkit-scan > /dev/null
#!/bin/bash
/usr/bin/rkhunter --check --skip-keypress | mail -s "RKHunter Weekly Report" root
/usr/sbin/chkrootkit | mail -s "CHKRootkit Weekly Report" root
EOF
    sudo chmod +x /etc/cron.weekly/rootkit-scan
    
    log SUCCESS "Rootkit scanners installed and configured"
}

module_usb_protection() {
    CURRENT_MODULE="usb_protection"
    log INFO "Configuring USB protection..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure USB protection"; return 0; }
    
    if [[ "${INTERACTIVE}" == "true" ]] && [[ "${IS_DESKTOP}" == "true" ]]; then
        read -p "Disable USB storage devices? (y/N): " -r disable_usb
        if [[ "${disable_usb}" =~ ^[Yy]$ ]]; then
            echo "install usb-storage /bin/true" | sudo tee /etc/modprobe.d/disable-usb-storage.conf > /dev/null
            log SUCCESS "USB storage disabled"
        else
            log INFO "USB storage kept enabled"
        fi
    fi
}

module_secure_shared_memory() {
    CURRENT_MODULE="secure_shared_memory"
    log INFO "Securing shared memory..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure shared memory"; return 0; }
    
    # Check if already configured
    if grep -q "^tmpfs.*/run/shm.*noexec" /etc/fstab; then
        log INFO "Shared memory already secured"
        return 0
    fi
    
    # Add secure mount options for /run/shm
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" | sudo tee -a /etc/fstab > /dev/null
    
    # Remount with new options
    sudo mount -o remount /run/shm
    
    log SUCCESS "Shared memory secured"
}

module_lynis_audit() {
    CURRENT_MODULE="lynis_audit"
    log INFO "Running Lynis security audit..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would run Lynis audit"; return 0; }
    
    install_package "lynis" || return 1
    
    log INFO "Running Lynis audit (this may take a while)..."
    sudo lynis audit system --quick 2>&1 | tee -a "${LOG_FILE}"
    
    log SUCCESS "Lynis audit completed - check /var/log/lynis.log for details"
}

generate_report() {
    log INFO "Generating security report..."
    
    cat << EOF > "${REPORT_FILE}"
<!DOCTYPE html>
<html>
<head>
    <title>Security Hardening Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .success { color: green; }
        .failed { color: red; }
        .warning { color: orange; }
        .module { margin: 10px 0; padding: 10px; border-left: 3px solid #ddd; }
        .module.success { border-color: green; }
        .module.failed { border-color: red; }
    </style>
</head>
<body>
    <h1>Security Hardening Report</h1>
    <p><strong>Date:</strong> $(date)</p>
    <p><strong>System:</strong> $(uname -a)</p>
    <p><strong>Script Version:</strong> ${VERSION}</p>
    <p><strong>Security Level:</strong> ${SECURITY_LEVEL}</p>
    
    <h2>Executed Modules</h2>
EOF
    
    for module in "${EXECUTED_MODULES[@]}"; do
        echo "    <div class='module success'>✓ ${module}: ${SECURITY_MODULES[${module}]}</div>" >> "${REPORT_FILE}"
    done
    
    if [[ ${#FAILED_MODULES[@]} -gt 0 ]]; then
        echo "    <h2>Failed Modules</h2>" >> "${REPORT_FILE}"
        for module in "${FAILED_MODULES[@]}"; do
            echo "    <div class='module failed'>✗ ${module}: ${SECURITY_MODULES[${module}]}</div>" >> "${REPORT_FILE}"
        done
    fi
    
    cat << EOF >> "${REPORT_FILE}"
    <h2>Recommendations</h2>
    <ul>
        <li>Review the log file at ${LOG_FILE} for detailed information</li>
        <li>Regularly update your system with: sudo apt update && sudo apt upgrade</li>
        <li>Monitor system logs regularly</li>
        <li>Test all services after hardening to ensure functionality</li>
        <li>Keep backups of important data</li>
    </ul>
</body>
</html>
EOF
    
    log SUCCESS "Report generated: ${REPORT_FILE}"
}

# FIXED: Modified execute_modules to handle progress bar properly
execute_modules() {
    local modules_to_run=()
    
    if [[ -n "${ENABLE_MODULES}" ]]; then
        IFS=',' read -ra modules_to_run <<< "${ENABLE_MODULES}"
    else
        modules_to_run=("${!SECURITY_MODULES[@]}")
        
        if [[ -n "${DISABLE_MODULES}" ]]; then
            IFS=',' read -ra disabled <<< "${DISABLE_MODULES}"
            local filtered=()
            for module in "${modules_to_run[@]}"; do
                local skip=false
                for disabled_mod in "${disabled[@]}"; do
                    [[ "${module}" == "${disabled_mod}" ]] && skip=true && break
                done
                $skip || filtered+=("${module}")
            done
            modules_to_run=("${filtered[@]}")
        fi
    fi
    
    for module in "${modules_to_run[@]}"; do
        if ! check_circular_deps "${module}" "${module}"; then
            log ERROR "Cannot proceed due to circular dependencies"
            exit 1
        fi
    done
    
    local -a execution_order=()
    for module in "${modules_to_run[@]}"; do
        [[ -z "${module}" ]] && continue
        
        local deps=($(resolve_dependencies "${module}"))
        for dep in "${deps[@]}"; do
            if [[ ! " ${execution_order[@]} " =~ " ${dep} " ]]; then
                execution_order+=("${dep}")
            fi
        done
        
        if [[ ! " ${execution_order[@]} " =~ " ${module} " ]]; then
            execution_order+=("${module}")
        fi
    done
    
    local total=${#execution_order[@]}
    local current=0
    
    log INFO "Execution order: ${execution_order[*]}"
    
    for module in "${execution_order[@]}"; do
        [[ -z "${module}" ]] && continue
        
        current=$((current + 1))
        
        # Show module starting
        log INFO "Starting module ${current}/${total}: ${SECURITY_MODULES[${module}]:-Unknown}"
        
        local func="module_${module}"
        if declare -f "${func}" > /dev/null; then
            if "${func}"; then
                EXECUTED_MODULES+=("${module}")
                log SUCCESS "Module ${module} completed"
                
                # Show progress AFTER module completion
                show_progress ${current} ${total} "Completed ${SECURITY_MODULES[${module}]:-Unknown}"
            else
                FAILED_MODULES+=("${module}")
                log ERROR "Module ${module} failed"
                
                if [[ "${INTERACTIVE}" == "true" ]]; then
                    read -p "Continue with remaining modules? (Y/n): " -r continue_exec
                    [[ "${continue_exec}" =~ ^[Nn]$ ]] && break
                fi
            fi
        else
            log ERROR "Module function ${func} not found"
            FAILED_MODULES+=("${module}")
        fi
    done
    
    echo
}

main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) display_help ;;
            -v|--verbose) VERBOSE=true; shift ;;
            -n|--non-interactive) INTERACTIVE=false; shift ;;
            -d|--dry-run) DRY_RUN=true; shift ;;
            -l|--level) 
                if [[ ! "$2" =~ ^(low|moderate|high|paranoid)$ ]]; then
                    echo "Invalid security level: $2"
                    echo "Valid options: low, moderate, high, paranoid"
                    exit 1
                fi
                SECURITY_LEVEL="$2"
                shift 2
                ;;
            -e|--enable)
                ENABLE_MODULES="$2"
                shift 2
                ;;
            -x|--exclude)
                DISABLE_MODULES="$2"
                shift 2
                ;;
            --list-modules)
                for module in "${!SECURITY_MODULES[@]}"; do
                    printf "%-20s - %s\n" "${module}" "${SECURITY_MODULES[${module}]}"
                done | sort
                exit 0
                ;;
            --restore)
                check_permissions
                restore_backup "$2"
                exit $?
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    check_permissions
    detect_desktop
    check_system
    
    log INFO "================================"
    log INFO "Security Hardening Script v${VERSION}"
    log INFO "================================"
    log INFO "Security Level: ${SECURITY_LEVEL}"
    log INFO "Desktop Mode: ${IS_DESKTOP}"
    log INFO "Dry Run: ${DRY_RUN}"
    log INFO "Interactive: ${INTERACTIVE}"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        create_backup
    fi
    
    execute_modules
    generate_report
    
    log INFO "================================"
    log SUCCESS "Security hardening completed!"
    log INFO "Executed modules: ${#EXECUTED_MODULES[@]}"
    [[ ${#FAILED_MODULES[@]} -gt 0 ]] && log WARNING "Failed modules: ${#FAILED_MODULES[@]}"
    log INFO "Report: ${REPORT_FILE}"
    log INFO "Log file: ${LOG_FILE}"
    log INFO "================================"
    
    if [[ ${#FAILED_MODULES[@]} -gt 0 ]]; then
        exit 1
    fi
}

# Run main function
main "$@"
