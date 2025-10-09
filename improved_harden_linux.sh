#!/bin/bash

# Enhanced Ubuntu/Kubuntu Linux Security Hardening Script
# Version: 3.3 - Critical Fixes Applied
# Author: captainzero93
# GitHub: https://github.com/captainzero93/security_harden_linux
# Optimized for Kubuntu 24.04+ and Ubuntu 25.10+

set -euo pipefail

# Global variables
readonly VERSION="3.3-fixed"
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
readonly LOG_FILE="/var/log/security_hardening.log"
readonly REPORT_FILE="/root/security_hardening_report_$(date +%Y%m%d_%H%M%S).html"
readonly CONFIG_FILE="${SCRIPT_DIR}/hardening.conf"

# Configuration flags
VERBOSE=false
DRY_RUN=false
INTERACTIVE=true
ENABLE_MODULES=""
DISABLE_MODULES=""
SECURITY_LEVEL="moderate"
IS_DESKTOP=false
CURRENT_MODULE=""

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

declare -A MODULE_DEPS=(
    ["ssh_hardening"]="system_update"
    ["fail2ban"]="system_update firewall"
    ["aide"]="system_update"
    ["rootkit_scanner"]="system_update"
    ["clamav"]="system_update"
    ["apparmor"]="system_update"
)

trap cleanup EXIT

cleanup() {
    # Cleanup function - currently no temp directories used
    # Reserved for future use if needed
    :
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    local log_entry="${timestamp} [${level}]: ${message}"
    
    echo "${log_entry}" | sudo tee -a "${LOG_FILE}" >/dev/null
    
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
            $VERBOSE && echo -e "${BLUE}[INFO]${NC} ${message}"
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

show_progress() {
    local current=$1
    local total=$2
    local task=$3
    local width=50
    local percentage=$((current * 100 / total))
    local filled=$((percentage * width / 100))
    
    printf "\r["
    printf "%${filled}s" | tr ' ' '='
    printf "%$((width - filled))s" | tr ' ' '-'
    printf "] %3d%% - %s" "${percentage}" "${task}"
    
    [[ ${current} -eq ${total} ]] && echo
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
        log INFO "Desktop environment detected"
    fi
}

load_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        log INFO "Loading configuration from ${CONFIG_FILE}"
        source "${CONFIG_FILE}"
    fi
}

display_help() {
    cat << EOF
Usage: sudo ./${SCRIPT_NAME} [OPTIONS]

Enhanced Linux Security Hardening Script v${VERSION}
Optimized for Kubuntu 24.04+ and Ubuntu 25.10+

OPTIONS:
    -h, --help              Display this help message
    -v, --verbose           Enable verbose output
    -n, --non-interactive   Run without user prompts
    -d, --dry-run          Perform a dry run without changes
    -l, --level LEVEL      Set security level (low|moderate|high|paranoid)
    -e, --enable MODULES   Enable specific modules (comma-separated)
    -x, --disable MODULES  Disable specific modules (comma-separated)
    -r, --restore          Restore from most recent backup
    -R, --report           Generate security report only
    -c, --config FILE      Use custom configuration file
    --version              Display script version
    --list-modules         List available security modules

SECURITY LEVELS:
    low       - Basic security (desktop-friendly)
    moderate  - Balanced security (default, recommended for desktops)
    high      - Strong security (may impact some desktop features)
    paranoid  - Maximum security (significant impact on usability)

EXAMPLES:
    sudo ./${SCRIPT_NAME}
    sudo ./${SCRIPT_NAME} -e firewall,ssh_hardening,fail2ban
    sudo ./${SCRIPT_NAME} -n -l moderate

EOF
    exit 0
}

list_modules() {
    echo "Available Security Modules:"
    echo "=========================="
    for module in "${!SECURITY_MODULES[@]}"; do
        printf "  %-20s - %s\n" "${module}" "${SECURITY_MODULES[${module}]}"
    done
    exit 0
}

validate_security_level() {
    case "${SECURITY_LEVEL}" in
        low|moderate|high|paranoid)
            return 0
            ;;
        *)
            log ERROR "Invalid security level: ${SECURITY_LEVEL}"
            echo "Valid options: low, moderate, high, paranoid"
            exit 1
            ;;
    esac
}

# FIXED: Improved internet connectivity check with multiple fallbacks
check_internet() {
    local hosts=("8.8.8.8" "1.1.1.1" "208.67.222.222")
    for host in "${hosts[@]}"; do
        if ping -c 1 -W 2 "$host" &> /dev/null; then
            return 0
        fi
    done
    return 1
}

check_requirements() {
    log INFO "Checking system requirements..."
    
    if ! command -v lsb_release &> /dev/null; then
        log ERROR "lsb_release not found. Installing lsb-release..."
        sudo apt-get update && sudo apt-get install -y lsb-release
    fi
    
    local os_name=$(lsb_release -si)
    local os_version=$(lsb_release -sr)
    
    if [[ ! "${os_name}" =~ ^(Ubuntu|Debian|Kubuntu)$ ]]; then
        log ERROR "Unsupported OS: ${os_name}. This script supports Ubuntu/Kubuntu/Debian."
        exit 1
    fi
    
    if [[ "${os_name}" =~ ^(Ubuntu|Kubuntu)$ ]]; then
        if command -v bc &> /dev/null; then
            if [[ $(echo "${os_version} < 22.04" | bc 2>/dev/null || echo 0) -eq 1 ]]; then
                log WARNING "Optimized for Ubuntu/Kubuntu 22.04+. Detected: ${os_version}"
            fi
        fi
    fi
    
    local available_space=$(df /root | awk 'NR==2 {print $4}')
    if [[ ${available_space} -lt 1048576 ]]; then
        log WARNING "Low disk space ($(( available_space / 1024 ))MB). Backup may fail."
    fi
    
    if ! check_internet; then
        log WARNING "No internet connectivity. Package installation may fail."
    fi
    
    log SUCCESS "System: ${os_name} ${os_version}"
}

backup_files() {
    log INFO "Creating comprehensive system backup..."
    
    if ! sudo mkdir -p "${BACKUP_DIR}"; then
        log ERROR "Failed to create backup directory"
        return 1
    fi
    
    local files_to_backup=(
        "/etc/default/grub"
        "/etc/ssh/sshd_config"
        "/etc/pam.d/"
        "/etc/login.defs"
        "/etc/sysctl.conf"
        "/etc/sysctl.d/"
        "/etc/security/"
        "/etc/audit/"
        "/etc/modprobe.d/"
        "/etc/systemd/"
        "/etc/apparmor.d/"
        "/etc/fail2ban/"
        "/etc/ufw/"
        "/etc/sudoers"
        "/etc/sudoers.d/"
        "/etc/fstab"
        "/etc/hosts"
        "/etc/hosts.allow"
        "/etc/hosts.deny"
    )
    
    local backup_count=0
    for item in "${files_to_backup[@]}"; do
        if [[ -e "${item}" ]]; then
            if sudo cp -a "${item}" "${BACKUP_DIR}/" 2>/dev/null; then
                backup_count=$((backup_count + 1))
            else
                log WARNING "Failed to backup ${item}"
            fi
        fi
    done
    
    systemctl list-unit-files --state=enabled > "${BACKUP_DIR}/enabled_services.txt" 2>/dev/null || true
    dpkg -l > "${BACKUP_DIR}/installed_packages.txt" 2>/dev/null || true
    sudo iptables-save > "${BACKUP_DIR}/iptables.rules" 2>/dev/null || true
    sudo ip6tables-save > "${BACKUP_DIR}/ip6tables.rules" 2>/dev/null || true
    
    cat > "${BACKUP_DIR}/backup_info.txt" << EOF
Backup Date: $(date)
Script Version: ${VERSION}
Security Level: ${SECURITY_LEVEL}
System: $(lsb_release -ds)
Kernel: $(uname -r)
Desktop: ${IS_DESKTOP}
Files Backed Up: ${backup_count}
EOF
    
    if sudo tar -czf "${BACKUP_DIR}.tar.gz" -C "$(dirname "${BACKUP_DIR}")" "$(basename "${BACKUP_DIR}")" 2>&1 | tee -a "${LOG_FILE}"; then
        cd "$(dirname "${BACKUP_DIR}")" || return 1
        sha256sum "$(basename "${BACKUP_DIR}.tar.gz")" > "${BACKUP_DIR}.tar.gz.sha256"
        log SUCCESS "Backup created: ${BACKUP_DIR}.tar.gz"
    else
        log WARNING "Failed to compress backup, keeping uncompressed version"
        log SUCCESS "Backup created: ${BACKUP_DIR}"
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

install_package() {
    local package="$1"
    
    if is_package_installed "${package}"; then
        log INFO "${package} already installed"
        return 0
    fi
    
    local max_retries=3
    local retry_count=0
    
    while [[ ${retry_count} -lt ${max_retries} ]]; do
        if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${package}" 2>&1 | tee -a "${LOG_FILE}"; then
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

# NEW: Check for circular dependencies
check_circular_deps() {
    local module=$1
    shift
    local -a visited=("$@")
    
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
    
    if [[ -n "${MODULE_DEPS[$module]:-}" ]]; then
        for dep in ${MODULE_DEPS[$module]}; do
            if [[ ! " ${EXECUTED_MODULES[@]} " =~ " ${dep} " ]]; then
                local sub_deps=($(resolve_dependencies "${dep}"))
                for sub_dep in "${sub_deps[@]}"; do
                    if [[ ! " ${resolved[@]} " =~ " ${sub_dep} " ]]; then
                        resolved+=("${sub_dep}")
                    fi
                done
                resolved+=("${dep}")
            fi
        done
    fi
    
    echo "${resolved[@]}"
}

check_kernel_version() {
    local required_version="$1"
    local current_version=$(uname -r | cut -d. -f1-2)
    
    if command -v bc &> /dev/null; then
        if [[ $(echo "${current_version} >= ${required_version}" | bc 2>/dev/null || echo 0) -eq 1 ]]; then
            return 0
        fi
    fi
    return 1
}

# Module: System Update
module_system_update() {
    CURRENT_MODULE="system_update"
    log INFO "Updating system packages..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would update packages"; return 0; }
    
    if ! sudo apt-get update -y 2>&1 | tee -a "${LOG_FILE}"; then
        log ERROR "Failed to update package lists"
        return 1
    fi
    
    if ! sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y 2>&1 | tee -a "${LOG_FILE}"; then
        log ERROR "Failed to upgrade packages"
        return 1
    fi
    
    sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y 2>&1 | tee -a "${LOG_FILE}" || true
    sudo apt-get autoremove -y 2>&1 | tee -a "${LOG_FILE}" || true
    sudo apt-get autoclean -y 2>&1 | tee -a "${LOG_FILE}" || true
    
    log SUCCESS "System packages updated"
}

# Module: Firewall
module_firewall() {
    CURRENT_MODULE="firewall"
    log INFO "Configuring firewall..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure firewall"; return 0; }
    
    install_package "ufw" || return 1
    
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw default deny routed
    
    local ssh_port=$(grep -E "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null | \
                     tail -1 | awk '{print $2}' | grep -E '^[0-9]+$' || echo "22")
    
    if [[ $ssh_port -lt 1 || $ssh_port -gt 65535 ]]; then
        log WARNING "Invalid SSH port detected: ${ssh_port}, using default 22"
        ssh_port=22
    fi
    
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
    fi
    
    sudo ufw logging medium
    sudo ufw --force enable
    
    log SUCCESS "Firewall configured"
}

# Module: Root Access
module_root_access() {
    CURRENT_MODULE="root_access"
    log INFO "Configuring root access restrictions..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would restrict root"; return 0; }
    
    local sudo_users=$(getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v "^root$" | grep -v "^$")
    
    if [[ -z "${sudo_users}" ]]; then
        log WARNING "No non-root users with sudo privileges found. Skipping root login disable for safety."
        echo "Please create a non-root user with sudo privileges before disabling root login."
        return 0
    fi
    
    log INFO "Non-root sudo users found: $(echo ${sudo_users} | tr '\n' ' ')"
    
    if sudo passwd -l root 2>&1 | tee -a "${LOG_FILE}"; then
        log SUCCESS "Root password login disabled"
    else
        log ERROR "Failed to lock root account"
        return 1
    fi
    
    if ! grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
        echo "auth required pam_wheel.so use_uid group=sudo" | sudo tee -a /etc/pam.d/su > /dev/null
        log SUCCESS "Restricted su command to sudo group"
    fi
    
    log SUCCESS "Root access restricted"
}

# FIXED: Module: SSH Hardening - Added SSH key verification
module_ssh_hardening() {
    CURRENT_MODULE="ssh_hardening"
    log INFO "Hardening SSH..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would harden SSH"; return 0; }
    
    local sshd_config="/etc/ssh/sshd_config"
    [[ ! -f "${sshd_config}" ]] && { log ERROR "SSH not installed"; return 1; }
    
    # FIXED: Check for SSH keys before disabling password authentication
    local has_ssh_keys=false
    if find /home -name "authorized_keys" -type f 2>/dev/null | grep -q .; then
        has_ssh_keys=true
        log INFO "SSH keys found for users"
    else
        log WARNING "No SSH keys found in user directories"
    fi
    
    sudo cp "${sshd_config}" "${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"
    
    local ssh_settings=(
        "Protocol 2"
        "PermitRootLogin no"
        "PubkeyAuthentication yes"
        "PermitEmptyPasswords no"
        "ChallengeResponseAuthentication no"
        "UsePAM yes"
        "X11Forwarding no"
        "PrintMotd no"
        "TCPKeepAlive yes"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 2"
        "MaxAuthTries 3"
        "MaxSessions 10"
        "MaxStartups 10:30:60"
        "LoginGraceTime 60"
    )
    
    # FIXED: Only disable password auth if SSH keys are present or user confirms
    if [[ "${has_ssh_keys}" == "true" ]]; then
        ssh_settings+=("PasswordAuthentication no")
    else
        if [[ "${INTERACTIVE}" == "true" ]]; then
            echo ""
            log WARNING "No SSH keys detected. Disabling password authentication without SSH keys will lock you out!"
            read -p "Do you have SSH keys configured and want to disable password auth? (y/N): " -r disable_pass
            if [[ "${disable_pass}" =~ ^[Yy]$ ]]; then
                ssh_settings+=("PasswordAuthentication no")
                log WARNING "Password authentication will be disabled. Ensure SSH keys work before logging out!"
            else
                ssh_settings+=("PasswordAuthentication yes")
                log INFO "Password authentication remains enabled for safety"
            fi
        else
            ssh_settings+=("PasswordAuthentication yes")
            log INFO "Password authentication remains enabled (no SSH keys found)"
        fi
    fi
    
    for setting in "${ssh_settings[@]}"; do
        local key=$(echo "${setting}" | cut -d' ' -f1)
        
        # Remove all existing entries for this key (commented or not)
        sudo sed -i "/^[#[:space:]]*${key}[[:space:]]/d" "${sshd_config}"
        
        # Add new setting at the end
        echo "${setting}" | sudo tee -a "${sshd_config}" > /dev/null
        log INFO "Set SSH parameter: ${setting}"
    done
    
    if sudo sshd -t 2>&1 | tee -a "${LOG_FILE}"; then
        sudo systemctl restart sshd
        log SUCCESS "SSH hardened and restarted"
    else
        log ERROR "SSH config validation failed, restoring backup"
        local latest_backup=$(ls -t "${sshd_config}.backup."* 2>/dev/null | head -1)
        [[ -n "${latest_backup}" ]] && sudo cp "${latest_backup}" "${sshd_config}"
        return 1
    fi
}

# Module: Fail2Ban
module_fail2ban() {
    CURRENT_MODULE="fail2ban"
    log INFO "Configuring Fail2Ban..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure Fail2Ban"; return 0; }
    
    install_package "fail2ban" || return 1
    
    cat << 'EOF' | sudo tee /etc/fail2ban/jail.local > /dev/null
[DEFAULT]
bantime  = 3600
findtime  = 600
maxretry = 5
backend = systemd

[sshd]
enabled = true
maxretry = 3
bantime  = 7200
EOF
    
    sudo systemctl enable fail2ban
    sudo systemctl restart fail2ban
    
    log SUCCESS "Fail2Ban configured"
}

# Module: ClamAV
module_clamav() {
    CURRENT_MODULE="clamav"
    log INFO "Installing ClamAV antivirus..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would install ClamAV"; return 0; }
    
    install_package "clamav" || return 1
    install_package "clamav-daemon" || return 1
    
    sudo systemctl stop clamav-freshclam 2>/dev/null || true
    if sudo freshclam 2>&1 | tee -a "${LOG_FILE}"; then
        log SUCCESS "ClamAV database updated"
    else
        log WARNING "Failed to update ClamAV database"
    fi
    sudo systemctl start clamav-freshclam
    sudo systemctl enable clamav-freshclam
    
    log INFO "ClamAV installed. Run 'sudo clamscan -r /home' to scan manually"
    log SUCCESS "ClamAV installed"
}

# Module: Remove Unnecessary Packages
module_packages() {
    CURRENT_MODULE="packages"
    log INFO "Removing unnecessary packages..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would remove packages"; return 0; }
    
    local packages_to_remove=(
        "telnet"
        "telnetd"
        "rsh-client"
        "rsh-redone-client"
        "nis"
        "yp-tools"
        "xinetd"
    )
    
    for pkg in "${packages_to_remove[@]}"; do
        if is_package_installed "${pkg}"; then
            log INFO "Removing ${pkg}"
            sudo apt-get remove --purge -y "${pkg}" 2>&1 | tee -a "${LOG_FILE}" || true
        fi
    done
    
    log SUCCESS "Unnecessary packages removed"
}

# Module: Auditd
module_audit() {
    CURRENT_MODULE="audit"
    log INFO "Configuring audit logging..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure auditd"; return 0; }
    
    install_package "auditd" || return 1
    install_package "audispd-plugins" || return 1
    
    cat << 'EOF' | sudo tee /etc/audit/rules.d/hardening.rules > /dev/null
# Monitor authentication
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Monitor network changes
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change

# Monitor login/logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
EOF
    
    sudo systemctl enable auditd
    if sudo systemctl restart auditd 2>&1 | tee -a "${LOG_FILE}"; then
        log SUCCESS "Auditd configured and restarted"
    else
        log WARNING "Auditd configuration may require manual restart"
    fi
}

# Module: Disable Unused Filesystems
module_filesystems() {
    CURRENT_MODULE="filesystems"
    log INFO "Disabling unused filesystems..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would disable filesystems"; return 0; }
    
    local filesystems=(
        "cramfs"
        "freevxfs"
        "jffs2"
        "hfs"
        "hfsplus"
        "udf"
    )
    
    for fs in "${filesystems[@]}"; do
        echo "install ${fs} /bin/true" | sudo tee "/etc/modprobe.d/${fs}.conf" > /dev/null
        log INFO "Disabled filesystem: ${fs}"
    done
    
    log SUCCESS "Unused filesystems disabled"
}

# FIXED: Module: Boot Security - Fixed regex escaping
module_boot_security() {
    CURRENT_MODULE="boot_security"
    log INFO "Securing boot configuration with kernel hardening..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure boot"; return 0; }
    
    local grub_config="/etc/default/grub"
    [[ ! -f "${grub_config}" ]] && { log WARNING "GRUB config not found"; return 0; }
    
    sudo cp "${grub_config}" "${grub_config}.backup.$(date +%Y%m%d_%H%M%S)" || return 1
    
    local kernel_params=(
        "page_alloc.shuffle=1"
        "slab_nomerge"
        "init_on_alloc=1"
        "init_on_free=1"
        "randomize_kstack_offset=1"
        "vsyscall=none"
        "debugfs=off"
        "oops=panic"
        "module.sig_enforce=1"
    )
    
    # Add kernel version dependent parameters
    if check_kernel_version "5.4"; then
        kernel_params+=("lockdown=confidentiality")
        log INFO "Added lockdown parameter (kernel 5.4+)"
    fi
    
    # Add sysctl-style parameters conditionally
    if check_kernel_version "5.0"; then
        kernel_params+=(
            "kernel.unprivileged_bpf_disabled=1"
            "net.core.bpf_jit_harden=2"
            "kernel.kptr_restrict=2"
            "kernel.dmesg_restrict=1"
            "kernel.perf_event_paranoid=3"
        )
    fi
    
    # Add memory randomization
    kernel_params+=(
        "vm.mmap_rnd_bits=32"
        "vm.mmap_rnd_compat_bits=16"
    )
    
    if [[ "${IS_DESKTOP}" == "false" ]] || [[ "${SECURITY_LEVEL}" =~ ^(high|paranoid)$ ]]; then
        kernel_params+=("nousb")
        log INFO "Added USB boot restriction"
    fi
    
    local current_params=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" "${grub_config}" | sed 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/\1/')
    
    local added_count=0
    local updated_params="${current_params}"
    
    for param in "${kernel_params[@]}"; do
        local param_key="${param%%=*}"
        local param_value="${param#*=}"
        
        # FIXED: Properly escape dots and other regex metacharacters
        local escaped_key=$(printf '%s\n' "$param_key" | sed 's/[.[\*^$]/\\&/g')
        
        # Check if parameter exists (with any value) using escaped key
        if echo " ${updated_params} " | grep -qE "[[:space:]]${escaped_key}(=[^[:space:]]*)?[[:space:]]"; then
            local existing_value=$(echo " ${updated_params} " | grep -oE "${escaped_key}=[^[:space:]]+" | cut -d= -f2 || echo "")
            if [[ "${existing_value}" != "${param_value}" ]] && [[ -n "${param_value}" ]]; then
                # Replace using escaped key
                updated_params=$(echo "${updated_params}" | sed -E "s/${escaped_key}=[^[:space:]]*/${param}/g")
                log INFO "Updated kernel parameter: ${param} (was: ${param_key}=${existing_value})"
                added_count=$((added_count + 1))
            else
                log INFO "Kernel parameter already present: ${param_key}"
            fi
        else
            updated_params="${updated_params} ${param}"
            added_count=$((added_count + 1))
            log INFO "Added kernel parameter: ${param}"
        fi
    done
    
    if [[ ${added_count} -gt 0 ]]; then
        updated_params=$(echo "${updated_params}" | sed 's/  */ /g' | sed 's/^ //;s/ $//')
        sudo sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${updated_params}\"|" "${grub_config}"
        log SUCCESS "Added/updated ${added_count} kernel hardening parameters"
    else
        log INFO "All kernel parameters already present with correct values"
    fi
    
    if [[ -e /dev/mapper/crypt* ]] || lsblk -o TYPE,FSTYPE 2>/dev/null | grep -q "crypt"; then
        if ! grep -q "^GRUB_ENABLE_CRYPTODISK=y" "${grub_config}"; then
            if grep -q "^GRUB_ENABLE_CRYPTODISK=" "${grub_config}"; then
                sudo sed -i 's/^GRUB_ENABLE_CRYPTODISK=.*/GRUB_ENABLE_CRYPTODISK=y/' "${grub_config}"
            else
                echo "GRUB_ENABLE_CRYPTODISK=y" | sudo tee -a "${grub_config}" > /dev/null
            fi
            log INFO "Enabled GRUB cryptodisk support"
        fi
    fi
    
    if [[ "${SECURITY_LEVEL}" =~ ^(high|paranoid)$ ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        read -p "Set GRUB password to prevent boot parameter tampering? (y/N): " -r set_grub_pass
        if [[ "${set_grub_pass}" =~ ^[Yy]$ ]]; then
            log INFO "To set GRUB password:"
            log INFO "1. Run: sudo grub-mkpasswd-pbkdf2"
            log INFO "2. Copy the generated hash"
            log INFO "3. Add to /etc/grub.d/40_custom:"
            log INFO "   set superusers=\"root\""
            log INFO "   password_pbkdf2 root <your-hash>"
        fi
    fi
    
    if [[ "${SECURITY_LEVEL}" == "paranoid" ]]; then
        if grep -q "^GRUB_TIMEOUT=" "${grub_config}"; then
            sudo sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=0/' "${grub_config}"
            log INFO "Set GRUB timeout to 0 (paranoid mode)"
        fi
    fi
    
    # FIXED: Validate GRUB config before updating
    log INFO "Validating GRUB configuration..."
    if command -v grub-script-check &> /dev/null; then
        if ! sudo grub-script-check "${grub_config}" 2>&1 | tee -a "${LOG_FILE}"; then
            log ERROR "GRUB config validation failed"
            local latest_backup=$(ls -t "${grub_config}.backup."* 2>/dev/null | head -1)
            [[ -n "${latest_backup}" ]] && sudo cp "${latest_backup}" "${grub_config}"
            return 1
        fi
    fi
    
    log INFO "Updating GRUB configuration..."
    if command -v update-grub &> /dev/null; then
        if sudo update-grub 2>&1 | tee -a "${LOG_FILE}"; then
            log SUCCESS "GRUB updated successfully"
        else
            log ERROR "Failed to update GRUB, restoring backup"
            local latest_backup=$(ls -t "${grub_config}.backup."* 2>/dev/null | head -1)
            [[ -n "${latest_backup}" ]] && sudo cp "${latest_backup}" "${grub_config}"
            return 1
        fi
    elif command -v grub2-mkconfig &> /dev/null; then
        if sudo grub2-mkconfig -o /boot/grub2/grub.cfg 2>&1 | tee -a "${LOG_FILE}"; then
            log SUCCESS "GRUB updated successfully"
        else
            log ERROR "Failed to update GRUB, restoring backup"
            local latest_backup=$(ls -t "${grub_config}.backup."* 2>/dev/null | head -1)
            [[ -n "${latest_backup}" ]] && sudo cp "${latest_backup}" "${grub_config}"
            return 1
        fi
    else
        log WARNING "GRUB update command not found. Update GRUB manually with 'sudo update-grub'"
        return 1
    fi
    
    log SUCCESS "Boot security configured with kernel hardening"
    log WARNING "Reboot required for boot security changes to take effect"
}

# Module: IPv6 Configuration
module_ipv6() {
    CURRENT_MODULE="ipv6"
    log INFO "Configuring IPv6..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure IPv6"; return 0; }
    
    local ipv6_disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
    
    if [[ "${ipv6_disabled}" == "1" ]]; then
        log INFO "IPv6 is already disabled"
        return 0
    fi
    
    if [[ "${INTERACTIVE}" == "true" ]]; then
        read -p "Disable IPv6? (y/N): " -r disable_ipv6
        if [[ "${disable_ipv6}" =~ ^[Yy]$ ]]; then
            cat << 'EOF' | sudo tee /etc/sysctl.d/60-disable-ipv6.conf > /dev/null
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
            sudo sysctl -p /etc/sysctl.d/60-disable-ipv6.conf 2>&1 | tee -a "${LOG_FILE}"
            log SUCCESS "IPv6 disabled"
        else
            log INFO "IPv6 remains enabled"
        fi
    fi
}

# Module: AppArmor
module_apparmor() {
    CURRENT_MODULE="apparmor"
    log INFO "Configuring AppArmor..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure AppArmor"; return 0; }
    
    install_package "apparmor" || return 1
    install_package "apparmor-utils" || return 1
    
    sudo systemctl enable apparmor
    sudo systemctl start apparmor
    
    if [[ "${SECURITY_LEVEL}" =~ ^(high|paranoid)$ ]]; then
        log INFO "Setting AppArmor profiles to complain mode first..."
        local complain_count=0
        local enforce_count=0
        local failed_profiles=()
        
        for profile in /etc/apparmor.d/*; do
            if [[ -f "$profile" ]] && \
               [[ ! "$profile" =~ \.(dpkg|save|disabled|cache)$ ]] && \
               [[ ! "$(basename "$profile")" =~ ^(abstractions|tunables|cache|disable|force-complain|local)$ ]]; then
                local profile_name=$(basename "$profile")
                
                # First set to complain mode
                if sudo aa-complain "$profile" 2>&1 | tee -a "${LOG_FILE}"; then
                    complain_count=$((complain_count + 1))
                fi
            fi
        done
        
        log SUCCESS "Set ${complain_count} AppArmor profiles to complain mode"
        log INFO "Monitor /var/log/syslog for AppArmor denials, then run:"
        log INFO "  sudo aa-enforce /etc/apparmor.d/<profile>"
        log INFO "to enforce profiles that don't cause issues"
    fi
    
    log SUCCESS "AppArmor configured"
}

# Module: NTP/Time Sync
module_ntp() {
    CURRENT_MODULE="ntp"
    log INFO "Configuring time synchronization..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure NTP"; return 0; }
    
    if systemctl list-unit-files | grep -q systemd-timesyncd.service; then
        log INFO "Using systemd-timesyncd"
        sudo systemctl enable systemd-timesyncd
        sudo systemctl start systemd-timesyncd
        sudo timedatectl set-ntp true
        log SUCCESS "Time synchronization configured (systemd-timesyncd)"
    else
        log INFO "Using traditional NTP"
        install_package "ntp" || return 1
        sudo systemctl enable ntp
        sudo systemctl start ntp
        log SUCCESS "Time synchronization configured (NTP)"
    fi
}

# Module: AIDE
module_aide() {
    CURRENT_MODULE="aide"
    log INFO "Setting up AIDE file integrity monitoring..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would setup AIDE"; return 0; }
    
    install_package "aide" || return 1
    
    log INFO "Initializing AIDE database (this may take several minutes)..."
    if ! sudo aideinit 2>&1 | tee -a "${LOG_FILE}"; then
        log ERROR "AIDE initialization failed"
        return 1
    fi
    
    if [[ ! -f /var/lib/aide/aide.db.new ]]; then
        log ERROR "AIDE database not created after initialization"
        return 1
    fi
    
    if ! sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db; then
        log ERROR "Failed to move AIDE database"
        return 1
    fi
    
    cat << 'EOF' | sudo tee /etc/cron.daily/aide-check > /dev/null
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report for $(hostname)" root
EOF
    sudo chmod +x /etc/cron.daily/aide-check
    
    log SUCCESS "AIDE configured"
}

# Module: Sysctl Hardening
module_sysctl() {
    CURRENT_MODULE="sysctl"
    log INFO "Configuring kernel parameters..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure sysctl"; return 0; }
    
    if [[ -f /etc/sysctl.d/99-security-hardening.conf ]]; then
        log INFO "Sysctl hardening already configured, updating..."
    fi
    
    cat << 'EOF' | sudo tee /etc/sysctl.d/99-security-hardening.conf > /dev/null
# IP Forwarding
net.ipv4.ip_forward = 0

# SYN cookies
net.ipv4.tcp_syncookies = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore ICMP pings (optional - set to 0 for desktop)
net.ipv4.icmp_echo_ignore_all = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Protect against tcp time-wait assassination
net.ipv4.tcp_rfc1337 = 1

# Kernel hardening
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
fs.suid_dumpable = 0

# Address space layout randomization
kernel.randomize_va_space = 2

# Core dumps
kernel.core_uses_pid = 1

# Restrict BPF to privileged users
kernel.unprivileged_bpf_disabled = 1

# Harden BPF JIT compiler
net.core.bpf_jit_harden = 2
EOF
    
    if sudo sysctl -p /etc/sysctl.d/99-security-hardening.conf 2>&1 | tee -a "${LOG_FILE}"; then
        log SUCCESS "Kernel parameters hardened"
    else
        log WARNING "Some kernel parameters may not have been applied"
    fi
}

# Module: Password Policy
module_password_policy() {
    CURRENT_MODULE="password_policy"
    log INFO "Configuring password policies..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure passwords"; return 0; }
    
    install_package "libpam-pwquality" || return 1
    
    sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    
    if [[ -f /etc/security/pwquality.conf.bak ]]; then
        log INFO "Password quality already configured, updating..."
    else
        sudo cp /etc/security/pwquality.conf /etc/security/pwquality.conf.bak 2>/dev/null || true
    fi
    
    cat << 'EOF' | sudo tee /etc/security/pwquality.conf > /dev/null
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 3
maxrepeat = 2
usercheck = 1
enforcing = 1
EOF
    
    log SUCCESS "Password policies configured"
}

# Module: Automatic Updates
module_automatic_updates() {
    CURRENT_MODULE="automatic_updates"
    log INFO "Enabling automatic security updates..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would enable auto-updates"; return 0; }
    
    install_package "unattended-upgrades" || return 1
    
    cat << 'EOF' | sudo tee /etc/apt/apt.conf.d/50unattended-upgrades > /dev/null
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    
    if [[ "${INTERACTIVE}" == "true" ]]; then
        sudo dpkg-reconfigure -plow unattended-upgrades
    else
        echo 'APT::Periodic::Unattended-Upgrade "1";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
    fi
    
    log SUCCESS "Automatic updates enabled"
}

# Module: Rootkit Scanner
module_rootkit_scanner() {
    CURRENT_MODULE="rootkit_scanner"
    log INFO "Installing rootkit scanners..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would install scanners"; return 0; }
    
    install_package "rkhunter" || return 1
    install_package "chkrootkit" || return 1
    
    sudo rkhunter --update 2>&1 | tee -a "${LOG_FILE}" || true
    sudo rkhunter --propupd 2>&1 | tee -a "${LOG_FILE}" || true
    
    log SUCCESS "Rootkit scanners installed"
    log INFO "Run 'sudo rkhunter --check' to scan for rootkits"
}

# Module: USB Protection
module_usb_protection() {
    CURRENT_MODULE="usb_protection"
    log INFO "Configuring USB policies..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure USB"; return 0; }
    
    cat << 'EOF' | sudo tee /etc/udev/rules.d/90-usb-logging.rules > /dev/null
ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/sh -c 'echo USB device: $attr{idVendor}:$attr{idProduct} >> /var/log/usb-devices.log'"
EOF
    
    sudo udevadm control --reload-rules
    sudo touch /var/log/usb-devices.log
    sudo chmod 644 /var/log/usb-devices.log
    
    log SUCCESS "USB logging configured"
    log INFO "USB device connections will be logged to /var/log/usb-devices.log"
}

# Module: Secure Shared Memory
module_secure_shared_memory() {
    CURRENT_MODULE="secure_shared_memory"
    log INFO "Securing shared memory..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure memory"; return 0; }
    
    local shm_mount="/run/shm"
    [[ ! -d "$shm_mount" ]] && shm_mount="/dev/shm"
    
    if [[ ! -d "$shm_mount" ]]; then
        log WARNING "Shared memory mount point not found"
        return 0
    fi
    
    if ! grep -q "tmpfs.*${shm_mount}.*noexec" /etc/fstab; then
        # Remove any existing tmpfs entries for this mount point
        sudo sed -i "\|^tmpfs[[:space:]]*${shm_mount}|d" /etc/fstab
        
        # Add secure mount
        echo "tmpfs ${shm_mount} tmpfs defaults,noexec,nosuid,nodev 0 0" | sudo tee -a /etc/fstab > /dev/null
        
        if sudo mount -o remount "${shm_mount}" 2>&1 | tee -a "${LOG_FILE}"; then
            log SUCCESS "Shared memory remounted with security options"
        else
            log WARNING "Failed to remount ${shm_mount}, will take effect after reboot"
        fi
    else
        log INFO "Shared memory already secured"
    fi
    
    log SUCCESS "Shared memory configured"
}

# Module: Lynis Audit
module_lynis_audit() {
    CURRENT_MODULE="lynis_audit"
    log INFO "Running Lynis security audit..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would run Lynis"; return 0; }
    
    if ! command -v lynis &> /dev/null; then
        log INFO "Installing Lynis..."
        install_package "lynis" || {
            log WARNING "Failed to install Lynis from repository"
            return 1
        }
    fi
    
    local audit_log="/var/log/lynis-$(date +%Y%m%d_%H%M%S).log"
    if sudo lynis audit system --quick --quiet --log-file "${audit_log}" 2>&1 | tee -a "${LOG_FILE}"; then
        log SUCCESS "Lynis audit completed: ${audit_log}"
    else
        log WARNING "Lynis audit completed with warnings"
    fi
}

generate_report() {
    log INFO "Generating security report..."
    
    local failed_list=""
    if [[ ${#FAILED_MODULES[@]} -gt 0 ]]; then
        failed_list="<p><strong>Failed Modules:</strong> ${FAILED_MODULES[*]}</p>"
    fi
    
    cat << EOF > "${REPORT_FILE}"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Hardening Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        .info-box { background: #e7f3ff; border-left: 4px solid #007bff; padding: 15px; margin: 15px 0; border-radius: 4px; }
        .success { background: #d4edda; border-left: 4px solid #28a745; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; }
        .error { background: #f8d7da; border-left: 4px solid #dc3545; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; border: 1px solid #ddd; text-align: left; }
        th { background: #007bff; color: white; font-weight: bold; }
        tr:nth-child(even) { background: #f9f9f9; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Hardening Report</h1>
        
        <div class="info-box">
            <h2>System Information</h2>
            <p><strong>System:</strong> $(lsb_release -ds)</p>
            <p><strong>Kernel:</strong> $(uname -r)</p>
            <p><strong>Hostname:</strong> $(hostname)</p>
            <p><strong>Date:</strong> $(date)</p>
            <p><strong>Desktop Environment:</strong> ${IS_DESKTOP}</p>
            <p><strong>Security Level:</strong> ${SECURITY_LEVEL}</p>
            <p><strong>Script Version:</strong> ${VERSION}</p>
        </div>
        
        <div class="info-box success">
            <h2>Executed Modules</h2>
            <p><strong>Total:</strong> ${#EXECUTED_MODULES[@]}</p>
            <p><strong>Modules:</strong> ${EXECUTED_MODULES[*]}</p>
        </div>
        
        ${failed_list:+<div class="info-box error">
            <h2>Failed Modules</h2>
            ${failed_list}
        </div>}
        
        <div class="info-box">
            <h2>Backup Information</h2>
            <p><strong>Backup Location:</strong> ${BACKUP_DIR}.tar.gz</p>
            <p><strong>Log File:</strong> ${LOG_FILE}</p>
            <p>To restore from backup, run:<br>
            <code>sudo ./${SCRIPT_NAME} --restore</code></p>
        </div>
        
        <div class="info-box warning">
            <h2>⚠️ Important Notes</h2>
            <ul>
                <li>A system restart is recommended to apply all changes</li>
                <li>Keep the backup file safe for recovery purposes</li>
                <li>Review the log file for detailed information: ${LOG_FILE}</li>
                <li>Test all critical services before deploying to production</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by Enhanced Linux Security Hardening Script v${VERSION}</p>
            <p>GitHub: <a href="https://github.com/captainzero93/security_harden_linux">captainzero93/security_harden_linux</a></p>
        </div>
    </div>
</body>
</html>
EOF
    
    log SUCCESS "Report generated: ${REPORT_FILE}"
}

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
    
    # Check for circular dependencies
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
        show_progress ${current} ${total} "${SECURITY_MODULES[${module}]:-Unknown}"
        
        local func="module_${module}"
        if declare -f "${func}" > /dev/null; then
            if "${func}"; then
                EXECUTED_MODULES+=("${module}")
                log SUCCESS "Module ${module} completed"
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
            -e|--enable) ENABLE_MODULES="$2"; shift 2 ;;
            -x|--disable) DISABLE_MODULES="$2"; shift 2 ;;
            -r|--restore) 
                check_permissions
                restore_backup "$2"
                exit $?
                ;;
            -R|--report) 
                check_permissions
                generate_report
                exit 0
                ;;
            -c|--config) CONFIG_FILE="$2"; shift 2 ;;
            --version) echo "v${VERSION}"; exit 0 ;;
            --list-modules) list_modules ;;
            *) 
                echo "Unknown option: $1"
                display_help
                ;;
        esac
    done
    
    check_permissions
    detect_desktop
    load_config
    validate_security_level
    check_requirements
    
    sudo touch "${LOG_FILE}"
    sudo chmod 640 "${LOG_FILE}"
    
    log INFO "Starting Security Hardening v${VERSION}"
    log INFO "Security Level: ${SECURITY_LEVEL}"
    log INFO "Desktop Mode: ${IS_DESKTOP}"
    log INFO "Dry Run: ${DRY_RUN}"
    
    [[ "${DRY_RUN}" == "false" ]] && backup_files
    
    execute_modules
    generate_report
    
    echo
    log SUCCESS "================================"
    log SUCCESS "Security hardening completed!"
    log SUCCESS "================================"
    log INFO "Executed modules: ${#EXECUTED_MODULES[@]}"
    [[ ${#FAILED_MODULES[@]} -gt 0 ]] && log WARNING "Failed modules: ${#FAILED_MODULES[@]} (${FAILED_MODULES[*]})"
    log INFO "Backup: ${BACKUP_DIR}.tar.gz"
    log INFO "Log: ${LOG_FILE}"
    log INFO "Report: ${REPORT_FILE}"
    
    if [[ "${DRY_RUN}" == "false" ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        echo
        read -p "Restart recommended to apply all changes. Restart now? (y/N): " -r restart
        [[ "${restart}" =~ ^[Yy]$ ]] && sudo reboot
    fi
}

main "$@"
