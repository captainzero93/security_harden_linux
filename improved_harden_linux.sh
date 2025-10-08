#!/bin/bash

# Enhanced Ubuntu/Kubuntu Linux Security Hardening Script
# Version: 3.1 - Fixed
# Author: captainzero93
# GitHub: https://github.com/captainzero93/security_harden_linux
# Optimized for Kubuntu 24.04+ and Ubuntu 25.10+

set -euo pipefail

# Global variables
readonly VERSION="3.1-fixed"
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
    if [[ -n "${TEMP_DIR:-}" ]] && [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
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
    
    log ERROR "Command failed with exit code ${exit_code} at line ${line_number}: ${command}"
    
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
    
    if ! ping -c 1 -W 2 8.8.8.8 &> /dev/null; then
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
    
    if sudo tar -czf "${BACKUP_DIR}.tar.gz" -C "$(dirname "${BACKUP_DIR}")" "$(basename "${BACKUP_DIR}")" 2>&1; then
        # Generate checksum
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
    
    # Verify checksum if available
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
    if ! sudo tar -xzf "${backup_file}" -C "${temp_dir}" 2>&1; then
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
    
    # Restore with verification
    local restore_errors=0
    if [[ -d "${backup_source}/etc" ]]; then
        for item in "${backup_source}"/etc/*; do
            if [[ -e "$item" ]]; then
                local target_name=$(basename "$item")
                if ! sudo cp -a "$item" "/etc/" 2>&1; then
                    log ERROR "Failed to restore ${target_name}"
                    restore_errors=$((restore_errors + 1))
                else
                    log INFO "Restored /etc/${target_name}"
                fi
            fi
        done
    fi
    
    # Restore iptables rules
    if [[ -f "${backup_source}/iptables.rules" ]]; then
        if sudo iptables-restore < "${backup_source}/iptables.rules" 2>&1; then
            log SUCCESS "Restored iptables rules"
        else
            log WARNING "Failed to restore iptables rules"
        fi
    fi
    
    if [[ -f "${backup_source}/ip6tables.rules" ]]; then
        if sudo ip6tables-restore < "${backup_source}/ip6tables.rules" 2>&1; then
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
    
    # Check if already installed
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

resolve_dependencies() {
    local module="$1"
    local -a resolved=()
    
    if [[ -n "${MODULE_DEPS[$module]:-}" ]]; then
        for dep in ${MODULE_DEPS[$module]}; do
            # Check if dependency already executed
            if [[ ! " ${EXECUTED_MODULES[@]} " =~ " ${dep} " ]]; then
                # Recursively resolve dependencies
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

# Module: System Update
module_system_update() {
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
    log INFO "Configuring firewall..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure firewall"; return 0; }
    
    install_package "ufw" || return 1
    
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw default deny routed
    
    # Detect SSH port with validation
    local ssh_port=$(grep -E "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config 2>/dev/null | \
                     tail -1 | awk '{print $2}' | grep -E '^[0-9]+$' || echo "22")
    
    # Validate port range
    if [[ $ssh_port -lt 1 || $ssh_port -gt 65535 ]]; then
        log WARNING "Invalid SSH port detected: ${ssh_port}, using default 22"
        ssh_port=22
    fi
    
    log INFO "Configuring SSH access on port ${ssh_port}"
    sudo ufw limit "${ssh_port}/tcp" comment 'SSH rate limited'
    
    # Desktop-friendly: Allow common services
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
    log INFO "Configuring root access restrictions..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would restrict root"; return 0; }
    
    # Check for non-root sudo users
    local sudo_users=$(getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v "^root$" | grep -v "^$")
    
    if [[ -z "${sudo_users}" ]]; then
        log WARNING "No non-root users with sudo privileges found. Skipping root login disable for safety."
        echo "Please create a non-root user with sudo privileges before disabling root login."
        return 0
    fi
    
    log INFO "Non-root sudo users found: $(echo ${sudo_users} | tr '\n' ' ')"
    
    # Disable root password login
    if sudo passwd -l root 2>&1; then
        log SUCCESS "Root password login disabled"
    else
        log ERROR "Failed to lock root account"
        return 1
    fi
    
    # Restrict su command to sudo group
    if ! grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
        echo "auth required pam_wheel.so use_uid group=sudo" | sudo tee -a /etc/pam.d/su > /dev/null
        log SUCCESS "Restricted su command to sudo group"
    fi
    
    log SUCCESS "Root access restricted"
}

# Module: SSH Hardening
module_ssh_hardening() {
    log INFO "Hardening SSH..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would harden SSH"; return 0; }
    
    local sshd_config="/etc/ssh/sshd_config"
    [[ ! -f "${sshd_config}" ]] && { log ERROR "SSH not installed"; return 1; }
    
    sudo cp "${sshd_config}" "${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"
    
    local ssh_settings=(
        "Protocol 2"
        "PermitRootLogin no"
        "PubkeyAuthentication yes"
        "PasswordAuthentication no"
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
    
    for setting in "${ssh_settings[@]}"; do
        local key=$(echo "${setting}" | cut -d' ' -f1)
        # Escape special characters for sed
        local escaped_setting=$(echo "${setting}" | sed 's/[\/&]/\\&/g')
        
        # Comment out existing entries
        sudo sed -i "s/^${key}/# &/" "${sshd_config}"
        
        # Add new setting
        if grep -q "^# ${key}" "${sshd_config}"; then
            sudo sed -i "0,/^# ${key}/s/^# ${key}.*/${escaped_setting}/" "${sshd_config}"
        else
            echo "${setting}" | sudo tee -a "${sshd_config}" > /dev/null
        fi
    done
    
    if sudo sshd -t 2>&1; then
        sudo systemctl restart sshd
        log SUCCESS "SSH hardened and restarted"
    else
        log ERROR "SSH config validation failed, restoring backup"
        sudo cp "${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)" "${sshd_config}"
        return 1
    fi
}

# Module: Fail2Ban
module_fail2ban() {
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
    log INFO "Configuring audit logging..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure auditd"; return 0; }
    
    install_package "auditd" || return 1
    install_package "audispd-plugins" || return 1
    
    # Create audit rules file
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
    if sudo systemctl restart auditd 2>&1; then
        log SUCCESS "Auditd configured and restarted"
    else
        log WARNING "Auditd configuration may require manual restart"
    fi
}

# Module: Disable Unused Filesystems
module_filesystems() {
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

# Module: Enhanced Boot Security with Comprehensive Kernel Hardening
module_boot_security() {
    log INFO "Securing boot configuration with kernel hardening..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure boot"; return 0; }
    
    local grub_config="/etc/default/grub"
    [[ ! -f "${grub_config}" ]] && { log WARNING "GRUB config not found"; return 0; }
    
    # Backup GRUB config
    sudo cp "${grub_config}" "${grub_config}.backup.$(date +%Y%m%d_%H%M%S)" || return 1
    
    # Comprehensive kernel hardening parameters
    local kernel_params=(
        # Memory hardening
        "page_alloc.shuffle=1"
        "slab_nomerge"
        "init_on_alloc=1"
        "init_on_free=1"
        "randomize_kstack_offset=1"
        
        # Kernel security
        "kernel.unprivileged_bpf_disabled=1"
        "net.core.bpf_jit_harden=2"
        "kernel.kptr_restrict=2"
        "kernel.dmesg_restrict=1"
        "kernel.perf_event_paranoid=3"
        
        # Memory randomization (ASLR enhancement)
        "vm.mmap_rnd_bits=32"
        "vm.mmap_rnd_compat_bits=16"
        
        # Additional hardening
        "vsyscall=none"
        "debugfs=off"
        "oops=panic"
        "module.sig_enforce=1"
        "lockdown=confidentiality"
    )
    
    # Add USB boot restriction only if not desktop or high security
    if [[ "${IS_DESKTOP}" == "false" ]] || [[ "${SECURITY_LEVEL}" =~ ^(high|paranoid)$ ]]; then
        kernel_params+=("nousb")
        log INFO "Added USB boot restriction"
    fi
    
    # Read current GRUB_CMDLINE_LINUX_DEFAULT
    local current_params=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" "${grub_config}" | sed 's/^GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/\1/')
    
    # Add new parameters if not already present
    local added_count=0
    for param in "${kernel_params[@]}"; do
        local param_name="${param%%=*}"
        # Use word boundaries and more precise matching
        if ! echo "${current_params}" | grep -qE "(^|[[:space:]])${param_name}(=|$)"; then
            current_params="${current_params} ${param}"
            added_count=$((added_count + 1))
            log INFO "Added kernel parameter: ${param}"
        else
            log INFO "Kernel parameter already present: ${param_name}"
        fi
    done
    
    # Update GRUB_CMDLINE_LINUX_DEFAULT
    if [[ ${added_count} -gt 0 ]]; then
        sudo sed -i "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${current_params}\"|" "${grub_config}"
        log SUCCESS "Added ${added_count} kernel hardening parameters"
    else
        log INFO "All kernel parameters already present"
    fi
    
    # Enable cryptodisk support if encrypted system
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
    
    # Set GRUB password (high security levels)
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
    
    # Disable GRUB timeout for extra security (paranoid mode)
    if [[ "${SECURITY_LEVEL}" == "paranoid" ]]; then
        if grep -q "^GRUB_TIMEOUT=" "${grub_config}"; then
            sudo sed -i 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=0/' "${grub_config}"
            log INFO "Set GRUB timeout to 0 (paranoid mode)"
        fi
    fi
    
    # Update GRUB
    log INFO "Updating GRUB configuration..."
    if command -v update-grub &> /dev/null; then
        if sudo update-grub 2>&1 | tee -a "${LOG_FILE}"; then
            log SUCCESS "GRUB updated successfully"
        else
            log ERROR "Failed to update GRUB"
            return 1
        fi
    elif command -v grub2-mkconfig &> /dev/null; then
        if sudo grub2-mkconfig -o /boot/grub2/grub.cfg 2>&1 | tee -a "${LOG_FILE}"; then
            log SUCCESS "GRUB updated successfully"
        else
            log ERROR "Failed to update GRUB"
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
    log INFO "Configuring IPv6..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure IPv6"; return 0; }
    
    # Check if IPv6 is currently enabled
    local ipv6_status=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "1")
    
    if [[ "${ipv6_status}" == "1" ]]; then
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
            sudo sysctl -p /etc/sysctl.d/60-disable-ipv6.conf
            log SUCCESS "IPv6 disabled"
        else
            log INFO "IPv6 remains enabled"
        fi
    fi
}

# Module: AppArmor
module_apparmor() {
    log INFO "Configuring AppArmor..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure AppArmor"; return 0; }
    
    install_package "apparmor" || return 1
    install_package "apparmor-utils" || return 1
    
    sudo systemctl enable apparmor
    sudo systemctl start apparmor
    
    # Set all profiles to enforce mode (high/paranoid security)
    if [[ "${SECURITY_LEVEL}" =~ ^(high|paranoid)$ ]]; then
        log INFO "Enforcing AppArmor profiles..."
        local failed_profiles=()
        local enforced_count=0
        
        for profile in /etc/apparmor.d/*; do
            if [[ -f "$profile" ]] && [[ ! "$profile" =~ \.(dpkg|save|disabled) ]]; then
                local profile_name=$(basename "$profile")
                if sudo aa-enforce "$profile" 2>&1 | tee -a "${LOG_FILE}"; then
                    enforced_count=$((enforced_count + 1))
                else
                    failed_profiles+=("${profile_name}")
                fi
            fi
        done
        
        log SUCCESS "Enforced ${enforced_count} AppArmor profiles"
        
        if [[ ${#failed_profiles[@]} -gt 0 ]]; then
            log WARNING "Failed to enforce ${#failed_profiles[@]} profiles: ${failed_profiles[*]}"
            log INFO "Run 'sudo aa-complain /etc/apparmor.d/<profile>' to set problematic profiles to complain mode"
        fi
    fi
    
    log SUCCESS "AppArmor configured"
}

# Module: NTP/Time Sync
module_ntp() {
    log INFO "Configuring time synchronization..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure NTP"; return 0; }
    
    # Modern Ubuntu uses systemd-timesyncd
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
    
    # Create daily check cron
    cat << 'EOF' | sudo tee /etc/cron.daily/aide-check > /dev/null
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Report for $(hostname)" root
EOF
    sudo chmod +x /etc/cron.daily/aide-check
    
    log SUCCESS "AIDE configured"
}

# Module: Sysctl Hardening
module_sysctl() {
    log INFO "Configuring kernel parameters..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure sysctl"; return 0; }
    
    # Check if already configured
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
EOF
    
    if sudo sysctl -p /etc/sysctl.d/99-security-hardening.conf 2>&1 | tee -a "${LOG_FILE}"; then
        log SUCCESS "Kernel parameters hardened"
    else
        log WARNING "Some kernel parameters may not have been applied"
    fi
}

# Module: Password Policy
module_password_policy() {
    log INFO "Configuring password policies..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure passwords"; return 0; }
    
    install_package "libpam-pwquality" || return 1
    
    sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    
    # Check if already configured
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
    log INFO "Configuring USB policies..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure USB"; return 0; }
    
    # Desktop-friendly: Only log, don't block
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
    log INFO "Securing shared memory..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure memory"; return 0; }
    
    # Check if /run/shm exists, fallback to /dev/shm
    local shm_mount="/run/shm"
    [[ ! -d "$shm_mount" ]] && shm_mount="/dev/shm"
    
    if [[ ! -d "$shm_mount" ]]; then
        log WARNING "Shared memory mount point not found"
        return 0
    fi
    
    if ! grep -q "tmpfs.*${shm_mount}.*noexec" /etc/fstab; then
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
    
    # Resolve dependencies and create execution order
    local -a execution_order=()
    for module in "${modules_to_run[@]}"; do
        [[ -z "${module}" ]] && continue
        
        # Get dependencies
        local deps=($(resolve_dependencies "${module}"))
        for dep in "${deps[@]}"; do
            if [[ ! " ${execution_order[@]} " =~ " ${dep} " ]]; then
                execution_order+=("${dep}")
            fi
        done
        
        # Add module itself
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
    
    echo # New line after progress bar
}

main() {
    # Parse command line arguments
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
