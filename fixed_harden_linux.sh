#!/bin/bash 

# Enhanced Ubuntu/Kubuntu Linux Security Hardening Script
# Version: 3.9 - Fixed /etc/os-release readonly variable issue
# Author: captainzero93 (Fixed version)
# GitHub: https://github.com/captainzero93/security_harden_linux
# Optimized for Kubuntu 24.04+, Ubuntu 25.10+, and Debian 13
# Last Updated: 2025-06-11
# 
# FIXES IN THIS VERSION:
# - Fixed /etc/os-release readonly variable error
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
readonly VERSION="3.9"
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

# Module dependencies
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

# FIXED: Extract OS information safely without sourcing /etc/os-release
get_os_info() {
    local key="$1"
    local default="${2:-unknown}"
    
    if [[ -f /etc/os-release ]]; then
        local value=$(grep "^${key}=" /etc/os-release | cut -d= -f2 | tr -d '"')
        echo "${value:-$default}"
    else
        echo "$default"
    fi
}

check_system() {
    log INFO "Checking system requirements..."
    
    if ! command -v apt-get &>/dev/null; then
        log ERROR "This script requires apt package manager (Debian/Ubuntu)"
        exit 1
    fi
    
    # FIXED: Use safe extraction method instead of sourcing
    local os_name=$(get_os_info "ID" "unknown")
    local os_version=$(get_os_info "VERSION_ID" "unknown")
    local os_pretty_name=$(get_os_info "PRETTY_NAME" "Unknown")
    local os_version_codename=$(get_os_info "VERSION_CODENAME" "")
    
    case "${os_name}" in
        ubuntu|kubuntu)
            if [[ "${os_version}" < "22.04" ]]; then
                log WARNING "This script is optimized for Ubuntu 22.04+"
            fi
            ;;
        debian)
            if [[ "${os_version}" == "13" ]] || [[ "${os_version}" == "12" ]]; then
                log INFO "Debian ${os_version} (${os_version_codename:-}) detected - using enhanced compatibility mode"
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
    
    log SUCCESS "System: ${os_pretty_name}"
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
    fi
}

restore_backup() {
    local backup_file="${1:-}"
    
    if [[ -z "${backup_file}" ]]; then
        local latest_backup=$(ls -t /root/security_backup_*.tar.gz 2>/dev/null | head -n1)
        if [[ -z "${latest_backup}" ]]; then
            log ERROR "No backup files found in /root/"
            return 1
        fi
        backup_file="${latest_backup}"
    fi
    
    if [[ ! -f "${backup_file}" ]]; then
        log ERROR "Backup file not found: ${backup_file}"
        return 1
    fi
    
    log INFO "Restoring from backup: ${backup_file}"
    
    if [[ -f "${backup_file}.sha256" ]]; then
        log INFO "Verifying backup integrity..."
        if ! sha256sum -c "${backup_file}.sha256" 2>&1 | tee -a "${LOG_FILE}"; then
            log ERROR "Backup integrity check failed!"
            return 1
        fi
        log SUCCESS "Backup integrity verified"
    fi
    
    local restore_dir="${TEMP_DIR}/restore"
    mkdir -p "${restore_dir}"
    
    if tar -xzf "${backup_file}" -C "${restore_dir}" 2>&1 | tee -a "${LOG_FILE}"; then
        local backup_name=$(basename "${backup_file}" .tar.gz)
        
        if [[ -d "${restore_dir}/${backup_name}" ]]; then
            sudo cp -a "${restore_dir}/${backup_name}"/* / 2>&1 | tee -a "${LOG_FILE}"
            log SUCCESS "Backup restored successfully"
            log WARNING "Please reboot the system to apply all changes"
        else
            log ERROR "Backup structure is invalid"
            return 1
        fi
    else
        log ERROR "Failed to extract backup"
        return 1
    fi
}

check_circular_deps() {
    local module="$1"
    local visited="$2"
    
    [[ -z "${MODULE_DEPS[${module}]:-}" ]] && return 0
    
    local deps=(${MODULE_DEPS[${module}]})
    for dep in "${deps[@]}"; do
        if [[ "${visited}" =~ (^|[[:space:]])${dep}($|[[:space:]]) ]]; then
            log ERROR "Circular dependency detected: ${module} -> ${dep}"
            return 1
        fi
        
        if ! check_circular_deps "${dep}" "${visited} ${dep}"; then
            return 1
        fi
    done
    
    return 0
}

resolve_dependencies() {
    local module="$1"
    local -a resolved=()
    
    if [[ -n "${MODULE_DEPS[${module}]:-}" ]]; then
        local deps=(${MODULE_DEPS[${module}]})
        for dep in "${deps[@]}"; do
            local sub_deps=($(resolve_dependencies "${dep}"))
            for sub_dep in "${sub_deps[@]}"; do
                if [[ ! " ${resolved[@]} " =~ " ${sub_dep} " ]]; then
                    resolved+=("${sub_dep}")
                fi
            done
            
            if [[ ! " ${resolved[@]} " =~ " ${dep} " ]]; then
                resolved+=("${dep}")
            fi
        done
    fi
    
    if [[ ! " ${resolved[@]} " =~ " ${module} " ]]; then
        resolved+=("${module}")
    fi
    
    echo "${resolved[@]}"
}

wait_for_apt() {
    local timeout=300
    local elapsed=0
    local check_interval=2
    
    log INFO "Checking if package manager is available..."
    
    while [[ ${elapsed} -lt ${timeout} ]]; do
        if ! sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 && \
           ! sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1 && \
           ! sudo fuser /var/cache/apt/archives/lock >/dev/null 2>&1; then
            log INFO "Package manager is available"
            return 0
        fi
        
        if [[ ${elapsed} -eq 0 ]]; then
            log WARNING "Package manager is locked, waiting..."
        fi
        
        sleep ${check_interval}
        elapsed=$((elapsed + check_interval))
    done
    
    log ERROR "Timeout waiting for package manager to become available"
    return 1
}

install_package() {
    local package="$1"
    local retry_count=0
    local max_retries=3
    
    if dpkg -l | grep -q "^ii.*${package}"; then
        log INFO "Package ${package} is already installed"
        return 0
    fi
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would install ${package}"; return 0; }
    
    wait_for_apt || return 1
    
    while [[ ${retry_count} -lt ${max_retries} ]]; do
        log INFO "Installing ${package} (attempt $((retry_count + 1))/${max_retries})..."
        
        if DEBIAN_FRONTEND=noninteractive sudo apt-get install -y "${package}" 2>&1 | tee -a "${LOG_FILE}"; then
            log SUCCESS "Package ${package} installed successfully"
            return 0
        else
            retry_count=$((retry_count + 1))
            if [[ ${retry_count} -lt ${max_retries} ]]; then
                log WARNING "Installation failed, retrying in 5 seconds..."
                sleep 5
                wait_for_apt || return 1
            fi
        fi
    done
    
    log ERROR "Failed to install ${package} after ${max_retries} attempts"
    return 1
}

module_system_update() {
    CURRENT_MODULE="system_update"
    log INFO "Updating system packages..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would update system"; return 0; }
    
    wait_for_apt || return 1
    
    log INFO "Running apt update..."
    if ! DEBIAN_FRONTEND=noninteractive sudo apt-get update 2>&1 | tee -a "${LOG_FILE}"; then
        log ERROR "Failed to update package lists"
        return 1
    fi
    
    log INFO "Running apt upgrade..."
    if ! DEBIAN_FRONTEND=noninteractive sudo apt-get upgrade -y 2>&1 | tee -a "${LOG_FILE}"; then
        log ERROR "Failed to upgrade packages"
        return 1
    fi
    
    log INFO "Running apt autoremove..."
    DEBIAN_FRONTEND=noninteractive sudo apt-get autoremove -y 2>&1 | tee -a "${LOG_FILE}" || true
    
    log SUCCESS "System update completed"
}

module_firewall() {
    CURRENT_MODULE="firewall"
    log INFO "Configuring UFW firewall..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure firewall"; return 0; }
    
    install_package "ufw" || return 1
    
    sudo ufw --force reset
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    case "${SECURITY_LEVEL}" in
        low|moderate)
            sudo ufw allow ssh
            [[ "${IS_DESKTOP}" == "true" ]] && sudo ufw allow 631
            ;;
        high|paranoid)
            sudo ufw limit ssh
            ;;
    esac
    
    sudo ufw logging on
    echo "y" | sudo ufw enable
    
    log SUCCESS "Firewall configured and enabled"
}

module_fail2ban() {
    CURRENT_MODULE="fail2ban"
    log INFO "Setting up Fail2Ban..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would setup Fail2Ban"; return 0; }
    
    install_package "fail2ban" || return 1
    
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
maxretry = 3
EOF
    
    sudo systemctl enable fail2ban
    sudo systemctl restart fail2ban
    
    log SUCCESS "Fail2Ban configured and enabled"
}

module_clamav() {
    CURRENT_MODULE="clamav"
    log INFO "Installing ClamAV antivirus..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would install ClamAV"; return 0; }
    
    install_package "clamav" || return 1
    install_package "clamav-daemon" || return 1
    
    log INFO "Updating virus definitions (this may take a while)..."
    sudo freshclam 2>&1 | tee -a "${LOG_FILE}" || true
    
    sudo systemctl enable clamav-freshclam
    sudo systemctl start clamav-freshclam
    
    log SUCCESS "ClamAV installed and configured"
}

module_root_access() {
    CURRENT_MODULE="root_access"
    log INFO "Configuring root access restrictions..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would restrict root access"; return 0; }
    
    if [[ "${SECURITY_LEVEL}" == "high" ]] || [[ "${SECURITY_LEVEL}" == "paranoid" ]]; then
        sudo passwd -l root 2>&1 | tee -a "${LOG_FILE}"
        log SUCCESS "Direct root login disabled"
    else
        log INFO "Root access not modified (security level: ${SECURITY_LEVEL})"
    fi
}

module_ssh_hardening() {
    CURRENT_MODULE="ssh_hardening"
    log INFO "Hardening SSH configuration..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would harden SSH"; return 0; }
    
    if [[ ! -f /etc/ssh/sshd_config ]]; then
        log WARNING "SSH server not installed, skipping SSH hardening"
        return 0
    fi
    
    local ssh_config="/etc/ssh/sshd_config"
    sudo cp "${ssh_config}" "${ssh_config}.backup.$(date +%Y%m%d_%H%M%S)"
    
    declare -A ssh_settings=(
        ["PermitRootLogin"]="no"
        ["PasswordAuthentication"]="no"
        ["PubkeyAuthentication"]="yes"
        ["X11Forwarding"]="no"
        ["PermitEmptyPasswords"]="no"
        ["MaxAuthTries"]="3"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="2"
        ["Protocol"]="2"
    )
    
    if [[ "${SECURITY_LEVEL}" == "low" ]] || [[ "${SECURITY_LEVEL}" == "moderate" ]]; then
        ssh_settings["PasswordAuthentication"]="yes"
    fi
    
    for setting in "${!ssh_settings[@]}"; do
        local value="${ssh_settings[${setting}]}"
        if grep -q "^#*${setting}" "${ssh_config}"; then
            sudo sed -i "s/^#*${setting}.*/${setting} ${value}/" "${ssh_config}"
        else
            echo "${setting} ${value}" | sudo tee -a "${ssh_config}" > /dev/null
        fi
    done
    
    if sudo sshd -t 2>&1 | tee -a "${LOG_FILE}"; then
        sudo systemctl restart sshd || sudo systemctl restart ssh
        log SUCCESS "SSH hardening completed"
    else
        log ERROR "SSH configuration test failed, restoring backup"
        sudo cp "${ssh_config}.backup."* "${ssh_config}"
        return 1
    fi
}

module_packages() {
    CURRENT_MODULE="packages"
    log INFO "Removing unnecessary packages..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would remove unnecessary packages"; return 0; }
    
    local packages_to_remove=()
    
    case "${SECURITY_LEVEL}" in
        high|paranoid)
            packages_to_remove+=(
                "telnet"
                "rsh-client"
                "rsh-redone-client"
                "nis"
                "ntpdate"
            )
            ;;
    esac
    
    for package in "${packages_to_remove[@]}"; do
        if dpkg -l | grep -q "^ii.*${package}"; then
            log INFO "Removing ${package}..."
            DEBIAN_FRONTEND=noninteractive sudo apt-get remove --purge -y "${package}" 2>&1 | tee -a "${LOG_FILE}"
        fi
    done
    
    DEBIAN_FRONTEND=noninteractive sudo apt-get autoremove -y 2>&1 | tee -a "${LOG_FILE}"
    
    log SUCCESS "Package cleanup completed"
}

module_audit() {
    CURRENT_MODULE="audit"
    log INFO "Configuring system auditing..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure auditing"; return 0; }
    
    install_package "auditd" || return 1
    install_package "audispd-plugins" || return 1
    
    sudo systemctl enable auditd
    sudo systemctl start auditd
    
    log SUCCESS "Auditd configured and enabled"
}

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
    done
    
    log SUCCESS "Unused filesystems disabled"
}

module_boot_security() {
    CURRENT_MODULE="boot_security"
    log INFO "Securing boot settings..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure boot"; return 0; }
    
    if [[ -f /etc/grub.d/40_custom ]]; then
        if ! grep -q "set superusers" /etc/grub.d/40_custom; then
            log INFO "GRUB password protection recommended but not automatically configured"
            log INFO "Please run 'grub-mkpasswd-pbkdf2' and update /etc/grub.d/40_custom manually"
        fi
    fi
    
    sudo chmod 600 /boot/grub/grub.cfg 2>/dev/null || true
    
    log SUCCESS "Boot security settings applied"
}

module_ipv6() {
    CURRENT_MODULE="ipv6"
    log INFO "Configuring IPv6 settings..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure IPv6"; return 0; }
    
    if [[ "${SECURITY_LEVEL}" == "paranoid" ]]; then
        cat >> /etc/sysctl.conf << EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
        sudo sysctl -p
        log SUCCESS "IPv6 disabled"
    else
        log INFO "IPv6 configuration skipped (security level: ${SECURITY_LEVEL})"
    fi
}

module_apparmor() {
    CURRENT_MODULE="apparmor"
    log INFO "Configuring AppArmor..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure AppArmor"; return 0; }
    
    install_package "apparmor" || return 1
    install_package "apparmor-utils" || return 1
    
    sudo systemctl enable apparmor
    sudo systemctl start apparmor
    
    sudo aa-enforce /etc/apparmor.d/* 2>&1 | tee -a "${LOG_FILE}" || true
    
    log SUCCESS "AppArmor configured"
}

module_ntp() {
    CURRENT_MODULE="ntp"
    log INFO "Configuring time synchronization..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure NTP"; return 0; }
    
    if ! systemctl is-active --quiet systemd-timesyncd; then
        sudo systemctl enable systemd-timesyncd
        sudo systemctl start systemd-timesyncd
    fi
    
    sudo timedatectl set-ntp true
    
    log SUCCESS "Time synchronization configured"
}

module_aide() {
    CURRENT_MODULE="aide"
    log INFO "Setting up AIDE file integrity monitoring..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would setup AIDE"; return 0; }
    
    install_package "aide" || return 1
    
    log INFO "Initializing AIDE database (this may take several minutes)..."
    sudo aideinit 2>&1 | tee -a "${LOG_FILE}" || sudo aide --init 2>&1 | tee -a "${LOG_FILE}"
    
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
    
    log SUCCESS "AIDE configured"
}

module_sysctl() {
    CURRENT_MODULE="sysctl"
    log INFO "Configuring kernel parameters..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure sysctl"; return 0; }
    
    cat >> /etc/sysctl.conf << EOF

# Security hardening parameters
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
fs.suid_dumpable = 0
EOF
    
    sudo sysctl -p 2>&1 | tee -a "${LOG_FILE}"
    
    log SUCCESS "Kernel parameters configured"
}

module_password_policy() {
    CURRENT_MODULE="password_policy"
    log INFO "Configuring password policies..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure password policy"; return 0; }
    
    install_package "libpam-pwquality" || return 1
    
    local pwquality_conf="/etc/security/pwquality.conf"
    
    declare -A password_settings=(
        ["minlen"]="12"
        ["dcredit"]="-1"
        ["ucredit"]="-1"
        ["ocredit"]="-1"
        ["lcredit"]="-1"
    )
    
    for setting in "${!password_settings[@]}"; do
        local value="${password_settings[${setting}]}"
        if grep -q "^#*${setting}" "${pwquality_conf}"; then
            sudo sed -i "s/^#*${setting}.*/${setting} = ${value}/" "${pwquality_conf}"
        else
            echo "${setting} = ${value}" | sudo tee -a "${pwquality_conf}" > /dev/null
        fi
    done
    
    log SUCCESS "Password policies configured"
}

module_automatic_updates() {
    CURRENT_MODULE="automatic_updates"
    log INFO "Enabling automatic security updates..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would enable automatic updates"; return 0; }
    
    install_package "unattended-upgrades" || return 1
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    
    sudo systemctl enable unattended-upgrades
    sudo systemctl start unattended-upgrades
    
    log SUCCESS "Automatic security updates enabled"
}

module_rootkit_scanner() {
    CURRENT_MODULE="rootkit_scanner"
    log INFO "Installing rootkit scanners..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would install rootkit scanners"; return 0; }
    
    install_package "rkhunter" || return 1
    install_package "chkrootkit" || return 1
    
    sudo rkhunter --update 2>&1 | tee -a "${LOG_FILE}" || true
    sudo rkhunter --propupd 2>&1 | tee -a "${LOG_FILE}" || true
    
    log SUCCESS "Rootkit scanners installed and updated"
}

module_usb_protection() {
    CURRENT_MODULE="usb_protection"
    log INFO "Configuring USB device policies..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure USB protection"; return 0; }
    
    if [[ "${SECURITY_LEVEL}" == "paranoid" ]]; then
        echo "install usb-storage /bin/true" | sudo tee /etc/modprobe.d/usb-storage.conf > /dev/null
        log SUCCESS "USB storage disabled"
    else
        log INFO "USB protection not configured (security level: ${SECURITY_LEVEL})"
    fi
}

module_secure_shared_memory() {
    CURRENT_MODULE="secure_shared_memory"
    log INFO "Securing shared memory..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure shared memory"; return 0; }
    
    if grep -q "^tmpfs.*/run/shm.*noexec" /etc/fstab; then
        log INFO "Shared memory already secured"
        return 0
    fi
    
    echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" | sudo tee -a /etc/fstab > /dev/null
    
    sudo mount -o remount /run/shm 2>/dev/null || true
    
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
        
        log INFO "Starting module ${current}/${total}: ${SECURITY_MODULES[${module}]:-Unknown}"
        
        local func="module_${module}"
        if declare -f "${func}" > /dev/null; then
            if "${func}"; then
                EXECUTED_MODULES+=("${module}")
                log SUCCESS "Module ${module} completed"
                
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

main "$@"
