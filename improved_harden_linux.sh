#!/bin/bash 

# Enhanced Ubuntu/Kubuntu Linux Security Hardening Script
# Version: 4.2 - ACTUAL FIX for premature exit at 4%
# Author: captainzero93 (Fixed by Claude)
# GitHub: https://github.com/captainzero93/security_harden_linux
# Optimized for Kubuntu 24.04+, Ubuntu 25.10+, and Debian 13
# Last Updated: 2025-11-07
# 
# FIXES IN THIS VERSION (4.2):
# - CRITICAL: Fixed show_progress() causing immediate exit with set -e
# - The pattern '[[ test ]] && command' returns 1 when test is false
# - With set -e, this caused script to exit after first module
# - Changed to use if statement which is safe with set -e
# - This was the ACTUAL cause of the 4% exit issue
#
# FIXES IN VERSION (4.1):
# - Added explicit 'return 0' to all module functions (preventive measure)
# - Previous fixes from v4.0 maintained (APT lock handling, progress bar, etc.)
#
# PREVIOUS FIXES (4.0):
# - Fixed wait_for_apt() hanging by properly handling stale locks
# - Fixed lock file detection logic - now removes stale locks automatically
# - Improved timeout handling with better feedback
# - Fixed progress bar not advancing between modules
# - Better error recovery and user feedback

set -euo pipefail

# Global variables
readonly VERSION="4.2"
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
    ["audit"]="Configure auditd logging"
    ["lynis_audit"]="Run Lynis security audit"
    ["secure_shared_memory"]="Secure shared memory"
    ["ssh_hardening"]="Harden SSH configuration"
    ["automatic_updates"]="Enable automatic security updates"
    ["ipv6"]="Configure IPv6 settings"
    ["clamav"]="Install ClamAV antivirus"
    ["sysctl"]="Configure kernel parameters"
    ["password_policy"]="Set strong password policies"
    ["ntp"]="Configure time synchronization"
    ["rootkit_scanner"]="Install rootkit scanners"
    ["firewall"]="Configure UFW firewall"
    ["apparmor"]="Setup AppArmor profiles"
    ["fail2ban"]="Setup Fail2Ban intrusion prevention"
    ["boot_security"]="Secure boot settings"
    ["root_access"]="Disable direct root login"
    ["packages"]="Remove unnecessary packages"
    ["usb_protection"]="Configure USB device policies"
    ["aide"]="Setup AIDE file integrity"
    ["filesystems"]="Disable unused filesystems"
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
    
    echo "${log_entry}" | sudo tee -a "${LOG_FILE}" >/dev/null 2>&1 || true
    
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
            $VERBOSE && echo -e "${BLUE}[INFO]${NC} ${message}" || true
            ;;
        *)
            echo "${message}"
            ;;
    esac
    return 0
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
    printf "\r%${COLUMNS:-80}s\r" " " || true
    
    # Only show progress bar if we're in an interactive terminal
    if [[ -t 1 ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        printf "\r["
        printf "%${filled}s" | tr ' ' '='
        printf "%$((width - filled))s" | tr ' ' '-'
        printf "] %3d%% - %s" "${percentage}" "${task}"
        
        # Add newline only at the end - safe with set -e
        if [[ ${current} -eq ${total} ]]; then
            echo
        fi
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

load_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        log INFO "Loading configuration from ${CONFIG_FILE}"
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
    fi
}

display_help() {
    cat << EOF
Usage: sudo ./${SCRIPT_NAME} [OPTIONS]

Enhanced Linux Security Hardening Script v${VERSION}
Optimized for Kubuntu 24.04+, Ubuntu 25.10+, and Debian 13

OPTIONS:
    -h, --help              Display this help message
    -v, --verbose           Enable verbose output
    -n, --non-interactive   Run without user prompts
    -d, --dry-run          Perform a dry run without changes
    -l, --level LEVEL      Set security level (low|moderate|high|paranoid)
    -e, --enable MODULES   Enable specific modules (comma-separated)
    -x, --disable MODULES  Disable specific modules (comma-separated)
    -r, --restore [FILE]   Restore from backup (optionally specify file)
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
    # Standard hardening with default (moderate) security
    sudo ./${SCRIPT_NAME} -v
    
    # Non-interactive high security hardening
    sudo ./${SCRIPT_NAME} -n -l high
    
    # Enable only firewall and SSH hardening
    sudo ./${SCRIPT_NAME} -e firewall,ssh_hardening,fail2ban
    
    # Harden with all except AIDE and ClamAV
    sudo ./${SCRIPT_NAME} -x aide,clamav
    
    # Dry run to preview changes
    sudo ./${SCRIPT_NAME} -d -v
    
    # Restore from backup
    sudo ./${SCRIPT_NAME} --restore

DOCUMENTATION:
    Full documentation: https://github.com/captainzero93/security_harden_linux
    Report issues: https://github.com/captainzero93/security_harden_linux/issues

EOF
    exit 0
}

list_modules() {
    echo "Available Security Modules:"
    echo "============================"
    echo ""
    for module in "${!SECURITY_MODULES[@]}"; do
        printf "  %-20s - %s\n" "${module}" "${SECURITY_MODULES[${module}]}"
    done
    echo ""
    echo "Dependencies:"
    for module in "${!MODULE_DEPS[@]}"; do
        if [[ -n "${MODULE_DEPS[${module}]}" ]]; then
            printf "  %-20s requires: %s\n" "${module}" "${MODULE_DEPS[${module}]}"
        fi
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
    
    # Check for lsb_release
    if ! command -v lsb_release &> /dev/null; then
        log WARNING "lsb_release not found. Installing lsb-release..."
        if sudo apt-get update && sudo apt-get install -y lsb-release; then
            log SUCCESS "lsb-release installed"
        else
            log ERROR "Failed to install lsb-release"
            return 1
        fi
    fi
    
    # Get OS information safely
    local os_name os_version os_version_codename
    if [[ -f /etc/os-release ]]; then
        # Source the file in a subshell to avoid readonly variable issues
        os_name=$(grep '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"' | tr '[:lower:]' '[:upper:]')
        os_version=$(grep '^VERSION_ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
        os_version_codename=$(grep '^VERSION_CODENAME=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
        
        # If using lsb_release, prefer it as fallback
        if [[ -z "$os_name" ]]; then
            os_name=$(lsb_release -si 2>/dev/null || echo "Unknown")
        fi
        if [[ -z "$os_version" ]]; then
            os_version=$(lsb_release -sr 2>/dev/null || echo "Unknown")
        fi
    else
        log WARNING "/etc/os-release not found, using lsb_release"
        os_name=$(lsb_release -si 2>/dev/null || echo "Unknown")
        os_version=$(lsb_release -sr 2>/dev/null || echo "Unknown")
    fi
    
    # Check for supported OS
    if [[ ! "${os_name}" =~ ^(UBUNTU|DEBIAN|KUBUNTU|LINUXMINT|POP)$ ]]; then
        log WARNING "OS '${os_name}' may not be fully supported. This script is optimized for Ubuntu/Debian-based systems."
    fi
    
    # Special handling for Debian 13 (Trixie)
    if [[ "${os_name}" =~ ^(DEBIAN)$ ]] && [[ "${os_version_codename}" == "trixie" ]]; then
        log INFO "Debian 13 (trixie) detected - using enhanced compatibility mode"
    fi
    
    # Check disk space
    local available_space=$(df /root | awk 'NR==2 {print $4}')
    if [[ ${available_space} -lt 1048576 ]]; then
        log WARNING "Low disk space ($(( available_space / 1024 ))MB). Backup may fail."
    fi
    
    # Check internet
    if ! check_internet; then
        log WARNING "No internet connectivity. Package installation may fail."
    fi
    
    log SUCCESS "System: ${os_name} ${os_version} ${os_version_codename:+(${os_version_codename})}"
}

# CRITICAL FIX: Completely rewritten wait_for_apt function
wait_for_apt() {
    local timeout=120  # Reduced from 300 to 120 seconds (2 minutes max wait)
    local elapsed=0
    local check_interval=2
    local warning_shown=false
    
    log INFO "Checking if package manager is available..."
    
    while [[ ${elapsed} -lt ${timeout} ]]; do
        # Check if lock files exist and if they're being used
        local locks_found=false
        local stale_locks=false
        
        # Check each lock file
        for lock_file in /var/lib/dpkg/lock-frontend /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
            if [[ -f "$lock_file" ]]; then
                locks_found=true
                # Check if the lock is actively held by a process
                if ! sudo fuser "$lock_file" >/dev/null 2>&1; then
                    stale_locks=true
                    break
                fi
            fi
        done
        
        # If no locks exist or if locks exist but aren't being used, we can proceed
        if [[ "$locks_found" == "false" ]] || [[ "$stale_locks" == "true" ]]; then
            if [[ "$stale_locks" == "true" ]]; then
                log WARNING "Detected stale APT locks. Attempting to clean them..."
                
                # Remove stale locks
                sudo rm -f /var/lib/dpkg/lock-frontend 2>/dev/null || true
                sudo rm -f /var/lib/dpkg/lock 2>/dev/null || true
                sudo rm -f /var/cache/apt/archives/lock 2>/dev/null || true
                sudo rm -f /var/lib/apt/lists/lock 2>/dev/null || true
                
                # Try to fix any broken dpkg state
                sudo dpkg --configure -a 2>/dev/null || true
                
                log SUCCESS "Stale locks removed, package manager is now available"
            else
                log INFO "Package manager is available"
            fi
            return 0
        fi
        
        # Show warning only once
        if [[ "$warning_shown" == "false" ]]; then
            log WARNING "Package manager is locked by another process, waiting..."
            log INFO "If this persists, you may need to manually stop apt/dpkg processes"
            warning_shown=true
        fi
        
        # Check if we're past half the timeout
        if [[ ${elapsed} -ge $((timeout / 2)) ]] && [[ ${elapsed} -lt $((timeout / 2 + check_interval)) ]]; then
            log WARNING "Still waiting for package manager (${elapsed}s elapsed)..."
            
            # Offer to force-remove locks if interactive
            if [[ "${INTERACTIVE}" == "true" ]]; then
                echo ""
                read -t 10 -p "Force remove APT locks? (y/N): " -r force_unlock || force_unlock="N"
                if [[ "${force_unlock}" =~ ^[Yy]$ ]]; then
                    log INFO "Force removing APT locks..."
                    sudo killall -9 apt apt-get dpkg 2>/dev/null || true
                    sudo rm -f /var/lib/dpkg/lock-frontend || true
                    sudo rm -f /var/lib/dpkg/lock || true
                    sudo rm -f /var/cache/apt/archives/lock || true
                    sudo rm -f /var/lib/apt/lists/lock || true
                    sudo dpkg --configure -a || true
                    log INFO "Locks removed, retrying..."
                    sleep 2
                    continue
                fi
            fi
        fi
        
        sleep ${check_interval}
        elapsed=$((elapsed + check_interval))
    done
    
    log ERROR "Timeout waiting for package manager to become available (${timeout}s)"
    log ERROR "Please close any running apt/dpkg processes and try again"
    log ERROR "Or run: sudo ./apt_diagnostic.sh"
    return 1
}

backup_files() {
    log INFO "Creating comprehensive system backup..."
    
    local backup_timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="/root/security_backup_${backup_timestamp}"
    
    if ! sudo mkdir -p "${backup_dir}"; then
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
System: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
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

install_package() {
    local package="$1"
    local retry_count=0
    local max_retries=3
    
    if dpkg -l | grep -q "^ii.*${package}"; then
        log INFO "Package ${package} is already installed"
        return 0
    fi
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would install ${package}"; return 0; }
    
    # CRITICAL: Ensure APT is available before attempting install
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

check_ssh_keys() {
    local has_valid_keys=false
    
    for user_home in /root /home/*; do
        [[ ! -d "$user_home" ]] && continue
        
        local auth_keys="$user_home/.ssh/authorized_keys"
        
        if [[ -f "$auth_keys" ]] && [[ -r "$auth_keys" ]] && [[ -s "$auth_keys" ]]; then
            if grep -qE '^(ssh-rsa|ssh-ed25519|ecdsa-sha2|ssh-dss) ' "$auth_keys"; then
                has_valid_keys=true
                log INFO "Valid SSH keys found in $auth_keys"
            fi
        fi
    done
    
    if [[ "$has_valid_keys" == "true" ]]; then
        return 0
    else
        return 1
    fi
}

module_system_update() {
    CURRENT_MODULE="system_update"
    log INFO "Updating system packages..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would update system"; return 0; }
    
    # CRITICAL: Ensure APT is available
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
    return 0
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
    return 0
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
    return 0
}

module_clamav() {
    CURRENT_MODULE="clamav"
    log INFO "Installing ClamAV antivirus..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would install ClamAV"; return 0; }
    
    install_package "clamav" || return 1
    install_package "clamav-daemon" || return 1
    
    log INFO "Updating ClamAV database (this may take a few minutes)..."
    sudo systemctl stop clamav-freshclam 2>/dev/null || true
    sudo freshclam 2>&1 | tee -a "${LOG_FILE}" || log WARNING "ClamAV update may have issues, will retry automatically"
    sudo systemctl start clamav-freshclam
    sudo systemctl enable clamav-freshclam
    
    log SUCCESS "ClamAV installed and database updated"
    return 0
}

module_root_access() {
    CURRENT_MODULE="root_access"
    log INFO "Securing root access..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure root access"; return 0; }
    
    sudo passwd -l root 2>&1 | tee -a "${LOG_FILE}"
    
    log SUCCESS "Root password login disabled"
    return 0
}

module_ssh_hardening() {
    CURRENT_MODULE="ssh_hardening"
    log INFO "Hardening SSH configuration..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would harden SSH"; return 0; }
    
    local sshd_config="/etc/ssh/sshd_config"
    
    if [[ ! -f "${sshd_config}" ]]; then
        log WARNING "SSH not installed, skipping SSH hardening"
        return 0
    fi
    
    sudo cp "${sshd_config}" "${sshd_config}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Basic SSH hardening
    sudo sed -i 's/^#*PermitRootLogin .*/PermitRootLogin no/' "${sshd_config}"
    sudo sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' "${sshd_config}"
    sudo sed -i 's/^#*PubkeyAuthentication .*/PubkeyAuthentication yes/' "${sshd_config}"
    sudo sed -i 's/^#*PermitEmptyPasswords .*/PermitEmptyPasswords no/' "${sshd_config}"
    sudo sed -i 's/^#*X11Forwarding .*/X11Forwarding no/' "${sshd_config}"
    
    # Restart SSH
    sudo systemctl restart sshd || sudo systemctl restart ssh
    
    log SUCCESS "SSH hardened successfully"
    return 0
}

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
    return 0
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
    return 0
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
    return 0
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
    return 0
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
        log INFO "IPv6 left enabled (not paranoid mode)"
    fi
    return 0
}

module_apparmor() {
    CURRENT_MODULE="apparmor"
    log INFO "Configuring AppArmor..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure AppArmor"; return 0; }
    
    install_package "apparmor" || return 1
    install_package "apparmor-utils" || return 1
    
    sudo systemctl enable apparmor
    sudo systemctl start apparmor
    
    log SUCCESS "AppArmor configured and enabled"
    return 0
}

module_ntp() {
    CURRENT_MODULE="ntp"
    log INFO "Configuring time synchronization..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure NTP"; return 0; }
    
    if systemctl list-unit-files | grep -q systemd-timesyncd.service; then
        sudo systemctl enable systemd-timesyncd
        sudo systemctl start systemd-timesyncd
        log SUCCESS "Time synchronization configured (systemd-timesyncd)"
    else
        install_package "ntp" || return 1
        sudo systemctl enable ntp
        sudo systemctl start ntp
        log SUCCESS "Time synchronization configured (NTP)"
    fi
    return 0
}

module_aide() {
    CURRENT_MODULE="aide"
    log INFO "Setting up AIDE file integrity monitoring..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would setup AIDE"; return 0; }
    
    install_package "aide" || return 1
    
    log INFO "Initializing AIDE database (this will take several minutes)..."
    sudo aideinit 2>&1 | tee -a "${LOG_FILE}"
    
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        log SUCCESS "AIDE configured successfully"
    else
        log WARNING "AIDE database creation may not have completed"
    fi
    return 0
}

module_sysctl() {
    CURRENT_MODULE="sysctl"
    log INFO "Configuring kernel security parameters..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure sysctl"; return 0; }
    
    cat >> /etc/sysctl.conf << EOF
# Security hardening parameters
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
EOF
    
    sudo sysctl -p
    
    log SUCCESS "Kernel security parameters configured"
    return 0
}

module_password_policy() {
    CURRENT_MODULE="password_policy"
    log INFO "Configuring strong password policies..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure passwords"; return 0; }
    
    install_package "libpam-pwquality" || return 1
    
    # Set password aging
    sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    
    # Configure password quality
    cat > /etc/security/pwquality.conf << EOF
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF
    
    log SUCCESS "Password policies configured"
    return 0
}

module_automatic_updates() {
    CURRENT_MODULE="automatic_updates"
    log INFO "Enabling automatic security updates..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would enable auto-updates"; return 0; }
    
    install_package "unattended-upgrades" || return 1
    
    sudo dpkg-reconfigure -plow unattended-upgrades
    
    log SUCCESS "Automatic updates enabled"
    return 0
}

module_rootkit_scanner() {
    CURRENT_MODULE="rootkit_scanner"
    log INFO "Installing rootkit scanners..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would install scanners"; return 0; }
    
    install_package "rkhunter" || return 1
    install_package "chkrootkit" || return 1
    
    sudo rkhunter --update 2>&1 | tee -a "${LOG_FILE}" || true
    sudo rkhunter --propupd 2>&1 | tee -a "${LOG_FILE}" || true
    
    log SUCCESS "Rootkit scanners installed"
    return 0
}

module_usb_protection() {
    CURRENT_MODULE="usb_protection"
    log INFO "Configuring USB device logging..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would configure USB"; return 0; }
    
    cat > /etc/udev/rules.d/90-usb-logging.rules << EOF
ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/sh -c 'echo USB device: \$attr{idVendor}:\$attr{idProduct} >> /var/log/usb-devices.log'"
EOF
    
    sudo udevadm control --reload-rules
    sudo touch /var/log/usb-devices.log
    sudo chmod 644 /var/log/usb-devices.log
    
    log SUCCESS "USB logging configured"
    return 0
}

module_secure_shared_memory() {
    CURRENT_MODULE="secure_shared_memory"
    log INFO "Securing shared memory..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would secure memory"; return 0; }
    
    if ! grep -q "tmpfs.*noexec" /etc/fstab; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" | sudo tee -a /etc/fstab
        log SUCCESS "Shared memory secured (takes effect after reboot)"
    else
        log INFO "Shared memory already secured"
    fi
    return 0
}

module_lynis_audit() {
    CURRENT_MODULE="lynis_audit"
    log INFO "Running Lynis security audit..."
    
    [[ "${DRY_RUN}" == "true" ]] && { log INFO "[DRY RUN] Would run Lynis"; return 0; }
    
    if ! command -v lynis &> /dev/null; then
        log WARNING "Lynis not available, skipping audit"
        return 0
    fi
    
    sudo lynis audit system --quick 2>&1 | tee -a "${LOG_FILE}" || log WARNING "Lynis audit completed with warnings"
    
    log SUCCESS "Lynis audit completed"
    return 0
}

generate_report() {
    log INFO "Generating security report..."
    
    local failed_list=""
    if [[ ${#FAILED_MODULES[@]} -gt 0 ]]; then
        failed_list="<div class=\"info-box error\"><h2>Failed Modules</h2><p><strong>Failed:</strong> ${FAILED_MODULES[*]}</p></div>"
    fi
    
    cat << EOF > "${REPORT_FILE}"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Hardening Report - $(hostname)</title>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 40px; 
            border-radius: 12px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.3); 
        }
        h1 { 
            color: #2d3748; 
            border-bottom: 4px solid #667eea; 
            padding-bottom: 15px; 
            font-size: 2.5em;
            margin-top: 0;
        }
        h2 {
            color: #4a5568;
            margin-top: 30px;
            font-size: 1.5em;
        }
        .info-box { 
            background: #edf2f7; 
            border-left: 6px solid #4299e1; 
            padding: 20px; 
            margin: 20px 0; 
            border-radius: 6px; 
        }
        .success { 
            background: #f0fff4; 
            border-left-color: #48bb78; 
        }
        .warning { 
            background: #fffaf0; 
            border-left-color: #ed8936; 
        }
        .error { 
            background: #fff5f5; 
            border-left-color: #f56565; 
        }
        .info-box p {
            margin: 10px 0;
            line-height: 1.6;
        }
        .info-box strong {
            color: #2d3748;
            font-weight: 600;
        }
        code {
            background: #2d3748;
            color: #68d391;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        ul {
            line-height: 1.8;
        }
        .footer { 
            margin-top: 40px; 
            padding-top: 20px; 
            border-top: 2px solid #e2e8f0; 
            color: #718096; 
            font-size: 0.9em; 
            text-align: center;
        }
        .footer a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        .footer a:hover {
            text-decoration: underline;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            margin-left: 10px;
        }
        .badge-success {
            background: #c6f6d5;
            color: #22543d;
        }
        .badge-warning {
            background: #feebc8;
            color: #7c2d12;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Hardening Report</h1>
        
        <div class="info-box">
            <h2>System Information</h2>
            <p><strong>System:</strong> $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)</p>
            <p><strong>Kernel:</strong> $(uname -r)</p>
            <p><strong>Hostname:</strong> $(hostname)</p>
            <p><strong>Date:</strong> $(date)</p>
            <p><strong>Desktop Environment:</strong> ${IS_DESKTOP}</p>
            <p><strong>Security Level:</strong> ${SECURITY_LEVEL} <span class="badge badge-success">Applied</span></p>
            <p><strong>Script Version:</strong> ${VERSION}</p>
        </div>
        
        <div class="info-box success">
            <h2>✅ Executed Modules</h2>
            <p><strong>Total Completed:</strong> ${#EXECUTED_MODULES[@]}</p>
            <p><strong>Modules:</strong> ${EXECUTED_MODULES[*]}</p>
        </div>
        
        ${failed_list}
        
        <div class="info-box">
            <h2>📋 Backup Information</h2>
            <p><strong>Log File:</strong> <code>${LOG_FILE}</code></p>
            <p>To restore from backup, run:<br>
            <code>sudo ./${SCRIPT_NAME} --restore</code></p>
        </div>
        
        <div class="info-box warning">
            <h2>⚠️ Important Next Steps</h2>
            <ul>
                <li><strong>Restart your system</strong> to apply all kernel and boot changes</li>
                <li>Keep the backup files safe for recovery purposes</li>
                <li>Review the detailed log: <code>${LOG_FILE}</code></li>
                <li>Test all critical services before deploying to production</li>
                <li>If using SSH, verify key-based login works before logging out</li>
                <li>Check firewall rules: <code>sudo ufw status verbose</code></li>
                <li>Monitor blocked IPs: <code>sudo fail2ban-client status sshd</code></li>
            </ul>
        </div>
        
        <div class="info-box">
            <h2>📊 Security Recommendations</h2>
            <ul>
                <li>Run periodic security scans: <code>sudo rkhunter --check</code></li>
                <li>Check AIDE reports: <code>sudo aide --check</code></li>
                <li>Review audit logs: <code>sudo ausearch -m USER_LOGIN -ts recent</code></li>
                <li>Monitor AppArmor: <code>sudo aa-status</code></li>
                <li>Keep system updated: <code>sudo apt update && sudo apt upgrade</code></li>
            </ul>
        </div>
        
        <div class="footer">
            <p><strong>Enhanced Linux Security Hardening Script v${VERSION}</strong></p>
            <p>Created by captainzero93 | Fixed by Claude | 
            <a href="https://github.com/captainzero93/security_harden_linux" target="_blank">GitHub Repository</a></p>
            <p>Report generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
        </div>
    </div>
</body>
</html>
EOF
    
    sudo chmod 600 "${REPORT_FILE}"
    
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
            # Execute the module
            if "${func}"; then
                EXECUTED_MODULES+=("${module}")
                log SUCCESS "Module ${module} completed"
                
                # Show progress AFTER module completes successfully
                show_progress ${current} ${total} "Completed ${SECURITY_MODULES[${module}]:-Unknown}"
                
                # CRITICAL: Small delay to ensure terminal output is flushed
                sleep 0.5
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
            -x|--disable)
                DISABLE_MODULES="$2"
                shift 2
                ;;
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
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            --version)
                echo "Enhanced Linux Security Hardening Script v${VERSION}"
                exit 0
                ;;
            --list-modules)
                list_modules
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
    load_config
    validate_security_level
    check_requirements
    
    sudo touch "${LOG_FILE}"
    sudo chmod 640 "${LOG_FILE}"
    
    echo ""
    log INFO "================================"
    log INFO "Security Hardening Script v${VERSION}"
    log INFO "================================"
    log INFO "Security Level: ${SECURITY_LEVEL}"
    log INFO "Desktop Mode: ${IS_DESKTOP}"
    log INFO "Dry Run: ${DRY_RUN}"
    log INFO "Interactive: ${INTERACTIVE}"
    echo ""
    
    [[ "${DRY_RUN}" == "false" ]] && backup_files
    
    execute_modules
    generate_report
    
    echo ""
    log SUCCESS "================================"
    log SUCCESS "Security hardening completed!"
    log SUCCESS "================================"
    log INFO "Executed modules: ${#EXECUTED_MODULES[@]}"
    [[ ${#FAILED_MODULES[@]} -gt 0 ]] && log WARNING "Failed modules: ${#FAILED_MODULES[@]} (${FAILED_MODULES[*]})"
    log INFO "Log: ${LOG_FILE}"
    log INFO "Report: ${REPORT_FILE}"
    echo ""
    
    if [[ "${DRY_RUN}" == "false" ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        read -p "Restart recommended to apply all changes. Restart now? (y/N): " -r restart
        [[ "${restart}" =~ ^[Yy]$ ]] && sudo reboot
    fi
}

main "$@"
