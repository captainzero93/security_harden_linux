#!/bin/bash

# FORTRESS.SH - Linux Security Hardening Script 
# Version: 5.1 - Critical Fixes & Enhanced Compatibility
# Author: captainzero93
# GitHub: https://github.com/captainzero93/security_harden_linux
# Optimized for Ubuntu 24.04+, Debian 13+
# Last Updated: 2026-01-31
#
# MAJOR CHANGES IN v5.1:
# - FIXED: Docker networking broken by IP forwarding disable (Issue #10)
# - FIXED: Browser launch failures from /dev/shm noexec (Issue #8)
# - FIXED: Custom configuration file not implemented (Issue #11)
# - ADDED: Docker detection and conditional IP forwarding
# - ADDED: Full configuration file support with fortress.conf
# - ADDED: Pre-flight application compatibility checking
# - IMPROVED: Desktop vs server mode intelligence

set -euo pipefail

#=============================================================================
# GLOBAL CONFIGURATION
#=============================================================================

readonly VERSION="5.1"
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/fortress_hardening.log"
readonly REPORT_FILE="/root/fortress_report_$(date +%Y%m%d_%H%M%S).html"
readonly BACKUP_DIR="/root/fortress_backups_$(date +%Y%m%d_%H%M%S)"
readonly CONFIG_FILE="${SCRIPT_DIR}/fortress.conf"
readonly TEMP_DIR=$(mktemp -d -t fortress.XXXXXXXXXX)

# Runtime configuration
VERBOSE=false
DRY_RUN=false
INTERACTIVE=true
EXPLAIN_MODE=false
ENABLE_MODULES=""
DISABLE_MODULES=""
SECURITY_LEVEL="moderate"
IS_DESKTOP=false
CURRENT_MODULE=""

# NEW in v5.1: Compatibility flags
DOCKER_DETECTED=false
ALLOW_DOCKER_FORWARDING=false
ALLOW_BROWSER_SHAREDMEM=false
FORCE_DESKTOP_MODE=false
FORCE_SERVER_MODE=false
GENERATE_CONFIG=false

# NEW in v5.1: Application detection
declare -a DETECTED_BROWSERS=()
declare -a DETECTED_CONTAINERS=()
declare -a DETECTED_VMS=()

# Tracking
declare -a EXECUTED_MODULES=()
declare -a FAILED_MODULES=()
declare -A MODULE_EXPLANATIONS=()

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

#=============================================================================
# SECURITY MODULES WITH DETAILED EXPLANATIONS
#=============================================================================

declare -A SECURITY_MODULES=(
    ["system_update"]="Update system packages"
    ["audit"]="Configure auditd logging"
    ["secure_shared_memory"]="Secure shared memory"
    ["ssh_hardening"]="Harden SSH configuration"
    ["automatic_updates"]="Enable automatic security updates"
    ["firewall"]="Configure UFW firewall"
    ["sysctl"]="Configure kernel parameters"
    ["password_policy"]="Set strong password policies"
    ["ntp"]="Configure time synchronization"
    ["apparmor"]="Setup AppArmor profiles"
    ["boot_security"]="Verify secure boot configuration"
    ["root_access"]="Disable direct root login"
    ["packages"]="Remove unnecessary packages"
    ["usb_protection"]="Configure USB device policies"
    ["filesystems"]="Disable unused filesystems"
    ["package_verification"]="Setup package integrity checking"
    ["fail2ban"]="Setup Fail2Ban (optional)"
)

# Module dependencies
declare -A MODULE_DEPS=(
    ["system_update"]=""
    ["audit"]="system_update"
    ["secure_shared_memory"]=""
    ["ssh_hardening"]="system_update"
    ["automatic_updates"]="system_update"
    ["firewall"]=""
    ["sysctl"]=""
    ["password_policy"]=""
    ["ntp"]="system_update"
    ["apparmor"]="system_update"
    ["boot_security"]=""
    ["root_access"]=""
    ["packages"]=""
    ["usb_protection"]=""
    ["filesystems"]=""
    ["package_verification"]="system_update"
    ["fail2ban"]="system_update firewall ssh_hardening"
)

#=============================================================================
# UTILITY FUNCTIONS
#=============================================================================

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
    local log_entry="${timestamp} [${level}] [${CURRENT_MODULE:-SYSTEM}]: ${message}"
    
    echo "${log_entry}" | sudo tee -a "${LOG_FILE}" >/dev/null 2>&1 || true
    
    case "${level}" in
        ERROR)
            echo -e "${RED}[ERROR]${NC} ${message}" >&2
            ;;
        WARNING|WARN)
            echo -e "${YELLOW}[WARNING]${NC} ${message}"
            ;;
        SUCCESS)
            echo -e "${GREEN}[✓]${NC} ${message}"
            ;;
        INFO)
            $VERBOSE && echo -e "${BLUE}[INFO]${NC} ${message}" || true
            ;;
        EXPLAIN)
            echo -e "${CYAN}[WHY]${NC} ${message}"
            ;;
        *)
            echo "${message}"
            ;;
    esac
}

explain() {
    if [[ "${EXPLAIN_MODE}" == "true" ]]; then
        echo ""
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║ EXPLANATION: ${1}${NC}"
        echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
        
        shift
        for line in "$@"; do
            echo -e "${CYAN}║${NC} ${line}"
        done
        
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        
        if [[ "${INTERACTIVE}" == "true" ]]; then
            read -p "Press Enter to continue..." -r
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
    # NEW in v5.1: Check for forced modes
    if [[ "${FORCE_DESKTOP_MODE}" == "true" ]]; then
        IS_DESKTOP=true
        log INFO "Desktop mode FORCED via configuration"
        return 0
    fi
    
    if [[ "${FORCE_SERVER_MODE}" == "true" ]]; then
        IS_DESKTOP=false
        log INFO "Server mode FORCED via configuration"
        return 0
    fi
    
    # Continue with existing desktop detection logic
    if [[ -n "${XDG_CURRENT_DESKTOP:-}" ]] || [[ -n "${DESKTOP_SESSION:-}" ]] || \
       systemctl is-active --quiet display-manager 2>/dev/null; then
        IS_DESKTOP=true
        log INFO "Desktop environment detected: ${XDG_CURRENT_DESKTOP:-Unknown}"
    else
        IS_DESKTOP=false
        log INFO "Server environment detected (no desktop)"
    fi
}

backup_file() {
    local file="$1"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would backup: ${file}"
        return 0
    fi
    
    if [[ -f "${file}" ]]; then
        local backup_path="${BACKUP_DIR}${file}"
        sudo mkdir -p "$(dirname "${backup_path}")"
        sudo cp -a "${file}" "${backup_path}"
        log INFO "Backed up: ${file} → ${backup_path}"
    fi
}

execute_command() {
    local description="$1"
    shift
    local command="$@"
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] ${description}: ${command}"
        return 0
    fi
    
    log INFO "${description}"
    eval "${command}"
}

wait_for_apt() {
    local max_wait=300
    local waited=0
    
    while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          sudo fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        
        if [[ ${waited} -eq 0 ]]; then
            log WARNING "Waiting for other package managers to finish..."
        fi
        
        sleep 2
        waited=$((waited + 2))
        
        if [[ ${waited} -ge ${max_wait} ]]; then
            log ERROR "Timed out waiting for package manager"
            return 1
        fi
    done
    
    return 0
}

#=============================================================================
# NEW in v5.1: CONFIGURATION FILE SUPPORT
#=============================================================================

load_config() {
    # Load configuration from fortress.conf if it exists
    if [[ -f "${CONFIG_FILE}" ]]; then
        log INFO "Loading configuration from ${CONFIG_FILE}"
        
        # Source the config file
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
        
        # Validate configuration
        if [[ -n "${SECURITY_LEVEL:-}" ]]; then
            case "${SECURITY_LEVEL}" in
                low|moderate|high|paranoid) ;;
                *)
                    log ERROR "Invalid SECURITY_LEVEL in config: ${SECURITY_LEVEL}"
                    log ERROR "Must be: low, moderate, high, or paranoid"
                    exit 1
                    ;;
            esac
        fi
        
        # Apply config file settings
        [[ "${VERBOSE:-}" == "true" ]] && VERBOSE=true
        [[ "${DRY_RUN:-}" == "true" ]] && DRY_RUN=true
        [[ "${INTERACTIVE:-}" == "false" ]] && INTERACTIVE=false
        [[ "${FORCE_DESKTOP_MODE:-}" == "true" ]] && FORCE_DESKTOP_MODE=true
        [[ "${FORCE_SERVER_MODE:-}" == "true" ]] && FORCE_SERVER_MODE=true
        [[ "${ALLOW_DOCKER_FORWARDING:-}" == "true" ]] && ALLOW_DOCKER_FORWARDING=true
        [[ "${ALLOW_BROWSER_SHAREDMEM:-}" == "true" ]] && ALLOW_BROWSER_SHAREDMEM=true
        
        log SUCCESS "Configuration loaded successfully"
    else
        log INFO "No configuration file found at ${CONFIG_FILE}, using defaults"
    fi
}

generate_config_template() {
    # Generate a template fortress.conf file
    local output_file="${1:-${SCRIPT_DIR}/fortress.conf}"
    
    cat > "${output_file}" << 'CONFIGEOF'
# FORTRESS.SH Configuration File v5.1
# =======================================================
# CLI arguments override these settings
# Documentation: https://github.com/captainzero93/security_harden_linux

# ===========================
# BASIC SETTINGS
# ===========================

# Security Level: low, moderate, high, paranoid
# - low: Minimal hardening, maximum compatibility
# - moderate: Balanced security and usability (recommended)
# - high: Maximum security, may break some applications
# - paranoid: Extreme security, requires careful configuration
SECURITY_LEVEL="moderate"

# Interactive prompts (set false for automation/scripts)
INTERACTIVE=true

# Verbose output (detailed logging)
VERBOSE=false

# Dry run mode (show what would be done without applying)
DRY_RUN=false

# Explain mode (show educational context for each action)
EXPLAIN_MODE=false

# ===========================
# COMPATIBILITY SETTINGS
# ===========================

# Docker Compatibility
# If true, enables IP forwarding required for Docker container networking
# Trade-off: Slightly reduced security, Docker works properly
ALLOW_DOCKER_FORWARDING=true

# Browser Shared Memory Compatibility
# If true, skips noexec on /dev/shm (required for Firefox/Chrome JIT)
# Trade-off: Attackers could execute code from /dev/shm, browsers work
ALLOW_BROWSER_SHAREDMEM=true

# Force Desktop Mode
# If true, applies desktop-friendly settings even if no DE detected
FORCE_DESKTOP_MODE=false

# Force Server Mode
# If true, applies strict server settings even if desktop detected
FORCE_SERVER_MODE=false

# ===========================
# MODULE CONTROL
# ===========================

# Enable only specific modules (comma-separated, leave empty for all)
# Example: ENABLE_MODULES="system_update,ssh_hardening,firewall,sysctl"
ENABLE_MODULES=""

# Disable specific modules (comma-separated)
# Example: DISABLE_MODULES="fail2ban,usb_protection,apparmor"
DISABLE_MODULES=""

# ===========================
# SSH HARDENING
# ===========================

# SSH Port (default 22, change for security through obscurity)
SSH_PORT=22

# Allowed SSH users (comma-separated, leave empty to allow all)
# Example: SSH_ALLOWED_USERS="admin,deploy,backup"
SSH_ALLOWED_USERS=""

# Maximum authentication attempts before disconnect
SSH_MAX_AUTH_TRIES=3

# ===========================
# FIREWALL SETTINGS
# ===========================

# UFW Default incoming policy: deny, reject, or allow
UFW_DEFAULT_INCOMING="deny"

# UFW Default outgoing policy: deny, reject, or allow
UFW_DEFAULT_OUTGOING="allow"

# Allow specific ports (comma-separated)
# Example: FIREWALL_ALLOW_PORTS="80,443,8080"
FIREWALL_ALLOW_PORTS=""

# ===========================
# PASSWORD POLICY
# ===========================

# Minimum password length
PASSWORD_MIN_LENGTH=12

# Password complexity requirements
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=true

# Password history (prevent reuse of last N passwords)
PASSWORD_HISTORY=5

# ===========================
# AUDIT LOGGING
# ===========================

# Enable audit logging
ENABLE_AUDIT_LOGGING=true

# Audit log size (MB)
AUDIT_MAX_LOG_FILE=50

# Number of audit log files to keep
AUDIT_NUM_LOGS=5

# ===========================
# AUTOMATIC UPDATES
# ===========================

# Enable automatic security updates
ENABLE_AUTO_UPDATES=true

# Auto-reboot after updates (if required)
AUTO_REBOOT_IF_REQUIRED=false

# Auto-reboot time (24-hour format, e.g., "03:00")
AUTO_REBOOT_TIME="03:00"

# ===========================
# FAIL2BAN (OPTIONAL)
# ===========================

# Enable fail2ban (recommended only for SSH-accessible servers)
ENABLE_FAIL2BAN=false

# Ban time (seconds)
FAIL2BAN_BANTIME=3600

# Find time window (seconds)
FAIL2BAN_FINDTIME=600

# Max retry attempts
FAIL2BAN_MAXRETRY=5

# ===========================
# USB PROTECTION
# ===========================

# Enable USB device restrictions
ENABLE_USB_PROTECTION=false

# Allowed USB device IDs (comma-separated, format: vendor:product)
# Example: USB_ALLOWED_DEVICES="046d:c52b,1d6b:0002"
USB_ALLOWED_DEVICES=""

# ===========================
# ADVANCED SETTINGS
# ===========================

# Sysctl custom parameters (one per line in format: key=value)
# Example:
# SYSCTL_CUSTOM="
# net.ipv4.tcp_keepalive_time=600
# net.core.netdev_max_backlog=5000
# "
SYSCTL_CUSTOM=""

# AppArmor custom profiles directory
APPARMOR_CUSTOM_PROFILES="/etc/apparmor.d/local"

# Backup directory (defaults to /root/fortress_backups_TIMESTAMP)
# BACKUP_DIR="/custom/backup/location"

# Log file location
# LOG_FILE="/var/log/fortress_hardening.log"
CONFIGEOF

    chmod 600 "${output_file}"
    log SUCCESS "Configuration template generated: ${output_file}"
    log INFO "Edit this file and run fortress_improved.sh to apply your settings"
    echo ""
    echo -e "${GREEN}Configuration template created:${NC} ${output_file}"
    echo ""
    echo "Next steps:"
    echo "1. Edit fortress.conf with your preferred settings"
    echo "2. Run: sudo ./fortress_improved.sh"
    echo ""
}

#=============================================================================
# NEW in v5.1: APPLICATION DETECTION
#=============================================================================

detect_docker() {
    # Detect if Docker is installed and running
    log INFO "Checking for Docker installation..."
    
    if command -v docker &>/dev/null; then
        DOCKER_DETECTED=true
        DETECTED_CONTAINERS+=("docker")
        log INFO "Docker detected: $(docker --version 2>/dev/null || echo 'version unknown')"
        
        # Check if Docker daemon is running
        if systemctl is-active --quiet docker 2>/dev/null || pgrep dockerd >/dev/null; then
            log INFO "Docker daemon is running"
            
            # Check for running containers
            local container_count=$(docker ps -q 2>/dev/null | wc -l)
            if [[ $container_count -gt 0 ]]; then
                log INFO "Found $container_count running Docker container(s)"
            fi
        else
            log WARN "Docker is installed but not running"
        fi
    else
        log INFO "Docker not detected"
    fi
    
    # Check for Podman
    if command -v podman &>/dev/null; then
        DETECTED_CONTAINERS+=("podman")
        log INFO "Podman detected: $(podman --version 2>/dev/null || echo 'version unknown')"
    fi
    
    # Check for LXC/LXD
    if command -v lxc &>/dev/null || command -v lxd &>/dev/null; then
        DETECTED_CONTAINERS+=("lxc")
        log INFO "LXC/LXD detected"
    fi
}

detect_browsers() {
    # Detect installed web browsers
    log INFO "Checking for installed web browsers..."
    
    local browsers=(
        "firefox:Firefox"
        "firefox-esr:Firefox ESR"
        "chromium:Chromium"
        "chromium-browser:Chromium"
        "google-chrome:Google Chrome"
        "brave-browser:Brave"
        "microsoft-edge:Edge"
        "vivaldi:Vivaldi"
        "opera:Opera"
    )
    
    for browser_pair in "${browsers[@]}"; do
        local cmd="${browser_pair%%:*}"
        local name="${browser_pair##*:}"
        
        if command -v "$cmd" &>/dev/null; then
            DETECTED_BROWSERS+=("$name")
            log INFO "Browser detected: $name"
        fi
    done
    
    if [[ ${#DETECTED_BROWSERS[@]} -eq 0 ]]; then
        log INFO "No browsers detected"
    else
        log INFO "Total browsers detected: ${#DETECTED_BROWSERS[@]}"
    fi
}

detect_virtualization() {
    # Detect virtualization platforms
    log INFO "Checking for virtualization platforms..."
    
    if command -v VBoxManage &>/dev/null; then
        DETECTED_VMS+=("VirtualBox")
        log INFO "VirtualBox detected"
    fi
    
    if command -v qemu-system-x86_64 &>/dev/null; then
        DETECTED_VMS+=("QEMU")
        log INFO "QEMU detected"
    fi
    
    if command -v vmware &>/dev/null || command -v vmrun &>/dev/null; then
        DETECTED_VMS+=("VMware")
        log INFO "VMware detected"
    fi
    
    if [[ ${#DETECTED_VMS[@]} -eq 0 ]]; then
        log INFO "No virtualization platforms detected"
    fi
}

detect_critical_applications() {
    # Run all application detection functions
    log INFO "Performing pre-flight application detection..."
    echo ""
    
    detect_docker
    detect_browsers
    detect_virtualization
    
    echo ""
    log INFO "Pre-flight detection complete"
}

prompt_docker_compatibility() {
    # Prompt user about Docker IP forwarding
    if [[ "${DOCKER_DETECTED}" == "true" ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        echo ""
        echo -e "${YELLOW}════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}⚠️  DOCKER DETECTED${NC}"
        echo -e "${YELLOW}════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "Docker requires IP forwarding to be ENABLED to route container traffic."
        echo "However, IP forwarding increases attack surface by allowing packet routing."
        echo ""
        echo "Your options:"
        echo "  ${GREEN}Y${NC} = Enable IP forwarding (Docker works, slight security reduction)"
        echo "  ${RED}N${NC} = Disable IP forwarding (Maximum security, Docker networking broken)"
        echo ""
        
        read -p "Allow IP forwarding for Docker? [Y/n]: " -r
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            ALLOW_DOCKER_FORWARDING=false
            log WARN "User chose to disable IP forwarding - Docker networking will be broken"
            echo ""
            echo -e "${RED}WARNING: Docker container networking will NOT work.${NC}"
            echo "You can re-enable later by manually editing /etc/sysctl.d/99-fortress.conf"
        else
            ALLOW_DOCKER_FORWARDING=true
            log INFO "User enabled IP forwarding for Docker compatibility"
        fi
        echo ""
    elif [[ "${DOCKER_DETECTED}" == "true" ]] && [[ "${INTERACTIVE}" == "false" ]]; then
        # Non-interactive mode with Docker detected
        if [[ "${ALLOW_DOCKER_FORWARDING}" == "true" ]]; then
            log INFO "Non-interactive mode: IP forwarding enabled for Docker (from config)"
        else
            log WARN "Non-interactive mode: IP forwarding disabled - Docker may not work"
        fi
    fi
}

prompt_browser_compatibility() {
    # Prompt user about /dev/shm noexec
    if [[ "${IS_DESKTOP}" == "true" ]] && [[ ${#DETECTED_BROWSERS[@]} -gt 0 ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        echo ""
        echo -e "${YELLOW}════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}⚠️  BROWSERS DETECTED${NC}"
        echo -e "${YELLOW}════════════════════════════════════════════════════════${NC}"
        echo ""
        echo "Detected browsers: ${DETECTED_BROWSERS[*]}"
        echo ""
        echo "Applying 'noexec' to /dev/shm prevents executing code from shared memory."
        echo "This BREAKS modern browsers (Firefox, Chrome) that use JIT compilation."
        echo ""
        echo "Your options:"
        echo "  ${GREEN}N${NC} = Skip noexec (Browsers work, slightly reduced security)"
        echo "  ${RED}Y${NC} = Apply noexec (Maximum security, browsers will NOT launch)"
        echo ""
        
        read -p "Apply noexec to /dev/shm? (breaks browsers) [y/N]: " -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            ALLOW_BROWSER_SHAREDMEM=false
            log WARN "User chose to apply noexec - browsers will be broken"
            echo ""
            echo -e "${RED}WARNING: Browsers will NOT work.${NC}"
            echo "You can fix later with: sudo ./fix_library_permissions.sh"
        else
            ALLOW_BROWSER_SHAREDMEM=true
            log INFO "User skipped noexec for browser compatibility"
        fi
        echo ""
    elif [[ "${IS_DESKTOP}" == "false" ]]; then
        # Server mode - always apply noexec
        ALLOW_BROWSER_SHAREDMEM=false
        log INFO "Server mode: Applying noexec to /dev/shm (no browsers detected)"
    fi
}

#=============================================================================
# HELP AND INFORMATION
#=============================================================================

display_help() {
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════╗
║                    FORTRESS.SH - Security Hardening                      ║
║                         Version 5.1                                      ║
╚══════════════════════════════════════════════════════════════════════════╝

USAGE:
    sudo ./fortress.sh [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -v, --verbose           Enable verbose output
    -n, --non-interactive   Run without user prompts
    -d, --dry-run          Show what would be done (no changes)
    -e, --enable MODULES   Enable specific modules (comma-separated)
    -x, --disable MODULES  Disable specific modules (comma-separated)
    -l, --level LEVEL      Security level (low|moderate|high|paranoid)
    
    --explain              Educational mode - explains WHY for each action
    --list-modules         List all available modules
    --version              Show version information

Compatibility Options:
    --allow-docker           Enable IP forwarding for Docker
    --no-docker-compat       Disable IP forwarding (breaks Docker)
    --allow-browser-shm      Skip noexec on /dev/shm (browsers work)
    --no-browser-compat      Apply noexec to /dev/shm (breaks browsers)
    --force-desktop          Force desktop-mode settings
    --force-server           Force server-mode settings

Configuration:
    --generate-config        Create fortress.conf template

EXAMPLES:
    # Run with explanations (recommended for learning)
    sudo ./fortress.sh --explain

    # Dry run to see what would be done
    sudo ./fortress.sh --dry-run --verbose

    # Enable only specific modules
    sudo ./fortress.sh -e system_update,ssh_hardening,firewall

    # High security level, non-interactive
    sudo ./fortress.sh -l high -n

    # Generate configuration file template
    sudo ./fortress.sh --generate-config

    # Run with Docker compatibility
    sudo ./fortress.sh --allow-docker

SECURITY LEVELS:
    low       - Minimal hardening, preserves compatibility
    moderate  - Balanced security and usability (default)
    high      - Strong security, may affect some services
    paranoid  - Maximum security, requires careful configuration

MODULES:
    Use --list-modules to see all available security modules

EDUCATIONAL MODE (--explain):
    Explains the security rationale behind each action:
    • What threats each configuration addresses
    • Why certain defaults are insecure
    • Trade-offs between security and usability
    • Common misconceptions and security theater

IMPORTANT NOTES:
    • Always run with --dry-run first to understand changes
    • Use --explain mode to learn about each security measure
    • SSH hardening requires key-based auth setup FIRST
    • fail2ban is optional - understand when it's actually useful
    • This script cannot protect against kernel-level rootkits
    • Secure Boot verification is recommended but not automated

NEW IN v5.1:
    • Docker detection with conditional IP forwarding
    • Browser compatibility mode (skip /dev/shm noexec)
    • Full configuration file support (fortress.conf)
    • Pre-flight application detection
    • Health verification script (verify_fortress.sh)

GITHUB: https://github.com/captainzero93/security_harden_linux
AUTHOR: captainzero93

EOF
}

list_modules() {
    echo ""
    echo "Available Security Modules:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    local sorted_modules=($(echo "${!SECURITY_MODULES[@]}" | tr ' ' '\n' | sort))
    
    for module in "${sorted_modules[@]}"; do
        local deps="${MODULE_DEPS[${module}]:-none}"
        [[ -z "${deps}" ]] && deps="none"
        
        printf "  %-25s %s\n" "${module}" "${SECURITY_MODULES[${module}]}"
        printf "  %-25s Dependencies: %s\n\n" "" "${deps}"
    done
    
    exit 0
}

#=============================================================================
# MODULE IMPLEMENTATIONS
#=============================================================================

module_system_update() {
    CURRENT_MODULE="system_update"
    
    explain "System Updates" \
        "Keeping your system updated is the SINGLE most important security measure." \
        "" \
        "Why: Most exploits target known vulnerabilities that have patches available." \
        "Security updates fix these vulnerabilities before attackers can exploit them." \
        "" \
        "Updates address:" \
        "  • Kernel vulnerabilities (privilege escalation)" \
        "  • Library vulnerabilities (remote code execution)" \
        "  • Application bugs (various attack vectors)" \
        "" \
        "Trade-offs: Updates can occasionally break compatibility, but the security" \
        "benefit far outweighs this risk. Test in non-production first."
    
    log INFO "Updating package repositories..."
    wait_for_apt
    
    execute_command "Refreshing package lists" \
        "sudo apt-get update"
    
    if [[ "${SECURITY_LEVEL}" == "paranoid" ]]; then
        execute_command "Upgrading all packages (full upgrade)" \
            "sudo DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y"
    else
        execute_command "Upgrading packages (safe upgrade)" \
            "sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"
    fi
    
    log SUCCESS "System packages updated"
    return 0
}

module_ssh_hardening() {
    CURRENT_MODULE="ssh_hardening"
    
    explain "SSH Hardening" \
        "SSH is often the primary remote access method and a common attack target." \
        "" \
        "What we configure:" \
        "  • Disable password authentication (KEY-BASED AUTH ONLY)" \
        "  • Disable root login (use sudo instead)" \
        "  • Use strong ciphers and key exchange algorithms" \
        "  • Change default port (optional, reduces noise)" \
        "" \
        "Why password auth is disabled:" \
        "  • Even 'strong' passwords are vulnerable to brute force" \
        "  • SSH keys are cryptographically much stronger" \
        "  • No password means no password attacks - simple" \
        "" \
        "CRITICAL: You MUST have SSH key authentication working BEFORE" \
        "running this module, or you will be locked out!" \
        "" \
        "Why fail2ban is NOT included here:" \
        "  • With password auth disabled, brute force is impossible" \
        "  • fail2ban only blocks IPs, which doesn't stop key-based attacks" \
        "  • Your logs will fill with failed attempts, but they're harmless" \
        "  • If log noise bothers you, run SSH on non-standard port" \
        "" \
        "Common misconception: fail2ban is NOT needed with proper SSH hardening."
    
    local ssh_config="/etc/ssh/sshd_config"
    
    # Check if SSH is even installed/needed
    if ! command -v sshd &>/dev/null; then
        if [[ "${IS_DESKTOP}" == "true" ]]; then
            log INFO "SSH server not installed (normal for desktop)"
            log INFO "Desktop systems typically don't need SSH server running"
            
            if [[ "${INTERACTIVE}" == "true" ]]; then
                read -p "Do you want to install and configure SSH? (y/N): " -r install_ssh
                [[ ! "${install_ssh}" =~ ^[Yy]$ ]] && return 0
                
                execute_command "Installing OpenSSH server" \
                    "sudo apt-get install -y openssh-server"
            else
                return 0
            fi
        fi
    fi
    
    # Safety check for existing key-based auth
    if [[ "${INTERACTIVE}" == "true" ]] && [[ "${DRY_RUN}" == "false" ]]; then
        echo ""
        echo -e "${YELLOW}⚠️  IMPORTANT SSH SAFETY CHECK${NC}"
        echo ""
        echo "This module will disable password authentication."
        echo "You MUST have SSH key-based authentication working."
        echo ""
        echo "Can you currently SSH into this system using a key? (not a password)"
        read -p "Type 'yes' to confirm you have working key-based SSH: " -r confirm
        
        if [[ "${confirm}" != "yes" ]]; then
            log WARNING "SSH hardening skipped - setup key-based auth first"
            echo ""
            echo "To setup SSH key authentication:"
            echo "  1. On your client: ssh-keygen -t ed25519"
            echo "  2. Copy key to server: ssh-copy-id user@server"
            echo "  3. Test: ssh -i ~/.ssh/id_ed25519 user@server"
            echo "  4. Only then run this hardening module"
            return 0
        fi
    fi
    
    backup_file "${ssh_config}"
    
    # Get SSH port from config or use default
    local ssh_port="${SSH_PORT:-22}"
    local ssh_max_auth="${SSH_MAX_AUTH_TRIES:-3}"
    
    # Configure SSH hardening
    if [[ "${DRY_RUN}" == "false" ]]; then
        sudo tee "${ssh_config}" > /dev/null << EOF
# FORTRESS.SH SSH Configuration v5.1
# Strong security, key-based authentication only

# Port configuration
Port ${ssh_port}

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Strong cryptography
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# Connection settings
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
MaxAuthTries ${ssh_max_auth}
MaxSessions 10

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Other security settings
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
Compression delayed
EOF
        
        # Add allowed users if configured
        if [[ -n "${SSH_ALLOWED_USERS:-}" ]]; then
            echo "AllowUsers ${SSH_ALLOWED_USERS//,/ }" | sudo tee -a "${ssh_config}" >/dev/null
            log INFO "SSH restricted to users: ${SSH_ALLOWED_USERS}"
        fi
        
        execute_command "Restarting SSH service" \
            "sudo systemctl restart sshd 2>/dev/null || sudo systemctl restart ssh"
        
        log SUCCESS "SSH hardening applied"
    else
        log INFO "[DRY RUN] Would harden SSH configuration"
    fi
    
    return 0
}

module_fail2ban() {
    CURRENT_MODULE="fail2ban"
    
    explain "Fail2Ban (Optional)" \
        "fail2ban monitors log files and bans IPs showing malicious behavior." \
        "" \
        "IMPORTANT CONTEXT - When fail2ban IS useful:" \
        "  • Protecting web servers (Apache/Nginx authentication)" \
        "  • Protecting mail servers (SMTP/IMAP authentication)" \
        "  • Protecting FTP servers or other services with password auth" \
        "  • Reducing log noise from script kiddies" \
        "" \
        "When fail2ban is NOT useful (waste of resources):" \
        "  • SSH with password authentication already disabled" \
        "  • Systems that only run SSH with key-based auth" \
        "  • Desktop systems with no exposed services" \
        "" \
        "Why it's limited:" \
        "  • Only blocks IPs, easily bypassed with IP rotation" \
        "  • Doesn't stop attacks using valid credentials" \
        "  • Doesn't protect against kernel-level exploits" \
        "  • Can't detect sophisticated attacks" \
        "" \
        "Real talk: If SSH is your only service and you've disabled password" \
        "auth, fail2ban is security theater. The failed login attempts in your" \
        "logs are harmless - they can't succeed with keys-only auth." \
        "" \
        "Better alternatives to fail2ban:" \
        "  • Run SSH on non-standard port (reduces noise)" \
        "  • Use port knocking for additional obscurity" \
        "  • VPN-only access to SSH" \
        "  • Firewall rules limiting SSH to known IPs" \
        "" \
        "This module is OPTIONAL and disabled by default for SSH-only systems."
    
    # Check if this is even worth installing
    local has_web_server=false
    local has_mail_server=false
    local ssh_has_password_auth=true
    
    command -v apache2 &>/dev/null && has_web_server=true
    command -v nginx &>/dev/null && has_web_server=true
    command -v postfix &>/dev/null && has_mail_server=true
    
    if [[ -f /etc/ssh/sshd_config ]]; then
        if grep -q "^PasswordAuthentication no" /etc/ssh/sshd_config; then
            ssh_has_password_auth=false
        fi
    fi
    
    # Provide intelligent recommendation
    if [[ "${has_web_server}" == "false" ]] && \
       [[ "${has_mail_server}" == "false" ]] && \
       [[ "${ssh_has_password_auth}" == "false" ]]; then
        
        log INFO "Fail2Ban analysis: Limited value for this system"
        log INFO "  • No web server detected"
        log INFO "  • No mail server detected"  
        log INFO "  • SSH password authentication disabled"
        echo ""
        
        if [[ "${INTERACTIVE}" == "true" ]]; then
            echo "fail2ban would provide minimal security benefit here."
            echo "It would only reduce log noise from failed SSH attempts."
            echo ""
            read -p "Install fail2ban anyway? (y/N): " -r install_f2b
            [[ ! "${install_f2b}" =~ ^[Yy]$ ]] && return 0
        else
            log INFO "Skipping fail2ban - not beneficial for this configuration"
            return 0
        fi
    fi
    
    # If we got here, either there are services that benefit, or user wants it anyway
    execute_command "Installing fail2ban" \
        "sudo apt-get install -y fail2ban"
    
    # Get fail2ban settings from config or use defaults
    local f2b_bantime="${FAIL2BAN_BANTIME:-3600}"
    local f2b_findtime="${FAIL2BAN_FINDTIME:-600}"
    local f2b_maxretry="${FAIL2BAN_MAXRETRY:-5}"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        # Configure fail2ban based on what services are present
        sudo tee /etc/fail2ban/jail.local > /dev/null << EOF
[DEFAULT]
bantime = ${f2b_bantime}
findtime = ${f2b_findtime}
maxretry = ${f2b_maxretry}
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = ${ssh_has_password_auth}
port = ssh
logpath = /var/log/auth.log
EOF

        if [[ "${has_web_server}" == "true" ]]; then
            sudo tee -a /etc/fail2ban/jail.local > /dev/null << 'EOF'

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[apache-auth]
enabled = true
port = http,https
logpath = /var/log/apache*/*error.log
EOF
        fi
        
        execute_command "Enabling fail2ban" \
            "sudo systemctl enable fail2ban && sudo systemctl restart fail2ban"
        
        log SUCCESS "Fail2ban configured for detected services"
    fi
    
    return 0
}

module_package_verification() {
    CURRENT_MODULE="package_verification"
    
    explain "Package Integrity Verification" \
        "Verify that installed packages haven't been tampered with." \
        "" \
        "What this does:" \
        "  • Uses dpkg's built-in verification (MD5 checksums)" \
        "  • Checks if any package files have been modified" \
        "  • Creates a report of anomalies" \
        "" \
        "Why NOT AIDE:" \
        "  • AIDE requires custom configuration per system" \
        "  • AIDE on a live system can't detect kernel rootkits" \
        "  • Generic AIDE configs generate tons of false positives" \
        "  • dpkg already tracks package file hashes" \
        "" \
        "Limitations of ANY file integrity checking on live systems:" \
        "  • Kernel-level rootkits can hide modifications" \
        "  • Sophisticated malware can modify the checker itself" \
        "  • Only detects changes, not whether changes are malicious" \
        "" \
        "Proper file integrity verification requires:" \
        "  • Booting from known-good external media (USB/network)" \
        "  • Offline scanning of the filesystem" \
        "  • Comparing against known-good baselines" \
        "" \
        "What we DO instead:" \
        "  • Basic dpkg verification (good for detecting corruption)" \
        "  • Recommend proper secure boot configuration" \
        "  • Log anomalies for investigation" \
        "" \
        "This is useful for detecting:" \
        "  • Package corruption from disk errors" \
        "  • Accidental file modifications" \
        "  • Simple tampering attempts" \
        "" \
        "This CANNOT detect:" \
        "  • Kernel-level rootkits" \
        "  • Sophisticated malware" \
        "  • Attacks that modify the verification tools"
    
    log INFO "Running package verification (this may take a while)..."
    
    local verify_report="${TEMP_DIR}/package_verification.txt"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        # Verify all packages
        dpkg --verify > "${verify_report}" 2>&1 || true
        
        if [[ -s "${verify_report}" ]]; then
            local anomaly_count=$(wc -l < "${verify_report}")
            log WARNING "Found ${anomaly_count} package file anomalies"
            log INFO "Verification report: ${verify_report}"
            
            # Save to permanent location
            sudo cp "${verify_report}" "/var/log/fortress_package_verification_$(date +%Y%m%d).txt"
            
            if [[ "${anomaly_count}" -gt 100 ]]; then
                log WARNING "High number of anomalies - may indicate system issues"
                log INFO "Review the report carefully"
            fi
            
            # Show a sample
            if [[ "${VERBOSE}" == "true" ]]; then
                echo ""
                echo "Sample anomalies (first 10):"
                head -10 "${verify_report}"
                echo ""
            fi
        else
            log SUCCESS "All package files verified successfully"
        fi
        
        # Create verification cron job
        local cron_script="/etc/cron.weekly/fortress-verify-packages"
        sudo tee "${cron_script}" > /dev/null << 'CRONEOF'
#!/bin/bash
# FORTRESS.SH - Weekly package verification

REPORT="/var/log/fortress_package_verification_$(date +%Y%m%d).txt"
dpkg --verify > "${REPORT}" 2>&1 || true

if [[ -s "${REPORT}" ]]; then
    ANOMALIES=$(wc -l < "${REPORT}")
    logger -t fortress "Package verification found ${ANOMALIES} anomalies - check ${REPORT}"
fi
CRONEOF
        
        sudo chmod +x "${cron_script}"
        log SUCCESS "Weekly package verification cron job created"
    else
        log INFO "[DRY RUN] Would verify all package integrity"
    fi
    
    return 0
}

module_firewall() {
    CURRENT_MODULE="firewall"
    
    explain "UFW Firewall Configuration" \
        "A firewall controls what network traffic is allowed to reach your system." \
        "" \
        "Default policy we use: DENY incoming, ALLOW outgoing" \
        "" \
        "Why this matters:" \
        "  • Limits attack surface by blocking unexpected connections" \
        "  • Prevents malware from opening backdoors" \
        "  • Makes port scanning less useful for attackers" \
        "" \
        "What we configure:" \
        "  • Block all incoming connections by default" \
        "  • Allow only specifically needed services (SSH, web, etc.)" \
        "  • Enable logging of blocked connection attempts" \
        "" \
        "Desktop vs Server considerations:" \
        "  • Desktop: Usually needs few/no incoming connections" \
        "  • Server: Needs specific ports open for services" \
        "" \
        "Limitations:" \
        "  • Can't stop attacks on allowed ports" \
        "  • Can't detect application-layer attacks" \
        "  • Doesn't replace proper service configuration"
    
    if ! command -v ufw &>/dev/null; then
        execute_command "Installing UFW" \
            "sudo apt-get install -y ufw"
    fi
    
    # Get firewall settings from config or use defaults
    local ufw_incoming="${UFW_DEFAULT_INCOMING:-deny}"
    local ufw_outgoing="${UFW_DEFAULT_OUTGOING:-allow}"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        # Reset UFW to clean state
        execute_command "Resetting UFW to defaults" \
            "sudo ufw --force reset"
        
        # Default policies
        sudo ufw default "${ufw_incoming}" incoming
        sudo ufw default "${ufw_outgoing}" outgoing
        sudo ufw default deny routed
        
        # Allow SSH (with rate limiting)
        if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
            local ssh_port="${SSH_PORT:-22}"
            sudo ufw limit "${ssh_port}/tcp" comment 'SSH with rate limiting'
            log INFO "SSH access allowed on port ${ssh_port} with rate limiting"
        fi
        
        # Allow common services if running
        if systemctl is-active --quiet apache2 2>/dev/null || \
           systemctl is-active --quiet nginx 2>/dev/null; then
            sudo ufw allow http comment 'HTTP'
            sudo ufw allow https comment 'HTTPS'
            log INFO "Web server ports allowed (80, 443)"
        fi
        
        # Allow custom ports from config
        if [[ -n "${FIREWALL_ALLOW_PORTS:-}" ]]; then
            IFS=',' read -ra PORTS <<< "${FIREWALL_ALLOW_PORTS}"
            for port in "${PORTS[@]}"; do
                sudo ufw allow "${port}/tcp" comment "Custom port ${port}"
                log INFO "Allowed custom port: ${port}"
            done
        fi
        
        # Enable logging
        sudo ufw logging low
        
        # Enable firewall
        execute_command "Enabling UFW firewall" \
            "sudo ufw --force enable"
        
        log SUCCESS "UFW firewall configured and enabled"
        
        if [[ "${VERBOSE}" == "true" ]]; then
            echo ""
            sudo ufw status verbose
            echo ""
        fi
    else
        log INFO "[DRY RUN] Would configure UFW firewall"
    fi
    
    return 0
}

module_sysctl() {
    CURRENT_MODULE="sysctl"
    
    explain "Kernel Parameter Hardening" \
        "Kernel parameters control low-level system behavior and security features." \
        "" \
        "What we configure:" \
        "  • Network security (SYN cookies, ICMP redirects, IP forwarding)" \
        "  • Memory protection (ASLR, exec-shield)" \
        "  • Core dump restrictions" \
        "" \
        "Key protections:" \
        "" \
        "1. SYN Cookies (tcp_syncookies)" \
        "   Protects against SYN flood DoS attacks" \
        "" \
        "2. IP Forwarding (conditional based on Docker)" \
        "   Disabled by default (not a router)" \
        "   Enabled if Docker detected and allowed" \
        "" \
        "3. ICMP Redirect acceptance disabled" \
        "   Prevents malicious routing table manipulation" \
        "" \
        "4. Source routing disabled" \
        "   Prevents attackers from forcing specific network paths" \
        "" \
        "5. Martian packet logging" \
        "   Logs packets with impossible source addresses" \
        "" \
        "6. Address Space Layout Randomization (ASLR)" \
        "   Randomizes memory locations to prevent exploit techniques" \
        "" \
        "NEW in v5.1: Docker-aware IP forwarding configuration" \
        "These are well-established best practices with minimal downsides."
    
    local sysctl_conf="/etc/sysctl.d/99-fortress.conf"
    
    backup_file "${sysctl_conf}"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        # Determine IP forwarding settings based on Docker detection
        local ip_forward="0"
        local ipv6_forward="0"
        local docker_bridge_iptables=""
        
        if [[ "${DOCKER_DETECTED}" == "true" ]] && [[ "${ALLOW_DOCKER_FORWARDING}" == "true" ]]; then
            ip_forward="1"
            ipv6_forward="1"
            docker_bridge_iptables="
# Docker bridge netfilter (required for container networking)
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1"
            log INFO "IP forwarding ENABLED for Docker compatibility"
        else
            log INFO "IP forwarding DISABLED (standard security)"
        fi
        
        sudo tee "${sysctl_conf}" > /dev/null <<EOF
# FORTRESS.SH v5.1 - Kernel Security Parameters
# Generated: $(date)
# Docker detected: ${DOCKER_DETECTED}
# IP forwarding allowed: ${ALLOW_DOCKER_FORWARDING}

# Network security
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# IP forwarding (Docker-aware configuration)
net.ipv4.ip_forward = ${ip_forward}
net.ipv6.conf.all.forwarding = ${ipv6_forward}${docker_bridge_iptables}

# Memory protection
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2

# Core dump restrictions
kernel.core_uses_pid = 1
fs.suid_dumpable = 0

# Process restrictions
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
EOF

        # Apply custom sysctl parameters if configured
        if [[ -n "${SYSCTL_CUSTOM:-}" ]]; then
            echo "" | sudo tee -a "${sysctl_conf}" >/dev/null
            echo "# Custom sysctl parameters from fortress.conf" | sudo tee -a "${sysctl_conf}" >/dev/null
            echo "${SYSCTL_CUSTOM}" | sudo tee -a "${sysctl_conf}" >/dev/null
            log INFO "Applied custom sysctl parameters from configuration"
        fi
        
        execute_command "Applying kernel parameters" \
            "sudo sysctl -p ${sysctl_conf} 2>/dev/null || true"
        
        log SUCCESS "Kernel security parameters configured"
        
        if [[ "${DOCKER_DETECTED}" == "true" ]] && [[ "${ALLOW_DOCKER_FORWARDING}" == "true" ]]; then
            log INFO "Docker containers should have working network connectivity"
        fi
    else
        log INFO "[DRY RUN] Would configure kernel security parameters"
        if [[ "${DOCKER_DETECTED}" == "true" ]]; then
            log INFO "[DRY RUN] Would enable IP forwarding for Docker: ${ALLOW_DOCKER_FORWARDING}"
        fi
    fi
    
    return 0
}

module_secure_shared_memory() {
    CURRENT_MODULE="secure_shared_memory"
    
    explain "Shared Memory Security" \
        "Shared memory can be exploited for privilege escalation and data exposure." \
        "" \
        "What we do:" \
        "  • Mount /dev/shm and /run/shm with nosuid, nodev" \
        "  • Conditionally apply noexec based on system type" \
        "" \
        "Why this matters:" \
        "  • nosuid: Prevents SUID bit execution from shared memory" \
        "  • nodev: Prevents device file creation" \
        "  • noexec: Prevents executing programs from shared memory" \
        "" \
        "Attack scenarios this prevents:" \
        "  • Attacker uploads malware to /tmp or /dev/shm" \
        "  • Without noexec, they could execute it" \
        "  • With noexec, execution is blocked" \
        "" \
        "Trade-offs:" \
        "  • noexec breaks modern browsers (Firefox, Chrome)" \
        "  • Browsers need JIT compilation in shared memory" \
        "  • Desktop systems: Skip noexec by default" \
        "  • Server systems: Apply full hardening" \
        "" \
        "NEW in v5.1: Browser-aware shared memory configuration"
    
    local fstab="/etc/fstab"
    backup_file "${fstab}"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        # Remove old entries if present
        sudo sed -i '/\/dev\/shm/d' "${fstab}"
        sudo sed -i '/\/run\/shm/d' "${fstab}"
        
        # Determine mount options based on desktop/browser detection
        local mount_options="defaults,nodev,nosuid"
        
        if [[ "${IS_DESKTOP}" == "true" ]] && [[ "${ALLOW_BROWSER_SHAREDMEM}" == "true" ]]; then
            # Desktop mode: Skip noexec for browser compatibility
            log INFO "Desktop mode: Skipping noexec on /dev/shm for browser compatibility"
            log WARN "Security reduced: Executables can run from /dev/shm"
        else
            # Server mode or user chose maximum security: Apply noexec
            mount_options="${mount_options},noexec"
            log INFO "Applying noexec to /dev/shm (maximum security)"
            
            if [[ ${#DETECTED_BROWSERS[@]} -gt 0 ]]; then
                log WARN "Browsers detected but noexec applied - browsers will NOT work"
                log WARN "Run 'sudo ./fix_library_permissions.sh' to restore browser functionality"
            fi
        fi
        
        # Add hardened shared memory mounts
        echo "tmpfs /dev/shm tmpfs ${mount_options} 0 0" | sudo tee -a "${fstab}" >/dev/null
        echo "tmpfs /run/shm tmpfs ${mount_options} 0 0" | sudo tee -a "${fstab}" >/dev/null
        
        # Remount immediately
        execute_command "Remounting /dev/shm with security options" \
            "sudo mount -o remount,${mount_options} /dev/shm 2>/dev/null || true"
        
        log SUCCESS "Shared memory secured with options: ${mount_options}"
    else
        log INFO "[DRY RUN] Would secure shared memory mounts"
        if [[ "${IS_DESKTOP}" == "true" ]] && [[ "${ALLOW_BROWSER_SHAREDMEM}" == "true" ]]; then
            log INFO "[DRY RUN] Would skip noexec for browser compatibility"
        else
            log INFO "[DRY RUN] Would apply noexec (browsers may break)"
        fi
    fi
    
    return 0
}

module_password_policy() {
    CURRENT_MODULE="password_policy"
    
    explain "Password Policy Configuration" \
        "Strong password policies help prevent weak passwords." \
        "" \
        "What we configure:" \
        "  • Minimum password length (12+ characters)" \
        "  • Password complexity requirements" \
        "  • Password history (prevent reuse)" \
        "  • Account lockout after failed attempts" \
        "" \
        "Why this matters:" \
        "  • Weak passwords are still common" \
        "  • Prevents dictionary and brute force attacks" \
        "  • Forces users to create stronger passwords" \
        "" \
        "Important context:" \
        "  • This ONLY matters if password auth is enabled" \
        "  • SSH with keys doesn't need password policy" \
        "  • Consider passphrase-based approach (4+ random words)" \
        "" \
        "Modern best practice:" \
        "  • Longer passphrases > complex short passwords" \
        "  • 'correct horse battery staple' > 'P@ssw0rd123'" \
        "  • But ideally, use keys not passwords"
    
    execute_command "Installing password quality tools" \
        "sudo apt-get install -y libpam-pwquality"
    
    local pwquality_conf="/etc/security/pwquality.conf"
    backup_file "${pwquality_conf}"
    
    # Get password settings from config or use defaults
    local pw_minlen="${PASSWORD_MIN_LENGTH:-12}"
    local pw_history="${PASSWORD_HISTORY:-5}"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        sudo tee "${pwquality_conf}" > /dev/null << EOF
# FORTRESS.SH v5.1 - Password Quality Requirements

# Minimum password length
minlen = ${pw_minlen}

# Require at least one digit
dcredit = -1

# Require at least one uppercase
ucredit = -1

# Require at least one lowercase
lcredit = -1

# Require at least one special character
ocredit = -1

# Remember last ${pw_history} passwords
remember = ${pw_history}

# Maximum consecutive characters
maxrepeat = 3

# Reject passwords with username
usercheck = 1

# Enforce for root too
enforce_for_root
EOF
        
        log SUCCESS "Password policy configured"
    else
        log INFO "[DRY RUN] Would configure password policy"
    fi
    
    return 0
}

module_audit() {
    CURRENT_MODULE="audit"
    
    explain "Audit Logging (auditd)" \
        "Audit logs record security-relevant events for forensics and compliance." \
        "" \
        "What auditd does:" \
        "  • Logs authentication events (login, su, sudo)" \
        "  • Logs file access to sensitive files" \
        "  • Logs system calls (optional, high overhead)" \
        "  • Creates tamper-resistant logs" \
        "" \
        "Why this matters:" \
        "  • After-the-fact investigation of incidents" \
        "  • Compliance requirements (PCI-DSS, HIPAA)" \
        "  • Detect unusual activity patterns" \
        "" \
        "What we log:" \
        "  • Failed login attempts" \
        "  • Changes to user accounts" \
        "  • Changes to authentication files" \
        "  • Sudo usage" \
        "  • AppArmor denials" \
        "" \
        "Limitations:" \
        "  • Can't prevent attacks, only records them" \
        "  • Sophisticated attackers may clear logs" \
        "  • High verbosity impacts performance" \
        "" \
        "Best practice:" \
        "  • Send logs to remote syslog server" \
        "  • Regular log review (manual or automated)" \
        "  • Alert on specific patterns"
    
    execute_command "Installing auditd" \
        "sudo apt-get install -y auditd audispd-plugins"
    
    local audit_rules="/etc/audit/rules.d/fortress.rules"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        sudo tee "${audit_rules}" > /dev/null << 'EOF'
# FORTRESS.SH v5.1 - Audit Rules

# Delete all existing rules
-D

# Buffer size
-b 8192

# Failure mode (1 = print, 2 = panic)
-f 1

# Authentication and authorization
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k actions
-w /etc/sudoers.d/ -p wa -k actions

# Login and logout
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Network configuration
-w /etc/hosts -p wa -k network
-w /etc/network/ -p wa -k network
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k network

# Discretionary access control
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Unauthorized access attempts
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# System administration
-w /var/log/sudo.log -p wa -k actions

# Kernel module loading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# Make configuration immutable (requires reboot to change)
-e 2
EOF
        
        execute_command "Loading audit rules" \
            "sudo augenrules --load"
        
        execute_command "Enabling auditd" \
            "sudo systemctl enable auditd && sudo systemctl restart auditd"
        
        log SUCCESS "Audit logging configured"
    else
        log INFO "[DRY RUN] Would configure audit logging"
    fi
    
    return 0
}

module_automatic_updates() {
    CURRENT_MODULE="automatic_updates"
    
    explain "Automatic Security Updates" \
        "Automatically install security updates to stay protected." \
        "" \
        "What we enable:" \
        "  • Daily checks for security updates" \
        "  • Automatic installation of security patches" \
        "  • Email notifications of updates (if configured)" \
        "" \
        "Why this matters:" \
        "  • Security updates need to be applied quickly" \
        "  • Manual updates are often delayed or forgotten" \
        "  • Exploits often appear within days of patch release" \
        "" \
        "What gets updated automatically:" \
        "  • Security updates only (by default)" \
        "  • From official Ubuntu/Debian repositories" \
        "" \
        "What does NOT get updated:" \
        "  • Major version upgrades" \
        "  • Packages requiring configuration changes" \
        "  • Third-party repositories (configurable)" \
        "" \
        "Trade-offs:" \
        "  • Rare chance of update breaking something" \
        "  • No control over update timing" \
        "  • Security benefit >> compatibility risk" \
        "" \
        "For production servers:" \
        "  • Test updates in staging first" \
        "  • Use configuration management" \
        "  • Monitor for update-related issues"
    
    execute_command "Installing unattended-upgrades" \
        "sudo apt-get install -y unattended-upgrades apt-listchanges"
    
    local auto_upgrades="/etc/apt/apt.conf.d/20auto-upgrades"
    local unattended_conf="/etc/apt/apt.conf.d/50unattended-upgrades"
    
    # Get auto-update settings from config
    local auto_reboot="${AUTO_REBOOT_IF_REQUIRED:-false}"
    local reboot_time="${AUTO_REBOOT_TIME:-03:00}"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        sudo tee "${auto_upgrades}" > /dev/null << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
        
        # Configure unattended upgrades
        sudo tee "${unattended_conf}" > /dev/null << EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "${auto_reboot}";
Unattended-Upgrade::Automatic-Reboot-Time "${reboot_time}";
EOF
        
        execute_command "Enabling automatic updates" \
            "sudo systemctl enable unattended-upgrades && sudo systemctl start unattended-upgrades"
        
        log SUCCESS "Automatic security updates enabled"
    else
        log INFO "[DRY RUN] Would enable automatic security updates"
    fi
    
    return 0
}

module_ntp() {
    CURRENT_MODULE="ntp"
    
    explain "Time Synchronization" \
        "Accurate system time is critical for security." \
        "" \
        "Why accurate time matters:" \
        "  • Logs must have correct timestamps for forensics" \
        "  • TLS/SSL certificates require accurate time" \
        "  • Kerberos authentication requires time sync" \
        "  • Two-factor auth (TOTP) requires correct time" \
        "" \
        "What we configure:" \
        "  • Use systemd-timesyncd (built-in)" \
        "  • Configure reliable NTP servers" \
        "  • Enable automatic time synchronization" \
        "" \
        "Common issues prevented:" \
        "  • SSL certificate errors from wrong time" \
        "  • TOTP codes not working" \
        "  • Log correlation difficulties"
    
    if systemctl is-active --quiet systemd-timesyncd; then
        log INFO "Time synchronization already active"
    else
        execute_command "Enabling systemd-timesyncd" \
            "sudo systemctl enable systemd-timesyncd && sudo systemctl start systemd-timesyncd"
    fi
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        sudo timedatectl set-ntp true
        log SUCCESS "Time synchronization enabled"
        
        if [[ "${VERBOSE}" == "true" ]]; then
            echo ""
            timedatectl status
            echo ""
        fi
    fi
    
    return 0
}

module_apparmor() {
    CURRENT_MODULE="apparmor"
    
    explain "AppArmor Mandatory Access Control" \
        "AppArmor restricts what programs can do, even if compromised." \
        "" \
        "How it works:" \
        "  • Each program has a 'profile' defining allowed actions" \
        "  • Attempts to violate profile are blocked and logged" \
        "  • Limits damage from exploited applications" \
        "" \
        "Example: If Apache is compromised:" \
        "  • Without AppArmor: Full access to system" \
        "  • With AppArmor: Only access to web files" \
        "" \
        "What we do:" \
        "  • Ensure AppArmor is enabled" \
        "  • Set profiles to enforce mode" \
        "  • Install additional profiles" \
        "" \
        "Modes:" \
        "  • Enforce: Violations are blocked" \
        "  • Complain: Violations are logged only" \
        "  • Disabled: No protection" \
        "" \
        "Trade-offs:" \
        "  • May need to adjust profiles for custom software" \
        "  • Can interfere with legitimate application behavior" \
        "  • Security benefit is substantial"
    
    execute_command "Installing AppArmor utilities" \
        "sudo apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        # Enable AppArmor
        execute_command "Enabling AppArmor" \
            "sudo systemctl enable apparmor && sudo systemctl start apparmor"
        
        # Set all profiles to enforce mode
        sudo aa-enforce /etc/apparmor.d/* 2>/dev/null || true
        
        log SUCCESS "AppArmor configured and enforcing"
        
        if [[ "${VERBOSE}" == "true" ]]; then
            echo ""
            sudo aa-status
            echo ""
        fi
    else
        log INFO "[DRY RUN] Would configure AppArmor"
    fi
    
    return 0
}

module_boot_security() {
    CURRENT_MODULE="boot_security"
    
    explain "Boot Security Verification" \
        "Secure Boot and boot loader protection prevent boot-time attacks." \
        "" \
        "What Secure Boot does:" \
        "  • Verifies bootloader signature before execution" \
        "  • Verifies kernel signature before execution" \
        "  • Prevents bootkits and rootkits at boot level" \
        "" \
        "Why this matters:" \
        "  • Kernel-level rootkits are nearly impossible to detect" \
        "  • Boot-time attacks can compromise entire system" \
        "  • Secure Boot provides hardware-based protection" \
        "" \
        "What this module does:" \
        "  • Checks if Secure Boot is enabled (UEFI systems)" \
        "  • Sets GRUB password (prevents boot parameter tampering)" \
        "  • Provides recommendations for enabling Secure Boot" \
        "" \
        "Secure Boot limitations:" \
        "  • Requires UEFI firmware support" \
        "  • May not work with some hardware" \
        "  • Needs signed kernel (Ubuntu/Debian kernels are signed)" \
        "" \
        "This module CANNOT automatically enable Secure Boot." \
        "That requires BIOS/UEFI configuration. We can only verify and guide."
    
    # Check Secure Boot status
    if [[ -d /sys/firmware/efi ]]; then
        log INFO "UEFI firmware detected"
        
        if command -v mokutil &>/dev/null; then
            local sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
            
            if [[ "${sb_state}" == *"enabled"* ]]; then
                log SUCCESS "Secure Boot is ENABLED - excellent!"
            else
                log WARNING "Secure Boot is NOT enabled"
                echo ""
                echo "Secure Boot provides important boot-time security."
                echo ""
                echo "To enable Secure Boot:"
                echo "  1. Reboot and enter BIOS/UEFI settings (usually DEL, F2, or F12)"
                echo "  2. Find 'Secure Boot' option (usually in Security or Boot section)"
                echo "  3. Enable Secure Boot"
                echo "  4. Save and exit"
                echo ""
                echo "Verify after enabling:"
                echo "  sudo mokutil --sb-state"
                echo ""
            fi
        else
            execute_command "Installing mokutil for Secure Boot checking" \
                "sudo apt-get install -y mokutil"
        fi
    else
        log INFO "Legacy BIOS detected - Secure Boot not available"
        log INFO "Consider upgrading to UEFI-capable hardware for better security"
    fi
    
    # Set GRUB password
    if [[ "${INTERACTIVE}" == "true" ]] && [[ "${DRY_RUN}" == "false" ]]; then
        echo ""
        read -p "Set GRUB bootloader password to prevent tampering? (y/N): " -r set_grub_pass
        
        if [[ "${set_grub_pass}" =~ ^[Yy]$ ]]; then
            echo ""
            echo "Enter GRUB password (this will be required to edit boot parameters):"
            sudo grub-mkpasswd-pbkdf2 | sudo tee /etc/grub.d/40_custom_password > /dev/null
            
            echo "cat << EOF" | sudo tee -a /etc/grub.d/40_custom_password > /dev/null
            echo "set superusers=\"root\"" | sudo tee -a /etc/grub.d/40_custom_password > /dev/null
            echo "password_pbkdf2 root $(grep 'grub.pbkdf2' /etc/grub.d/40_custom_password | awk '{print $NF}')" | sudo tee -a /etc/grub.d/40_custom_password > /dev/null
            echo "EOF" | sudo tee -a /etc/grub.d/40_custom_password > /dev/null
            
            sudo chmod +x /etc/grub.d/40_custom_password
            execute_command "Updating GRUB configuration" \
                "sudo update-grub"
            
            log SUCCESS "GRUB password set - boot parameters now protected"
        fi
    fi
    
    return 0
}

module_root_access() {
    CURRENT_MODULE="root_access"
    
    explain "Disable Direct Root Login" \
        "Force use of sudo instead of direct root login." \
        "" \
        "Why this matters:" \
        "  • Accountability: sudo logs which user ran what command" \
        "  • Least privilege: Users can elevate only when needed" \
        "  • Audit trail: All root actions are logged to specific users" \
        "" \
        "What we do:" \
        "  • Disable root account password login" \
        "  • Force all administrative tasks through sudo" \
        "  • Require users to be in sudo group" \
        "" \
        "Best practices:" \
        "  • Use individual user accounts" \
        "  • Add users to sudo group: usermod -aG sudo username" \
        "  • Each admin uses their own credentials" \
        "  • All root actions are traceable to specific users" \
        "" \
        "This is reversible by setting root password again."
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        # Lock root account
        execute_command "Disabling direct root login" \
            "sudo passwd -l root"
        
        log SUCCESS "Direct root login disabled - use sudo instead"
    else
        log INFO "[DRY RUN] Would disable direct root login"
    fi
    
    return 0
}

module_packages() {
    CURRENT_MODULE="packages"
    
    explain "Remove Unnecessary Packages" \
        "Reduce attack surface by removing unused software." \
        "" \
        "Security principle: Minimalism" \
        "  • Every installed package is potential attack surface" \
        "  • Unused services may have unpatched vulnerabilities" \
        "  • Less software = less to secure and maintain" \
        "" \
        "What we identify for removal:" \
        "  • Compilers (gcc, make) on production servers" \
        "  • Development tools not needed in production" \
        "  • Unused network services" \
        "" \
        "We DON'T automatically remove anything." \
        "We only identify candidates and let you decide." \
        "" \
        "Desktop vs Server:" \
        "  • Desktops: Keep most packages (user needs them)" \
        "  • Servers: Minimize to only required services"
    
    log INFO "Analyzing installed packages..."
    
    local potentially_unnecessary=(
        "telnet"
        "rsh-client"
        "rsh-server"
        "nis"
        "xinetd"
    )
    
    local found_packages=()
    
    for pkg in "${potentially_unnecessary[@]}"; do
        if dpkg -l | grep -q "^ii.*${pkg}"; then
            found_packages+=("${pkg}")
        fi
    done
    
    if [[ ${#found_packages[@]} -gt 0 ]]; then
        log WARNING "Found potentially unnecessary packages:"
        for pkg in "${found_packages[@]}"; do
            echo "  - ${pkg}"
        done
        
        if [[ "${INTERACTIVE}" == "true" ]]; then
            echo ""
            read -p "Remove these packages? (y/N): " -r remove_pkgs
            
            if [[ "${remove_pkgs}" =~ ^[Yy]$ ]]; then
                execute_command "Removing unnecessary packages" \
                    "sudo apt-get remove -y ${found_packages[*]}"
                
                execute_command "Cleaning up" \
                    "sudo apt-get autoremove -y"
            fi
        fi
    else
        log SUCCESS "No obviously unnecessary packages found"
    fi
    
    return 0
}

module_usb_protection() {
    CURRENT_MODULE="usb_protection"
    
    explain "USB Device Protection" \
        "Prevent unauthorized USB devices from automatically mounting." \
        "" \
        "Attack vectors:" \
        "  • USB rubber ducky (auto-executing payloads)" \
        "  • BadUSB attacks (malicious USB firmware)" \
        "  • Physical access with USB malware" \
        "" \
        "What we configure:" \
        "  • Disable USB storage auto-mounting" \
        "  • Create udev rules to control USB devices" \
        "" \
        "Limitations:" \
        "  • Can't prevent all USB attacks" \
        "  • Keyboard/mouse attacks still possible" \
        "  • Physical access is game over anyway" \
        "" \
        "This is most useful for:" \
        "  • Servers in public spaces" \
        "  • High-security environments" \
        "  • Preventing casual data theft"
    
    if [[ "${IS_DESKTOP}" == "true" ]]; then
        log INFO "Desktop detected - USB protection may interfere with normal use"
        
        if [[ "${INTERACTIVE}" == "true" ]]; then
            read -p "Apply USB restrictions anyway? (y/N): " -r apply_usb
            [[ ! "${apply_usb}" =~ ^[Yy]$ ]] && return 0
        else
            log INFO "Skipping USB protection on desktop"
            return 0
        fi
    fi
    
    local udev_rule="/etc/udev/rules.d/99-fortress-usb.rules"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        sudo tee "${udev_rule}" > /dev/null << 'EOF'
# FORTRESS.SH v5.1 - USB Device Protection
# Prevent unauthorized USB storage devices

# Block USB storage devices
SUBSYSTEM=="usb", ATTRS{bDeviceClass}=="08", OPTIONS+="ignore_device"

# Whitelist specific devices by vendor ID if needed:
# SUBSYSTEM=="usb", ATTR{idVendor}=="1234", ATTR{idProduct}=="5678", MODE="0660"
EOF

        # Add allowed USB devices from config
        if [[ -n "${USB_ALLOWED_DEVICES:-}" ]]; then
            IFS=',' read -ra USB_DEVS <<< "${USB_ALLOWED_DEVICES}"
            for device in "${USB_DEVS[@]}"; do
                local vendor="${device%%:*}"
                local product="${device##*:}"
                echo "SUBSYSTEM==\"usb\", ATTR{idVendor}==\"${vendor}\", ATTR{idProduct}==\"${product}\", MODE=\"0660\"" | sudo tee -a "${udev_rule}" >/dev/null
                log INFO "Whitelisted USB device: ${vendor}:${product}"
            done
        fi
        
        execute_command "Reloading udev rules" \
            "sudo udevadm control --reload-rules && sudo udevadm trigger"
        
        log SUCCESS "USB storage protection enabled"
        log INFO "To whitelist specific USB devices, edit: ${udev_rule}"
    else
        log INFO "[DRY RUN] Would configure USB protection"
    fi
    
    return 0
}

module_filesystems() {
    CURRENT_MODULE="filesystems"
    
    explain "Disable Unused Filesystems" \
        "Reduce attack surface by disabling filesystem types you don't use." \
        "" \
        "Why this matters:" \
        "  • Kernel filesystem drivers can have vulnerabilities" \
        "  • Obscure filesystems are rarely audited" \
        "  • Attackers may exploit unusual filesystem handling" \
        "" \
        "What we disable:" \
        "  • cramfs, freevxfs, jffs2, hfs, hfsplus, udf" \
        "  • These are rarely used on modern Linux systems" \
        "" \
        "What we DON'T disable:" \
        "  • ext4, xfs, btrfs (common Linux filesystems)" \
        "  • vfat (USB drives, EFI)" \
        "  • iso9660 (CD/DVD)" \
        "" \
        "This is safe unless you specifically use exotic filesystems."
    
    local modprobe_conf="/etc/modprobe.d/fortress-filesystems.conf"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        sudo tee "${modprobe_conf}" > /dev/null << 'EOF'
# FORTRESS.SH v5.1 - Disable Unused Filesystems

install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
EOF
        
        log SUCCESS "Unused filesystems disabled"
    else
        log INFO "[DRY RUN] Would disable unused filesystems"
    fi
    
    return 0
}

#=============================================================================
# MODULE EXECUTION FRAMEWORK
#=============================================================================

check_circular_deps() {
    local module="$1"
    local chain="$2"
    
    local deps="${MODULE_DEPS[${module}]:-}"
    [[ -z "${deps}" ]] && return 0
    
    for dep in ${deps}; do
        if [[ " ${chain} " =~ " ${dep} " ]]; then
            log ERROR "Circular dependency detected: ${chain} -> ${dep}"
            return 1
        fi
        
        check_circular_deps "${dep}" "${chain} ${dep}" || return 1
    done
    
    return 0
}

resolve_dependencies() {
    local module="$1"
    local -a result=()
    
    local deps="${MODULE_DEPS[${module}]:-}"
    [[ -z "${deps}" ]] && echo "${module}" && return
    
    for dep in ${deps}; do
        local subdeps=($(resolve_dependencies "${dep}"))
        for subdep in "${subdeps[@]}"; do
            if [[ ! " ${result[@]} " =~ " ${subdep} " ]]; then
                result+=("${subdep}")
            fi
        done
    done
    
    result+=("${module}")
    echo "${result[@]}"
}

execute_modules() {
    local modules_to_run=()
    
    # Determine which modules to run
    if [[ -n "${ENABLE_MODULES}" ]]; then
        IFS=',' read -ra modules_to_run <<< "${ENABLE_MODULES}"
    else
        modules_to_run=("${!SECURITY_MODULES[@]}")
        
        # Apply disabled modules filter
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
    
    # Resolve dependencies and build execution order
    local -a execution_order=()
    for module in "${modules_to_run[@]}"; do
        [[ -z "${module}" ]] && continue
        
        local deps=($(resolve_dependencies "${module}"))
        for dep in "${deps[@]}"; do
            if [[ ! " ${execution_order[@]} " =~ " ${dep} " ]]; then
                execution_order+=("${dep}")
            fi
        done
    done
    
    local total=${#execution_order[@]}
    local current=0
    
    echo ""
    log INFO "================================================"
    log INFO "Execution order (${total} modules):"
    log INFO "${execution_order[*]}"
    log INFO "================================================"
    echo ""
    
    # Execute modules
    for module in "${execution_order[@]}"; do
        [[ -z "${module}" ]] && continue
        
        current=$((current + 1))
        
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log INFO "Module ${current}/${total}: ${SECURITY_MODULES[${module}]:-Unknown}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        local func="module_${module}"
        if declare -f "${func}" > /dev/null; then
            if "${func}"; then
                EXECUTED_MODULES+=("${module}")
                log SUCCESS "Module ${module} completed successfully"
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
        
        sleep 0.5
    done
    
    echo ""
}

#=============================================================================
# REPORTING
#=============================================================================

generate_report() {
    local failed_list=""
    
    if [[ ${#FAILED_MODULES[@]} -gt 0 ]]; then
        failed_list="<div class=\"info-box error\">
            <h2>❌ Failed Modules</h2>
            <p><strong>Total Failed:</strong> ${#FAILED_MODULES[@]}</p>
            <p><strong>Modules:</strong> ${FAILED_MODULES[*]}</p>
        </div>"
    fi
    
    # Generate compatibility info for v5.1
    local compat_info=""
    if [[ "${DOCKER_DETECTED}" == "true" ]]; then
        compat_info="${compat_info}<p><strong>Docker:</strong> Detected - IP forwarding ${ALLOW_DOCKER_FORWARDING}</p>"
    fi
    if [[ ${#DETECTED_BROWSERS[@]} -gt 0 ]]; then
        compat_info="${compat_info}<p><strong>Browsers:</strong> ${DETECTED_BROWSERS[*]} - /dev/shm noexec skipped: ${ALLOW_BROWSER_SHAREDMEM}</p>"
    fi
    
    sudo tee "${REPORT_FILE}" > /dev/null << EOF
<!DOCTYPE html>
<html>
<head>
    <title>FORTRESS.SH Security Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
        }
        .info-box {
            background: #ecf0f1;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
            border-left: 5px solid #3498db;
        }
        .info-box.success {
            border-left-color: #27ae60;
            background: #d5f4e6;
        }
        .info-box.warning {
            border-left-color: #f39c12;
            background: #fef5e7;
        }
        .info-box.error {
            border-left-color: #e74c3c;
            background: #fadbd8;
        }
        code {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        ul {
            line-height: 1.8;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ FORTRESS.SH Security Hardening Report</h1>
        
        <div class="info-box">
            <h2>📊 System Information</h2>
            <p><strong>Hostname:</strong> $(hostname)</p>
            <p><strong>Date:</strong> $(date)</p>
            <p><strong>Desktop Environment:</strong> ${IS_DESKTOP}</p>
            <p><strong>Security Level:</strong> ${SECURITY_LEVEL}</p>
            <p><strong>Script Version:</strong> ${VERSION}</p>
            ${compat_info}
        </div>
        
        <div class="info-box success">
            <h2>✅ Executed Modules</h2>
            <p><strong>Total Completed:</strong> ${#EXECUTED_MODULES[@]}</p>
            <p><strong>Modules:</strong> ${EXECUTED_MODULES[*]}</p>
        </div>
        
        ${failed_list}
        
        <div class="info-box">
            <h2>📋 Backup Information</h2>
            <p><strong>Backup Directory:</strong> <code>${BACKUP_DIR}</code></p>
            <p><strong>Log File:</strong> <code>${LOG_FILE}</code></p>
        </div>
        
        <div class="info-box warning">
            <h2>⚠️ Important Next Steps</h2>
            <ul>
                <li><strong>Restart your system</strong> to apply all changes</li>
                <li>Verify SSH access works (if SSH was hardened)</li>
                <li>Check firewall rules: <code>sudo ufw status verbose</code></li>
                <li>Review logs: <code>${LOG_FILE}</code></li>
                <li>Test all critical services</li>
                <li>Run health check: <code>sudo ./verify_fortress.sh</code></li>
            </ul>
        </div>
        
        <div class="info-box">
            <h2>🔍 Security Recommendations</h2>
            <ul>
                <li>Keep system updated: <code>sudo apt update && sudo apt upgrade</code></li>
                <li>Monitor audit logs: <code>sudo ausearch -m USER_LOGIN -ts recent</code></li>
                <li>Check AppArmor: <code>sudo aa-status</code></li>
                <li>Verify package integrity: <code>dpkg --verify</code></li>
                <li>Review firewall: <code>sudo ufw status verbose</code></li>
                <li>Enable Secure Boot in BIOS (if supported)</li>
            </ul>
        </div>
        
        <div class="footer">
            <p><strong>FORTRESS.SH v${VERSION}</strong></p>
            <p>Created by captainzero93</p>
            <p><a href="https://github.com/captainzero93/security_harden_linux">GitHub Repository</a></p>
            <p>Report generated: $(date '+%Y-%m-%d %H:%M:%S')</p>
        </div>
    </div>
</body>
</html>
EOF
    
    sudo chmod 600 "${REPORT_FILE}"
    log SUCCESS "Report generated: ${REPORT_FILE}"
}

#=============================================================================
# MAIN EXECUTION
#=============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                display_help
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -n|--non-interactive)
                INTERACTIVE=false
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            --explain)
                EXPLAIN_MODE=true
                shift
                ;;
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
            --version)
                echo "FORTRESS.SH v${VERSION}"
                exit 0
                ;;
            --list-modules)
                list_modules
                ;;
            --generate-config)
                GENERATE_CONFIG=true
                shift
                ;;
            --allow-docker)
                ALLOW_DOCKER_FORWARDING=true
                shift
                ;;
            --no-docker-compat)
                ALLOW_DOCKER_FORWARDING=false
                shift
                ;;
            --allow-browser-shm)
                ALLOW_BROWSER_SHAREDMEM=true
                shift
                ;;
            --no-browser-compat)
                ALLOW_BROWSER_SHAREDMEM=false
                shift
                ;;
            --force-desktop)
                FORCE_DESKTOP_MODE=true
                shift
                ;;
            --force-server)
                FORCE_SERVER_MODE=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    # Initial checks
    check_permissions
    
    # NEW in v5.1: Generate config if requested
    if [[ "${GENERATE_CONFIG}" == "true" ]]; then
        generate_config_template
        exit 0
    fi
    
    # NEW in v5.1: Load configuration file
    load_config
    
    # Detect desktop environment
    detect_desktop
    
    # NEW in v5.1: Detect critical applications
    detect_critical_applications
    
    # NEW in v5.1: Prompt for compatibility settings
    prompt_docker_compatibility
    prompt_browser_compatibility
    
    # Create log file
    sudo touch "${LOG_FILE}"
    sudo chmod 640 "${LOG_FILE}"
    
    # Create backup directory
    if [[ "${DRY_RUN}" == "false" ]]; then
        sudo mkdir -p "${BACKUP_DIR}"
        log INFO "Backup directory: ${BACKUP_DIR}"
    fi
    
    # Display banner
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║              FORTRESS.SH - Security Hardening v${VERSION}             ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
    log INFO "Security Level: ${SECURITY_LEVEL}"
    log INFO "Desktop Mode: ${IS_DESKTOP}"
    log INFO "Dry Run: ${DRY_RUN}"
    log INFO "Interactive: ${INTERACTIVE}"
    log INFO "Explain Mode: ${EXPLAIN_MODE}"
    log INFO "Docker Detected: ${DOCKER_DETECTED}"
    log INFO "Docker IP Forwarding: ${ALLOW_DOCKER_FORWARDING}"
    log INFO "Browser /dev/shm Compat: ${ALLOW_BROWSER_SHAREDMEM}"
    echo ""
    
    if [[ "${EXPLAIN_MODE}" == "true" ]]; then
        echo -e "${CYAN}Educational mode enabled - you'll see detailed explanations.${NC}"
        echo ""
    fi
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        echo -e "${YELLOW}DRY RUN MODE - No changes will be made${NC}"
        echo ""
    fi
    
    # Execute modules
    execute_modules
    
    # Generate report
    if [[ "${DRY_RUN}" == "false" ]]; then
        generate_report
    fi
    
    # Summary
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log SUCCESS "Security hardening completed!"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log INFO "Executed modules: ${#EXECUTED_MODULES[@]}"
    [[ ${#FAILED_MODULES[@]} -gt 0 ]] && log WARNING "Failed modules: ${#FAILED_MODULES[@]} (${FAILED_MODULES[*]})"
    log INFO "Log: ${LOG_FILE}"
    [[ "${DRY_RUN}" == "false" ]] && log INFO "Report: ${REPORT_FILE}"
    echo ""
    echo -e "${CYAN}Run health check: sudo ./verify_fortress.sh${NC}"
    echo ""
    
    if [[ "${DRY_RUN}" == "false" ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        read -p "Restart recommended to apply all changes. Restart now? (y/N): " -r restart
        [[ "${restart}" =~ ^[Yy]$ ]] && sudo reboot
    fi
}

main "$@"
