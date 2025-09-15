#!/bin/bash

# Enhanced Ubuntu/Debian Linux Security Hardening Script
# Version: 3.0
# Author: Enhanced version based on captainzero93's work
# GitHub: https://github.com/captainzero93/security_harden_linux

set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# Global variables
readonly VERSION="3.0"
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
SECURITY_LEVEL="moderate"  # low, moderate, high, paranoid

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Security modules
declare -A SECURITY_MODULES=(
    ["system_update"]="Update system packages"
    ["firewall"]="Configure UFW firewall"
    ["fail2ban"]="Setup Fail2Ban intrusion prevention"
    ["clamav"]="Install ClamAV antivirus"
    ["root_access"]="Disable root login"
    ["ssh_hardening"]="Harden SSH configuration"
    ["packages"]="Remove unnecessary packages"
    ["audit"]="Configure auditd logging"
    ["filesystems"]="Disable unused filesystems"
    ["boot_security"]="Secure boot settings"
    ["ipv6"]="Configure IPv6"
    ["apparmor"]="Setup AppArmor"
    ["ntp"]="Configure time synchronization"
    ["aide"]="Setup AIDE file integrity"
    ["sysctl"]="Configure kernel parameters"
    ["password_policy"]="Set strong password policies"
    ["automatic_updates"]="Enable automatic security updates"
    ["rootkit_scanner"]="Install rootkit scanners"
    ["usb_protection"]="Restrict USB devices"
    ["secure_shared_memory"]="Secure shared memory"
    ["lynis_audit"]="Run Lynis security audit"
)

# Module dependencies
declare -A MODULE_DEPS=(
    ["ssh_hardening"]="system_update"
    ["fail2ban"]="system_update firewall"
    ["aide"]="system_update"
    ["rootkit_scanner"]="system_update"
)

# Trap for cleanup on exit
trap cleanup EXIT

# Cleanup function
cleanup() {
    if [[ -n "${TEMP_DIR:-}" ]] && [[ -d "${TEMP_DIR}" ]]; then
        rm -rf "${TEMP_DIR}"
    fi
}

# Enhanced logging function
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

# Enhanced error handling
handle_error() {
    local exit_code=$?
    local line_number=$1
    local command="${2:-}"
    
    log ERROR "Command failed with exit code ${exit_code} at line ${line_number}: ${command}"
    
    if [[ "${DRY_RUN}" == "false" ]]; then
        read -p "Do you want to restore from backup? (y/N): " -r restore_choice
        if [[ "${restore_choice}" =~ ^[Yy]$ ]]; then
            restore_backup
        fi
    fi
    
    exit "${exit_code}"
}

# Set error trap
trap 'handle_error ${LINENO} "${BASH_COMMAND}"' ERR

# Progress indicator
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
    
    if [[ ${current} -eq ${total} ]]; then
        echo
    fi
}

# Check root privileges
check_permissions() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${RED}This script must be run with sudo privileges.${NC}"
        echo "Please run it again using: sudo $0"
        exit 1
    fi
}

# Load configuration file
load_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        log INFO "Loading configuration from ${CONFIG_FILE}"
        # shellcheck source=/dev/null
        source "${CONFIG_FILE}"
    fi
}

# Display help
display_help() {
    cat << EOF
Usage: sudo ./${SCRIPT_NAME} [OPTIONS]

Enhanced Linux Security Hardening Script v${VERSION}

OPTIONS:
    -h, --help              Display this help message
    -v, --verbose           Enable verbose output
    -n, --non-interactive   Run without user prompts (use defaults)
    -d, --dry-run          Perform a dry run without making changes
    -l, --level LEVEL      Set security level (low|moderate|high|paranoid)
    -e, --enable MODULES   Enable specific modules (comma-separated)
    -x, --disable MODULES  Disable specific modules (comma-separated)
    -r, --restore          Restore system from the most recent backup
    -R, --report           Generate security report only
    -c, --config FILE      Use custom configuration file
    --version              Display script version
    --list-modules         List available security modules

SECURITY LEVELS:
    low       - Basic security hardening
    moderate  - Balanced security (default)
    high      - Strong security, may impact usability
    paranoid  - Maximum security, significant usability impact

EXAMPLES:
    # Run with default settings
    sudo ./${SCRIPT_NAME}
    
    # Run specific modules only
    sudo ./${SCRIPT_NAME} -e firewall,ssh_hardening,fail2ban
    
    # Run all except specific modules
    sudo ./${SCRIPT_NAME} -x ipv6,usb_protection
    
    # Non-interactive mode with high security
    sudo ./${SCRIPT_NAME} -n -l high

EOF
    exit 0
}

# List available modules
list_modules() {
    echo "Available Security Modules:"
    echo "=========================="
    for module in "${!SECURITY_MODULES[@]}"; do
        printf "  %-20s - %s\n" "${module}" "${SECURITY_MODULES[${module}]}"
    done
    exit 0
}

# Check system requirements
check_requirements() {
    log INFO "Checking system requirements..."
    
    # Check OS
    if ! command -v lsb_release &> /dev/null; then
        log ERROR "lsb_release command not found. This script requires an Ubuntu/Debian-based system."
        exit 1
    fi
    
    local os_name=$(lsb_release -si)
    local os_version=$(lsb_release -sr)
    local os_codename=$(lsb_release -sc)
    
    if [[ ! "${os_name}" =~ ^(Ubuntu|Debian)$ ]]; then
        log ERROR "This script is designed for Ubuntu or Debian. Detected: ${os_name}"
        exit 1
    fi
    
    # Version check
    if [[ "${os_name}" == "Ubuntu" ]]; then
        if [[ $(echo "${os_version} < 20.04" | bc) -eq 1 ]]; then
            log WARNING "This script is optimized for Ubuntu 20.04+. Detected: ${os_version}"
        fi
    elif [[ "${os_name}" == "Debian" ]]; then
        if [[ $(echo "${os_version} < 11.0" | bc) -eq 1 ]]; then
            log WARNING "This script is optimized for Debian 11+. Detected: ${os_version}"
        fi
    fi
    
    # Check available disk space
    local available_space=$(df /root | awk 'NR==2 {print $4}')
    if [[ ${available_space} -lt 1048576 ]]; then  # Less than 1GB
        log WARNING "Low disk space available. Backup might fail."
    fi
    
    # Check network connectivity
    if ! ping -c 1 -W 2 8.8.8.8 &> /dev/null; then
        log WARNING "No internet connectivity detected. Package installation may fail."
    fi
    
    log SUCCESS "System: ${os_name} ${os_version} (${os_codename})"
}

# Create comprehensive backup
backup_files() {
    log INFO "Creating comprehensive system backup..."
    
    sudo mkdir -p "${BACKUP_DIR}" || return 1
    
    # Extended list of files to backup
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
        "/etc/issue"
        "/etc/issue.net"
    )
    
    for item in "${files_to_backup[@]}"; do
        if [[ -e "${item}" ]]; then
            sudo cp -a "${item}" "${BACKUP_DIR}/" 2>/dev/null || \
                log WARNING "Failed to backup ${item}"
        fi
    done
    
    # Save current service states
    systemctl list-unit-files --state=enabled > "${BACKUP_DIR}/enabled_services.txt"
    
    # Save installed packages
    dpkg -l > "${BACKUP_DIR}/installed_packages.txt"
    
    # Save iptables rules
    sudo iptables-save > "${BACKUP_DIR}/iptables.rules" 2>/dev/null || true
    sudo ip6tables-save > "${BACKUP_DIR}/ip6tables.rules" 2>/dev/null || true
    
    # Create backup metadata
    cat > "${BACKUP_DIR}/backup_info.txt" << EOF
Backup Date: $(date)
Script Version: ${VERSION}
Security Level: ${SECURITY_LEVEL}
System: $(lsb_release -ds)
Kernel: $(uname -r)
EOF
    
    # Compress backup
    sudo tar -czf "${BACKUP_DIR}.tar.gz" -C "$(dirname "${BACKUP_DIR}")" "$(basename "${BACKUP_DIR}")" || \
        log WARNING "Failed to compress backup"
    
    log SUCCESS "Backup created: ${BACKUP_DIR}.tar.gz"
}

# Restore from backup
restore_backup() {
    local backup_file
    
    if [[ -n "${1:-}" ]]; then
        backup_file="$1"
    else
        # Find most recent backup
        backup_file=$(ls -t /root/security_backup_*.tar.gz 2>/dev/null | head -1)
    fi
    
    if [[ ! -f "${backup_file}" ]]; then
        log ERROR "No backup file found"
        return 1
    fi
    
    log INFO "Restoring from ${backup_file}..."
    
    local temp_dir=$(mktemp -d)
    sudo tar -xzf "${backup_file}" -C "${temp_dir}"
    
    local backup_source=$(find "${temp_dir}" -maxdepth 1 -type d -name "security_backup_*" | head -1)
    
    if [[ -z "${backup_source}" ]]; then
        log ERROR "Invalid backup file structure"
        rm -rf "${temp_dir}"
        return 1
    fi
    
    # Restore files
    sudo cp -a "${backup_source}"/etc/* /etc/ 2>/dev/null || true
    
    # Restore iptables rules
    if [[ -f "${backup_source}/iptables.rules" ]]; then
        sudo iptables-restore < "${backup_source}/iptables.rules" 2>/dev/null || true
    fi
    
    if [[ -f "${backup_source}/ip6tables.rules" ]]; then
        sudo ip6tables-restore < "${backup_source}/ip6tables.rules" 2>/dev/null || true
    fi
    
    rm -rf "${temp_dir}"
    
    log SUCCESS "System restored from backup"
    log INFO "You may need to restart services for changes to take effect"
}

# Install package with retry logic
install_package() {
    local package="$1"
    local max_retries=3
    local retry_count=0
    
    while [[ ${retry_count} -lt ${max_retries} ]]; do
        if sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${package}" 2>/dev/null; then
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

# Module: System Update
module_system_update() {
    log INFO "Updating system packages..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would update system packages"
        return 0
    fi
    
    # Update package lists
    sudo apt-get update -y || return 1
    
    # Upgrade packages
    sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || return 1
    
    # Perform distribution upgrade
    sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y || return 1
    
    # Clean up
    sudo apt-get autoremove -y || true
    sudo apt-get autoclean -y || true
    
    log SUCCESS "System packages updated"
}

# Module: Enhanced Firewall Setup
module_firewall() {
    log INFO "Configuring enhanced firewall..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would configure firewall"
        return 0
    fi
    
    install_package "ufw" || return 1
    
    # Reset UFW to defaults
    sudo ufw --force reset || return 1
    
    # Default policies
    sudo ufw default deny incoming || return 1
    sudo ufw default allow outgoing || return 1
    sudo ufw default deny routed || return 1
    
    # Allow SSH with rate limiting
    local ssh_port=$(grep "^Port" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    sudo ufw limit "${ssh_port}/tcp" comment 'SSH with rate limiting' || return 1
    
    # Basic services (conditional)
    if [[ "${INTERACTIVE}" == "true" ]]; then
        read -p "Allow HTTP (80/tcp)? (y/N): " -r allow_http
        [[ "${allow_http}" =~ ^[Yy]$ ]] && sudo ufw allow 80/tcp comment 'HTTP'
        
        read -p "Allow HTTPS (443/tcp)? (y/N): " -r allow_https
        [[ "${allow_https}" =~ ^[Yy]$ ]] && sudo ufw allow 443/tcp comment 'HTTPS'
        
        read -p "Allow custom ports? (y/N): " -r allow_custom
        if [[ "${allow_custom}" =~ ^[Yy]$ ]]; then
            read -p "Enter ports (comma-separated, e.g., 8080/tcp,9000/udp): " -r custom_ports
            IFS=',' read -ra PORTS <<< "${custom_ports}"
            for port in "${PORTS[@]}"; do
                port=$(echo "${port}" | xargs)  # Trim whitespace
                sudo ufw allow "${port}" || log WARNING "Failed to add rule for ${port}"
            done
        fi
    fi
    
    # Enable logging
    sudo ufw logging on || return 1
    sudo ufw logging high || true  # High logging for paranoid mode
    
    # Enable UFW
    sudo ufw --force enable || return 1
    
    # Additional iptables rules for DDoS protection
    if [[ "${SECURITY_LEVEL}" == "high" ]] || [[ "${SECURITY_LEVEL}" == "paranoid" ]]; then
        # SYN flood protection
        sudo iptables -N syn_flood
        sudo iptables -A INPUT -p tcp --syn -j syn_flood
        sudo iptables -A syn_flood -m limit --limit 1/s --limit-burst 3 -j RETURN
        sudo iptables -A syn_flood -j DROP
        
        # Limit connections per IP
        sudo iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset
        
        # Save rules
        sudo netfilter-persistent save || true
    fi
    
    log SUCCESS "Firewall configured and enabled"
}

# Module: Enhanced SSH Hardening
module_ssh_hardening() {
    log INFO "Hardening SSH configuration..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would harden SSH configuration"
        return 0
    fi
    
    local sshd_config="/etc/ssh/sshd_config"
    
    if [[ ! -f "${sshd_config}" ]]; then
        log ERROR "SSH config file not found"
        return 1
    fi
    
    # Backup original
    sudo cp "${sshd_config}" "${sshd_config}.backup.$(date +%Y%m%d)" || return 1
    
    # Enhanced SSH settings
    local ssh_settings=(
        "Protocol 2"
        "Port 22"  # Consider changing in production
        "PermitRootLogin no"
        "PubkeyAuthentication yes"
        "PasswordAuthentication no"
        "PermitEmptyPasswords no"
        "ChallengeResponseAuthentication no"
        "UsePAM yes"
        "X11Forwarding no"
        "PrintMotd no"
        "PrintLastLog yes"
        "TCPKeepAlive yes"
        "Compression delayed"
        "ClientAliveInterval 300"
        "ClientAliveCountMax 2"
        "UseDNS no"
        "MaxAuthTries 3"
        "MaxSessions 10"
        "MaxStartups 10:30:60"
        "LoginGraceTime 60"
        "StrictModes yes"
        "IgnoreRhosts yes"
        "HostbasedAuthentication no"
    )
    
    # Apply settings
    for setting in "${ssh_settings[@]}"; do
        local key=$(echo "${setting}" | cut -d' ' -f1)
        if grep -q "^${key}" "${sshd_config}"; then
            sudo sed -i "s/^${key}.*/${setting}/" "${sshd_config}"
        elif grep -q "^#${key}" "${sshd_config}"; then
            sudo sed -i "s/^#${key}.*/${setting}/" "${sshd_config}"
        else
            echo "${setting}" | sudo tee -a "${sshd_config}" > /dev/null
        fi
    done
    
    # Add allowed users/groups if specified
    if [[ "${SECURITY_LEVEL}" == "high" ]] || [[ "${SECURITY_LEVEL}" == "paranoid" ]]; then
        # Get sudo users
        local sudo_users=$(getent group sudo | cut -d: -f4)
        if [[ -n "${sudo_users}" ]]; then
            echo "AllowUsers ${sudo_users//,/ }" | sudo tee -a "${sshd_config}" > /dev/null
        fi
        
        # Use only strong ciphers and MACs
        cat << 'EOF' | sudo tee -a "${sshd_config}" > /dev/null

# Strong Cryptography
Ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com
MACs umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
EOF
    fi
    
    # Create SSH banner
    cat << 'EOF' | sudo tee /etc/ssh/banner > /dev/null
############################################################
#                      SECURITY WARNING                    #
############################################################
# Unauthorized access to this system is strictly prohibited#
# All access attempts are logged and monitored             #
############################################################
EOF
    
    echo "Banner /etc/ssh/banner" | sudo tee -a "${sshd_config}" > /dev/null
    
    # Test SSH config
    if sudo sshd -t -f "${sshd_config}"; then
        sudo systemctl restart sshd || return 1
        log SUCCESS "SSH hardening completed"
    else
        log ERROR "SSH configuration test failed"
        sudo cp "${sshd_config}.backup.$(date +%Y%m%d)" "${sshd_config}"
        return 1
    fi
}

# Module: Enhanced Fail2Ban Configuration
module_fail2ban() {
    log INFO "Configuring Fail2Ban..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would configure Fail2Ban"
        return 0
    fi
    
    install_package "fail2ban" || return 1
    
    # Create local jail configuration
    cat << 'EOF' | sudo tee /etc/fail2ban/jail.local > /dev/null
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1
bantime  = 3600
findtime  = 600
maxretry = 5
backend = systemd
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

[sshd]
enabled = true
port    = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 7200

[sshd-ddos]
enabled = true
port    = ssh
filter   = sshd-ddos
logpath  = /var/log/auth.log
maxretry = 10
bantime  = 3600

[apache-auth]
enabled  = false
port     = http,https
filter   = apache-auth
logpath  = /var/log/apache*/*error.log
maxretry = 3

[nginx-http-auth]
enabled  = false
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 3

[postfix]
enabled  = false
port     = smtp,465,submission
filter   = postfix
logpath  = /var/log/mail.log
maxretry = 5

[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = %(action_mwl)s
bantime  = 86400
maxretry = 3
EOF
    
    # Create custom filter for SSH DDoS
    cat << 'EOF' | sudo tee /etc/fail2ban/filter.d/sshd-ddos.conf > /dev/null
[Definition]
failregex = sshd(?:\[\d+\])?: Did not receive identification string from <HOST>
            sshd(?:\[\d+\])?: Connection from <HOST> port \d+ on \S+ port \d+ rdomain ""$
ignoreregex =
EOF
    
    # Enable and start Fail2Ban
    sudo systemctl enable fail2ban || return 1
    sudo systemctl restart fail2ban || return 1
    
    log SUCCESS "Fail2Ban configured and started"
}

# Module: Setup Rootkit Scanners
module_rootkit_scanner() {
    log INFO "Installing rootkit scanners..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would install rootkit scanners"
        return 0
    fi
    
    # Install rkhunter
    install_package "rkhunter" || return 1
    
    # Update rkhunter database
    sudo rkhunter --update || log WARNING "Failed to update rkhunter database"
    sudo rkhunter --propupd || log WARNING "Failed to update rkhunter properties"
    
    # Configure rkhunter
    sudo sed -i 's/^CRON_DAILY_RUN=""/CRON_DAILY_RUN="yes"/' /etc/default/rkhunter || true
    sudo sed -i 's/^CRON_DB_UPDATE=""/CRON_DB_UPDATE="yes"/' /etc/default/rkhunter || true
    
    # Install chkrootkit
    install_package "chkrootkit" || return 1
    
    # Create daily cron job for scanning
    cat << 'EOF' | sudo tee /etc/cron.daily/rootkit-scan > /dev/null
#!/bin/bash
# Daily rootkit scan

LOG_FILE="/var/log/rootkit-scan.log"

echo "Rootkit scan started: $(date)" >> "${LOG_FILE}"

# Run rkhunter
/usr/bin/rkhunter --check --skip-keypress --report-warnings-only >> "${LOG_FILE}" 2>&1

# Run chkrootkit
/usr/sbin/chkrootkit -q >> "${LOG_FILE}" 2>&1

echo "Rootkit scan completed: $(date)" >> "${LOG_FILE}"

# Check for warnings and alert
if grep -q "Warning:" "${LOG_FILE}"; then
    mail -s "Rootkit Scanner Alert on $(hostname)" root < "${LOG_FILE}"
fi
EOF
    
    sudo chmod +x /etc/cron.daily/rootkit-scan || return 1
    
    log SUCCESS "Rootkit scanners installed and configured"
}

# Module: USB Protection
module_usb_protection() {
    log INFO "Configuring USB device restrictions..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would configure USB restrictions"
        return 0
    fi
    
    if [[ "${SECURITY_LEVEL}" == "paranoid" ]]; then
        # Disable USB storage completely
        cat << 'EOF' | sudo tee /etc/modprobe.d/blacklist-usb-storage.conf > /dev/null
# Disable USB storage
blacklist usb-storage
blacklist uas
blacklist usbhid
install usb-storage /bin/true
EOF
        log WARNING "USB storage devices have been disabled"
    else
        # Create udev rules for USB restrictions
        cat << 'EOF' | sudo tee /etc/udev/rules.d/01-usb-restrictions.rules > /dev/null
# USB device restrictions
# Log all USB device connections
ACTION=="add", SUBSYSTEM=="usb", RUN+="/bin/sh -c 'echo USB device connected: $attr{idVendor}:$attr{idProduct} >> /var/log/usb-devices.log'"

# Disable USB storage for non-root users (uncomment to enable)
# ACTION=="add", SUBSYSTEM=="block", SUBSYSTEMS=="usb", ENV{UDISKS_IGNORE}="1"
EOF
    fi
    
    # Reload udev rules
    sudo udevadm control --reload-rules || return 1
    
    log SUCCESS "USB protection configured"
}

# Module: Secure Shared Memory
module_secure_shared_memory() {
    log INFO "Securing shared memory..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would secure shared memory"
        return 0
    fi
    
    # Add tmpfs mount options to fstab
    if ! grep -q "tmpfs.*noexec" /etc/fstab; then
        echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0" | sudo tee -a /etc/fstab > /dev/null
        
        # Remount immediately
        sudo mount -o remount /run/shm || log WARNING "Failed to remount /run/shm"
    fi
    
    # Secure /tmp if it's a separate partition
    if mountpoint -q /tmp; then
        sudo mount -o remount,noexec,nosuid,nodev /tmp || log WARNING "Failed to remount /tmp"
    fi
    
    log SUCCESS "Shared memory secured"
}

# Module: Lynis Security Audit
module_lynis_audit() {
    log INFO "Running Lynis security audit..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would run Lynis audit"
        return 0
    fi
    
    # Install Lynis
    if ! command -v lynis &> /dev/null; then
        # Add Lynis repository
        wget -O - https://packages.cisofy.com/keys/cisofy-software-public.key | sudo apt-key add - || return 1
        echo "deb https://packages.cisofy.com/community/lynis/deb/ stable main" | sudo tee /etc/apt/sources.list.d/cisofy-lynis.list > /dev/null
        sudo apt-get update || return 1
        install_package "lynis" || return 1
    fi
    
    # Run audit
    local audit_log="/var/log/lynis-audit-$(date +%Y%m%d).log"
    sudo lynis audit system --quick --quiet --log-file "${audit_log}" || true
    
    # Parse results
    if [[ -f "${audit_log}" ]]; then
        local warnings=$(grep -c "Warning" "${audit_log}" || echo "0")
        local suggestions=$(grep -c "Suggestion" "${audit_log}" || echo "0")
        
        log INFO "Lynis audit completed: ${warnings} warnings, ${suggestions} suggestions"
        log INFO "Full report available at: ${audit_log}"
    fi
    
    log SUCCESS "Lynis audit completed"
}

# Module: Enhanced Password Policy
module_password_policy() {
    log INFO "Configuring enhanced password policies..."
    
    if [[ "${DRY_RUN}" == "true" ]]; then
        log INFO "[DRY RUN] Would configure password policies"
        return 0
    fi
    
    # Install required packages
    install_package "libpam-pwquality" || return 1
    install_package "libpam-cracklib" || return 1
    
    # Configure login.defs
    sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs || return 1
    sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs || return 1
    sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs || return 1
    sudo sed -i 's/^UMASK.*/UMASK           077/' /etc/login.defs || return 1
    
    # Configure PAM password quality
    cat << 'EOF' | sudo tee /etc/security/pwquality.conf > /dev/null
# Password quality configuration
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 3
maxrepeat = 2
maxsequence = 3
gecoscheck = 1
dictcheck = 1
usercheck = 1
enforcing = 1
retry = 3
EOF
    
    # Update PAM configuration
    sudo sed -i 's/^password.*requisite.*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3/' /etc/pam.d/common-password || true
    
    # Configure account lockout policy
    cat << 'EOF' | sudo tee /etc/pam.d/common-auth-lockout > /dev/null
# Account lockout policy
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
EOF
    
    # Include in common-auth
    if ! grep -q "common-auth-lockout" /etc/pam.d/common-auth; then
        sudo sed -i '1i @include common-auth-lockout' /etc/pam.d/common-auth || true
    fi
    
    log SUCCESS "Password policies configured"
}

# Generate HTML Security Report
generate_report() {
    log INFO "Generating security report..."
    
    cat << 'EOF' > "${REPORT_FILE}"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Hardening Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f4f4f4; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .info-box { background: #e7f3ff; border-left: 4px solid #007bff; padding: 10px; margin: 10px 0; }
        .success { background: #d4edda; border-left: 4px solid #28a745; }
        .warning { background: #fff3cd; border-left: 4px solid #ffc107; }
        .error { background: #f8d7da; border-left: 4px solid #dc3545; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 10px; text-align: left; border: 1px solid #ddd; }
        th { background: #007bff; color: white; }
        tr:nth-child(even) { background: #f9f9f9; }
        .metric { display: inline-block; margin: 10px 20px; }
        .metric-value { font-size: 24px; font-weight: bold; color: #007bff; }
        .metric-label { color: #666; font-size: 14px; }
        pre { background: #f4f4f4; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Hardening Report</h1>
EOF
    
    # System Information
    cat << EOF >> "${REPORT_FILE}"
        <div class="info-box">
            <h2>System Information</h2>
            <p><strong>Hostname:</strong> $(hostname)</p>
            <p><strong>Operating System:</strong> $(lsb_release -ds)</p>
            <p><strong>Kernel:</strong> $(uname -r)</p>
            <p><strong>Report Date:</strong> $(date)</p>
            <p><strong>Script Version:</strong> ${VERSION}</p>
            <p><strong>Security Level:</strong> ${SECURITY_LEVEL}</p>
        </div>
EOF
    
    # Security Metrics
    cat << EOF >> "${REPORT_FILE}"
        <h2>Security Metrics</h2>
        <div class="metrics">
            <div class="metric">
                <div class="metric-value">$(sudo ufw status | grep -c "ALLOW" || echo "0")</div>
                <div class="metric-label">Firewall Rules</div>
            </div>
            <div class="metric">
                <div class="metric-value">$(systemctl list-units --type=service --state=running | grep -c running || echo "0")</div>
                <div class="metric-label">Running Services</div>
            </div>
            <div class="metric">
                <div class="metric-value">$(sudo fail2ban-client status | grep -c "Jail list" || echo "0")</div>
                <div class="metric-label">Fail2Ban Jails</div>
            </div>
        </div>
EOF
    
    # Module Status
    cat << EOF >> "${REPORT_FILE}"
        <h2>Security Modules Status</h2>
        <table>
            <tr>
                <th>Module</th>
                <th>Description</th>
                <th>Status</th>
            </tr>
EOF
    
    for module in "${!SECURITY_MODULES[@]}"; do
        local status="Not Run"
        local class="warning"
        
        # Check if module was executed (simplified check)
        if grep -q "module_${module}" "${LOG_FILE}" 2>/dev/null; then
            if grep -q "SUCCESS.*${module}" "${LOG_FILE}" 2>/dev/null; then
                status="Completed"
                class="success"
            elif grep -q "ERROR.*${module}" "${LOG_FILE}" 2>/dev/null; then
                status="Failed"
                class="error"
            fi
        fi
        
        cat << EOF >> "${REPORT_FILE}"
            <tr class="${class}">
                <td>${module}</td>
                <td>${SECURITY_MODULES[${module}]}</td>
                <td>${status}</td>
            </tr>
EOF
    done
    
    cat << EOF >> "${REPORT_FILE}"
        </table>
EOF
    
    # Open Ports
    cat << EOF >> "${REPORT_FILE}"
        <h2>Network Configuration</h2>
        <h3>Open Ports</h3>
        <pre>$(sudo ss -tulpn | grep LISTEN || echo "No listening ports found")</pre>
        
        <h3>Firewall Status</h3>
        <pre>$(sudo ufw status verbose || echo "Firewall not configured")</pre>
EOF
    
    # Recent Security Events
    cat << EOF >> "${REPORT_FILE}"
        <h2>Recent Security Events</h2>
        <h3>Failed Login Attempts (Last 10)</h3>
        <pre>$(grep "Failed password" /var/log/auth.log | tail -10 || echo "No failed login attempts found")</pre>
        
        <h3>Sudo Usage (Last 10)</h3>
        <pre>$(grep "sudo" /var/log/auth.log | tail -10 || echo "No sudo usage found")</pre>
EOF
    
    # Recommendations
    cat << EOF >> "${REPORT_FILE}"
        <h2>Recommendations</h2>
        <ul>
            <li>Regularly review and update firewall rules</li>
            <li>Monitor logs in /var/log/auth.log and /var/log/syslog</li>
            <li>Keep system packages updated with automatic security updates</li>
            <li>Perform regular security audits using Lynis</li>
            <li>Review and test backup restoration procedures</li>
            <li>Consider implementing additional monitoring solutions</li>
            <li>Regularly scan for rootkits using rkhunter and chkrootkit</li>
        </ul>
EOF
    
    # Close HTML
    cat << EOF >> "${REPORT_FILE}"
    </div>
</body>
</html>
EOF
    
    log SUCCESS "Security report generated: ${REPORT_FILE}"
    
    # Optionally open in browser
    if [[ "${INTERACTIVE}" == "true" ]] && command -v xdg-open &> /dev/null; then
        read -p "Open report in browser? (y/N): " -r open_report
        [[ "${open_report}" =~ ^[Yy]$ ]] && xdg-open "${REPORT_FILE}"
    fi
}

# Execute security modules based on configuration
execute_modules() {
    local modules_to_run=()
    
    # Determine which modules to run
    if [[ -n "${ENABLE_MODULES}" ]]; then
        IFS=',' read -ra modules_to_run <<< "${ENABLE_MODULES}"
    else
        modules_to_run=("${!SECURITY_MODULES[@]}")
        
        # Remove disabled modules
        if [[ -n "${DISABLE_MODULES}" ]]; then
            IFS=',' read -ra disabled <<< "${DISABLE_MODULES}"
            for module in "${disabled[@]}"; do
                modules_to_run=("${modules_to_run[@]/$module}")
            done
        fi
    fi
    
    # Check dependencies and order modules
    local ordered_modules=()
    for module in "${modules_to_run[@]}"; do
        if [[ -n "${MODULE_DEPS[${module}]}" ]]; then
            IFS=' ' read -ra deps <<< "${MODULE_DEPS[${module}]}"
            for dep in "${deps[@]}"; do
                if [[ ! " ${ordered_modules[@]} " =~ " ${dep} " ]]; then
                    ordered_modules+=("${dep}")
                fi
            done
        fi
        if [[ ! " ${ordered_modules[@]} " =~ " ${module} " ]]; then
            ordered_modules+=("${module}")
        fi
    done
    
    # Execute modules
    local total=${#ordered_modules[@]}
    local current=0
    
    for module in "${ordered_modules[@]}"; do
        [[ -z "${module}" ]] && continue
        
        current=$((current + 1))
        show_progress ${current} ${total} "${SECURITY_MODULES[${module}]:-Unknown module}"
        
        local func="module_${module}"
        if declare -f "${func}" > /dev/null; then
            log INFO "Executing module: ${module}"
            if "${func}"; then
                log SUCCESS "Module ${module} completed successfully"
            else
                log ERROR "Module ${module} failed"
                if [[ "${INTERACTIVE}" == "true" ]]; then
                    read -p "Continue with remaining modules? (y/N): " -r continue_choice
                    [[ ! "${continue_choice}" =~ ^[Yy]$ ]] && exit 1
                fi
            fi
        else
            log WARNING "Module function ${func} not found"
        fi
    done
}

# Main execution
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                display_help
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
            -l|--level)
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
                display_help
                ;;
        esac
    done
    
    # Initialize
    check_permissions
    load_config
    check_requirements
    
    # Create log file
    sudo touch "${LOG_FILE}"
    sudo chmod 640 "${LOG_FILE}"
    
    log INFO "Starting Security Hardening Script v${VERSION}"
    log INFO "Security Level: ${SECURITY_LEVEL}"
    log INFO "Dry Run: ${DRY_RUN}"
    
    # Create backup unless in dry-run mode
    if [[ "${DRY_RUN}" == "false" ]]; then
        backup_files
    fi
    
    # Execute security modules
    execute_modules
    
    # Generate report
    generate_report
    
    # Final summary
    log SUCCESS "Security hardening completed!"
    log INFO "Backup location: ${BACKUP_DIR}.tar.gz"
    log INFO "Log file: ${LOG_FILE}"
    log INFO "Report: ${REPORT_FILE}"
    
    if [[ "${DRY_RUN}" == "false" ]] && [[ "${INTERACTIVE}" == "true" ]]; then
        echo
        read -p "System restart recommended. Restart now? (y/N): " -r restart_choice
        if [[ "${restart_choice}" =~ ^[Yy]$ ]]; then
            log INFO "Restarting system..."
            sudo reboot
        else
            log INFO "Please restart your system manually to apply all changes"
        fi
    fi
}

# Execute
main "$@"
