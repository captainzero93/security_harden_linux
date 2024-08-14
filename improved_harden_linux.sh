#!/bin/bash

# Enhanced Ubuntu Linux Security Script

# Global variables
verbose=false
backup_dir="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
log_file="/var/log/security_hardening.log"

# Function for logging
log() {
    local message="$(date '+%Y-%m-%d %H:%M:%S'): $1"
    echo "$message" | sudo tee -a "$log_file"
    $verbose && echo "$message"
}

# Function for error handling
handle_error() {
    log "Error: $1"
    exit 1
}

# Function to install packages
install_package() {
    log "Installing $1..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" || handle_error "Failed to install $1"
}

# Backup important files
backup_files() {
    sudo mkdir -p "$backup_dir" || handle_error "Failed to create backup directory"
    
    local files_to_backup=(
        "/etc/default/grub"
        "/etc/ssh/sshd_config"
        "/etc/pam.d/common-password"
        "/etc/login.defs"
        "/etc/sysctl.conf"
    )
    
    for file in "${files_to_backup[@]}"; do
        if [ -f "$file" ]; then
            sudo cp "$file" "$backup_dir/" || log "Warning: Failed to backup $file"
        else
            log "Warning: $file not found, skipping backup"
        fi
    done
    
    log "Backup created in $backup_dir"
}

# Restore from backup
restore_backup() {
    if [ -d "$backup_dir" ]; then
        for file in "$backup_dir"/*; do
            sudo cp "$file" "$(dirname "$(readlink -f "$file")")" || log "Warning: Failed to restore $(basename "$file")"
        done
        log "Restored configurations from $backup_dir"
    else
        log "Backup directory not found. Cannot restore."
    fi
}

check_permissions() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run with sudo privileges."
        echo "Please run it again using: sudo $0"
        exit 1
    fi
}

# Update System
update_system() {
    log "Updating System..."
    sudo apt-get update -y || handle_error "System update failed"
    sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || handle_error "System upgrade failed"
}

# Install and Configure Firewall
setup_firewall() {
    log "Installing and Configuring Firewall..."
    install_package "ufw"
    sudo ufw default deny incoming || handle_error "Failed to set UFW default incoming policy"
    sudo ufw default allow outgoing || handle_error "Failed to set UFW default outgoing policy"
    sudo ufw limit ssh comment 'Allow SSH with rate limiting' || handle_error "Failed to configure SSH in UFW"
    sudo ufw allow 80/tcp comment 'Allow HTTP' || handle_error "Failed to allow HTTP in UFW"
    sudo ufw allow 443/tcp comment 'Allow HTTPS' || handle_error "Failed to allow HTTPS in UFW"
    
    local apply_ipv6_rules
    read -p "Do you want to apply IPv6-specific firewall rules? (y/N): " apply_ipv6_rules
    case $apply_ipv6_rules in
        [Yy]* )
            log "Applying IPv6-specific firewall rules..."
            sudo ufw allow in on lo || handle_error "Failed to allow loopback traffic"
            sudo ufw allow out on lo || handle_error "Failed to allow loopback traffic"
            sudo ufw deny in from ::/0 || handle_error "Failed to deny all incoming IPv6 traffic"
            sudo ufw allow out to ::/0 || handle_error "Failed to allow all outgoing IPv6 traffic"
            log "IPv6 firewall rules applied"
            ;;
        * )
            log "Skipping IPv6-specific firewall rules"
            ;;
    esac
    
    sudo ufw logging on || handle_error "Failed to enable UFW logging"
    sudo ufw --force enable || handle_error "Failed to enable UFW"
    log "Firewall configured and enabled"
}

# Install and Configure Fail2Ban
setup_fail2ban() {
    log "Installing and Configuring Fail2Ban..."
    install_package "fail2ban"
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local || handle_error "Failed to create Fail2Ban local config"
    sudo sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local || handle_error "Failed to set Fail2Ban bantime"
    sudo sed -i 's/maxretry = 5/maxretry = 3/' /etc/fail2ban/jail.local || handle_error "Failed to set Fail2Ban maxretry"
    sudo systemctl enable fail2ban || handle_error "Failed to enable Fail2Ban service"
    sudo systemctl start fail2ban || handle_error "Failed to start Fail2Ban service"
    log "Fail2Ban configured and started"
}

# Install and Update ClamAV
setup_clamav() {
    log "Installing and Updating ClamAV..."
    install_package "clamav"
    install_package "clamav-daemon"
    sudo systemctl stop clamav-freshclam || log "Warning: Failed to stop clamav-freshclam"
    sudo freshclam || log "Warning: ClamAV database update failed"
    sudo systemctl start clamav-freshclam || handle_error "Failed to start clamav-freshclam"
    sudo systemctl enable clamav-freshclam || handle_error "Failed to enable clamav-freshclam"
    log "ClamAV installed and updated"
}

# Disable root login
disable_root() {
    log "Checking for non-root users with sudo privileges..."
    
    # Get the list of users with sudo privileges
    sudo_users=$(getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v "^root$")
    
    # Check if there are any non-root users with sudo privileges
    if [ -z "$sudo_users" ]; then
        log "Warning: No non-root users with sudo privileges found. Skipping root login disable for safety."
        echo "Please create a non-root user with sudo privileges before disabling root login."
        return
    fi
    
    log "Non-root users with sudo privileges found. Proceeding to disable root login..."
    
    # Disable root login
    if sudo passwd -l root; then
        log "Root login disabled successfully."
    else
        handle_error "Failed to lock root account"
    fi
    
    # Disable root SSH login as an additional precaution
    if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || handle_error "Failed to disable root SSH login in sshd_config"
    else
        echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config > /dev/null || handle_error "Failed to add PermitRootLogin no to sshd_config"
    fi
    
    # Restart SSH service to apply changes
    sudo systemctl restart sshd || handle_error "Failed to restart SSH service"
    
    log "Root login has been disabled and SSH root login has been explicitly prohibited."
}

# Remove unnecessary packages
remove_packages() {
    log "Removing unnecessary packages..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y telnetd nis yp-tools rsh-client rsh-redone-client xinetd || log "Warning: Failed to remove some packages"
    sudo apt-get autoremove -y || log "Warning: autoremove failed"
    log "Unnecessary packages removed"
}

# Configure audit rules
setup_audit() {
    log "Configuring audit rules..."
    install_package "auditd"
    
    local audit_rules=(
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/group -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
        "-w /etc/sudoers -p wa -k sudoers"
        "-w /var/log/auth.log -p wa -k auth_log"
        "-w /sbin/insmod -p x -k modules"
        "-w /sbin/rmmod -p x -k modules"
        "-w /sbin/modprobe -p x -k modules"
    )
    
    for rule in "${audit_rules[@]}"; do
        echo "$rule" | sudo tee -a /etc/audit/rules.d/security.rules || handle_error "Failed to add audit rule: $rule"
    done
    
    sudo systemctl enable auditd || handle_error "Failed to enable auditd service"
    sudo systemctl start auditd || handle_error "Failed to start auditd service"
    log "Audit rules configured and auditd started"
}

# Disable Unused Filesystems
disable_filesystems() {
    log "Disabling Unused Filesystems..."
    local filesystems=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf" "vfat")
    
    for fs in "${filesystems[@]}"; do
        echo "install $fs /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf || handle_error "Failed to disable filesystem: $fs"
    done
    
    log "Unused filesystems disabled"
}

secure_boot() {
    log "Securing Boot Settings..."
    
    # Secure GRUB configuration file
    if [ -f /boot/grub/grub.cfg ]; then
        sudo chown root:root /boot/grub/grub.cfg || handle_error "Failed to change ownership of grub.cfg"
        sudo chmod 600 /boot/grub/grub.cfg || handle_error "Failed to change permissions of grub.cfg"
        log "GRUB configuration file secured"
    else
        log "Warning: /boot/grub/grub.cfg not found. Skipping GRUB file permissions."
    fi
    
    # Modify kernel parameters
    if [ -f /etc/default/grub ]; then
        # Backup original file
        sudo cp /etc/default/grub /etc/default/grub.bak || handle_error "Failed to backup grub file"
        
        # Add or modify kernel parameters
        local kernel_params="audit=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.all.send_redirects=0"
        
        # Ask if user wants to disable SACK
        local disable_sack
        read -p "Do you want to disable TCP SACK? This is generally not recommended. (y/N): " disable_sack
        case $disable_sack in
            [Yy]* )
                kernel_params+=" net.ipv4.tcp_sack=0"
                log "TCP SACK will be disabled"
                ;;
            * )
                log "TCP SACK will remain enabled"
                ;;
        esac
        
        sudo sed -i "s/GRUB_CMDLINE_LINUX=\"\"/GRUB_CMDLINE_LINUX=\"$kernel_params\"/" /etc/default/grub || handle_error "Failed to modify kernel parameters"
        
        # Update GRUB
        if command -v update-grub &> /dev/null; then
            sudo update-grub || handle_error "Failed to update GRUB"
        elif command -v grub2-mkconfig &> /dev/null; then
            sudo grub2-mkconfig -o /boot/grub2/grub.cfg || handle_error "Failed to update GRUB"
        else
            log "Warning: Neither update-grub nor grub2-mkconfig found. Please update GRUB manually."
        fi
        
        log "Kernel parameters updated"
    else
        log "Warning: /etc/default/grub not found. Skipping kernel parameter modifications."
    fi
    
    log "Boot settings secured"
}

configure_ipv6() {
    local disable_ipv6
    read -p "Do you want to disable IPv6? (y/N): " disable_ipv6
    case $disable_ipv6 in
        [Yy]* )
            log "Disabling IPv6..."
            echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf || handle_error "Failed to disable IPv6 (all)"
            echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf || handle_error "Failed to disable IPv6 (default)"
            echo "net.ipv6.conf.lo.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf || handle_error "Failed to disable IPv6 (lo)"
            sudo sysctl -p || handle_error "Failed to apply sysctl changes"
            log "IPv6 has been disabled"
            ;;
        * )
            log "IPv6 will remain enabled"
            ;;
    esac
}

setup_apparmor() {
    log "Setting up AppArmor..."
    
    if ! command -v apparmor_status &> /dev/null; then
        install_package "apparmor"
        install_package "apparmor-utils"
    else
        log "AppArmor is already installed. Skipping installation."
    fi

    sudo systemctl enable apparmor || handle_error "Failed to enable AppArmor service"
    sudo systemctl start apparmor || handle_error "Failed to start AppArmor service"

    sudo aa-enforce /etc/apparmor.d/* || log "Warning: Failed to enforce some AppArmor profiles"

    log "AppArmor setup complete. All profiles are in enforce mode."
    log "Monitor /var/log/syslog and /var/log/auth.log for any AppArmor-related issues."
}

setup_ntp() {
    log "Setting up NTP..."
    install_package "ntp"
    sudo systemctl enable ntp || handle_error "Failed to enable NTP service"
    sudo systemctl start ntp || handle_error "Failed to start NTP service"
    log "NTP setup complete"
}

setup_aide() {
    log "Setting up AIDE..."
    install_package "aide"
    sudo aideinit || handle_error "Failed to initialize AIDE database"
    sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || handle_error "Failed to move AIDE database"
    log "AIDE setup complete"
}

configure_sysctl() {
    log "Configuring sysctl settings..."
    
    local sysctl_config=(
        "# IP Spoofing protection"
        "net.ipv4.conf.all.rp_filter = 1"
        "net.ipv4.conf.default.rp_filter = 1"
        ""
        "# Ignore ICMP broadcast requests"
        "net.ipv4.icmp_echo_ignore_broadcasts = 1"
        ""
        "# Disable source packet routing"
        "net.ipv4.conf.all.accept_source_route = 0"
        "net.ipv6.conf.all.accept_source_route = 0"
        ""
        "# Ignore send redirects"
        "net.ipv4.conf.all.send_redirects = 0"
        "net.ipv4.conf.default.send_redirects = 0"
        ""
        "# Block SYN attacks"
        "net.ipv4.tcp_syncookies = 1"
        "net.ipv4.tcp_max_syn_backlog = 2048"
        "net.ipv4.tcp_synack_retries = 2"
        "net.ipv4.tcp_syn_retries = 5"
        ""
        "# Log Martians"
        "net.ipv4.conf.all.log_martians = 1"
        "net.ipv4.icmp_ignore_bogus_error_responses = 1"
        ""
        "# Ignore ICMP redirects"
        "net.ipv4.conf.all.accept_redirects = 0"
        "net.ipv6.conf.all.accept_redirects = 0"
        ""
        "# Ignore Directed pings"
        "net.ipv4.icmp_echo_ignore_all = 1"
        ""
        "# Enable ASLR"
        "kernel.randomize_va_space = 2"
    )
    
    printf "%s\n" "${sysctl_config[@]}" | sudo tee -a /etc/sysctl.conf || handle_error "Failed to update sysctl.conf"
    sudo sysctl -p || handle_error "Failed to apply sysctl changes"
    log "sysctl settings configured"
}

additional_security() {
    log "Applying additional security measures..."
    
    # Disable core dumps
    echo "* hard core 0" | sudo tee -a /etc/security/limits.conf || handle_error "Failed to disable core dumps"
    
    # Set proper permissions on sensitive files
    sudo chmod 600 /etc/shadow || handle_error "Failed to set permissions on /etc/shadow"
    sudo chmod 600 /etc/gshadow || handle_error "Failed to set permissions on /etc/gshadow"
    
    # Enable process accounting
    install_package "acct"
    sudo /usr/sbin/accton on || handle_error "Failed to enable process accounting"
    
    # Restrict SSH
    sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || handle_error "Failed to disable root login via SSH"
    sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config || handle_error "Failed to disable password authentication for SSH"
    sudo sed -i 's/^#Protocol.*/Protocol 2/' /etc/ssh/sshd_config || handle_error "Failed to set SSH protocol version"
    sudo systemctl restart sshd || handle_error "Failed to restart SSH service"
    
    # Configure strong password policy
    sudo sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs || handle_error "Failed to set password max days"
    sudo sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/' /etc/login.defs || handle_error "Failed to set password min days"
    sudo sed -i 's/password.*pam_unix.so.*/password    [success=1 default=ignore]    pam_unix.so obscure sha512 minlen=14 remember=5/' /etc/pam.d/common-password || handle_error "Failed to configure password policy"
    
    log "Additional security measures applied"
}

setup_automatic_updates() {
    log "Setting up automatic security updates..."
    install_package "unattended-upgrades"
    sudo dpkg-reconfigure -plow unattended-upgrades || handle_error "Failed to configure unattended-upgrades"
    log "Automatic security updates configured"
}

main() {
    check_permissions
    backup_files

    # Ask user for verbose mode
    read -p "Do you want to enable verbose mode? (y/N): " enable_verbose
    case $enable_verbose in
        [Yy]* ) verbose=true;;
        * ) verbose=false;;
    esac

    update_system
    setup_firewall
    setup_fail2ban
    setup_clamav
    disable_root
    remove_packages
    setup_audit
    disable_filesystems
    secure_boot
    configure_ipv6
    setup_apparmor
    setup_ntp
    setup_aide
    configure_sysctl
    additional_security
    setup_automatic_updates
    
    log "Enhanced Security Configuration executed! Script by captainzero93, improved by Claude"

    # Ask user if they want to restart
    read -p "Do you want to restart the system now to apply all changes? (y/N): " restart_now
    case $restart_now in
        [Yy]* ) 
            log "Restarting system..."
            sudo reboot
            ;;
        * ) 
            log "Please restart your system manually to apply all changes."
            ;;
    esac
}

# Run the main function
main
