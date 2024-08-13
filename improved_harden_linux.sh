#!/bin/bash

# Enhanced Ubuntu/Debian Linux Security Script

# Global variables
verbose=false
non_interactive=false
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
    if [ "$non_interactive" = true ]; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" || handle_error "$1 installation failed"
    else
        sudo apt-get install -y "$1" || handle_error "$1 installation failed"
    fi
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

    if [ "$non_interactive" = true ]; then
        log "Upgrading system in non-interactive mode..."
        sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || handle_error "System upgrade failed"
    else
        read -p "Do you want to upgrade the system? (y/N): " do_upgrade
        case $do_upgrade in
            [Yy]* )
                sudo apt-get upgrade -y || handle_error "System upgrade failed"
                log "System upgraded successfully"
                ;;
            * )
                log "System upgrade skipped"
                ;;
        esac
    fi
}

# Install and Configure Firewall
setup_firewall() {
    log "Installing and Configuring Firewall..."
    install_package "ufw"
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw limit ssh comment 'Allow SSH with rate limiting'
    sudo ufw allow 80/tcp comment 'Allow HTTP'
    sudo ufw allow 443/tcp comment 'Allow HTTPS'
    sudo ufw logging on
    sudo ufw --force enable
    log "Firewall configured and enabled"
}

# Install and Configure Fail2Ban
setup_fail2ban() {
    log "Installing and Configuring Fail2Ban..."
    install_package "fail2ban"
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local
    sudo sed -i 's/maxretry = 5/maxretry = 3/' /etc/fail2ban/jail.local
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
    log "Fail2Ban configured and started"
}

# Install and Update ClamAV
setup_clamav() {
    log "Installing and Updating ClamAV..."
    install_package "clamav"
    install_package "clamav-daemon"
    sudo systemctl stop clamav-freshclam
    sudo freshclam || log "Warning: ClamAV database update failed"
    sudo systemctl start clamav-freshclam
    sudo systemctl enable clamav-freshclam
    log "ClamAV installed and updated"
}

# Disable root login
disable_root() {
    log "Disabling root login..."
    sudo passwd -l root
    log "Root login disabled"
}

# Remove unnecessary packages
remove_packages() {
    log "Removing unnecessary packages..."
    sudo apt-get remove --purge telnetd nis yp-tools rsh-client rsh-redone-client xinetd -y
    sudo apt-get autoremove -y
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
        "-w /etc/ssh/sshd_config -p wa -k sshd_config"
        "-w /etc/crontab -p wa -k crontab"
        "-w /etc/cron.allow -p wa -k cron_allow"
        "-w /etc/cron.deny -p wa -k cron_deny"
        "-w /etc/cron.d/ -p wa -k cron_d"
        "-w /etc/cron.daily/ -p wa -k cron_daily"
        "-w /etc/cron.hourly/ -p wa -k cron_hourly"
        "-w /etc/cron.monthly/ -p wa -k cron_monthly"
        "-w /etc/cron.weekly/ -p wa -k cron_weekly"
    )
    
    for rule in "${audit_rules[@]}"; do
        echo "$rule" | sudo tee -a /etc/audit/rules.d/security.rules
    done
    
    sudo systemctl enable auditd
    sudo systemctl start auditd
    log "Audit rules configured and auditd started"
}

# Disable Unused Filesystems
disable_filesystems() {
    log "Disabling Unused Filesystems..."
    local filesystems=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf")
    
    for fs in "${filesystems[@]}"; do
        echo "install $fs /bin/true" | sudo tee -a /etc/modprobe.d/CIS.conf
    done
    
    log "Unused filesystems disabled"
}

secure_boot() {
    log "Securing Boot Settings..."
    
    # Secure GRUB configuration file
    if [ -f /boot/grub/grub.cfg ]; then
        sudo chown root:root /boot/grub/grub.cfg
        sudo chmod 600 /boot/grub/grub.cfg
        log "GRUB configuration file secured"
    else
        log "Warning: /boot/grub/grub.cfg not found. Skipping GRUB file permissions."
    fi
    
    # Modify kernel parameters
    if [ -f /etc/default/grub ]; then
        # Backup original file
        sudo cp /etc/default/grub /etc/default/grub.bak
        
        # Add or modify kernel parameters
        sudo sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.all.send_redirects=0 ipv6.disable=1 quiet splash"/' /etc/default/grub
        
        # Update GRUB
        if command -v update-grub &> /dev/null; then
            sudo update-grub
        elif command -v grub2-mkconfig &> /dev/null; then
            sudo grub2-mkconfig -o /boot/grub2/grub.cfg
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
    if [ "$non_interactive" = true ]; then
        log "Disabling IPv6 in non-interactive mode..."
        echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
        echo "net.ipv6.conf.lo.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
        sudo sysctl -p
        log "IPv6 has been disabled"
    else
        local disable_ipv6
        read -p "Do you want to disable IPv6? (y/N): " disable_ipv6
        case $disable_ipv6 in
            [Yy]* )
                log "Disabling IPv6..."
                echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
                echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
                echo "net.ipv6.conf.lo.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
                sudo sysctl -p
                log "IPv6 has been disabled"
                ;;
            * )
                log "IPv6 will remain enabled"
                ;;
        esac
    fi
}

setup_apparmor() {
    log "Setting up AppArmor..."
    
    if ! command -v apparmor_status &> /dev/null; then
        install_package "apparmor"
        install_package "apparmor-utils"
    else
        log "AppArmor is already installed. Skipping installation."
    fi

    sudo systemctl enable apparmor
    sudo systemctl start apparmor

    sudo aa-enforce /etc/apparmor.d/*

    log "AppArmor setup complete. All profiles are in enforce mode."
    log "Monitor /var/log/syslog and /var/log/auth.log for any AppArmor-related issues."
}

setup_ntp() {
    log "Setting up NTP..."
    install_package "systemd-timesyncd"
    sudo systemctl enable systemd-timesyncd
    sudo systemctl start systemd-timesyncd
    log "NTP (systemd-timesyncd) setup complete"
}

setup_aide() {
    log "Setting up AIDE..."
    install_package "aide"
    sudo aideinit
    sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
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
        "net.ipv4.icmp_echo_ignore_all = 0"
        ""
        "# Enable ASLR"
        "kernel.randomize_va_space = 2"
        ""
        "# Increase system file descriptor limit"
        "fs.file-max = 65535"
        ""
        "# Allow for more PIDs"
        "kernel.pid_max = 65536"
        ""
        "# Protect against SACK exploitation"
        "net.ipv4.tcp_sack = 0"
    )
    
    printf "%s\n" "${sysctl_config[@]}" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
    log "sysctl settings configured"
}

configure_password_expiration() {
    if [ "$non_interactive" = true ]; then
        log "Setting default password expiration policy in non-interactive mode..."
        sudo sed -i "s/PASS_MAX_DAYS\t[0-9]*/PASS_MAX_DAYS\t90/" /etc/login.defs
        sudo sed -i "s/PASS_WARN_AGE\t[0-9]*/PASS_WARN_AGE\t7/" /etc/login.defs
        log "Password expiration policy set: Max age 90 days, Warning at 7 days"
    else
        log "Configuring password expiration policy..."
        
        local enable_expiration
        local max_days
        local warn_days
        read -p "Do you want to enable password expiration? (y/N): " enable_expiration
        case $enable_expiration in
            [Yy]* )
                read -p "Enter the maximum number of days before password expiration (default 90): " max_days
                max_days=${max_days:-90}
                
                read -p "Enter the number of days to warn before password expires (default 7): " warn_days
                warn_days=${warn_days:-7}
                
                sudo sed -i "s/PASS_MAX_DAYS\t[0-9]*/PASS_MAX_DAYS\t$max_days/" /etc/login.defs
                sudo sed -i "s/PASS_WARN_AGE\t[0-9]*/PASS_WARN_AGE\t$warn_days/" /etc/login.defs
                
                log "Password expiration policy set: Max age $max_days days, Warning at $warn_days days"
                ;;
            * )
                log "Password expiration policy not changed"
                ;;
        esac
    fi
}

additional_security() {
    log "Applying additional security measures..."
    
    # Disable core dumps
    echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
    
    # Set proper permissions on sensitive files
    sudo chmod 600 /etc/shadow
    sudo chmod 600 /etc/gshadow
    
    # Enable process accounting
    install_package "acct"
    sudo /usr/sbin/accton on
    
    # Restrict SSH
    sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#Protocol.*/Protocol 2/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    
    # Configure strong password policy
    sudo sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/' /etc/login.defs
    sudo sed -i 's/password.*pam_unix.so.*/password    [success=1 default=ignore]    pam_unix.so obscure sha512 minlen=14 remember=5/' /etc/pam.d/common-password
    
    # Call the new function to configure password expiration
    configure_password_expiration
    
    log "Additional security measures applied"
}

setup_automatic_updates() {
    log "Setting up automatic security updates..."
    install_package "unattended-upgrades"
    sudo dpkg-reconfigure -plow unattended-upgrades
    log "Automatic security updates configured"
}

main() {
    check_permissions
    backup_files

    # Check for non-interactive mode
    if [[ "$1" == "--non-interactive" ]]; then
        non_interactive=true
        log "Running in non-interactive mode"
    else
        # Ask user for verbose mode
        read -p "Do you want to enable verbose mode? (y/N): " enable_verbose
        case $enable_verbose in
            [Yy]* ) verbose=true;;
            * ) verbose=false;;
        esac
    fi

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

    if [ "$non_interactive" = false ]; then
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
    else
        log "System hardening complete. A reboot is recommended to apply all changes."
    fi
}

# Run the main function
if [[ "$1" == "--non-interactive" ]]; then
    main --non-interactive
else
    main
fi
