#!/bin/bash

# Improved Ubuntu Linux Security Script

# Function for logging
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $1" | sudo tee -a /var/log/security_hardening.log
}

# Function for error handling
handle_error() {
    log "Error: $1"
    exit 1
}

# Backup important files
backup_files() {
    local backup_dir="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
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
    sudo apt-get upgrade -y || handle_error "System upgrade failed"
}

# Install and Configure Firewall
setup_firewall() {
    log "Installing and Configuring Firewall..."
    sudo apt-get install ufw -y || handle_error "UFW installation failed"
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
    sudo apt-get install fail2ban -y || handle_error "Fail2Ban installation failed"
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
    sudo apt-get install clamav clamav-daemon -y || handle_error "ClamAV installation failed"
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
    sudo apt-get install auditd -y || handle_error "Auditd installation failed"
    
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
        echo "$rule" | sudo tee -a /etc/audit/rules.d/security.rules
    done
    
    sudo systemctl enable auditd
    sudo systemctl start auditd
    log "Audit rules configured and auditd started"
}

# Disable Unused Filesystems
disable_filesystems() {
    log "Disabling Unused Filesystems..."
    local filesystems=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf" "vfat")
    
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
        sudo sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1 ipv6.disable=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.all.send_redirects=0"/' /etc/default/grub
        
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
}

setup_apparmor() {
    log "Setting up AppArmor..."
    
    if ! command -v apparmor_status &> /dev/null; then
        sudo apt-get install apparmor apparmor-utils -y || handle_error "AppArmor installation failed"
    else
        log "AppArmor is already installed. Skipping installation."
    fi

    sudo systemctl enable apparmor
    sudo systemctl start apparmor

    sudo aa-enforce /etc/apparmor.d/*

    log "AppArmor setup complete. All profiles are in enforce mode."
    log "Monitor /var/log/syslog and /var/log/auth.log for any AppArmor-related issues."
}

additional_security() {
    log "Applying additional security measures..."
    
    # Disable core dumps
    echo "* hard core 0" | sudo tee -a /etc/security/limits.conf
    
    # Set proper permissions on sensitive files
    sudo chmod 600 /etc/shadow
    sudo chmod 600 /etc/gshadow
    
    # Enable process accounting
    sudo apt-get install acct -y
    sudo /usr/sbin/accton on
    
    # Restrict SSH
    sudo sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#Protocol.*/Protocol 2/' /etc/ssh/sshd_config
    sudo systemctl restart sshd
    
    # Configure strong password policy
    sudo sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs
    sudo sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/' /etc/login.defs
    sudo sed -i 's/password.*pam_unix.so.*/password    [success=1 default=ignore]    pam_unix.so obscure sha512 minlen=14 remember=5/' /etc/pam.d/common-password
    
    # Enable address space layout randomization (ASLR)
    echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
    
    # Additional sysctl hardening
    cat << EOF | sudo tee -a /etc/sysctl.conf
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0 

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 1
EOF

    # Apply sysctl changes
    sudo sysctl -p
    
    log "Additional security measures applied"
}

main() {
    check_permissions
    backup_files
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
    additional_security
    
    log "Enhanced Security Configuration executed! Script by captainzero93, improved by Claude"
}

# Run the main function
main
