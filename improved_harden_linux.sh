#!/bin/bash

# Function for logging
log() {
    echo "$(date): $1" | sudo tee -a /var/log/security_hardening.log
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
    sudo cp /etc/default/grub "$backup_dir/" || handle_error "Failed to backup GRUB config"
    sudo cp /etc/ssh/sshd_config "$backup_dir/" || handle_error "Failed to backup SSH config"
    sudo cp /etc/pam.d/common-password "$backup_dir/" || handle_error "Failed to backup PAM password config"
    log "Backup created in $backup_dir"
}

# Update System
update_system() {
    log "Updating System..."
    sudo apt-get update -y || handle_error "System update failed"
    # sudo apt-get upgrade -y || handle_error "System upgrade failed"
}

# Install and Configure Firewall
setup_firewall() {
    log "Installing and Configuring Firewall..."
    sudo apt-get install ufw -y || handle_error "UFW installation failed"
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh
    sudo ufw allow http
    sudo ufw allow https
    sudo ufw --force enable
}

# Install and Configure Fail2Ban
setup_fail2ban() {
    log "Installing and Configuring Fail2Ban..."
    sudo apt-get install fail2ban -y || handle_error "Fail2Ban installation failed"
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban
}

# Install and Update ClamAV
setup_clamav() {
    log "Installing and Updating ClamAV..."
    sudo apt-get install clamav clamav-daemon -y || handle_error "ClamAV installation failed"
    sudo systemctl stop clamav-freshclam
    sudo freshclam || log "Warning: ClamAV database update failed"
    sudo systemctl start clamav-freshclam
    sudo systemctl enable clamav-freshclam
}

# Disable root login
disable_root() {
    log "Disabling root login..."
    sudo passwd -l root
}

# Remove unnecessary packages
remove_packages() {
    log "Removing unnecessary packages..."
    sudo apt-get remove --purge telnetd nis yp-tools rsh-client rsh-redone-client xinetd -y
}

# Configure audit rules
setup_audit() {
    log "Configuring audit rules..."
    sudo apt-get install auditd -y || handle_error "Auditd installation failed"
    echo "-w /etc/passwd -p wa -k identity" | sudo tee /etc/audit/rules.d/identity.rules
    echo "-w /etc/group -p wa -k identity" | sudo tee -a /etc/audit/rules.d/identity.rules
    echo "-w /etc/shadow -p wa -k identity" | sudo tee -a /etc/audit/rules.d/identity.rules
    sudo systemctl enable auditd
    sudo systemctl start auditd
}

# Disable Unused Filesystems
disable_filesystems() {
    log "Disabling Unused Filesystems..."
    sudo bash -c 'cat << EOF > /etc/modprobe.d/CIS.conf
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF'
}

secure_boot() {
    log "Securing Boot Settings..."
    
    # Secure GRUB configuration file
    if [ -f /boot/grub/grub.cfg ]; then
        sudo chown root:root /boot/grub/grub.cfg
        sudo chmod 600 /boot/grub/grub.cfg
    else
        log "Warning: /boot/grub/grub.cfg not found. Skipping GRUB file permissions."
    fi
    
    # Modify kernel parameters
    if [ -f /etc/default/grub ]; then
        # Backup original file
        sudo cp /etc/default/grub /etc/default/grub.bak
        
        # Add or modify kernel parameters
        sudo sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="audit=1"/' /etc/default/grub
        
        # Update GRUB
        if command -v update-grub &> /dev/null; then
            sudo update-grub
        elif command -v grub2-mkconfig &> /dev/null; then
            sudo grub2-mkconfig -o /boot/grub2/grub.cfg
        else
            log "Warning: Neither update-grub nor grub2-mkconfig found. Please update GRUB manually."
        fi
    else
        log "Warning: /etc/default/grub not found. Skipping kernel parameter modifications."
    fi
    
    log "Boot settings secured."
}

# Additional Security Measures
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
    # sudo sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs
    # sudo sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t10/' /etc/login.defs
    # sudo sed -i 's/password.*pam_unix.so.*/password    [success=1 default=ignore]    pam_unix.so obscure sha512 minlen=14/' /etc/pam.d/common-password
    
    # Enable address space layout randomization (ASLR)
    echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
    
# New function to handle IPv6 configuration
configure_ipv6() {
    local disable_ipv6
    read -p "Do you want to disable IPv6? (y/N): " disable_ipv6
    case $disable_ipv6 in
        [Yy]* )
            log "Disabling IPv6..."
            echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
            echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
            sudo sysctl -p
            log "IPv6 has been disabled."
            ;;
        * )
            log "IPv6 will remain enabled."
            ;;
    esac
}

# Additional Security Measures
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
    # sudo sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs
    # sudo sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t10/' /etc/login.defs
    # sudo sed -i 's/password.*pam_unix.so.*/password    [success=1 default=ignore]    pam_unix.so obscure sha512 minlen=14/' /etc/pam.d/common-password
    
    # Enable address space layout randomization (ASLR)
    echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
    
    # Call the new IPv6 configuration function
    configure_ipv6
    
    # Apply sysctl changes
    sudo sysctl -p
}

# Main execution
main() {
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
    additional_security
    
    log "Enhanced Security Configuration Applied Successfully!"
}

# Run the main function
main

# Run the main function
main

