#!/bin/bash

# Function for logging
log() {
    echo "$(date): $1" | tee -a /var/log/security_hardening.log
}

# Function for error handling
handle_error() {
    log "Error: $1"
    exit 1
}

# Backup important files
backup_files() {
    local backup_dir="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir" || handle_error "Failed to create backup directory"
    cp /etc/default/grub "$backup_dir/" || handle_error "Failed to backup GRUB config"
    cp /etc/ssh/sshd_config "$backup_dir/" || handle_error "Failed to backup SSH config"
    log "Backup created in $backup_dir"
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
    sudo ufw allow ssh
    sudo ufw --force enable
}

# Install and Configure Fail2Ban
setup_fail2ban() {
    log "Installing and Configuring Fail2Ban..."
    sudo apt-get install fail2ban -y || handle_error "Fail2Ban installation failed"
    # Add custom Fail2Ban configuration here if needed
}

# Install and Update ClamAV
setup_clamav() {
    log "Installing and Updating ClamAV..."
    sudo apt-get install clamav -y || handle_error "ClamAV installation failed"
    sudo freshclam || log "Warning: ClamAV database update failed"
}

# Disable root login
disable_root() {
    log "Disabling root login..."
    sudo passwd -l root
}

# Remove unnecessary packages
remove_packages() {
    log "Removing unnecessary packages..."
    sudo apt-get remove telnetd nis yp-tools rsh-client rsh-redone-client xinetd -y
}

# Configure audit rules
setup_audit() {
    log "Configuring audit rules..."
    sudo apt-get install auditd -y || handle_error "Auditd installation failed"
    echo "-w /etc/passwd -p wa -k identity" | sudo tee /etc/audit/rules.d/identity.rules
    echo "-w /etc/group -p wa -k identity" | sudo tee -a /etc/audit/rules.d/identity.rules
    sudo systemctl enable auditd
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

# Secure Boot Settings
secure_boot() {
    log "Securing Boot Settings..."
    sudo chown root:root /boot/grub/grub.cfg
    sudo chmod og-rwx /boot/grub/grub.cfg
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
    sudo systemctl restart sshd
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
    
    log "Basic Security Configuration Applied Successfully!"
}

# Run the main function
main
