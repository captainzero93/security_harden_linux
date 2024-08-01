# Linux Security Hardening Scripts (Debian based, Ubuntu etc)

This repository contains two bash scripts designed to enhance security:

1. `improved_harden_linux.sh`: A comprehensive script for hardening Linux systems
2. `update_grub_config.sh`: A script for updating GRUB configuration with security-enhancing parameters

## 1. Updated Linux Hardening Script (`improved_harden_linux.sh`)

Features:

- Creates a backup of important configuration files before making changes

- System Update
  - Updates and upgrades the system packages

- Firewall Setup
  - Installs and configures Uncomplicated Firewall (UFW)
  - Sets default secure policies

- Fail2Ban Installation
  - Installs Fail2Ban to protect against brute-force attacks

- Antivirus Setup
  - Installs ClamAV antivirus and updates its database

- User Account Security
  - Disables root login and password authentication for better security

- Package Management
  - Removes unnecessary and potentially vulnerable packages

- Audit Configuration
  - Installs and configures the audit system
  - Sets up rules to monitor changes to user and group files

- Filesystem Security
  - Disables unused and potentially risky filesystems

- Boot Security
  - Secures GRUB configuration file permissions

- Additional Security Measures
  - Disables core dumps
  - Sets proper permissions on sensitive files
  - Enables process accounting
  - Restricts SSH access

- IPv6 Configuration
  - Offers an option to disable IPv6 during script execution

## Customisation Options

- Password Policy
  - The script includes commented-out lines for implementing a stricter password policy. To enable these, uncomment the following lines in the `additional_security()` function:
    ```bash
    # sudo sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs
    # sudo sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t10/' /etc/login.defs
    # sudo sed -i 's/password.*pam_unix.so.*/password    [success=1 default=ignore]    pam_unix.so obscure sha512 minlen=14/' /etc/pam.d/common-password
    ```

## 2. GRUB Configuration Update Script (`update_grub_config.sh`)

[The content for this section remains unchanged]

## Usage

To use these scripts:

1. Clone this repository:
   ```
   git clone https://github.com/captainzero93/security_harden_linux.git
   ```

2. Navigate to the script directory:
   ```
   cd security_harden_linux
   ```

3. Make the scripts executable:
   ```
   chmod +x improved_harden_linux.sh update_grub_config.sh
   ```

4. Run the main hardening script (requires sudo):
   ```
   sudo ./improved_harden_linux.sh
   ```
   Note: You will be prompted whether you want to disable IPv6 during the execution of this script.

5. Run the GRUB configuration script (requires sudo):
   ```
   sudo ./update_grub_config.sh
   ```

6. Reboot your system for all changes to take effect.

## Caution

These scripts make significant changes to your system configuration. It's recommended to:
- Run these scripts in a test environment first
- Understand each change being made
- Have a backup or recovery method in place before running on a production system

## Contributing

Contributions to improve these scripts are welcome. Please submit a pull request or open an issue to discuss proposed changes.

## Disclaimer
These scripts are provided as-is, without any warranty. The author is not responsible for any damage or data loss caused by the use of these scripts. Use at your own risk.
