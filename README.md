# Ubuntu/Debian Linux Security Hardening Scripts

## Overview
This project consists of two scripts designed to enhance the security of Ubuntu and other Debian-based Linux systems. The main script implements a variety of security measures and best practices to harden your system against common threats, while the GRUB configuration script specifically focuses on securing the boot process.

## Scripts
1. `improved_harden_linux.sh`: The main security hardening script
2. `update_grub_config.sh`: A script to update GRUB configuration with additional security parameters

## Features
- System update and upgrade
- Firewall (UFW) configuration
- Fail2Ban installation and setup
- ClamAV antivirus installation and update
- Root login disabling
- Removal of unnecessary packages
- Audit system configuration
- Disabling of unused filesystems
- Boot settings security enhancements
- IPv6 configuration options
- AppArmor setup and enforcement
- Network Time Protocol (NTP) setup
- Advanced Intrusion Detection Environment (AIDE) setup
- Sysctl security parameter configuration
- Automatic security updates setup
- GRUB configuration hardening
- Additional security measures including:
  - Core dump disabling
  - SSH hardening
  - Strong password policy configuration
  - ASLR enablement
  - Process accounting enablement

## Prerequisites
- Ubuntu / Debian-based Linux system (tested on Ubuntu 20.04 LTS and later)
- Root or sudo access
- Internet connection for package installation and updates

## Usage
### Main Hardening Script
1. Download the script:
   ```
   wget https://raw.githubusercontent.com/captainzero93/ubuntu-security-script/main/improved_harden_linux.sh
   ```
2. Make the script executable:
   ```
   chmod +x improved_harden_linux.sh
   ```
3. Run the script with sudo privileges:
   ```
   sudo ./improved_harden_linux.sh
   ```
4. Follow the prompts during script execution, including options for verbose mode and system restart.

### GRUB Configuration Script
1. Download the script:
   ```
   wget https://raw.githubusercontent.com/captainzero93/ubuntu-security-script/main/update_grub_config.sh
   ```
2. Make the script executable:
   ```
   chmod +x update_grub_config.sh
   ```
3. Run the script with sudo privileges:
   ```
   sudo ./update_grub_config.sh
   ```

## Important Notes
- These scripts make significant changes to your system. It is strongly recommended to run them on a test system or VM before applying to production environments.
- A backup of important configuration files is created before changes are made. The main script creates backups in `/root/security_backup_[timestamp]`, and the GRUB script backs up to `/etc/default/grub.bak`.
- Some changes, particularly to network settings, AppArmor, and GRUB, may impact system functionality. Be prepared to troubleshoot if issues arise.
- The main script log is saved to `/var/log/security_hardening.log` for review and troubleshooting.
- You can enable verbose mode for more detailed logging during the main script execution.

## Customization
You may want to review and customize the scripts before running them, particularly:
- Firewall rules in the `setup_firewall` function
- Audit rules in the `setup_audit` function
- AppArmor profile enforcement in the `setup_apparmor` function
- Sysctl parameters in the `configure_sysctl` function
- Automatic update settings in the `setup_automatic_updates` function
- GRUB parameters in the `PARAMS` array of the `update_grub_config.sh` script

## Contributing
Contributions to improve the scripts are welcome. Please submit pull requests or open issues on the GitHub repository.

## Disclaimer
These scripts are provided as-is, without any warranty. The authors are not responsible for any damage or data loss that may occur from using these scripts. Use at your own risk and always back up your system before making significant changes.

## License
This project is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0).

For more details, see the full license text at: https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode
