# Ubuntu / Debian Linux Security Hardening Scripts

## Table of Contents
- [Overview](#overview)
- [Scripts](#scripts)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [Main Hardening Script](#main-hardening-script)
  - [GRUB Configuration Script](#grub-configuration-script)
- [Important Notes](#important-notes)
- [Recent Updates and Fixes](#recent-updates-and-fixes)
- [Customization](#customization)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)
  - [General Questions](#general-questions)
  - [Firewall and Network Security](#firewall-and-network-security)
  - [System Auditing and Logging](#system-auditing-and-logging)
  - [AppArmor](#apparmor)
  - [Password and Account Security](#password-and-account-security)
  - [System Updates and Package Management](#system-updates-and-package-management)
  - [Troubleshooting](#troubleshooting)

## Overview
This project consists of two scripts designed to enhance the security of Ubuntu and other Debian-based Linux systems. The main script implements a variety of security measures and best practices to harden your system against common threats, while the GRUB configuration script specifically focuses on securing the boot process.

## Scripts
1. `improved_harden_linux.sh`: The main security hardening script
2. `update_grub_config.sh`: A script to update GRUB configuration with additional security parameters

## Features
- System update and upgrade (optional)
- Firewall (UFW) configuration
- Fail2Ban installation and setup
- ClamAV antivirus installation and update
- Root login disabling
- Removal of unnecessary packages
- Comprehensive audit system configuration
- Disabling of unused filesystems
- Boot settings security enhancements
- IPv6 configuration options
- AppArmor setup with customizable enforcement levels
- Network Time Protocol (NTP) setup using systemd-timesyncd
- Advanced Intrusion Detection Environment (AIDE) setup
- Enhanced sysctl security parameter configuration
- Automatic security updates setup
- GRUB configuration hardening
- Additional security measures including:
  - Core dump disabling
  - SSH hardening with key-based authentication
  - Configurable password expiration policy
  - Strong password policy configuration
  - ASLR enablement
  - Process accounting enablement
  - Increased system file descriptor limits
  - Protection against SACK exploitation

## Prerequisites
- Ubuntu / Debian-based Linux system
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
   For non-interactive mode (use with caution):
   ```
   sudo ./improved_harden_linux.sh --non-interactive
   ```
4. Follow the prompts during script execution, including options for verbose mode, system upgrade, IPv6 configuration, AppArmor enforcement, password expiration policy, and system restart.

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
- A backup of important configuration files is created before changes are made. The main script creates backups in `/root/security_backup_[timestamp]`, and the GRUB script backs up to `/etc/default/grub.bak.[timestamp]`.
- Some changes, particularly to network settings, AppArmor, and GRUB, may impact system functionality. Be prepared to troubleshoot if issues arise.
- The main script log is saved to `/var/log/security_hardening.log` for review and troubleshooting.
- You can enable verbose mode for more detailed logging during the main script execution.
- The script offers both interactive and non-interactive modes. Use non-interactive mode with caution.

## Recent Updates and Fixes
- Added optional system upgrade prompt
- Implemented non-interactive mode for automated deployments
- Enhanced logging functionality with a dedicated log file
- Improved package installation process with options for interactive and non-interactive modes
- Added more comprehensive audit rules
- Updated the list of disabled filesystems
- Implemented user-configurable password expiration policy
- Enhanced sysctl configurations for improved security
- Fixed redundant SSH protocol configuration
- Updated NTP setup to use systemd-timesyncd instead of the traditional NTP daemon
- Added protection against SACK exploitation
- Improved GRUB configuration with additional security parameters
- Enhanced AppArmor setup with options for default or comprehensive profile enforcement

## Customization
You may want to review and customize the scripts before running them, particularly:
- Firewall rules in the `setup_firewall` function
- Audit rules in the `setup_audit` function
- AppArmor profile enforcement in the `setup_apparmor` function
- Sysctl parameters in the `configure_sysctl` function
- Automatic update settings in the `setup_automatic_updates` function
- GRUB parameters in the `PARAMS` array of the `update_grub_config.sh` script
- Password expiration policy in the `configure_password_expiration` function

## Contributing
Contributions to improve the scripts are welcome. Please submit pull requests or open issues on the GitHub repository.

## Disclaimer
These scripts are provided as-is, without any warranty. The authors are not responsible for any damage or data loss that may occur from using these scripts. Use at your own risk and always back up your system before making significant changes.

## License
This project is licensed under the Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0).

For more details, see the full license text at: https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode

## Frequently Asked Questions (FAQ)

### General Questions

#### Q1: How do I check if the script ran successfully?
A1: Check the log file at `/var/log/security_hardening.log`. This file contains a detailed record of all actions performed by the script. You can view it using the command:
```
sudo cat /var/log/security_hardening.log
```

#### Q2: How can I undo the changes made by the script?
A2: The script creates a backup of important configuration files in `/root/security_backup_[timestamp]`. To restore these, you can use the `restore_backup` function in the script. However, for safety reasons, this function is not directly callable. You may need to manually copy the backed-up files to their original locations.

#### Q3: Is it safe to run this script on a production system?
A3: While the script is designed to be as safe as possible, it's always recommended to test it on a non-production system first. The script makes significant changes to your system configuration, which could potentially impact running services.

### Firewall and Network Security

#### Q4: How do I check if the firewall is properly configured?
A4: You can check the UFW status using the command:
```
sudo ufw status verbose
```
This will show you all active firewall rules.

#### Q5: How can I modify the firewall rules after running the script?
A5: You can add or remove rules using the `ufw` command. For example, to allow incoming traffic on port 8080:
```
sudo ufw allow 8080/tcp
```
Remember to reload the firewall after making changes:
```
sudo ufw reload
```

#### Q6: How do I check if IPv6 is disabled?
A6: You can check the IPv6 status using:
```
cat /proc/sys/net/ipv6/conf/all/disable_ipv6
```
If it returns 1, IPv6 is disabled.

### System Auditing and Logging

#### Q7: How do I check the audit logs?
A7: The audit logs are typically located in `/var/log/audit/audit.log`. You can view them using:
```
sudo ausearch -ts today -i
```
This command shows today's audit logs in a human-readable format.

#### Q8: How do I know if the audit rules are active?
A8: You can list all active audit rules using:
```
sudo auditctl -l
```

#### Q9: How often does AIDE check for system file changes?
A9: By default, AIDE doesn't run automatic checks. You need to run it manually or set up a cron job. To manually initiate an AIDE check, use:
```
sudo aide --check
```

### AppArmor

#### Q10: How do I check which AppArmor profiles are enforced?
A10: You can see the status of AppArmor profiles using:
```
sudo aa-status
```

#### Q11: How can I disable an AppArmor profile if it's causing issues?
A11: You can set a profile to complain mode instead of enforce mode using:
```
sudo aa-complain /path/to/binary
```
Replace `/path/to/binary` with the actual path of the binary whose profile you want to modify.

### Password and Account Security

#### Q12: How do I check the current password policy?
A12: You can view the current password policy settings in `/etc/login.defs`. To see password aging information for a specific user, use:
```
sudo chage -l username
```

#### Q13: How do I modify the password expiration policy after running the script?
A13: You can modify `/etc/login.defs` to change global settings, or use the `chage` command for individual users. For example:
```
sudo chage -M 60 -W 7 username
```
This sets the maximum password age to 60 days and the warning period to 7 days for the specified user.

### System Updates and Package Management

#### Q14: How do I check if automatic updates are working?
A14: You can check the status of the unattended-upgrades service using:
```
systemctl status unattended-upgrades
```
You can also check the log at `/var/log/unattended-upgrades/unattended-upgrades.log`.

#### Q15: How can I modify which updates are installed automatically?
A15: Edit the configuration file at `/etc/apt/apt.conf.d/50unattended-upgrades`. Be cautious when modifying this file, as incorrect configurations can lead to system instability.

### Troubleshooting

#### Q16: What should I do if a service stops working after running the script?
A16: First, check the service status using `systemctl status service_name`. Then, review the relevant logs in `/var/log/`. If the issue is related to AppArmor, you might need to adjust the AppArmor profile for that service.

#### Q17: How can I revert a specific change made by the script?
A17: Check the backup directory created by the script (`/root/security_backup_[timestamp]`), find the original configuration file, and replace the current file with the backup. Always make sure you understand the implications of reverting changes before doing so.

#### Q18: The system seems slower after running the script. What could be the cause?
A18: This could be due to increased logging, stricter firewall rules, or AppArmor profiles. Review the changes made by the script and consider adjusting settings that might be impacting performance.

## Remember, security is an ongoing process. Regularly review your system's security settings, keep your system updated, and stay informed about new security practices and vulnerabilities.


## Citation
If you use my concepts or code, as software or protection concepts in your research or projects, please cite it as follows:
```
[captainzero93]. (2024). #GitHub. https://github.com/captainzero93/security_harden_linux
```

## License
This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0). See the [LICENSE](LICENSE) file for details.

 - For comercial requests email joe.faulkner.0@gmail.com
