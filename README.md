# Ubuntu / Debian Linux Security Hardening Scripts

## Table of Contents
- [Overview](#overview)
- [Scripts](#scripts)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [Main Hardening Script](#main-hardening-script)
- [Important Notes](#important-notes)
- [Recent Updates and Fixes](#recent-updates-and-fixes)
- [Customization](#customization)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)

## Overview
This project consists of a comprehensive script designed to enhance the security of Ubuntu and other Debian-based Linux systems. The script implements a variety of security measures and best practices to harden your system against common threats.

## Scripts
1. `improved_harden_linux.sh`: The main security hardening script

## Features
- System update and upgrade
- Firewall (UFW) configuration
- Fail2Ban installation and setup
- ClamAV antivirus installation and update
- Root login disabling with safety checks
- Removal of unnecessary packages
- Comprehensive audit system configuration
- Disabling of unused filesystems
- Boot settings security enhancements
- IPv6 configuration options
- AppArmor setup
- Network Time Protocol (NTP) setup
- Advanced Intrusion Detection Environment (AIDE) setup
- Enhanced sysctl security parameter configuration
- Automatic security updates setup
- Additional security measures including:
  - Core dump disabling
  - SSH hardening
  - Strong password policy configuration
  - Process accounting enablement

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
4. Follow the prompts during script execution, including options for verbose mode, IPv6 configuration, and system restart.

## Important Notes
- This script makes significant changes to your system. It is strongly recommended to run it on a test system or VM before applying to production environments.
- A backup of important configuration files is created before changes are made. The script creates backups in `/root/security_backup_[timestamp]`.
- Some changes may impact system functionality. Be prepared to troubleshoot if issues arise.
- The script log is saved to `/var/log/security_hardening.log` for review and troubleshooting.
- You can enable verbose mode for more detailed logging during script execution.

## Recent Updates and Fixes
- Improved root login disabling with checks for existing sudo users
- Enhanced error handling and logging throughout the script
- Non-interactive package installation to prevent hanging in automated environments
- Updated firewall configuration with additional rules
- Improved AppArmor setup
- Enhanced sysctl configurations for improved security
- Updated SSH hardening measures

## Customization
You may want to review and customize the script before running it, particularly:
- Firewall rules in the `setup_firewall` function
- Audit rules in the `setup_audit` function
- AppArmor setup in the `setup_apparmor` function
- Sysctl parameters in the `configure_sysctl` function
- SSH configuration in the `additional_security` function

## Contributing
Contributions to improve the script are welcome. Please submit pull requests or open issues on the GitHub repository.

## Disclaimer
This script is provided as-is, without any warranty. The authors are not responsible for any damage or data loss that may occur from using this script. Use at your own risk and always back up your system before making significant changes.

## License
This project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0). For commercial requests, please email joe.faulkner.0@gmail.com.
## Frequently Asked Questions (FAQ)

### General Questions

#### Q1: How do I check if the script ran successfully?
A1: Check the log file at `/var/log/security_hardening.log`. This file contains a detailed record of all actions performed by the script. You can view it using the command:
```
sudo cat /var/log/security_hardening.log
```

#### Q2: How can I undo the changes made by the script?
A2: The script creates a backup of important configuration files in `/root/security_backup_[timestamp]`. To restore these, you can manually copy the backed-up files to their original locations. Be cautious when doing this, as it may revert security improvements.

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

#### Q13: How do I modify the password policy after running the script?
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

Remember, security is an ongoing process. Regularly review your system's security settings, keep your system updated, and stay informed about new security practices and vulnerabilities.

## Citation
If you use these concepts or code in your research or projects, please cite it as follows:
```
[captainzero93]. (2024). #GitHub. https://github.com/captainzero93/security_harden_linux
```
