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
- [Citation](#citation)

## Overview
This project consists of two scripts designed to enhance the security of Ubuntu and other Debian-based Linux systems. The main script implements a variety of security measures and best practices to harden your system against common threats, while the GRUB configuration script specifically focuses on securing the boot process. NOTE: these scripts try to be accessible to average users and therefore are not as strict as some auditing / standards you may expect to see, please open a push request if you are able to help. 

## Scripts
1. `improved_harden_linux.sh`: The main security hardening script
2. `update_grub_config.sh`: A script to update GRUB configuration with additional security parameters

## Features
- System update and upgrade (optional)
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
- GRUB configuration hardening for secure boot process
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
4. The script will automatically update the GRUB configuration with additional security parameters.

## Important Notes
- These scripts make significant changes to your system. It is strongly recommended to run them on a test system or VM before applying to production environments.
- Backups of important configuration files are created before changes are made. The main script creates backups in `/root/security_backup_[timestamp]`, and the GRUB script backs up to `/etc/default/grub.bak`.
- Some changes may impact system functionality. Be prepared to troubleshoot if issues arise.
- The main script log is saved to `/var/log/security_hardening.log` for review and troubleshooting.
- You can enable verbose mode for more detailed logging during the main script execution.

## Recent Updates and Fixes

* Improved root login disabling with checks for existing sudo users
* Enhanced error handling and logging throughout the main script
* Non-interactive package installation to prevent hanging in automated environments
* Updated firewall configuration with additional rules
* Improved AppArmor setup
* Enhanced sysctl configurations for improved security
* Updated SSH hardening measures
* Added GRUB configuration script for additional boot-time security

Recent updates bring our scripts closer to alignment with several industry-standard security benchmarks and guidelines, including:

* CIS (Center for Internet Security) Benchmarks: Our enhanced configurations for SSH, firewall rules, and system auditing are moving towards CIS recommendations for Ubuntu Linux.
* NIST (National Institute of Standards and Technology) SP 800-53: Improvements in access control (root login disabling) and system hardening align with several NIST controls.
* DISA STIG (Defense Information Systems Agency Security Technical Implementation Guides): Our GRUB configuration hardening and AppArmor improvements are steps towards meeting DISA STIG requirements.
* OWASP (Open Web Application Security Project) Security Principles: While primarily for web applications, our system hardening measures align with OWASP's defense-in-depth approach.

Please note that while we're working towards these standards, full compliance is not guaranteed. Users are encouraged to review their specific security requirements and adjust the scripts as needed.

## Customization
You may want to review and customize the scripts before running them, particularly:
- Firewall rules in the `setup_firewall` function of the main script
- Audit rules in the `setup_audit` function of the main script
- AppArmor setup in the `setup_apparmor` function of the main script
- Sysctl parameters in the `configure_sysctl` function of the main script
- SSH configuration in the `additional_security` function of the main script
- GRUB parameters in the `PARAMS` array of the `update_grub_config.sh` script

## Contributing
Contributions to improve the scripts are welcome. Please submit requests or open issues on the GitHub repository. Explicitly mapping the implemented measures to standards like CIS benchmarks or DISA STIGs would enhance credibility for instance.

## Disclaimer
These scripts are provided as-is, without any warranty. The authors are not responsible for any damage or data loss that may occur from using these scripts. Use at your own risk and always back up your system before making significant changes.

## License

This project is available under a dual license:

1. **Non-Commercial Use**: For non-commercial purposes, this project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0). This allows for sharing and adaptation of the scripts for non-commercial purposes, with appropriate attribution.

2. **Commercial Use**: Any commercial use, including but not limited to selling the scripts, incorporating them into commercial products or services, or any revenue-generating activities, requires a separate commercial license. You must contact the project owner to discuss terms and potential payment.

Please see the [LICENSE](LICENSE) file for full details on both licenses.

For commercial licensing inquiries, please contact: joe.faulkner.0@gmail.com

By using this project, you agree to abide by the terms of the appropriate license based on your intended use.

## Frequently Asked Questions (FAQ)

### General Questions

#### Q1: How do I check if the scripts ran successfully?
A1: For the main script, check the log file at `/var/log/security_hardening.log`. For the GRUB script, check if the file `/etc/default/grub` has been updated with new parameters.

#### Q2: How can I undo the changes made by the scripts?
A2: The main script creates backups in `/root/security_backup_[timestamp]`, and the GRUB script creates a backup at `/etc/default/grub.bak`. You can manually restore these files, but be cautious as it may revert security improvements.

#### Q3: Is it safe to run these scripts on a production system?
A3: While the scripts are designed to be as safe as possible, it's always recommended to test them on a non-production system first. They make significant changes to your system configuration.

### Firewall and Network Security

#### Q4: How do I check if the firewall is properly configured?
A4: You can check the UFW status using the command:
```
sudo ufw status verbose
```

#### Q5: How can I modify the firewall rules after running the script?
A5: You can add or remove rules using the `ufw` command. For example:
```
sudo ufw allow 8080/tcp
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

#### Q8: How do I know if the audit rules are active?
A8: You can list all active audit rules using:
```
sudo auditctl -l
```

#### Q9: How often does AIDE check for system file changes?
A9: By default, AIDE doesn't run automatic checks. You need to run it manually or set up a cron job:
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
A11: You can set a profile to complain mode instead of enforce mode:
```
sudo aa-complain /path/to/binary
```

### Password and Account Security

#### Q13: How do I modify the password policy after running the script?
A13: You can modify `/etc/login.defs` for global settings, or use the `chage` command for individual users. For example:

```
sudo chage -M 60 -W 7 username
```

This command modifies the password policy for a specific user:
- It sets the password to expire after 60 days (-M 60)
- It sets a 7-day warning period before the password expires (-W 7)
- Replace 'username' with the actual username you want to modify

You can adjust these values based on your security requirements. For a stricter policy, you might use shorter periods, while for a more lenient policy, you could use longer periods.

### System Updates and Package Management

#### Q14: How do I check if automatic updates are working?
A14: Check the status of the unattended-upgrades service:
```
systemctl status unattended-upgrades
```

#### Q15: How can I modify which updates are installed automatically?
A15: Edit the configuration file at `/etc/apt/apt.conf.d/50unattended-upgrades`.

### GRUB Configuration

#### Q16: How do I verify that the GRUB configuration has been updated securely?
A16: After running the update_grub_config.sh script, check the GRUB configuration file:
```
cat /etc/default/grub
```
Look for the added security parameters in the GRUB_CMDLINE_LINUX_DEFAULT line.

#### Q17: What do the new GRUB parameters do?
A17: The new parameters enhance kernel security. For example, "page_alloc.shuffle=1" randomizes memory allocation, and "init_on_alloc=1" initializes memory on allocation.

### Troubleshooting

#### Q18: What should I do if a service stops working after running the scripts?
A18: Check the service status, review logs, and if it's AppArmor-related, you might need to adjust the AppArmor profile.

#### Q19: How can I revert a specific change made by the scripts?
A19: Use the backup files created by the scripts to restore specific configurations. Always understand the implications before reverting changes.

#### Q20: The system seems slower after running the scripts. What could be the cause?
A20: This could be due to increased logging, stricter firewall rules, or security measures. Review and adjust settings as needed.

Remember, security is an ongoing process. Regularly review your system's security settings, keep your system updated, and stay informed about new security practices and vulnerabilities.

## Citation

If you use these scripts or concepts in your non-commercial research or projects, please cite it as follows:
```
[captainzero93]. (2024). Ubuntu / Debian Linux Security Hardening Scripts. GitHub. https://github.com/captainzero93/security_harden_linux
```

For commercial use, please contact joe.faulkner.0@gmail.com to discuss licensing terms.
