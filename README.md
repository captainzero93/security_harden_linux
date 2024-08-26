# Ubuntu / Debian Linux Security Hardening Scripts

## Table of Contents
- [Overview](#overview)
- [Scripts](#scripts)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [Main Hardening Script](#main-hardening-script)
  - [GRUB Configuration Script](#grub-configuration-script)
- [Command-line Options](#command-line-options)
- [Important Notes](#important-notes)
- [Recent Updates and Fixes](#recent-updates-and-fixes)
- [Customization](#customization)
- [Security Standards Compliance](#security-standards-compliance)
- [Backup and Restore](#backup-and-restore)
- [Logging](#logging)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Feedback and Issues](#feedback-and-issues)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq)
- [Citation](#citation)

## Overview
This project consists of two scripts designed to enhance the security of Ubuntu based distros and other Debian-based Linux systems. The main script implements a variety of security measures and best practices to harden your system against common threats, while the GRUB configuration script specifically focuses on securing the boot process. This latest version adheres more closely to DISA STIG and CIS Compliance standards.

The goal is to provide a tool that balances robust security measures with accessibility for average users. While the scripts implement many professional-grade security standards, I've aimed to make the process as user-friendly as possible for desktop machines. Check the [Frequently Asked Questions (FAQ)](#frequently-asked-questions-faq) if you are having issues.

## Scripts
1. `improved_harden_linux.sh` (v2.0): The main security hardening script
2. `update_grub_config.sh` (v2.0): A script to update GRUB configuration with additional security parameters

Both scripts now include options for:
- Dry run mode (--dry-run): See potential changes without applying them
- Version display (--version): Check the current version of the script
- Help (--help): Display usage information

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
- Ubuntu 18.04 or later / Debian-based Linux system
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

## Command-line Options
Both scripts support the following command-line options:
- `-h, --help`: Display help message
- `--version`: Display script version
- `--dry-run`: Perform a dry run without making changes

The main script also supports:
- `-v, --verbose`: Enable verbose output
- `--restore`: Restore system from the most recent backup

## Important Notes
- These scripts make significant changes to your system. It is strongly recommended to run them on a test system or VM before applying to production environments.
- Backups of important configuration files are created before changes are made. The main script creates backups in `/root/security_backup_[timestamp]`, and the GRUB script backs up to `/etc/default/grub.bak.[timestamp]`.
- Some changes may impact system functionality. Be prepared to troubleshoot if issues arise.
- Always use the --dry-run option first to review potential changes before applying them.

## Recent Updates and Fixes
- Added dry run functionality to both scripts
- Improved command-line options for both scripts
- Enhanced logging for both scripts
- Improved root login disabling with checks for existing sudo users
- Enhanced error handling throughout both scripts
- Non-interactive package installation to prevent hanging in automated environments
- Updated firewall configuration with additional rules
- Improved AppArmor setup
- Enhanced sysctl configurations for improved security
- Updated SSH hardening measures
- Improved accessibility for average users while maintaining strong security standards

## Customisation
You may want to review and customize the scripts before running them, particularly:
- Firewall rules in the `setup_firewall` function of the main script
- Audit rules in the `setup_audit` function of the main script
- AppArmor setup in the `setup_apparmor` function of the main script
- Sysctl parameters in the `configure_sysctl` function of the main script
- SSH configuration in the `additional_security` function of the main script
- GRUB parameters in the `PARAMS` array of the `update_grub_config.sh` script

## Security Standards Compliance
These scripts aim to align with DISA STIG and CIS Compliance standards. While not exhaustive, they implement many best practices from these standards. Users are encouraged to review these standards and further customize the scripts to meet specific compliance needs.

## Backup and Restore
- The main script creates backups in `/root/security_backup_[timestamp]`
- The GRUB script creates a backup at `/etc/default/grub.bak.[timestamp]`
- To restore from a backup using the main script, use the --restore option:
  ```
  sudo ./improved_harden_linux.sh --restore
  ```
- For manual restoration, copy the backed-up files to their original locations

## Logging
- The main script logs to `/var/log/security_hardening.log`
- The GRUB script logs to `/var/log/grub_config_update.log`
- Use these logs for reviewing changes and troubleshooting

## Testing
It is crucial to test these scripts in a non-production environment before applying them to critical systems. Consider using a virtual machine or a test system that mirrors your production environment.

## Troubleshooting
If you encounter issues after running the scripts:
1. Check the log files for error messages
2. Use the --dry-run option to review potential changes
3. Consider restoring from backups if critical functionality is impaired
4. Review the [FAQ](#frequently-asked-questions-faq) section for common issues and solutions

## Contributing
Contributions to improve the scripts are welcome. Please submit pull requests or open issues on the GitHub repository. We especially encourage contributions that:
- Enhance user-friendliness without compromising security
- Improve documentation and user guidance
- Explicitly map implemented measures to standards like CIS benchmarks or DISA STIGs to enhance credibility

## Feedback and Issues
I welcome feedback and bug reports. Please open an issue [GitHub Issues page](https://github.com/captainzero93/security_harden_linux/issues) for any problems, questions, or suggestions.

## Disclaimer
These scripts are provided as-is, without any warranty. The authors are not responsible for any damage or data loss that may occur from using these scripts. Use at your own risk and always back up your system before making significant changes.

## License
This project is available under a dual license:

1. **Non-Commercial Use**: For non-commercial purposes, this project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0). This allows for sharing and adaptation of the code for non-commercial purposes, with appropriate attribution.

2. **Commercial Use**: Any commercial use, including but not limited to selling the code, using it in commercial products or services, or any revenue-generating activities, requires a separate commercial license. You must contact the project owner to discuss terms before deployment.

Please see the [LICENSE](LICENSE) file for full details on both licenses.

## Frequently Asked Questions (FAQ)

#### Q1: How do I check if the scripts ran successfully?
A1: For the main script, check the log file at `/var/log/security_hardening.log`. For the GRUB script, check the log at `/var/log/grub_config_update.log`. These logs will contain details of all actions taken by the scripts.

#### Q2: How can I undo the changes made by the scripts?
A2: The main script creates backups in `/root/security_backup_[timestamp]`, and the GRUB script creates a backup at `/etc/default/grub.bak.[timestamp]`. You can manually restore these files, but be cautious as it may revert security improvements. For the main script, you can also use the --restore option:
```
sudo ./improved_harden_linux.sh --restore
```

#### Q3: Is it safe to run these scripts on a production system?
A3: While the scripts are designed to be as safe as possible, it's always recommended to test them on a non-production system first. They make significant changes to your system configuration. Use the --dry-run option to preview changes before applying them.

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

#### Q12: How do I check the current password policy?
A12: You can view the current password policy settings in `/etc/login.defs`. For specific user info:
```
sudo chage -l username
```

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
A17: The new parameters enhance kernel security. For example:
- "page_alloc.shuffle=1" randomizes memory allocation
- "init_on_alloc=1" initializes memory on allocation
- "slab_nomerge" prevents the merging of slabs of similar sizes
- "randomize_kstack_offset=1" randomizes the kernel stack offset
- "vsyscall=none" disables the deprecated vsyscall table

### Troubleshooting

#### Q18: What should I do if a service stops working after running the scripts?
A18: Check the service status, review logs, and if it's AppArmor-related, you might need to adjust the AppArmor profile. You can also try to restore the specific configuration file from the backup created by the script.


#### Q19: How can I revert a specific change made by the scripts?
A19: Use the backup files created by the scripts to restore specific configurations. Always understand the implications before reverting changes. For example, to restore the original GRUB configuration:
```
sudo cp /etc/default/grub.bak.[timestamp] /etc/default/grub
sudo update-grub
```

#### Q20: The system seems slower after running the scripts. What could be the cause?
A20: This could be due to increased logging, stricter firewall rules, or security measures. Review and adjust settings as needed. Common areas to check include:
- Audit rules (you might reduce the number of events being audited)
- AppArmor profiles (ensure they're not overly restrictive for your use case)
- Firewall rules (ensure they're not blocking necessary traffic)

## Q21: Will this break common programs from running?
A21: Generally, no, here's why;
-Firewall (UFW) configuration: Properly configured, it won’t block necessary traffic for games or browsing.
-Fail2Ban: It only acts after multiple failed login attempts, so it won’t affect regular use.
-ClamAV: Runs in the background and scans files, which shouldn’t impact performance significantly.
-Root login disabling: Normal users typically don’t need root access for daily tasks.
-Removal of unnecessary packages: Frees up resources without affecting essential applications.
-Audit system: Logs activities without interfering with normal operations.
-Disabling unused filesystems: Only affects filesystems that aren’t in use.
-Boot settings security: Enhances security without affecting daily use once the system is booted.
-IPv6 configuration: Properly configured, it won’t impact normal internet use.
-AppArmor: Restricts applications but shouldn’t affect well-behaved software.
-NTP setup: Ensures accurate timekeeping without user impact.
-AIDE: Monitors filesystem changes without affecting normal use.
-Sysctl parameters: Enhances security without noticeable impact on performance.
-Automatic security updates: Keeps the system secure without user intervention.
-GRUB hardening: Secures the boot process without affecting normal use.
-Core dump disabling: Prevents exposure of sensitive information without affecting normal use.
-SSH hardening: Enhances security for remote access without affecting local use.
-Strong password policy: Ensures secure passwords without affecting daily tasks.
-Process accounting: Logs user activities without interfering with normal operations.

Remember, security is an ongoing process. Regularly review your system's security settings, keep your system updated, and stay informed about new security practices and vulnerabilities.

## Citation
If you use these concepts or code in your research or projects, please cite it as follows:
```
[Joe Faulkner] (captainzero93). (2024). https://github.com/captainzero93/security_harden_linux
```
