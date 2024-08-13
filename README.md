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
(Include relevant FAQs from the original README, focusing on those that apply to the updated script)

## Citation
If you use these concepts or code in your research or projects, please cite it as follows:
```
[captainzero93]. (2024). #GitHub. https://github.com/captainzero93/security_harden_linux
```
