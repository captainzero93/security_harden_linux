# Ubuntu Linux Security Hardening Scripts

## Overview

These scripts are designed to enhance the security of ( Debian) Ubuntu Linux systems. It implements a variety of security measures and best practices to harden your system against common threats. The script is intended for use on Ubuntu systems but is easly aaapted or will run on Debian-based distributions.

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
- Additional security measures including:
  - Core dump disabling
  - SSH hardening
  - Strong password policy configuration
  - ASLR enablement
  - Sysctl security parameter adjustments

## Prerequisites

- Ubuntu Linux system (tested on Ubuntu 20.04 LTS and later)
- Root or sudo access
- Internet connection for package installation and updates

## Usage

1. Download the script:
   ```
   wget https://raw.githubusercontent.com/captainzero93/ubuntu-security-script/main/security_hardening.sh
   ```

2. Make the script executable:
   ```
   chmod +x security_hardening.sh
   ```

3. Run the script with sudo privileges:
   ```
   sudo ./security_hardening.sh
   ```

4. Follow any prompts during script execution.

## Important Notes

- This script makes significant changes to your system. It is strongly recommended to run it on a test system or VM before applying it to production environments.
- A backup of important configuration files is created in `/root/security_backup_[timestamp]` before changes are made.
- Some changes, particularly to network settings and AppArmor, may impact system functionality. Be prepared to troubleshoot if issues arise.
- The script log is saved to `/var/log/security_hardening.log` for review and troubleshooting.

## Customization

You may want to review and customize the script before running it, particularly:

- Firewall rules in the `setup_firewall` function
- Audit rules in the `setup_audit` function
- AppArmor profile enforcement in the `setup_apparmor` function
- Sysctl parameters in the `additional_security` function

## Contributing

Contributions to improve the script are welcome. Please submit pull requests or open issues on the GitHub repository.

## Disclaimer

This script is provided as-is, without any warranty. The author is not responsible for any damage or data loss that may occur from using this script. Use at your own risk and always back up your system before making significant changes.

## Author

Original script by captainzero93
Improvements and README by Claude

## License

This project is licensed under the MIT License - see the LICENSE file for details.
