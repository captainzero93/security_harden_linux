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
This project consists of two scripts designed to enhance the security of Ubuntu and other Debian-based Linux systems. The main script implements a variety of security measures and best practices to harden your system against common threats, while the GRUB configuration script specifically focuses on securing the boot process. This latest version adheres more closely to DISA STIG and CIS Compliance standards.

The goal is to provide a tool that balances robust security measures with accessibility for average users. While the scripts implement many professional-grade security standards, we've aimed to make the process as user-friendly as possible for desktop machines.

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

## Customization
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
I welcome feedback and bug reports. Please open an issue on our [GitHub Issues page](https://github.com/captainzero93/security_harden_linux/issues) for any problems, questions, or suggestions.

## Disclaimer
These scripts are provided as-is, without any warranty. The authors are not responsible for any damage or data loss that may occur from using these scripts. Use at your own risk and always back up your system before making significant changes.

## License
This project is available under a dual license:

1. **Non-Commercial Use**: For non-commercial purposes, this project is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0). This allows for sharing and adaptation of the code for non-commercial purposes, with appropriate attribution.

2. **Commercial Use**: Any commercial use, including but not limited to selling the code, using it in commercial products or services, or any revenue-generating activities, requires a separate commercial license. You must contact the project owner to discuss terms before deployment.

Please see the [LICENSE](LICENSE) file for full details on both licenses.

## Frequently Asked Questions (FAQ)

[The FAQ section remains the same as in the previous version]

## Citation
If you use these concepts or code in your research or projects, please cite it as follows:
```
[Joe Faulkner] (captainzero93). (2024). https://github.com/captainzero93/security_harden_linux
```
