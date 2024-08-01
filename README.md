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

This script modifies the GRUB bootloader configuration to enhance system security. It performs the following actions:

### Backup
- Creates a backup of the current GRUB configuration file before making any changes.

### Parameter Addition
Adds the following security-enhancing parameters to the GRUB configuration:

- `page_alloc.shuffle=1`: Randomizes page allocator freelists, improving security against certain types of attacks.
- `slab_nomerge`: Disables slab merging, which can help mitigate certain kernel exploits.
- `init_on_alloc=1`: Initializes heap memory allocations, helping to prevent information leaks.
- `kernel.unprivileged_bpf_disabled=1`: Disables unprivileged eBPF, which can be a source of security vulnerabilities.
- `net.core.bpf_jit_harden=2`: Enables BPF JIT hardening, improving security against JIT spraying attacks.
- `vm.mmap_rnd_bits=32`: Increases the bits used for mmap ASLR (Address Space Layout Randomization) on 64-bit systems, enhancing protection against memory corruption vulnerabilities.
- `vm.mmap_rnd_compat_bits=16`: Increases the bits used for mmap ASLR on 32-bit systems.

### GRUB Update
- Updates the GRUB configuration file with the new parameters.
- Runs `update-grub` to apply changes (or `grub2-mkconfig` on systems that use it).

### Error Handling
- Provides warnings if the GRUB configuration file is not found or if the update command is not available etc.

### Logging
- Logs all actions and any warnings or errors to help with troubleshooting.

### Usage
To use these scripts:

1. Ensure you have sudo privileges.
2. Make the script executable:
   ```
   chmod +x update_grub_config.sh
   ```
3. Run the script with sudo:
   ```
   sudo ./update_grub_config.sh
   ```
4. Reboot your system for the changes to take effect.

### Caution
This script modifies your system's boot configuration. It's recommended to:
- Run this script in a test environment first.
- Understand the implications of each kernel parameter being added.
- Have a backup or recovery method in place before running on a production system.

Note: Some of these parameters may have performance implications or may not be suitable for all systems. Please research each parameter and its effects on your specific use case before applying.

## Contributing

Contributions to improve these scripts are welcome. Please submit a pull request or open an issue to discuss proposed changes.

## Disclaimer
These scripts are provided as-is, without any warranty. The author is not responsible for any damage or data loss caused by the use of these scripts. Use at your own risk.
