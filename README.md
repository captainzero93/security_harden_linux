# Linux Security Hardening Scripts ( Debian based, Ubuntu etc )

This repository contains two bash scripts designed to enhance security;

1. `improved_harden_linux.sh`: A ( somewhat ) comprehensive script for hardening Linux systems
2. `update_grub_config.sh`: A script for updating GRUB configuration with security-enhancing parameters

## 1. Improved Linux Hardening Script (`improved_harden_linux.sh`)

Features:


Creates a backup of important configuration files before making changes

-System Update

Updates and upgrades the system packages

-Firewall Setup

Installs and configures Uncomplicated Firewall (UFW)
Sets default secure policies

-Fail2Ban Installation

Installs Fail2Ban to protect against brute-force attacks

-Antivirus Setup

Installs ClamAV antivirus and updates its database

-User Account Security

Disables root login and password authentication for better security

-Package Management

Removes unnecessary and potentially vulnerable packages

-Audit Configuration

Installs and configures the audit system. 

Sets up rules to monitor changes to user and group files

-Filesystem Security

Disables unused and potentially risky filesystems

-Boot Security

Secures GRUB configuration file permissions

-Additional Security Measures

Disables core dumps, 
Sets proper permissions on sensitive files, 
Enables process accounting, 
Restricts SSH access.

## 2. GRUB Configuration Update Script (`update_grub_config.sh`)

This script modifies the GRUB bootloader configuration to enhance system security. It performs the following actions:

### Backup
- Creates a backup of the current GRUB configuration

### Parameter Addition
Adds the following security-enhancing parameters to the GRUB configuration:
- `page_alloc.shuffle=1`: Randomizes page allocator freelists
- `slab_nomerge`: Disables slab merging
- `init_on_alloc=1`: Initializes heap memory allocations
- `kernel.unprivileged_bpf_disabled=1`: Restricts eBPF access
- `net.core.bpf_jit_harden=2`: Enables eBPF JIT hardening
- `vm.mmap_rnd_bits=32`: Increases bits used for mmap ASLR
- `vm.mmap_rnd_compat_bits=16`: Increases bits used for 32-bit mmap ASLR

### GRUB Update
- Updates the GRUB configuration file
- Runs `update-grub` to apply changes

## Usage

To use these scripts:

1. Clone this repository:
   ```
   git clone https://github.com/captainzero93/security_harden_linux.git
   ```

2. Navigate to the script directory:
   ```
   cd linux-hardening-scripts
   ```

3. Make the scripts executable:
   ```
   chmod +x improved_harden_linux.sh update_grub_config.sh
   ```

4. Run the main hardening script (requires sudo):
   ```
   sudo ./improved_harden_linux.sh
   ```

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
These scripts are provided as-is, without any warranty. The author is not responsible for any damage or data loss caused by the use of this script. Use at your own risk.
