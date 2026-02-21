# FORTRESS.SH :: Debian Linux Defence Configuration

**One-command security hardening that implements enterprise-grade protections (DISA STIG + CIS) while letting you decide the level of protection vs usability trade-off. Casual desktop use through to strict server enforcement.**

**Version 5.1** - Critical Fixes: Docker compatibility, browser support, full configuration file. Tested WORKING on Debian 13, Ubuntu 24.04+.

[![License](https://img.shields.io/badge/License-CC%20BY--NC%204.0-blue.svg)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%2B-orange.svg)](https://ubuntu.com/)
[![Kubuntu](https://img.shields.io/badge/Kubuntu-24.04%2B-blue.svg)](https://kubuntu.org/)
[![Debian](https://img.shields.io/badge/Debian-11%2B%20%7C%2013-red.svg)](https://www.debian.org/)
[![Linux Mint](https://img.shields.io/badge/Linux%20Mint-21%2B-87CF3E.svg)](https://linuxmint.com/)
[![Pop!\_OS](https://img.shields.io/badge/Pop!__OS-22.04%2B-48B9C7.svg)](https://pop.system76.com/)
[![Version](https://img.shields.io/badge/Version-5.1-green.svg)]()

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/captainzero)

---

## CRITICAL WARNING FOR REMOTE SERVER USERS

**Set up SSH keys FIRST or you WILL be locked out.**

v5.1 includes multiple safety checks to prevent SSH lockouts, but you still need working key-based authentication before running the script. See [Critical Warning for Remote Servers](#critical-warning-for-remote-servers) for full setup instructions.

### Notice

This script handles network/system hardening, AppArmor (not SELinux), audit logging and other security features. It does NOT do user group management, SELinux, or touch VFIO/IOMMU configs. Handle those separately before or after running the script.

---

## Quick Start

### Desktop Users:

```bash
# Download and make executable
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/fortress_improved.sh
chmod +x fortress_improved.sh

# Learn what it does (recommended first time)
sudo ./fortress_improved.sh --explain --dry-run

# Apply with defaults
sudo ./fortress_improved.sh

# Answer the interactive prompts, then reboot when done
```

### Server Users:

```bash
# FIRST: Set up SSH keys (CRITICAL - see full warning below)
ssh-keygen -t ed25519
ssh-copy-id user@your-server

# Then run hardening
sudo ./fortress_improved.sh -l high -n
```

**Something broke?** Restore from backup directory: `/root/fortress_backups_*/`

---

## Table of Contents

* [Your Fresh Linux Install Isn't Secure](#your-fresh-linux-install-isnt-secure)
* [Who This Is For](#who-this-is-for)
* [What This Actually Does](#what-this-actually-does)
* [Desktop Users: This Won't Ruin Your Workflow](#desktop-users-this-wont-ruin-your-workflow)
* [Critical Warning for Remote Servers](#critical-warning-for-remote-servers)
* [Why This Matters - Real-World Attacks](#why-this-matters---real-world-attacks)
* [What's New](#whats-new)
* [Installation](#installation)
* [Usage Guide](#usage-guide)
* [Security Levels Explained](#security-levels-explained)
* [Available Modules](#available-modules)
* [What Gets Hardened](#what-gets-hardened)
* [Emergency Recovery](#emergency-recovery)
* [Common Questions](#common-questions)
* [Troubleshooting](#troubleshooting)
* [Advanced Usage](#advanced-usage)
* [Requirements](#requirements)
* [Security Compliance](#security-compliance)
* [License & Support](#license--support)
* [Version History](#version-history)
* [Additional Resources](#additional-resources)
* [Important Legal Disclaimer](#important-legal-disclaimer)
* [Contact & Support](#contact--support)
* [Quick Reference Card](#quick-reference-card)

---

## Your Fresh Linux Install Isn't Secure

Ubuntu, Fedora, Mint, Kubuntu - they all ship with security settings that prioritise "making things work" over "keeping you safe." This is intentional. Distributions assume you'll configure security later.

**But most people never do.**

Right now, your system likely has: no firewall enabled so any service you run is exposed to the internet, SSH ports wide open to brute force bots trying thousands of passwords per hour, no tracking of failed login attempts giving attackers unlimited tries, no automatic security updates meaning you could be vulnerable for weeks, minimal kernel protections making exploits easier, and no intrusion detection so if someone breaks in you won't know.

**This isn't a Linux flaw** - it's a conscious trade-off. Distributions prioritise compatibility and ease-of-use for new users. Great for getting started, terrible for security.

---

## Who This Is For

**You, if you:** game on Linux and want security without FPS loss, create art/music/videos without security getting in the way, work from home and need basic protection, just want a secure personal computer that works normally, are tired of complicated security guides written for sysadmins, run a home server or self-host services, develop software and want security without breaking your tools, are learning Linux and want to start with good habits, or want to understand security rather than just blindly apply it.

**What makes this different:** This script applies industry-standard security WITHOUT breaking your desktop experience. No more choosing between security and usability. v5.1 also intelligently detects Docker and browsers to avoid breaking them.

---

## What This Actually Does

Instead of spending 40+ hours reading security guides and manually configuring dozens of tools, this script handles it in one go.

### Security You Get:

* Enables your firewall (UFW) - but keeps Steam, Discord, KDE Connect working
* Hardens SSH - prevents brute force attacks if you use remote access
* Blocks repeated failed logins - optional fail2ban (only if beneficial for your setup)
* Secures the kernel - protection against memory exploits and attacks
* Verifies package integrity - weekly dpkg verification (detects tampering/corruption)
* Enforces strong passwords - because "password123" is still too common
* Enables automatic security updates - patches critical bugs while you sleep
* Configures audit logging - forensics and evidence if something happens
* Verifies boot security - checks Secure Boot status and guides configuration
* Removes unnecessary packages - smaller attack surface

### Things That Should Keep Working:

* Steam and all your games (zero/low FPS impact)
* Discord, Zoom, Slack, Teams
* Wacom tablets, drawing tools, pen pressure and tilt
* Audio production (Jack, PipeWire, ALSA) - real-time scheduling preserved
* Video editing (DaVinci Resolve, Kdenlive, OBS) - hardware encoding intact
* Game development (Godot, Unity, Unreal) - build processes unaffected
* Bluetooth audio and devices
* Network printers and file sharing
* KDE Connect phone integration
* USB devices (with optional logging)
* RGB peripherals and gaming gear
* Virtual machines (VirtualBox, QEMU)
* Docker and development tools (v5.1 conditional IP forwarding)
* Firefox, Chrome, Brave browsers (v5.1 smart /dev/shm handling)

---

## Desktop Users: This Won't Ruin Your Workflow

The script detects desktop environments automatically and knows you're not a server. It asks before blocking features like mDNS (network discovery), KDE Connect, and Samba. Gaming functionality is preserved with no/little impact on Steam, Lutris, or Proton. There are no background processes eating CPU/GPU. Audio production, creative tools, and Bluetooth all work as normal. It uses "moderate" security by default (balanced, not paranoid), creates automatic backups before every change, and explains each action in educational mode with the `--explain` flag.

**At "moderate" level** (the default), you won't even notice the changes. Your computer will feel exactly the same, just with far fewer security holes.

---

## Critical Warning for Remote Servers

### YOU WILL LOCK YOURSELF OUT IF YOU SKIP THIS SECTION

This script **disables password authentication for SSH** and switches to key-only authentication. This is the single most effective security improvement you can make for SSH. But if you don't have SSH keys set up BEFORE running this script, you will be permanently locked out of your server.

### Before Running This Script on ANY Remote Server:

```bash
# On your LOCAL machine (laptop/desktop):
ssh-keygen -t ed25519 -C "your_email@example.com"

# Copy the key to your server:
ssh-copy-id username@your-server-ip

# Test that it works:
ssh -i ~/.ssh/id_ed25519 username@your-server-ip

# If you can log in without typing a password, you're good to go
# ONLY THEN run the hardening script on the server
```

**Safety features built into the script:** It detects if SSH server is running, requires explicit "yes" confirmation that you have working SSH keys, provides setup instructions if you don't have keys, gives multiple warnings before disabling password auth, validates configuration before applying changes, and auto-rolls back on SSH configuration errors.

**If you still lock yourself out:** You'll need physical access to the server (or console access from your hosting provider) to restore `/etc/ssh/sshd_config` from the backup.

**For desktop users:** If you don't use SSH to remotely access your computer, this doesn't affect you. The script will detect this and handle it appropriately.

---

## Why This Matters - Real-World Attacks

### The Brute Force Bot

Without this script, your SSH port (22) is open to the internet. Automated bots try 10,000+ password combinations per hour. Eventually, a weak password gets cracked.

**What this script does:** Disables password authentication completely (key-only access), optionally changes SSH port, rate limits connection attempts, and offers optional fail2ban for additional services.

**Why fail2ban is optional:** With password auth disabled and key-only SSH, brute force attacks become impossible. The script intelligently detects this and recommends skipping fail2ban unless you have web/mail servers that benefit from it.

### The Kernel Exploit

A vulnerability in the Linux kernel allows attackers to escalate privileges, going from limited user to root access.

**What this script does:** Enables kernel hardening (sysctl parameters), restricts access to kernel symbols, enables ASLR (Address Space Layout Randomization), and configures memory protections.

### The Supply Chain Attack

A compromised package update installs malware. You don't notice until your data is encrypted or stolen.

**What this script does:** Weekly package integrity verification using dpkg, audit logging for file changes, system file monitoring for tampering, and AppArmor to limit what processes can do.

**Note:** v5.0 removed AIDE because it can't detect kernel-level rootkits on live systems. dpkg's built-in verification is more appropriate for package integrity checking.

### The Physical Access Attack

Someone boots your computer from USB, mounts your drive, and steals everything.

**What this script does:** Verifies Secure Boot status, provides instructions for enabling Secure Boot in BIOS, sets GRUB bootloader password, restricts boot parameter modification, and secures boot configuration files.

---

## What's New

### v5.1 - Compatibility Edition

**Critical fixes** based on Issues #8, #10, #11:

**Fixed:** Browsers (Firefox, Chrome) no longer break after hardening (Issue #8), Docker container networking now works properly (Issue #10), and the configuration file (`fortress.conf`) is fully functional (Issue #11).

**Added:** Docker/Podman/LXC detection with conditional IP forwarding, browser detection with smart /dev/shm handling, full configuration file support (`--generate-config`), health verification script (`verify_fortress.sh`), pre-flight application detection, and new CLI options for compatibility control.

**New CLI Options:**

* `--allow-docker` - Enable IP forwarding for Docker compatibility
* `--no-docker-compat` - Disable IP forwarding (maximum security, breaks Docker)
* `--allow-browser-shm` - Skip noexec on /dev/shm (browsers work)
* `--no-browser-compat` - Apply noexec to /dev/shm (maximum security, breaks browsers)
* `--force-desktop` - Force desktop-mode settings
* `--force-server` - Force server-mode settings
* `--generate-config` - Create fortress.conf template

### v5.0 - Educational Edition

**Major rewrite** with a complete philosophical shift from "automate everything" to "educate and execute intelligently."

**Removed (security theatre):** AIDE (replaced with dpkg verification), IPv6 disable (not a security feature), ClamAV (minimal Linux benefit), lynis_audit (run separately), rootkit_scanner (false sense of security).

**Added:** Educational mode (`--explain` flag), Secure Boot verification, package verification (dpkg-based, weekly cron), intelligent module recommendations, SSH lockout prevention (multiple safety checks), honest limitation statements.

---

## Installation

### Prerequisites:

* Debian-based Linux (Ubuntu, Kubuntu, Mint, Pop!\_OS, Debian)
* Root/sudo access
* Internet connection
* **For servers:** SSH keys set up BEFORE running

### Quick Install:

```bash
# Download
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/fortress_improved.sh

# Make executable
chmod +x fortress_improved.sh

# Run with educational mode (recommended first time)
sudo ./fortress_improved.sh --explain --dry-run
```

### Clone the Repository:

```bash
git clone https://github.com/captainzero93/security_harden_linux.git
cd security_harden_linux

# Make executable
chmod +x fortress_improved.sh

# Review the code (always a good idea)
less fortress_improved.sh

# Run
sudo ./fortress_improved.sh
```

### Helper Scripts:

There's a permissions fix script (`fix_library_permissions.sh`) in case shared libraries are preventing apps from launching, a diagnostic tool (`PERM_diagnostic.sh`) - create a ticket with the output if you need help, and a health check script (`verify_fortress.sh`) to validate the system after hardening.

---

## Usage Guide

### Basic Usage:

```bash
# Educational mode - learn about each action
sudo ./fortress_improved.sh --explain

# Dry run - see what would change without making changes
sudo ./fortress_improved.sh --dry-run

# Default hardening (moderate level, interactive)
sudo ./fortress_improved.sh

# High security level
sudo ./fortress_improved.sh -l high

# Non-interactive mode (servers)
sudo ./fortress_improved.sh -n
```

### Selective Hardening:

```bash
# Only specific modules
sudo ./fortress_improved.sh -e system_update,ssh_hardening,firewall

# Skip certain modules
sudo ./fortress_improved.sh -x fail2ban,usb_protection

# List all available modules
sudo ./fortress_improved.sh --list-modules
```

### Advanced Options:

```bash
# Combine options
sudo ./fortress_improved.sh --explain -d -v

# Specific security level
sudo ./fortress_improved.sh -l paranoid

# Use custom config file
sudo ./fortress_improved.sh -c /path/to/config.conf

# Show version
sudo ./fortress_improved.sh --version
```

### The --explain Flag

This mode shows detailed explanations before each module: what the module does, why it matters (threat model), what attacks it prevents, trade-offs and limitations, what it CAN'T protect against, common misconceptions, and alternative approaches.

**Use this to learn security, not just apply it blindly.**

### After Hardening:

```bash
# Run health verification
sudo ./verify_fortress.sh

# Check the HTML report
cat /root/fortress_report_*.html

# Review the log
tail -100 /var/log/fortress_hardening.log

# Reboot to apply all changes
sudo reboot
```

### Monitoring:

```bash
# Check firewall status
sudo ufw status verbose

# Check AppArmor status
sudo aa-status

# View recent authentication attempts
sudo ausearch -m USER_LOGIN -ts recent

# Verify package integrity
dpkg --verify

# Check if fail2ban is active (if installed)
sudo fail2ban-client status
```

---

## Security Levels Explained

### Low (Basic Protection)

**For:** Testing, compatibility checking, minimal disruption.

Applies: system updates, basic firewall, automatic updates, basic audit logging. Skips: SSH hardening, AppArmor enforcement, strict kernel parameters, optional modules.

**Use when:** You want security without any risk of breaking things.

### Moderate (Recommended Default)

**For:** Desktop users, home servers, balanced security.

Applies: Everything in Low, plus SSH hardening (if SSH installed), kernel hardening, AppArmor enforcement, package verification, boot security checks. Skips: Aggressive restrictions, USB blocking (asks first), paranoid settings.

**Use when:** You want good security that doesn't interfere with normal use.

### High (Production Servers)

**For:** Servers, high-value targets, stricter security.

Applies: Everything in Moderate, plus stricter kernel parameters, full audit logging, USB restrictions, all hardening modules. Skips: Extreme paranoia settings, features that might break software.

**Use when:** Security is more important than convenience.

### Paranoid (Maximum Security)

**For:** High-security environments, compliance requirements.

Applies everything at maximum settings with the most restrictive parameters, full monitoring, and aggressive restrictions.

**Warning:** May break some applications. Test thoroughly.

---

## Available Modules

v5.0 includes 17 security modules (reduced from 21 - removed security theatre):

### Core Modules (Always Recommended):

1. **system_update** - Update all packages (most important!)
2. **firewall** - Configure UFW firewall
3. **ssh_hardening** - Harden SSH (if installed)
4. **automatic_updates** - Enable automatic security updates
5. **sysctl** - Kernel parameter hardening
6. **audit** - Configure auditd logging
7. **apparmor** - Mandatory access control

### Security Modules:

8. **package_verification** - Weekly dpkg integrity checks
9. **boot_security** - Secure Boot verification and GRUB password
10. **password_policy** - Strong password requirements
11. **ntp** - Time synchronisation
12. **secure_shared_memory** - Shared memory protections
13. **root_access** - Disable direct root login

### Optional Modules:

14. **fail2ban** - IP banning (optional, contextual)
15. **packages** - Remove unnecessary software
16. **usb_protection** - USB device restrictions
17. **filesystems** - Disable unused filesystems

### Removed in v5.0 (Security Theatre):

* ~~aide~~ - Replaced with package_verification (dpkg-based)
* ~~ipv6~~ - Not a security feature, removed entirely
* ~~clamav~~ - Minimal Linux benefit, install separately if needed
* ~~lynis_audit~~ - Run separately, removed for focus
* ~~rootkit_scanner~~ - Can't detect kernel rootkits, false sense of security

### Module Selection:

```bash
# Enable specific modules only
sudo ./fortress_improved.sh -e system_update,firewall,ssh_hardening

# Disable specific modules
sudo ./fortress_improved.sh -x fail2ban,usb_protection

# See all available modules
sudo ./fortress_improved.sh --list-modules
```

---

## What Gets Hardened

### Network Security:

* **Firewall (UFW):** Enabled with intelligent port opening, default deny incoming
* **SSH:** Key-only auth, strong ciphers, root login disabled, connection rate limiting
* **fail2ban (optional):** Only if beneficial for your services
* **Network parameters:** SYN cookies, ICMP redirects disabled, IP forwarding off (unless Docker detected)

### System Security:

* **Kernel:** ASLR enabled, kernel symbols restricted, memory protections, hardened network stack
* **Boot:** Secure Boot verification, GRUB password, boot parameter restrictions
* **Packages:** Integrity verification (dpkg), automatic security updates, unnecessary packages removed
* **AppArmor:** Mandatory access control enabled and enforcing

### Access Control:

* **SSH:** Password auth disabled, key-only access
* **Root:** Direct root login disabled, sudo required, all actions traceable
* **Passwords:** Strong policy enforced (12+ chars, complexity, lockout)
* **USB (optional):** Device restrictions, logging, optional whitelisting

### Monitoring:

* **Audit logs:** Authentication, file changes, privilege escalation
* **Package verification:** Weekly dpkg checks for tampering
* **AppArmor:** Logs policy violations

### Files Changed:

* `/etc/ssh/sshd_config` - SSH configuration
* `/etc/ufw/` - Firewall rules
* `/etc/sysctl.d/99-fortress.conf` - Kernel parameters
* `/etc/audit/rules.d/fortress.rules` - Audit rules
* `/etc/security/pwquality.conf` - Password policy
* `/etc/apt/apt.conf.d/50unattended-upgrades` - Auto updates
* `/etc/fstab` - Shared memory mount options
* `/etc/modprobe.d/fortress-filesystems.conf` - Disabled filesystems
* `/etc/cron.weekly/fortress-verify-packages` - Package verification

All modified files are backed up to `/root/fortress_backups_TIMESTAMP/` before changes are made.

---

## Emergency Recovery

### SSH Lockout:

1. Access server via console (physical or VPS console)
2. Restore SSH config:
   ```bash
   sudo cp /root/fortress_backups_*/etc/ssh/sshd_config /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```
3. Set up SSH keys properly, then re-run the hardening script

### Firewall Blocking Something:

```bash
# Allow specific port
sudo ufw allow 8080/tcp

# Disable firewall temporarily
sudo ufw disable

# Re-enable after fixing
sudo ufw enable
```

### Boot Failure:

1. Boot into recovery mode (hold Shift during boot)
2. Select "Drop to root shell prompt"
3. Restore:
   ```bash
   mount -o remount,rw /
   cp /root/fortress_backups_*/etc/default/grub /etc/default/grub
   update-grub
   reboot
   ```

### Full System Restore:

```bash
# Restore all configuration files from backup
cd /root/fortress_backups_TIMESTAMP/
sudo cp -a * /

# Restart services
sudo systemctl restart sshd
sudo systemctl restart ufw
sudo systemctl restart auditd
sudo systemctl restart apparmor

# Reboot
sudo reboot
```

---

## Common Questions

### Will this break my system?

Unlikely. The script creates backups before all changes, has been tested on multiple distributions, uses safe defaults at "moderate" level, and includes rollback functionality with multiple safety checks. But always test in a VM first, especially at "high" or "paranoid" levels.

### Will this slow down my computer?

No. There are no background processes eating resources, no FPS impact on games, no audio latency increase, and kernel hardening has negligible performance cost. You won't notice a difference.

### Why did you remove AIDE, ClamAV, and IPv6 disable?

AIDE on live systems can't detect kernel rootkits, generates false positives with generic configs, and dpkg already has built-in file verification. ClamAV has minimal effectiveness on Linux and mainly useful for mail servers scanning Windows attachments. IPv6 disable was security theatre - it doesn't improve security and can break things like Docker and modern networks. All removed in v5.0 based on community feedback.

### Why is fail2ban optional?

With SSH password auth disabled and key-only access, brute force attacks become impossible, so fail2ban provides no additional SSH protection. It IS still useful for web servers, mail servers, and other password-authenticated services. The script detects your setup and recommends accordingly.

### Can I use this on a Raspberry Pi?

Yes, but use "low" or "moderate" level, test thoroughly, and note that some modules may not apply to ARM.

### How do I verify packages now?

```bash
# Manual check
dpkg --verify

# Check weekly cron job
cat /etc/cron.weekly/fortress-verify-packages

# View last report
ls -lht /var/log/fortress_package_verification_*.txt
```

### Does this replace professional security audits?

No. This provides a solid security foundation and protection against common attacks. It does NOT replace professional assessment, guarantee 100% security, provide monitoring/incident response, or configure application-specific security.

### Can I run this multiple times?

Yes. First run creates the configuration, subsequent runs update/reapply settings. Each run creates new backups. Safe to re-run after system updates.

### What if a module fails?

The script logs all errors, continues with remaining modules, tracks which modules failed, and creates an HTML report showing failures. Check `/var/log/fortress_hardening.log` for details.

### Is this suitable for production servers?

Yes, with caveats: test in staging first, use "high" security level, review all changes, ensure SSH keys are set up, have console access available, and consider a professional assessment.

### What distributions are supported?

Tested on Ubuntu 22.04, 24.04, 25.10, Debian 11, 12, 13, Kubuntu 24.04+, Linux Mint 21+, and Pop!\_OS 22.04+. Should work on any Debian-based distribution.

### How do I update the script?

```bash
# Download latest version
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/fortress_improved.sh -O fortress_improved.sh

# Review changes
./fortress_improved.sh --version

# Run with --dry-run first
sudo ./fortress_improved.sh --dry-run
```

---

## Troubleshooting

### Docker Containers Can't Reach Internet

**Cause:** IP forwarding disabled by fortress.

**Fix:** Re-run with `sudo ./fortress_improved.sh --allow-docker`, or manually:
```bash
sudo sed -i 's/net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/' /etc/sysctl.d/99-fortress.conf
sudo sysctl -p /etc/sysctl.d/99-fortress.conf
```

### Firefox/Chrome Won't Launch

**Cause:** /dev/shm mounted with noexec (breaks JIT compilation).

**Fix:** Run `sudo ./fix_library_permissions.sh`, or manually:
```bash
sudo sed -i 's/nodev,nosuid,noexec/nodev,nosuid/' /etc/fstab
sudo mount -o remount /dev/shm
```

### SSH Connection Refused

1. Check if SSH is running: `sudo systemctl status sshd`
2. Check firewall: `sudo ufw status` then `sudo ufw allow ssh`
3. Check SSH config: `sudo sshd -t`
4. Restore from backup if needed:
   ```bash
   sudo cp /root/fortress_backups_*/etc/ssh/sshd_config /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```

### Firewall Blocking a Service

1. Find which port: `sudo netstat -tlnp`
2. Allow it: `sudo ufw allow 8080/tcp`
3. Reload: `sudo ufw reload`

### Package Verification Alerts

Config files, log files, and cache files changing is normal. Investigate if system binaries or security files have changed, or if there's an unexpected number of changes. Reinstall suspicious packages with `sudo apt-get install --reinstall package-name`.

### Performance Problems

Check audit logging overhead with `sudo auditctl -l` and disable if needed with `sudo systemctl stop auditd`. The script shouldn't cause performance issues at default settings.

### Boot Fails After Hardening

Boot into recovery mode, drop to root shell, then:
```bash
mount -o remount,rw /
cp /root/fortress_backups_*/etc/default/grub /etc/default/grub
update-grub
reboot
```

### AppArmor Blocks Application

1. Check logs: `sudo journalctl -xe | grep apparmor`
2. Set profile to complain mode: `sudo aa-complain /etc/apparmor.d/usr.bin.application`
3. Or disable profile: `sudo aa-disable /etc/apparmor.d/usr.bin.application`

### USB Devices Not Working

1. Check rules: `cat /etc/udev/rules.d/99-fortress-usb.rules`
2. Temporarily disable:
   ```bash
   sudo mv /etc/udev/rules.d/99-fortress-usb.rules /etc/udev/rules.d/99-fortress-usb.rules.disabled
   sudo udevadm control --reload-rules
   ```

### Getting More Help

Run the health verification with `sudo ./verify_fortress.sh`, check detailed logs with `sudo tail -100 /var/log/fortress_hardening.log`, run with verbose output using `sudo ./fortress_improved.sh --dry-run --verbose`, check system logs with `sudo journalctl -xe`, and open a GitHub issue with your distribution/version, security level used, error messages, log excerpts, and output of `verify_fortress.sh`.

---

## Advanced Usage

### Configuration File (v5.1):

Generate a configuration template:

```bash
sudo ./fortress_improved.sh --generate-config
```

This creates `fortress.conf` with all available settings. Key options:

```bash
# Security and compatibility
SECURITY_LEVEL="moderate"
ALLOW_DOCKER_FORWARDING=true
ALLOW_BROWSER_SHAREDMEM=true

# Module control
DISABLE_MODULES="fail2ban,usb_protection"
ENABLE_MODULES="system_update,ssh_hardening,firewall,apparmor"

# SSH settings
SSH_PORT=22
SSH_ALLOWED_USERS=""

# Firewall
FIREWALL_ALLOW_PORTS="80,443"
```

The config file is automatically loaded if present in the same directory as the script. You can also specify a custom path with `sudo ./fortress_improved.sh -c /path/to/config.conf`.

### Automated Deployment (Multiple Servers):

```bash
#!/bin/bash
# deploy_hardening.sh

SERVERS="server1 server2 server3"

for server in $SERVERS; do
    echo "Hardening $server..."
    scp fortress_improved.sh user@$server:/tmp/
    ssh user@$server "sudo /tmp/fortress_improved.sh -l high -n"
done
```

### Integration with Ansible:

```yaml
- name: Deploy security hardening
  hosts: all
  tasks:
    - name: Copy script
      copy:
        src: fortress_improved.sh
        dest: /tmp/fortress_improved.sh
        mode: '0755'
    
    - name: Run hardening
      command: /tmp/fortress_improved.sh -l high -n
      become: yes
```

### Periodic Re-hardening:

```bash
# Add to cron for monthly re-hardening
sudo crontab -e

# Add line:
0 2 1 * * /root/fortress_improved.sh -n -e system_update,package_verification
```

### Module Development:

Create custom modules by adding to the script:

```bash
module_custom_security() {
    CURRENT_MODULE="custom_security"
    
    explain "Custom Security" \
        "Description of what this does" \
        "Why it matters"
    
    log INFO "Applying custom security"
    
    # Your hardening code here
    
    return 0
}
```

### Testing in Docker:

```bash
# Create test container
docker run -it --rm ubuntu:24.04 bash

# Inside container:
apt update && apt install -y wget sudo
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/fortress_improved.sh
chmod +x fortress_improved.sh
./fortress_improved.sh --dry-run
```

---

## Requirements

### Minimum:

* **OS:** Debian-based Linux (Ubuntu, Debian, Mint, Pop, Kubuntu)
* **Access:** Root or sudo privileges
* **Internet:** Required for downloading packages
* **Disk:** ~500MB free space (for backups and new packages)
* **RAM:** No additional requirement

### Recommended:

* Fresh system or recent backup
* Console/physical access for servers
* SSH keys set up (for remote servers)
* Understanding of Linux basics

### Incompatible With:

* Non-Debian distributions (Fedora, Arch, etc.)
* Extremely old systems (Debian < 11)
* Systems with conflicting security tools
* Docker containers (limited functionality)

---

## Security Compliance

This script helps implement controls from DISA STIG, CIS Benchmarks, NIST 800-53, PCI-DSS (partial), and HIPAA (partial).

**Important:** This provides a foundation, not complete compliance. Professional assessment is required for PCI-DSS certification, HIPAA compliance, SOC 2 audit, ISO 27001 certification, or government contracts. You'll still need professional security assessment, vulnerability scanning, penetration testing, security awareness training, incident response plan, disaster recovery plan, encryption at rest, and regular audits.

---

## License & Support

### License:

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**

You are free to share (copy and redistribute) and adapt (remix, transform, and build upon) under the terms of attribution (give appropriate credit), non-commercial use, and no additional restrictions.

Full license: https://creativecommons.org/licenses/by-nc/4.0/

### Commercial Use:

For commercial licensing, email: cyberjunk77@protonmail.com with subject "Commercial License Request".

### Support:

**Community Support (Free):** GitHub Issues, documentation, best-effort responses.

**Commercial Support (Paid):** Priority responses, custom development, professional consultation, training and workshops.

---

## Version History

### v5.1 (2026-02) - Compatibility Edition

Critical fixes for Issues #8, #10, #11. Fixed browser launch failures from /dev/shm noexec, Docker networking broken by IP forwarding disable, and config file not loading. Added Docker/Podman/LXC detection, browser detection, full config file support, pre-flight application detection, health verification script, and new CLI options. Improved desktop vs server detection and interactive prompts.

### v5.0 (2025-11-16) - Educational Edition

Major rewrite. Removed security theatre (AIDE, IPv6, ClamAV, lynis, rootkit scanner). Added educational mode, Secure Boot verification, dpkg-based package verification, intelligent module recommendations, SSH lockout prevention. Made fail2ban optional and contextual. Philosophy shift from "automate everything" to "educate and execute intelligently."

### v4.2 (2025-11-07)

Fixed premature exit at 4% issue, fixed show_progress() causing immediate exit with set -e, changed progress bar to use if statement, added explicit return 0 to all module functions.

### v4.1

Improved APT lock handling, fixed progress bar advancement, better error recovery, enhanced user feedback.

### v4.0

Fixed wait_for_apt() hanging, improved lock file detection, better timeout handling, various bug fixes.

### v3.x and earlier

Initial releases with basic hardening features and module system implementation.

---

## Additional Resources

### Official Documentation:

* [Ubuntu Security](https://ubuntu.com/security)
* [Debian Security](https://www.debian.org/security/)
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

### Tools Documentation:

* [UFW Documentation](https://help.ubuntu.com/community/UFW)
* [AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)
* [Auditd Manual](https://linux.die.net/man/8/auditd)
* [fail2ban Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)

### Related Projects:

* [Dev-Sec Hardening Framework](https://dev-sec.io/)
* [Ansible Hardening](https://github.com/openstack/ansible-hardening)
* [Lynis](https://cisofy.com/lynis/) - Security auditing tool
* [OpenSCAP](https://www.open-scap.org/) - Security compliance tool
* [Bastille Linux](http://bastille-linux.sourceforge.net/) - Hardening toolkit

### Learning Resources:

**Beginner:** [Linux Journey](https://linuxjourney.com/), [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/), [Cybrary](https://www.cybrary.it/)

**Intermediate:** [TryHackMe Defensive Security](https://tryhackme.com/paths), [Linux Academy](https://linuxacademy.com/), [SANS Reading Room](https://www.sans.org/white-papers/)

**Advanced:** [Exploit Education](https://exploit.education/), [PentesterLab](https://pentesterlab.com/), [HackTheBox](https://www.hackthebox.com/)

### Books:

* "Linux Basics for Hackers" - OccupyTheWeb
* "Practical Linux Security" - Michael Boelen
* "Linux Security Cookbook" - Gregor N. Purdy
* "The Practice of Network Security Monitoring" - Richard Bejtlich

### YouTube Channels:

NetworkChuck, LiveOverflow, IppSec, John Hammond

---

## Important Legal Disclaimer

**READ BEFORE USE**

### No Warranty

This script is provided "AS IS" without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.

### Compliance

This script provides a security foundation, not complete compliance with any framework. Professional assessment and additional controls are required for PCI-DSS, HIPAA, SOC 2, or similar standards. Consult qualified security professionals for compliance requirements.

### Limitations

This script does not guarantee absolute security (no system is 100% secure), replace professional security assessment, provide monitoring or incident response, implement application-specific security, configure backups or disaster recovery, provide encryption at rest, replace security awareness training, detect all types of malware or rootkits, protect against zero-day exploits, or guarantee compliance with any standard.

**What this script is honest about:** Package verification can't detect sophisticated rootkits. fail2ban only blocks IPs (easily bypassed). SSH hardening can't stop attacks using valid keys. AppArmor can be bypassed by kernel exploits. System updates are more important than any hardening. Script can't auto-enable Secure Boot (requires BIOS config), detect kernel-level rootkits on live systems, protect against all physical access attacks, prevent attacks on allowed network ports, or replace application-level security.

### Liability

To the maximum extent permitted by law, the authors and contributors disclaim all liability for any damages arising from use of this script. Users assume all risk associated with use, including but not limited to data loss, system damage, service disruption, security breaches, compliance violations, or financial losses.

### Support Disclaimer

Support is provided on a best-effort basis with no guaranteed response time, no service level agreements (SLAs), and bug fixes/updates provided when possible but not guaranteed.

**BY USING THIS SCRIPT, YOU ACKNOWLEDGE THAT YOU HAVE READ, UNDERSTOOD, AND AGREE TO THESE TERMS.**

---

## Contact & Support

### Getting Help:

**Before asking for help:** Read this README thoroughly, check existing [GitHub Issues](https://github.com/captainzero93/security_harden_linux/issues), review the [Troubleshooting](#troubleshooting) section, and run with `--verbose` and check logs at `/var/log/fortress_hardening.log`.

**Security Vulnerabilities:** DO NOT open a public issue. Email directly: [cyberjunk77@protonmail.com](mailto:cyberjunk77@protonmail.com). Use subject: "SECURITY: [brief description]". Response target: within 48 hours.

**Note:** All support is provided on a best-effort basis.

### Commercial Support:

For commercial licensing, professional support, or consulting services: [cyberjunk77@protonmail.com](mailto:cyberjunk77@protonmail.com)

**Services available:** Custom script development, professional security assessment, compliance consulting, training and workshops, priority support contracts.

---

## Quick Reference Card

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    FORTRESS.SH QUICK REFERENCE v5.1

ESSENTIAL COMMANDS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Learn:        sudo ./fortress_improved.sh --explain --dry-run
Preview:      sudo ./fortress_improved.sh --dry-run -v
Apply:        sudo ./fortress_improved.sh
Verify:       sudo ./verify_fortress.sh
Report:       cat /root/fortress_report_*.html
Help:         sudo ./fortress_improved.sh --help
List modules: sudo ./fortress_improved.sh --list-modules

CONFIGURATION (v5.1):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Generate:     sudo ./fortress_improved.sh --generate-config
Edit:         nano fortress.conf
Apply:        sudo ./fortress_improved.sh  (auto-loads config)

SECURITY LEVELS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Desktop:      sudo ./fortress_improved.sh -l moderate
Server:       sudo ./fortress_improved.sh -l high -n
Maximum:      sudo ./fortress_improved.sh -l paranoid
Basic:        sudo ./fortress_improved.sh -l low

COMPATIBILITY (v5.1):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
With Docker:  sudo ./fortress_improved.sh --allow-docker
No Docker:    sudo ./fortress_improved.sh --no-docker-compat
Browsers OK:  sudo ./fortress_improved.sh --allow-browser-shm
Max security: sudo ./fortress_improved.sh --no-browser-compat

MODULE SELECTION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Enable:       sudo ./fortress_improved.sh -e module1,module2
Disable:      sudo ./fortress_improved.sh -x module1,module2
Educational:  sudo ./fortress_improved.sh --explain

MONITORING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Health:       sudo ./verify_fortress.sh
Firewall:     sudo ufw status
Fail2ban:     sudo fail2ban-client status (if installed)
Unban IP:     sudo fail2ban-client set sshd unbanip IP
Audit:        sudo ausearch -m USER_LOGIN -ts recent
AppArmor:     sudo aa-status
Logs:         sudo tail -f /var/log/fortress_hardening.log

FILE CHECKS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Packages:     dpkg --verify
Reports:      ls -lht /var/log/fortress_package_verification_*.txt
Weekly cron:  cat /etc/cron.weekly/fortress-verify-packages

BACKUPS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Location:     /root/fortress_backups_*/
List:         ls -lht /root/fortress_backups_*
Restore:      cp -a /root/fortress_backups_*/* /

EMERGENCY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SSH lockout:  Use console, restore /etc/ssh/sshd_config
Firewall:     sudo ufw disable (from console)
Boot fail:    Recovery mode, restore /etc/default/grub
Full restore: cp -a /root/fortress_backups_*/* /

QUICK FIXES (v5.1):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Docker net:   Edit /etc/sysctl.d/99-fortress.conf, set ip_forward=1
Browsers:     Remove noexec from /dev/shm in /etc/fstab
Allow port:   sudo ufw allow PORT/tcp
Stop service: sudo systemctl stop SERVICE

RESOURCES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GitHub:       https://github.com/captainzero93/security_harden_linux
Issues:       https://github.com/captainzero93/security_harden_linux/issues

```

---

**Star this repo if it helped you.**

**Version:** 5.1 | **Author:** captainzero93 |

**GitHub:** https://github.com/captainzero93/

---
