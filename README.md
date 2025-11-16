# FORTRESS.SH :: Debian Linux Defence Configuration

**One-command security hardening that implements many enterprise-grade protections (DISA STIG + CIS) while allowing the user to decide the level of protection / use trade-off. This enables casual use and more strict enforcement.** 

**Version 5.0** - Major Rewrite: Removes security theater, adds intelligent recommendations. Tested WORKING on Debian 13, Ubuntu 24.04+.

[![License](https://img.shields.io/badge/License-CC%20BY--NC%204.0-blue.svg)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%2B-orange.svg)](https://ubuntu.com/)
[![Kubuntu](https://img.shields.io/badge/Kubuntu-24.04%2B-blue.svg)](https://kubuntu.org/)
[![Debian](https://img.shields.io/badge/Debian-11%2B%20%7C%2013-red.svg)](https://www.debian.org/)
[![Linux Mint](https://img.shields.io/badge/Linux%20Mint-21%2B-87CF3E.svg)](https://linuxmint.com/)
[![Pop!\_OS](https://img.shields.io/badge/Pop!__OS-22.04%2B-48B9C7.svg)](https://pop.system76.com/)
[![Version](https://img.shields.io/badge/Version-5.0-green.svg)]() 

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/captainzero)

---

## **CRITICAL WARNING FOR REMOTE SERVER USERS**

**REMOTE SERVER USERS**: Set up SSH keys FIRST or you WILL be locked out.

v5.0 includes multiple safety checks to prevent SSH lockouts, but you still need working key-based authentication before running the script.

### <b> This script does network/system hardening, AppArmor (not SELinux), audit logging and other security features. This script doesn't do User group management, SELinux, or touch VFIO/IOMMU configs, If you need user group stuff, you will want to handle that separately before or after running the script. </b>

---

## What's New in v5.0 

**MAJOR REWRITE** based on community feedback to remove security theater and add real education:

### Removed:
* **AIDE** - Ineffective on live systems, can't detect kernel rootkits. Replaced with `dpkg --verify`
* **IPv6 disable** - Not a security feature, removed entirely
* **ClamAV** - Minimal benefit on Linux, removed (install separately if needed)
* **Blanket fail2ban installation** - Now optional and intelligent

### Added:
* **Educational mode** (`--explain`) - Learn WHY each security measure matters
* **Secure Boot verification** - Checks if enabled, provides setup instructions
* **Package verification** - Uses dpkg's built-in checksums (weekly cron job)
* **Intelligent recommendations** - Analyzes your system before suggesting modules
* **SSH lockout prevention** - Multiple safety checks with explicit confirmation
* **Honest limitations** - Every module explains what it CAN'T protect against

### Improved:
* **fail2ban** - Only recommended when actually beneficial (web/mail servers, password-auth services)
* **SSH hardening** - Requires explicit confirmation of working key-based auth
* **Boot security** - Now verifies Secure Boot status and guides BIOS configuration
* **All modules** - Include educational explanations and threat modeling

**Philosophy change:** From "automate everything" to "educate and execute"

---

## 30-Second Quickstart

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

* [Your fresh Linux install isn't secure](#your-fresh-linux-install-isnt-secure)
* [Who This Is For](#who-this-is-for)
* [What This Actually Does](#what-this-actually-does)
* [Desktop Users: This Won't Ruin Your Workflow](#desktop-users-this-wont-ruin-your-workflow)
* [Critical Warning for Remote Servers](#critical-warning-for-remote-servers)
* [TL;DR - Quick Commands](#tldr---quick-commands)
* [Quick Start](#quick-start)
* [Why This Matters - Real-World Attacks](#why-this-matters---real-world-attacks)
* [Why Each Security Measure Matters](#why-each-security-measure-matters)
* [What's New in v5.0](#whats-new-in-v50-educational-edition)
* [Installation](#installation)
* [Usage Guide](#usage-guide)
* [Security Levels Explained](#security-levels-explained)
* [Available Modules](#available-modules)
* [What Gets Hardened?](#what-gets-hardened)
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

## Your fresh Linux install isn't secure.

Ubuntu, Fedora, Mint, Kubuntu - they all ship with security settings that prioritize "making things work" over "keeping you safe." This is intentional. Distributions assume you'll configure security later.

**But most people never do.**

**What this means for you right now:**

* Your firewall probably isn't even enabled - any service you run is exposed to the internet
* SSH ports are wide open to brute force attacks - bots try thousands of passwords per hour
* Failed login attempts aren't tracked - attackers get unlimited tries
* Your system accepts connections you never asked for - port scanners probe you 24/7
* Critical security updates might not install automatically - you could be vulnerable for weeks
* The kernel runs with minimal protections - exploits are easier to pull off
* No intrusion detection - if someone breaks in, you won't know

**This isn't a Linux flaw** - it's a conscious trade-off. Distributions prioritize compatibility and ease-of-use for new users. That's great for getting started, but terrible for security.

---

## Who This Is For

### You, if you:

* **Game on Linux** and want to stay secure without / minimal FPS loss
* **Create art, music, or videos** without security getting in your way
* **Work from home** and need basic protection
* **Just want a secure personal computer** that works normally
* **Are tired of complicated security guides** written for sysadmins
* **Run a home server** or self-host services
* **Develop software** and want security without breaking your tools
* **Are learning Linux** and want to start with good habits
* **Want to understand security** - not just blindly apply it

### What makes this different:

This script applies **industry-standard security WITHOUT breaking your desktop experience.** No more choosing between security and usability. **v5.0 also teaches you WHY each security measure matters.**

**Tested and optimized for:**

* Gamers (Steam, Lutris, Proton, Discord)
* Content creators (DaVinci Resolve, Kdenlive, Blender, GIMP)
* Music producers (Jack, PipeWire, Ardour, Reaper)
* Developers (Docker, VSCode, databases, IDEs)
* Office users (LibreOffice, browsers, email)
* Anyone who just wants more security with minimal hassle

---

## What This Actually Does

Instead of spending 40+ hours reading security guides and manually configuring dozens of tools, this script:

### Security You Get:

* Enables your firewall (UFW) - but keeps Steam, Discord, KDE Connect working
* Hardens SSH - prevents brute force attacks if you use remote access
* Blocks repeated failed logins - optional fail2ban (only if beneficial for your setup)
* Secures the kernel - protection against memory exploits and attacks
* Verifies package integrity - weekly dpkg verification (detects tampering/corruption)
* Enforces strong passwords - because "password123" is still too common
* Enables automatic security updates - patches critical bugs while you sleep
* Configures audit logging - forensics and evidence if something happens
* Applies kernel hardening - makes exploits far harder to pull off
* Verifies boot security - checks Secure Boot status and guides configuration
* Removes unnecessary packages - smaller attack surface

### Things That KEEP Working:

* Steam and all your games (zero/low FPS impact)
* Discord, Zoom, Slack, Teams
* Wacom tablets and drawing tools
* Audio production (Jack, PipeWire, ALSA)
* Video editing (DaVinci, Kdenlive, OBS)
* Game development (Godot, Unity, Unreal)
* Bluetooth audio and devices
* Network printers and file sharing
* KDE Connect phone integration
* USB devices (with optional logging)
* RGB peripherals and gaming gear
* Virtual machines (VirtualBox, QEMU)
* Docker and development tools

---

## Desktop Users: This Won't Ruin Your Workflow

The script:

* **Detects desktop environments automatically** - knows you're not a server
* **Asks before blocking features** like mDNS (network discovery), KDE Connect, and Samba
* **Preserves gaming functionality** - no/little impact on Steam, Lutris, or Proton
* **Zero performance impact** - no background processes eating CPU/GPU
* **Audio production safe** - Jack, PipeWire, ALSA untouched
* **Creative tools work** - Wacom, DaVinci, Blender all function normally
* **Bluetooth works** - headphones, mice, controllers all fine
* **Uses "moderate" security by default** - balanced, not paranoid
* **Creates automatic backups** before every change
* **Explains each action** in educational mode (--explain flag)

**At "moderate" level:** (the default), you won't even notice the changes. Your computer will feel exactly the same, just with far fewer security holes.

### Special Considerations for Creative Users

**Digital Art:**

* Wacom/Huion tablets work perfectly
* Krita, GIMP, Blender unchanged
* Pen pressure and tilt functional
* USB tablets logged but not blocked

**Video Editing:**

* DaVinci Resolve (all features work)
* Kdenlive, OpenShot, Shotcut
* Hardware encoding intact
* Proxy workflows unaffected

**Audio Production:**

* Jack, PipeWire, PulseAudio all work
* Real-time kernel scheduling preserved
* Low-latency monitoring works
* USB audio interfaces function normally

**Game Development:**

* Godot, Unity, Unreal work fine
* Build processes unaffected
* Steam integration intact
* Version control (Git) works

---

## Critical Warning for Remote Servers

### YOU WILL LOCK YOURSELF OUT IF YOU SKIP THIS SECTION

This script **disables password authentication for SSH** and switches to key-only authentication. This is the single most effective security improvement you can make for SSH.

**But if you don't have SSH keys set up BEFORE running this script, you will be permanently locked out of your server.**

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

**v5.0 Safety Features:**

* Script detects if SSH server is running
* Requires explicit "yes" confirmation that you have working SSH keys
* Provides setup instructions if you don't have keys
* Multiple warnings before disabling password auth
* Configuration validation before applying changes
* Auto-rollback on SSH configuration errors

**If you still lock yourself out:**

You'll need physical access to the server (or console access from your hosting provider) to restore `/etc/ssh/sshd_config` from the backup.

### For Desktop Users:

If you don't use SSH to remotely access your computer, this doesn't affect you. The script will detect this and handle it appropriately.

---

## TL;DR - Quick Commands

### First Time Setup:

```bash
# Learn what the script does (RECOMMENDED)
sudo ./fortress_improved.sh --explain --dry-run

# See what would change without making changes
sudo ./fortress_improved.sh --dry-run

# Apply default hardening (interactive)
sudo ./fortress_improved.sh

# High security, non-interactive (servers)
sudo ./fortress_improved.sh -l high -n
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

### Monitoring After Hardening:

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

## Quick Start

### Step 1: Download

```bash
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/fortress_improved.sh
chmod +x fortress_improved.sh
```

### Step 2: Preview Changes (Recommended)

```bash
# Educational mode - learn about each security measure
sudo ./fortress_improved.sh --explain --dry-run

# Or just see what would change
sudo ./fortress_improved.sh --dry-run --verbose
```

### Step 3: Apply Hardening

**Desktop (Interactive):**

```bash
sudo ./fortress_improved.sh
```

**Server (Non-Interactive):**

```bash
# Make sure SSH keys are set up first!
sudo ./fortress_improved.sh -l high -n
```

### Step 4: Review and Reboot

```bash
# Check the HTML report
cat /root/fortress_report_*.html

# Review the log
tail -100 /var/log/fortress_hardening.log

# Reboot to apply all changes
sudo reboot
```

---

## Why This Matters - Real-World Attacks

### Attack #1: The Brute Force Bot

**What happens without this script:**

Your SSH port (22) is open to the internet. Automated bots try 10,000+ password combinations per hour. Eventually, a weak password gets cracked. Game over.

**What this script does:**

* Disables password authentication completely (key-only access)
* Changes SSH port (optional)
* Rate limits connection attempts
* Optional fail2ban for additional services

**Why fail2ban is optional in v5.0:** With password auth disabled and key-only SSH, brute force attacks become impossible. The script intelligently detects this and recommends skipping fail2ban unless you have web/mail servers that benefit from it.

### Attack #2: The Kernel Exploit

**What happens without this script:**

A vulnerability in the Linux kernel allows attackers to escalate privileges. They go from limited user to root access.

**What this script does:**

* Enables kernel hardening (sysctl parameters)
* Restricts access to kernel symbols
* Enables ASLR (Address Space Layout Randomization)
* Configures memory protections

### Attack #3: The Supply Chain Attack

**What happens without this script:**

A compromised package update installs malware. You don't notice until your data is encrypted or stolen.

**What this script does:**

* **NEW in v5.0:** Weekly package integrity verification using dpkg
* Enables audit logging for file changes
* Monitors system files for tampering
* AppArmor limits what processes can do

**Note:** v5.0 removed AIDE because it can't detect kernel-level rootkits on live systems. Instead, we use dpkg's built-in verification which is more appropriate for package integrity checking.

### Attack #4: The Physical Access Attack

**What happens without this script:**

Someone boots your computer from USB, mounts your drive, and steals everything.

**What this script does:**

* **NEW in v5.0:** Verifies Secure Boot status
* Provides instructions for enabling Secure Boot in BIOS
* Sets GRUB bootloader password
* Restricts boot parameter modification
* Secures boot configuration files

---

## Why Each Security Measure Matters

### System Updates (Priority #1)

**The single most important security measure.** Most attacks exploit known vulnerabilities that already have patches available.

* Automatic security updates keep you protected
* Kernel vulnerabilities are patched quickly
* Critical bugs fixed before exploits appear

**v5.0 explains:** Why this is more important than any other hardening measure.

### SSH Hardening

**If you use remote access, this prevents 99% of SSH attacks.**

* Password auth disabled (keys only)
* Root login disabled
* Strong ciphers enforced
* Connection rate limiting

**v5.0 improvements:** Multiple safety checks prevent lockouts, explains why fail2ban is NOT needed with key-only auth.

### Firewall (UFW)

**Blocks unexpected network connections.**

* Default deny incoming
* Allow only needed services
* Logs blocked attempts
* Prevents backdoor connections

**v5.0 intelligently:** Detects running services and opens only necessary ports.

### Kernel Hardening (sysctl)

**Makes kernel exploits harder.**

* ASLR randomizes memory layout
* Restricts kernel symbols access
* Protects against memory attacks
* Hardens network stack

**v5.0 explains:** What each parameter does and why it matters.

### Package Verification (NEW in v5.0)

**Detects package tampering and corruption.**

* Uses dpkg's built-in MD5 checksums
* Weekly automated verification
* Alerts on anomalies
* Honest about limitations (can't detect kernel rootkits)

**Replaced AIDE because:** AIDE on live systems can't detect sophisticated attacks and generates false positives with generic configs.

### Secure Boot Verification (NEW in v5.0)

**Prevents boot-level malware.**

* Checks if Secure Boot is enabled
* Provides BIOS setup instructions
* Verifies bootloader signatures
* Protects against bootkits

**Note:** Script can't auto-enable Secure Boot (requires BIOS config), but guides you through the process.

### Audit Logging

**Records security-relevant events for forensics.**

* Tracks authentication attempts
* Logs file access to sensitive files
* Monitors privilege escalation
* Creates tamper-resistant logs

**v5.0 explains:** What auditd can and can't detect, when to use it.

### Automatic Updates

**Applies security patches automatically.**

* Daily checks for updates
* Installs security fixes
* Removes old kernels
* Optional reboot scheduling

**v5.0 improved:** Better configuration, explains trade-offs.

### AppArmor

**Limits what programs can do, even if compromised.**

* Mandatory access control
* Restricts file access
* Prevents privilege escalation
* Logs policy violations

**v5.0 explains:** How AppArmor works and its limitations.

### Password Policy

**Enforces strong passwords.**

* Minimum length (12+ characters)
* Complexity requirements
* Password history
* Account lockout

**v5.0 notes:** This only matters if password auth is enabled. With SSH keys, password policy is less critical.

### fail2ban (Optional in v5.0)

**Bans IPs with suspicious behavior.**

* Monitors log files
* Detects brute force attempts
* Automatically blocks attackers
* Configurable ban duration

**v5.0 intelligence:** Only recommends installation if you have services that benefit (web/mail servers). Explains why it's unnecessary with key-only SSH.

### Shared Memory Security

**Prevents shared memory exploits.**

* Mount /dev/shm with nosuid
* Prevents SUID execution
* Blocks device creation
* Restricts shared memory attacks

### Boot Security

**Protects boot process.**

* Secure Boot verification
* GRUB password protection
* Boot parameter restrictions
* Bootloader file permissions

### Root Access Restrictions

**Forces use of sudo.**

* Direct root login disabled
* All actions traceable to users
* Accountability and audit trail
* Least privilege principle

### USB Protection (Optional)

**Controls USB device access.**

* Prevents auto-mounting
* Logs USB connections
* Optional device whitelisting
* Reduces attack surface

**v5.0 intelligence:** Desktop detection - asks before applying USB restrictions that might interfere with normal use.

### Unused Filesystem Disable

**Reduces kernel attack surface.**

* Disables rarely-used filesystems
* Fewer kernel modules loaded
* Smaller attack surface
* Prevents obscure exploits

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

### Manual Install:

```bash
# Clone repository
git clone https://github.com/captainzero93/security_harden_linux.git
cd security_harden_linux

# Make executable
chmod +x fortress_improved.sh

# Review the code (always a good idea)
less fortress_improved.sh

# Run
sudo ./fortress_improved.sh
```

---

## Usage Guide

### Basic Usage:

```bash
# Educational mode - learn about each action
sudo ./fortress_improved.sh --explain

# Dry run - see what would change
sudo ./fortress_improved.sh --dry-run

# Default hardening (moderate level)
sudo ./fortress_improved.sh

# High security level
sudo ./fortress_improved.sh -l high

# Non-interactive mode
sudo ./fortress_improved.sh -n
```

### Advanced Options:

```bash
# Combine options
sudo ./fortress_improved.sh --explain -d -v

# Specific security level
sudo ./fortress_improved.sh -l paranoid

# Enable only specific modules
sudo ./fortress_improved.sh -e system_update,ssh_hardening,firewall

# Disable specific modules
sudo ./fortress_improved.sh -x fail2ban,usb_protection

# Use custom config file
sudo ./fortress_improved.sh -c /path/to/config.conf

# List all available modules
sudo ./fortress_improved.sh --list-modules

# Show version
sudo ./fortress_improved.sh --version
```

### Understanding the --explain Flag (NEW in v5.0):

```bash
sudo ./fortress_improved.sh --explain
```

This mode shows detailed explanations before each module:

* What the module does
* Why it matters (threat model)
* What attacks it prevents
* Trade-offs and limitations
* What it CAN'T protect against
* Common misconceptions
* Alternative approaches

**Use this to learn security, not just apply it blindly.**

---

## Security Levels Explained

### Low (Basic Protection)

**For:** Testing, compatibility checking, minimal disruption

**What it does:**

* Updates system packages
* Enables basic firewall
* Configures automatic updates
* Basic audit logging

**What it skips:**

* SSH hardening
* AppArmor enforcement
* Strict kernel parameters
* Optional modules

**Use when:** You want security without any risk of breaking things.

### Moderate (Recommended Default)

**For:** Desktop users, home servers, balanced security

**What it does:**

* All "Low" features
* SSH hardening (if SSH installed)
* Kernel hardening
* AppArmor enforcement
* Package verification
* Boot security checks

**What it skips:**

* Aggressive restrictions
* USB blocking (asks first)
* Paranoid settings

**Use when:** You want good security that doesn't interfere with normal use.

### High (Production Servers)

**For:** Servers, high-value targets, stricter security

**What it does:**

* All "Moderate" features
* Stricter kernel parameters
* Full audit logging
* USB restrictions
* All hardening modules

**What it skips:**

* Extreme paranoia settings
* Features that might break software

**Use when:** Security is more important than convenience.

### Paranoid (Maximum Security)

**For:** High-security environments, compliance requirements

**What it does:**

* Everything at maximum settings
* Most restrictive parameters
* Full monitoring
* All security modules
* Aggressive restrictions

**Warning:** May break some applications. Test thoroughly.

**Use when:** You need maximum security and are willing to troubleshoot issues.

---

## Available Modules

v5.0 includes 17 security modules (reduced from 21 - removed security theater):

### Core Modules (Always Recommended):

1. **system_update** - Update all packages (most important!)
2. **firewall** - Configure UFW firewall
3. **ssh_hardening** - Harden SSH (if installed)
4. **automatic_updates** - Enable automatic security updates
5. **sysctl** - Kernel parameter hardening
6. **audit** - Configure auditd logging
7. **apparmor** - Mandatory access control

### Security Modules:

8. **package_verification** - Weekly dpkg integrity checks (NEW in v5.0)
9. **boot_security** - Secure Boot verification and GRUB password (IMPROVED in v5.0)
10. **password_policy** - Strong password requirements
11. **ntp** - Time synchronization
12. **secure_shared_memory** - Shared memory protections
13. **root_access** - Disable direct root login

### Optional Modules:

14. **fail2ban** - IP banning (optional, contextual in v5.0)
15. **packages** - Remove unnecessary software
16. **usb_protection** - USB device restrictions
17. **filesystems** - Disable unused filesystems

### Removed in v5.0 (Security Theater):

* ~~aide~~ - Replaced with package_verification (dpkg-based)
* ~~ipv6~~ - Not a security feature, removed entirely
* ~~clamav~~ - Minimal Linux benefit, install separately if needed
* ~~lynis_audit~~ - Run separately, removed for focus
* ~~rootkit_scanner~~ - Can't detect kernel rootkits, removed

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

## What Gets Hardened?

### Network Security:

* **Firewall (UFW):** Enabled with intelligent port opening
* **SSH:** Key-only auth, strong ciphers, root login disabled
* **fail2ban (optional):** Only if beneficial for your services
* **Network parameters:** SYN cookies, ICMP redirects disabled, IP forwarding off

### System Security:

* **Kernel:** ASLR enabled, kernel symbols restricted, memory protections
* **Boot:** Secure Boot verification, GRUB password, boot security
* **Packages:** Integrity verification (dpkg), automatic security updates
* **AppArmor:** Mandatory access control enabled and enforcing
* **Audit:** Comprehensive logging of security events

### Access Control:

* **SSH:** Password auth disabled, key-only access
* **Root:** Direct root login disabled, sudo required
* **Passwords:** Strong policy enforced (if used)
* **USB (optional):** Device restrictions and logging

### Monitoring:

* **Audit logs:** Authentication, file changes, privilege escalation
* **Package verification:** Weekly dpkg checks for tampering
* **fail2ban (optional):** Monitors and bans malicious IPs
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
* `/etc/cron.weekly/fortress-verify-packages` - Package verification (NEW)

### Backups Created:

All modified files are backed up to:

* `/root/fortress_backups_TIMESTAMP/`

Original files can be restored from these backups.

---

## Emergency Recovery

### SSH Lockout Recovery:

**If you can't log in via SSH:**

1. Access server via console (physical or VPS console)
2. Restore SSH config:
   ```bash
   sudo cp /root/fortress_backups_*/etc/ssh/sshd_config /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```
3. Set up SSH keys properly
4. Re-run hardening script

**v5.0 Prevention:** Multiple confirmation prompts and SSH key verification before disabling password auth.

### Firewall Issues:

**If firewall blocks something you need:**

```bash
# Allow specific port
sudo ufw allow 8080/tcp

# Disable firewall temporarily
sudo ufw disable

# Re-enable after fixing
sudo ufw enable
```

### Boot Failure:

**If system won't boot:**

1. Boot into recovery mode (hold Shift during boot)
2. Select "Drop to root shell prompt"
3. Remount filesystem:
   ```bash
   mount -o remount,rw /
   ```
4. Restore GRUB config:
   ```bash
   cp /root/fortress_backups_*/etc/default/grub /etc/default/grub
   update-grub
   ```
5. Reboot

### Full System Restore:

**To restore all changes:**

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

### Q: Will this break my system?

**A:** Unlikely. The script:

* Creates backups before all changes
* Has been tested on multiple distributions
* Uses safe defaults at "moderate" level
* Includes rollback functionality
* v5.0 adds multiple safety checks

**But:** Always test in a VM first, especially at "high" or "paranoid" levels.

### Q: What if I lock myself out of SSH?

**A:** v5.0 has multiple safeguards:

* Detects if SSH keys are set up
* Requires explicit "yes" confirmation
* Provides SSH key setup instructions
* Validates SSH config before applying
* Auto-rollbacks on SSH errors

You'd need to ignore multiple warnings to lock yourself out.

**If it happens:** Console access required to restore `/etc/ssh/sshd_config` from backup.

### Q: Why did you remove AIDE?

**A:** Community feedback revealed that:

* AIDE on live systems can't detect kernel rootkits
* Generic AIDE configs generate false positives
* dpkg already has built-in file verification
* Sophisticated malware can hide from AIDE

v5.0 uses `dpkg --verify` which is more appropriate for package integrity checking.

### Q: Why is fail2ban optional now?

**A:** With SSH password auth disabled and key-only access:

* Brute force attacks become impossible
* Failed login attempts are harmless
* fail2ban provides no additional SSH protection

fail2ban IS still useful for:
* Web servers with authentication
* Mail servers
* Other password-authenticated services

v5.0 intelligently detects your setup and recommends accordingly.

### Q: What happened to IPv6 disable?

**A:** It was security theater. Disabling IPv6:

* Doesn't improve security
* Can break things (Docker, modern networks)
* Is not a recognized security best practice

Removed in v5.0 based on community feedback.

### Q: Will this slow down my computer?

**A:** No. The script:

* Doesn't add background processes
* No FPS impact on games
* No audio latency increase
* Kernel hardening has negligible performance cost

You won't notice any performance difference.

### Q: Can I use this on a Raspberry Pi?

**A:** Yes, but:

* Use "low" or "moderate" level
* May need to adjust for ARM-specific settings
* Test thoroughly first
* Some modules may not apply to ARM

### Q: What about ClamAV antivirus?

**A:** Removed in v5.0 because:

* Minimal effectiveness on Linux
* Mainly useful for mail servers scanning Windows attachments
* Causes performance overhead
* Rarely catches actual Linux threats

Install separately if you need it for a mail server.

### Q: How do I verify packages now without AIDE?

**A:** v5.0 uses dpkg verification:

```bash
# Manual check
dpkg --verify

# Check weekly cron job
cat /etc/cron.weekly/fortress-verify-packages

# View last report
ls -lht /var/log/fortress_package_verification_*.txt
```

### Q: What's this --explain mode?

**A:** NEW in v5.0. Educational mode that shows:

* What each module does
* Why it matters (threat model)
* What attacks it prevents
* Limitations and trade-offs
* Common misconceptions

Run with: `sudo ./fortress_improved.sh --explain`

**Use it to learn security, not just apply it.**

### Q: Does this replace professional security audits?

**A:** No. This provides:

* Solid security foundation
* Best practices implementation
* Protection against common attacks

**It does NOT:**

* Replace professional assessment
* Guarantee 100% security
* Provide monitoring/incident response
* Configure application-specific security

### Q: How do I update the script?

```bash
# Download latest version
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/fortress_improved.sh -O fortress_improved.sh

# Review changes
./fortress_improved.sh --version

# Run with --dry-run first
sudo ./fortress_improved.sh --dry-run
```

### Q: Can I run this multiple times?

**A:** Yes, but:

* First run creates configuration
* Subsequent runs update/reapply settings
* Each run creates new backups
* Safe to re-run after system updates

### Q: What if a module fails?

**A:** The script:

* Logs all errors
* Continues with remaining modules
* Tracks which modules failed
* Creates HTML report showing failures

Check `/var/log/fortress_hardening.log` for details.

### Q: Is this suitable for production servers?

**A:** Yes, with caveats:

* Test in staging first
* Use "high" security level
* Review all changes
* Ensure SSH keys are set up
* Have console access available
* Consider professional assessment

### Q: What Linux distributions are supported?

**A:** Tested on:

* Ubuntu 22.04, 24.04, 25.10
* Debian 11, 12, 13
* Kubuntu 24.04+
* Linux Mint 21+
* Pop!\_OS 22.04+

**Should work on any Debian-based distribution.**

### Q: How is v5.0 different from v4.x?

**A:** Major changes:

* Removed security theater (AIDE, IPv6, ClamAV)
* Added educational mode (--explain)
* Intelligent module recommendations
* SSH lockout prevention
* Secure Boot verification
* Package verification (dpkg-based)
* Honest about limitations
* fail2ban now optional and contextual

See "What's New in v5.0" section for full details.

---

## Troubleshooting

### Issue: SSH Connection Refused

**Symptoms:** Can't connect to server via SSH

**Solutions:**

1. Check if SSH is running:
   ```bash
   sudo systemctl status sshd
   ```

2. Check firewall:
   ```bash
   sudo ufw status
   sudo ufw allow ssh
   ```

3. Check SSH config:
   ```bash
   sudo sshd -t
   ```

4. Restore from backup if needed:
   ```bash
   sudo cp /root/fortress_backups_*/etc/ssh/sshd_config /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```

### Issue: Firewall Blocking Service

**Symptoms:** Service not accessible from network

**Solutions:**

1. Check which port service uses:
   ```bash
   sudo netstat -tlnp
   ```

2. Allow port through firewall:
   ```bash
   sudo ufw allow 8080/tcp
   sudo ufw reload
   ```

3. Check UFW status:
   ```bash
   sudo ufw status verbose
   ```

### Issue: Package Verification Alerts

**Symptoms:** dpkg --verify shows many files changed

**Solutions:**

1. Check the report:
   ```bash
   cat /var/log/fortress_package_verification_*.txt
   ```

2. **Normal changes:**
   * Configuration files (expected)
   * Log files (expected)
   * Cache files (expected)

3. **Investigate if:**
   * System binaries changed
   * Security files changed
   * Unexpected number of changes

4. Reinstall suspicious packages:
   ```bash
   sudo apt-get install --reinstall package-name
   ```

### Issue: Performance Problems

**Symptoms:** System slower after hardening

**Check:**

1. Audit logging overhead:
   ```bash
   sudo auditctl -l
   ```

2. Disable if needed:
   ```bash
   sudo systemctl stop auditd
   ```

3. Check fail2ban (if installed):
   ```bash
   sudo systemctl status fail2ban
   ```

**Note:** Script shouldn't cause performance issues at default settings.

### Issue: Boot Fails After Hardening

**Symptoms:** System won't boot

**Solutions:**

1. Boot into recovery mode
2. Drop to root shell
3. Restore GRUB config:
   ```bash
   mount -o remount,rw /
   cp /root/fortress_backups_*/etc/default/grub /etc/default/grub
   update-grub
   reboot
   ```

### Issue: AppArmor Blocks Application

**Symptoms:** Application won't run, AppArmor logs show denials

**Solutions:**

1. Check AppArmor logs:
   ```bash
   sudo aa-status
   sudo journalctl -xe | grep apparmor
   ```

2. Set profile to complain mode:
   ```bash
   sudo aa-complain /etc/apparmor.d/usr.bin.application
   ```

3. Or disable profile:
   ```bash
   sudo aa-disable /etc/apparmor.d/usr.bin.application
   ```

### Issue: USB Devices Not Working

**Symptoms:** USB storage won't mount

**Solutions:**

1. Check USB protection settings:
   ```bash
   cat /etc/udev/rules.d/99-fortress-usb.rules
   ```

2. Temporarily disable:
   ```bash
   sudo mv /etc/udev/rules.d/99-fortress-usb.rules /etc/udev/rules.d/99-fortress-usb.rules.disabled
   sudo udevadm control --reload-rules
   ```

3. Whitelist specific device (edit rules file)

### Getting More Help:

1. Check detailed logs:
   ```bash
   sudo tail -100 /var/log/fortress_hardening.log
   ```

2. Run with verbose output:
   ```bash
   sudo ./fortress_improved.sh --dry-run --verbose
   ```

3. Check system logs:
   ```bash
   sudo journalctl -xe
   ```

4. Open GitHub issue with:
   * Distribution and version
   * Security level used
   * Error messages
   * Log excerpts

---

## Advanced Usage

### Custom Configuration File:

Create `fortress.conf`:

```bash
# Custom hardening configuration
SECURITY_LEVEL="high"
DISABLE_MODULES="fail2ban,usb_protection"
ENABLE_MODULES="system_update,ssh_hardening,firewall,apparmor"
```

Run with:

```bash
sudo ./fortress_improved.sh -c fortress.conf
```

### Automated Deployment:

**For multiple servers:**

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

Create custom modules by adding to script:

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

### Minimum Requirements:

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

### Not Required:

* SELinux (script uses AppArmor)
* Specific kernel version
* Commercial software
* Paid subscriptions

### Incompatible With:

* Non-Debian distributions (Fedora, Arch, etc.)
* Extremely old systems (Debian < 11)
* Systems with conflicting security tools
* Docker containers (limited functionality)

---

## Security Compliance

This script helps implement controls from:

* **DISA STIG** (Defense Information Systems Agency Security Technical Implementation Guide)
* **CIS Benchmarks** (Center for Internet Security)
* **NIST 800-53** (National Institute of Standards and Technology)
* **PCI-DSS** (Payment Card Industry Data Security Standard) - partial
* **HIPAA** (Health Insurance Portability and Accountability Act) - partial

**Important:** This provides a foundation, not complete compliance. Professional assessment required for:

* PCI-DSS certification
* HIPAA compliance
* SOC 2 audit
* ISO 27001 certification
* Government contracts

**What you still need for compliance:**

* Professional security assessment
* Vulnerability scanning
* Penetration testing
* Security awareness training
* Incident response plan
* Disaster recovery plan
* Encryption at rest
* Data classification
* Access control policies
* Regular audits

---

## License & Support

### License:

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**

You are free to:

* Share - copy and redistribute
* Adapt - remix, transform, and build upon

Under these terms:

* **Attribution** - Give appropriate credit
* **NonCommercial** - Not for commercial use
* **No additional restrictions**

Full license: https://creativecommons.org/licenses/by-nc/4.0/

### Commercial Use:

For commercial licensing:

* Email: cyberjunk77@protonmail.com
* Subject: "Commercial License Request"

### Support:

**Community Support (Free):**

* GitHub Issues
* Documentation
* Best-effort responses

**Commercial Support (Paid):**

* Priority responses
* Custom development
* Professional consultation
* Training and workshops

---

## Version History

### v5.0 (2025-11-16) - Educational Edition

**MAJOR REWRITE** - Complete philosophical shift

**Removed (Security Theater):**

* AIDE - Can't detect kernel rootkits, replaced with dpkg verification
* IPv6 disable - Not a security feature
* ClamAV - Minimal Linux benefit
* lynis_audit - Run separately
* rootkit_scanner - False sense of security

**Added (Real Security):**

* Educational mode (--explain flag)
* Secure Boot verification
* Package verification (dpkg-based, weekly cron)
* Intelligent module recommendations
* SSH lockout prevention (multiple safety checks)
* Honest limitation statements

**Improved:**

* fail2ban - Now optional and contextual
* SSH hardening - Explicit key confirmation required
* Boot security - Verifies Secure Boot status
* All modules - Include educational explanations

**Philosophy:** From "automate everything" to "educate and execute intelligently"

### v4.2 (2025-11-07)

* Fixed premature exit at 4% issue
* Fixed show_progress() causing immediate exit with set -e
* Changed progress bar to use if statement (safe with set -e)
* Added explicit return 0 to all module functions

### v4.1

* Improved APT lock handling
* Fixed progress bar advancement
* Better error recovery
* Enhanced user feedback

### v4.0

* Fixed wait_for_apt() hanging
* Improved lock file detection
* Better timeout handling
* Fixed various bugs

### v3.x and earlier

* Initial releases
* Basic hardening features
* Module system implementation

---

## Additional Resources

### Official Documentation:

**Security Guides:**

* [Ubuntu Security](https://ubuntu.com/security)
* [Debian Security](https://www.debian.org/security/)
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

**Tools Documentation:**

* [UFW Documentation](https://help.ubuntu.com/community/UFW)
* [AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)
* [Auditd Manual](https://linux.die.net/man/8/auditd)
* [fail2ban Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)

### Related Projects:

**Security Hardening:**

* [Dev-Sec Hardening Framework](https://dev-sec.io/)
* [Ansible Hardening](https://github.com/openstack/ansible-hardening)
* [Lynis](https://cisofy.com/lynis/) - Security auditing tool
* [OpenSCAP](https://www.open-scap.org/) - Security compliance tool
* [Bastille Linux](http://bastille-linux.sourceforge.net/) - Hardening toolkit

### Learning Resources:

**Beginner:**

* [Linux Journey](https://linuxjourney.com/) - Learn Linux basics
* [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/) - Security challenges
* [Cybrary](https://www.cybrary.it/) - Free security training

**Intermediate:**

* [Defensive Security](https://tryhackme.com/paths) - TryHackMe paths
* [Linux Academy](https://linuxacademy.com/) - Linux training
* [SANS Reading Room](https://www.sans.org/white-papers/) - Security papers

**Advanced:**

* [Exploit Education](https://exploit.education/) - Security exercises
* [PentesterLab](https://pentesterlab.com/) - Web security
* [HackTheBox](https://www.hackthebox.com/) - Security challenges

### Books:

* **"Linux Basics for Hackers"** - OccupyTheWeb
* **"Practical Linux Security"** - Michael Boelen
* **"Linux Security Cookbook"** - Gregor N. Purdy
* **"The Practice of Network Security Monitoring"** - Richard Bejtlich

### YouTube Channels:

* NetworkChuck - Linux and security basics
* LiveOverflow - Security research and exploitation
* IppSec - HackTheBox walkthroughs
* John Hammond - CTF challenges and security

---

**Quick links:**

* Documentation is this README
* [Report Bug](https://github.com/captainzero93/security_harden_linux/issues/new)

---

## Important Legal Disclaimer

**READ BEFORE USE**

### No Warranty

This script is provided "AS IS" without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.

### Compliance

This script provides a security foundation, not complete compliance with any framework. Professional assessment and additional controls are required for PCI-DSS, HIPAA, SOC 2, or similar standards. Consult qualified security professionals for compliance requirements.

### Limitations

This script does not:

* Guarantee absolute security (no system is 100% secure)
* Replace professional security assessment
* Provide monitoring or incident response
* Implement application-specific security
* Configure backups or disaster recovery
* Provide encryption at rest
* Replace security awareness training
* Detect all types of malware or rootkits
* Protect against zero-day exploits
* Guarantee compliance with any standard

### v5.0 Specific Limitations

**What v5.0 CAN'T do:**

* Automatically enable Secure Boot (requires BIOS configuration)
* Detect kernel-level rootkits on live systems
* Protect against all physical access attacks
* Prevent attacks on allowed network ports
* Replace application-level security

**What v5.0 IS honest about:**

* Package verification can't detect sophisticated rootkits
* fail2ban only blocks IPs (easily bypassed)
* SSH hardening can't stop attacks using valid keys
* AppArmor can be bypassed by kernel exploits
* System updates are more important than any hardening

### Liability

To the maximum extent permitted by law:

* The authors and contributors disclaim all liability for any damages arising from use of this script
* Users assume all risk associated with use
* This includes but is not limited to: data loss, system damage, service disruption, security breaches, compliance violations, or financial losses

### Support Disclaimer

* Support is provided on a best-effort basis with no guaranteed response time
* No service level agreements (SLAs)
* Bug fixes and updates provided when possible, not guaranteed

**BY USING THIS SCRIPT, YOU ACKNOWLEDGE THAT YOU HAVE READ, UNDERSTOOD, AND AGREE TO THESE TERMS.**

---

## Contact & Support

### Getting Help:

**Before asking for help:**

1. Read this README thoroughly
2. Check existing [GitHub Issues](https://github.com/captainzero93/security_harden_linux/issues)
3. Review [Troubleshooting](#troubleshooting) section
4. Run with `--verbose` and check logs at `/var/log/fortress_hardening.log`

**Security Vulnerabilities:**

* **DO NOT** open a public issue
* Email directly: [cyberjunk77@protonmail.com](mailto:cyberjunk77@protonmail.com)
* Use subject: "SECURITY: [brief description]"
* Response target: within 48 hours

**Note:** all support is provided on best-effort basis.

### Commercial Support:

For commercial licensing, professional support, or consulting services:

* [cyberjunk77@protonmail.com](mailto:cyberjunk77@protonmail.com)

**Services available:**

* Custom script development
* Professional security assessment
* Compliance consulting
* Training and workshops
* Priority support contracts

---

## Quick Reference Card

```
═══════════════════════════════════════════════════════════════════
                    FORTRESS.SH QUICK REFERENCE
═══════════════════════════════════════════════════════════════════

ESSENTIAL COMMANDS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Learn:        sudo ./fortress_improved.sh --explain --dry-run
Preview:      sudo ./fortress_improved.sh --dry-run -v
Apply:        sudo ./fortress_improved.sh
Report:       cat /root/fortress_report_*.html
Help:         sudo ./fortress_improved.sh --help
List modules: sudo ./fortress_improved.sh --list-modules

SECURITY LEVELS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Desktop:      sudo ./fortress_improved.sh -l moderate
Server:       sudo ./fortress_improved.sh -l high -n
Maximum:      sudo ./fortress_improved.sh -l paranoid
Basic:        sudo ./fortress_improved.sh -l low

MODULE SELECTION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Enable:       sudo ./fortress_improved.sh -e module1,module2
Disable:      sudo ./fortress_improved.sh -x module1,module2
Educational:  sudo ./fortress_improved.sh --explain

MONITORING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Firewall:     sudo ufw status
Fail2ban:     sudo fail2ban-client status (if installed)
Unban IP:     sudo fail2ban-client set sshd unbanip IP
Audit:        sudo ausearch -m USER_LOGIN -ts recent
AppArmor:     sudo aa-status
Logs:         sudo tail -f /var/log/fortress_hardening.log

FILE CHECKS (v5.0):
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

QUICK FIXES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Allow port:   sudo ufw allow PORT/tcp
Stop service: sudo systemctl stop SERVICE

RESOURCES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GitHub:       https://github.com/captainzero93/security_harden_linux
Issues:       https://github.com/captainzero93/security_harden_linux/issues

```

---

**Star this repo if it helped you.**

**Version:** 5.0 | **Author:** captainzero93 |

**GitHub:** https://github.com/captainzero93/

---
