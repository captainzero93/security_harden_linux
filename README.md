# FORTRESS.SH :: Debian Linux Defence Configuration

**One-command security hardening that implements many enterprise-grade protections (DISA STIG + CIS) while allowing the user to decide the level of protection / use trade-off. This enables casual use and more strict.**

**Version 4.2** - Critical Fixes for Module(s) Execution - Tested WORKING on Debian 13

[![License](https://img.shields.io/badge/License-CC%20BY--NC%204.0-blue.svg)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%2B-orange.svg)](https://ubuntu.com/)
[![Kubuntu](https://img.shields.io/badge/Kubuntu-24.04%2B-blue.svg)](https://kubuntu.org/)
[![Debian](https://img.shields.io/badge/Debian-11%2B%20%7C%2013-red.svg)](https://www.debian.org/)
[![Linux Mint](https://img.shields.io/badge/Linux%20Mint-21%2B-87CF3E.svg)](https://linuxmint.com/)
[![Pop!\_OS](https://img.shields.io/badge/Pop!__OS-22.04%2B-48B9C7.svg)](https://pop.system76.com/)
[![Version](https://img.shields.io/badge/Version-4.1-green.svg)]()

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/captainzero)

---

## **CRITICAL WARNING FOR REMOTE SERVER USERS**

**REMOTE SERVER USERS**: Set up SSH keys FIRST or you WILL be locked out.

---

## 30-Second Quickstart

### Desktop Users:

```bash
# Download and make executable
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh
chmod +x improved_harden_linux.sh

# Preview changes (recommended)
sudo ./improved_harden_linux.sh --dry-run

# Apply with defaults
sudo ./improved_harden_linux.sh

# Answer the interactive prompts, then reboot when done
```

### Server Users:

```bash
# FIRST: Set up SSH keys (CRITICAL - see full warning below)
ssh-keygen -t ed25519
ssh-copy-id user@your-server

# Then run hardening
sudo ./improved_harden_linux.sh -l high -n
```

**Something broke?** `sudo ./improved_harden_linux.sh --restore`

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
* [What's New in v4.1](#whats-new-in-v41)
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

* **Game on Linux** and want to stay secure without FPS loss
* **Create art, music, or videos** without security getting in your way
* **Work from home** and need basic protection
* **Just want a secure personal computer** that works normally
* **Are tired of complicated security guides** written for sysadmins
* **Run a home server** or self-host services
* **Develop software** and want security without breaking your tools
* **Are learning Linux** and want to start with good habits

### What makes this different:

This script applies **industry-standard security WITHOUT breaking your desktop experience.** No more choosing between security and usability.

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
* Blocks repeated failed logins - automatic IP banning with Fail2Ban
* Installs antivirus - ClamAV (yes, Linux can get malware)
* Secures the kernel - protection against memory exploits and attacks
* Sets up file integrity monitoring - alerts you if system files change
* Enforces strong passwords - because "password123" is still too common
* Enables automatic security updates - patches critical bugs while you sleep
* Configures audit logging - forensics and evidence if something happens
* Applies kernel hardening - makes exploits far harder to pull off
* Secures boot process - protects against physical attacks
* Removes unnecessary packages - smaller attack surface

### Things That KEEP Working:

* Steam and all your games (zero FPS impact)
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
* **Preserves gaming functionality** - no impact on Steam, Lutris, or Proton
* **Zero performance impact** - no background processes eating CPU/GPU
* **Audio production safe** - Jack, PipeWire, ALSA untouched
* **Creative tools work** - Wacom, DaVinci, Blender all function normally
* **Bluetooth works** - headphones, mice, controllers all fine
* **Uses "moderate" security by default** - balanced, not paranoid
* **Creates automatic backups** before every change
* **One-command restore** if anything goes wrong

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
* MIDI controllers work

**3D Modeling:**

* Blender with GPU rendering
* FreeCAD, OpenSCAD work
* 3D printers remain functional
* USB dongles for licenses work

**Gaming:**

* Steam, Lutris, Heroic Launcher
* Proton compatibility layer untouched
* Anti-cheat systems work
* RGB control software functions
* Game controllers and wheels work
* VR headsets supported

---

## Critical Warning for Remote Servers

**READ THIS IF YOU'RE RUNNING THIS ON A REMOTE SERVER (VPS, cloud, etc.)**

### YOU WILL LOCK YOURSELF OUT IF YOU DON'T FOLLOW THESE STEPS:

**Before running this script on a remote server:**

1. **Set up SSH key authentication:**

```bash
# On your LOCAL machine (not the server):
ssh-keygen -t ed25519 -C "your_email@example.com"

# Copy the key to your server:
ssh-copy-id username@your-server-ip

# Test that key-based login works:
ssh username@your-server-ip

# If that works, you're safe to proceed
```

2. **Verify you have console access:**

* Cloud providers (AWS, DigitalOcean, Linode, etc.) provide web-based consoles
* Physical servers need KVM/IPMI or physical access
* VPS providers usually have VNC or serial console access

3. **Keep an SSH session open:**

* Before running the script, open a second SSH session
* Keep it open until after reboot
* If something breaks, you can fix it from that session

### Why This Matters:

This script **disables password authentication** for SSH when using "high" or "paranoid" security levels. If you don't have SSH keys set up:

* You won't be able to log in via SSH
* Password login will be disabled
* You'll need console access to fix it
* You might need to restore from backup
* Cloud providers might charge for console access

### Recovery If You Get Locked Out:

**If you can access the console:**

```bash
# Edit SSH config:
sudo nano /etc/ssh/sshd_config

# Change this line:
PasswordAuthentication no
# To:
PasswordAuthentication yes

# Restart SSH:
sudo systemctl restart sshd

# Now you can log in with password again
```

**If you can't access the console:**

You'll need to:

1. Boot from rescue mode (if your provider supports it)
2. Mount your filesystem
3. Edit `/etc/ssh/sshd_config` as shown above
4. Reboot normally

**Or restore from the automatic backup:**

```bash
# The script creates backups in /root/
ls -lh /root/security_backup_*.tar.gz

# Restore using:
sudo ./improved_harden_linux.sh --restore
```

### Safe Approach for Servers:

```bash
# 1. Test with dry-run first:
sudo ./improved_harden_linux.sh --dry-run -v

# 2. Use moderate level initially:
sudo ./improved_harden_linux.sh -l moderate -n

# 3. Verify SSH still works after reboot

# 4. Only then upgrade to high:
sudo ./improved_harden_linux.sh -l high -n
```

---

## TL;DR - Quick Commands

**First time user (recommended):**

```bash
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh
chmod +x improved_harden_linux.sh
sudo ./improved_harden_linux.sh --dry-run -v  # Preview
sudo ./improved_harden_linux.sh                # Apply
sudo reboot                                    # Reboot
```

**Desktop users:**

```bash
sudo ./improved_harden_linux.sh
```

**Servers (after SSH keys set up):**

```bash
sudo ./improved_harden_linux.sh -l high -n
```

**Something broke?**

```bash
sudo ./improved_harden_linux.sh --restore
```

**See what it will do:**

```bash
sudo ./improved_harden_linux.sh --dry-run -v
```

**Skip slow modules (AIDE, ClamAV):**

```bash
sudo ./improved_harden_linux.sh -x aide,clamav
```

**Only specific modules:**

```bash
sudo ./improved_harden_linux.sh -e firewall,ssh_hardening,fail2ban
```

**Generate security report:**

```bash
sudo ./improved_harden_linux.sh --report
```

---

## Quick Start

### Step 1: Download

```bash
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh
chmod +x improved_harden_linux.sh
```

### Step 2: Preview (Recommended)

```bash
sudo ./improved_harden_linux.sh --dry-run -v
```

This shows exactly what would change without modifying anything.

### Step 3: Apply

**Desktop users:**

```bash
sudo ./improved_harden_linux.sh
```

Answer the interactive prompts about desktop features you want to keep.

**Server users (after SSH keys set up):**

```bash
sudo ./improved_harden_linux.sh -l high -n
```

### Step 4: Reboot

```bash
sudo reboot
```

### Step 5: Verify

```bash
# Check firewall:
sudo ufw status

# Check Fail2Ban:
sudo fail2ban-client status

# Check if SSH still works (from another machine):
ssh your-username@your-server
```

**Done.** Your system is now significantly more secure.

---

## Why This Matters - Real-World Attacks

These aren't hypothetical threats. Here's what actually happens:

### SSH Brute Force (Happens Daily):

Without this script:

```
Nov 01 03:42:15 Failed password for root from 185.220.101.34
Nov 01 03:42:17 Failed password for root from 185.220.101.34
Nov 01 03:42:19 Failed password for root from 185.220.101.34
[... 10,000 more attempts ...]
```

Attackers try thousands of passwords. Eventually they might guess yours.

With this script:

```
Nov 01 03:42:15 Failed password for root from 185.220.101.34
Nov 01 03:42:17 Failed password for root from 185.220.101.34
Nov 01 03:42:19 Failed password for root from 185.220.101.34
Nov 01 03:42:19 Fail2Ban: Banned 185.220.101.34 for 1 hour
```

After 3 failed attempts, they're banned. No more tries.

### Port Scanning (Happens Hourly):

Bots constantly scan for open services:

```
Scanning 203.0.113.45...
Port 22 (SSH): OPEN
Port 80 (HTTP): OPEN
Port 3306 (MySQL): OPEN    <- Your database exposed!
Port 5432 (PostgreSQL): OPEN  <- Another database!
Port 6379 (Redis): OPEN     <- And another!
```

With UFW enabled, only the ports you actually need are accessible. Everything else is blocked.

### Kernel Exploits:

Modern kernel exploits often rely on:

* Unprivileged BPF access
* /proc/kallsyms information disclosure
* Predictable memory layouts

This script hardens kernel parameters to make these exploits much harder.

### Malware (Yes, on Linux):

Linux malware exists:

* Cryptocurrency miners (common on hacked servers)
* Botnet agents
* Ransomware (increasing)
* Backdoors and rootkits

ClamAV provides basic detection. It's not perfect, but it catches a lot.

### Real Incident Examples:

**Example 1: WordPress Site Hack**

* Attacker finds vulnerability in old WordPress plugin
* Uploads web shell to server
* Server has no AppArmor, no file integrity monitoring
* Attacker installs crypto miner
* Server runs at 100% CPU for 3 months before owner notices
* Mining profits: ~$200. Electricity costs: ~$300

With AIDE: File changes detected immediately
With AppArmor: Web shell blocked from executing
With resource limits: Miner would be constrained

**Example 2: SSH Brute Force Success**

* Server has password authentication enabled
* User password: "server2024"
* Attacker tries common passwords for 3 days
* Eventually succeeds
* Installs ransomware
* All data encrypted
* Ransom demand: $5,000

With SSH key auth: Password attacks impossible
With Fail2Ban: Attacker banned after 3 tries
With automatic updates: Vulnerabilities patched

**Example 3: Unsecured Database**

* Developer installs MySQL
* Binds to 0.0.0.0 (all interfaces)
* Uses default password
* Firewall disabled
* Database contains customer data
* Bot finds it in 6 hours
* Data exfiltrated and sold

With UFW: Only localhost can access MySQL
With strong passwords: Default passwords don't work
With audit logging: Attack detected and logged

---

## Why Each Security Measure Matters

### Firewall (UFW):

**Without it:** Every service you run is accessible from the internet
**With it:** Only explicitly allowed services are accessible
**Impact:** Prevents 90% of automated attacks

### Fail2Ban:

**Without it:** Unlimited login attempts, brute force succeeds eventually
**With it:** 3 failed attempts = IP banned for hours
**Impact:** Makes brute force attacks impossible

### SSH Hardening:

**Without it:** Password authentication, root login allowed
**With it:** Key-based auth only, no root login, strong ciphers
**Impact:** Eliminates password attacks completely

### ClamAV:

**Without it:** No malware detection
**With it:** Basic detection of known malware
**Impact:** Catches common malware, especially miners

### Audit Logging (auditd):

**Without it:** No record of system changes
**With it:** Every login, file change, and command logged
**Impact:** Forensics and incident response capability

### File Integrity (AIDE):

**Without it:** Malware can modify system files silently
**With it:** Any system file change triggers alert
**Impact:** Detects rootkits and unauthorized changes

### Kernel Hardening:

**Without it:** Kernel vulnerable to memory exploits
**With it:** ASLR, DEP, kernel pointer protection
**Impact:** Makes kernel exploits much harder

### Password Policy:

**Without it:** Users can set "password" as password
**With it:** Minimum 12 chars, complexity required
**Impact:** Prevents weak passwords

### Automatic Updates:

**Without it:** Critical patches might not be installed for weeks
**With it:** Security updates install automatically
**Impact:** Reduces vulnerability window

### AppArmor:

**Without it:** Compromised services have full system access
**With it:** Services confined to specific files/actions
**Impact:** Limits damage from compromised services

### Boot Security:

**Without it:** Attacker with physical access can boot rescue mode
**With it:** GRUB password, kernel hardening params
**Impact:** Protects against physical attacks

### USB Protection:

**Without it:** Any USB device silently accepted
**With it:** USB devices logged, malicious devices harder to use
**Impact:** Detects rubber ducky attacks

---

## What's New in v4.1

### CRITICAL FIX - Module Functions Missing Return Statements:

**Problem Resolved:**

Version 4.0 and earlier would complete the system_update module successfully, show 4% progress, then immediately exit without continuing to the next module. The script appeared to hang or terminate prematurely after the first module.

**Root Cause:**

All module functions were missing explicit `return 0` statements. In bash, when a function doesn't have an explicit return statement, it returns the exit code of the last command executed. Since `log SUCCESS "..."` was typically the last command in modules, the functions would return unpredictable exit codes. When the main execution loop checked `if "${func}"; then`, it would sometimes interpret the module as failed due to the missing explicit success return code, causing the script to terminate.

**The Fix:**

Version 4.1 adds explicit `return 0` statements to all 21 module functions to ensure each one properly signals successful completion to the execution loop.

**Technical Changes:**

```bash
# Before (v4.0) - Missing explicit return statement:
module_system_update() {
    # ... commands ...
    log SUCCESS "System update completed"
}  # Returns exit code of log function (unpredictable)

# After (v4.1) - Explicit success return:
module_system_update() {
    # ... commands ...
    log SUCCESS "System update completed"
    return 0  # Explicitly signals success
}
```

**Modules Fixed (All 21):**

* module_system_update
* module_firewall
* module_fail2ban
* module_clamav
* module_root_access
* module_ssh_hardening
* module_packages
* module_audit
* module_filesystems
* module_boot_security
* module_ipv6
* module_apparmor
* module_ntp
* module_aide
* module_sysctl
* module_password_policy
* module_automatic_updates
* module_rootkit_scanner
* module_usb_protection
* module_secure_shared_memory
* module_lynis_audit

**User Experience Improvements:**

* Script now executes all 21 modules sequentially without premature termination
* Progress advances correctly from 4% through 100%
* Module completion status now reliably indicates success or failure
* Execution loop correctly identifies successful module completions
* No more mysterious exits after the first module

### Previous Fixes Maintained from v4.0:

**1. APT Lock Handling:**

* Fixed wait_for_apt() hanging with stale locks
* Automatic detection and removal of stale APT locks
* Interactive force-unlock option at 60 seconds
* Better timeout handling and user feedback

**2. Enhanced Stability:**

* Fixed progress bar display between modules
* Improved terminal output flushing
* Better handling of interrupted operations
* More robust error recovery

**3. OS Detection:**

* Fixed readonly variable errors in /etc/os-release parsing
* Safe extraction of OS information
* Better fallback to lsb_release when needed
* Enhanced Debian 13 (Trixie) compatibility

**4. Documentation:**

* Comprehensive fix documentation
* Technical explination available
* Before/after code comparison
* Troubleshooting guides

### For Upgraders from v4.0:

No breaking changes. The fix is transparent - the script should simply completes all modules now:

```bash
# Download v4.1:
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh
chmod +x improved_harden_linux.sh

# Run normally - no special steps needed:
sudo ./improved_harden_linux.sh -v

# Script will now complete all 21 modules without premature exit
```

Your existing backups remain fully compatible.

### What You'll Notice:

**Before (v4.0):**
```
[SUCCESS] Module system_update completed
[==------------------------------------------------]   4% - Completed Update system
[Script exits immediately - no further modules execute]
```

**After (v4.1):**
```
[SUCCESS] Module system_update completed
[==------------------------------------------------]   4% - Completed Update system
[INFO] Starting module 2/21: Configure auditd logging
[INFO] Installing auditd...
[====----------------------------------------------]   9% - Completed Configure auditd
[INFO] Starting module 3/21: Run Lynis security audit
[======--------------------------------------------]  14% - Completed Run Lynis
[Continues smoothly to 100%]
```

### Compatibility:

* Full support for Debian 13 (Trixie)
* Ubuntu 25.10 (Oracular) - working
* Kubuntu 24.04+ - tested
* All previously supported distributions - no regressions
* Maintains all v4.0 improvements for APT lock handling

### Testing:

Testing performed on:

* Debian 13 (Trixie) - all modules execute successfully
* Fresh systems - completes all 21 modules
* Systems with APT lock issues - handled by v4.0 improvements
* Interactive mode - all prompts working correctly
* Non-interactive mode - completed successfully
* All security levels (low/moderate/high/paranoid) - working



---

## Installation

### Requirements Check:

```bash
# Supported distributions:
# - Ubuntu 22.04+ / 25.10+
# - Kubuntu 24.04+
# - Debian 11+ / 13
# - Linux Mint 21+
# - Pop!_OS 22.04+

# Check your version:
cat /etc/os-release
```

### Method 1: Direct Download (Recommended)

```bash
# Download the script:
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh

# Make it executable:
chmod +x improved_harden_linux.sh

```

### Method 2: Git Clone

```bash
git clone https://github.com/captainzero93/security_harden_linux.git
cd security_harden_linux
chmod +x improved_harden_linux.sh
```

### Method 3: Direct Run (Advanced Users Only)

```bash
# ONLY if you trust the source:
wget -O - https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh | sudo bash
```

### Verification (Recommended):

```bash
# View the script before running:
less improved_harden_linux.sh

# Or with syntax highlighting:
nano improved_harden_linux.sh
```

---

## Usage Guide

### Basic Usage:

**Preview Changes (Recommended First Step):**

```bash
sudo ./improved_harden_linux.sh --dry-run -v
```

Shows exactly what would be changed without modifying anything.

**Apply with Defaults (Moderate Security):**

```bash
sudo ./improved_harden_linux.sh
```

Interactive mode - asks questions about desktop features.

**Non-Interactive Mode (Servers):**

```bash
sudo ./improved_harden_linux.sh -n
```

Runs with sensible defaults, no prompts.

### Command-Line Options:

```
Usage: sudo ./improved_harden_linux.sh [OPTIONS]

OPTIONS:
    -h, --help              Display help message
    -v, --verbose           Enable verbose output
    -n, --non-interactive   Run without user prompts
    -d, --dry-run           Perform a dry run without changes
    -l, --level LEVEL       Set security level (low|moderate|high|paranoid)
    -e, --enable MODULES    Enable specific modules (comma-separated)
    -x, --disable MODULES   Disable specific modules (comma-separated)
    -r, --restore [FILE]    Restore from backup
    -R, --report            Generate security report only
    -c, --config FILE       Use custom configuration file
    --version               Display script version
    --list-modules          List available security modules
```

### Security Levels:

**low** - Basic security (desktop-friendly):

* Firewall enabled with desktop services allowed
* SSH hardening (but password auth still works)
* Fail2Ban with lenient settings
* Minimal impact on usability

**moderate** (DEFAULT) - Balanced security:

* All basic protections
* Stronger SSH settings (keys recommended)
* File integrity monitoring
* Audit logging
* Recommended for desktops

**high** - Strong security (servers):

* SSH key authentication required
* Strict firewall rules
* Aggressive intrusion prevention
* Full audit logging
* Some desktop features may need manual allow-listing

**paranoid** - Maximum security (experts only):

* All protections at maximum
* IPv6 disabled (unless needed)
* Minimal services
* Strict access controls
* Significant usability impact

### Examples:

**Desktop User - First Time:**

```bash
# Preview:
sudo ./improved_harden_linux.sh --dry-run -v

# Apply moderate security:
sudo ./improved_harden_linux.sh

# Reboot:
sudo reboot
```

**Development Server:**

```bash
# Moderate security, non-interactive:
sudo ./improved_harden_linux.sh -l moderate -n
```

**Production Server (After SSH Keys Set Up):**

```bash
# High security, non-interactive:
sudo ./improved_harden_linux.sh -l high -n
```

**Custom Module Selection:**

```bash
# Only firewall, SSH, and Fail2Ban:
sudo ./improved_harden_linux.sh -e firewall,ssh_hardening,fail2ban

# Everything except ClamAV (slow on low-power systems):
sudo ./improved_harden_linux.sh -x clamav

# Specific level with custom modules:
sudo ./improved_harden_linux.sh -l high -x usb_protection,clamav
```

**Using Configuration File:**

```bash
# Create config file (see hardening.conf.example):
cp hardening.conf.example hardening.conf
nano hardening.conf

# Run with config:
sudo ./improved_harden_linux.sh -c hardening.conf
```

---

## Security Levels Explained

### Low Security:

**Best for:** brand new Linux users, systems where security isn't critical

**What it includes:**

* Basic firewall (UFW) with desktop ports allowed
* SSH hardening (passwords still work)
* Fail2Ban with lenient settings (5 attempts before ban)
* Automatic security updates
* Basic package cleanup

**What it skips:**

* Aggressive kernel hardening
* Mandatory SSH keys
* AIDE file integrity checks
* Rootkit scanning
* USB device logging

**Impact:** minimal. You probably won't notice any changes.

### Moderate Security (DEFAULT):

**Best for:** desktop users, home servers, developers

**What it includes:**
Everything from Low, plus:

* Stronger SSH settings (keys strongly recommended)
* File integrity monitoring (AIDE)
* Comprehensive audit logging
* Kernel hardening (sysctl parameters)
* AppArmor enforcement
* Rootkit detection
* Password policy enforcement

**What it balances:**

* Desktop features work (KDE Connect, mDNS, Samba)
* Development tools function (Docker, databases)
* Gaming unaffected (Steam, Discord)
* Security significantly improved

**Impact:** barely noticeable. Your system feels the same but is much more secure.

### High Security:

**Best for:** production servers, systems handling sensitive data

**What it includes:**
Everything from Moderate, plus:

* SSH key authentication REQUIRED (no passwords)
* Strict firewall rules
* USB device protection
* More aggressive Fail2Ban (3 attempts before ban)
* Comprehensive security scanning
* Stricter password policies
* More audit logging

**Trade-offs:**

* Must use SSH keys (password login disabled)
* Some desktop features require manual configuration
* Stricter network controls
* More aggressive security = more maintenance

**Impact:** moderate. You'll notice security prompts and may need to configure some services manually.

### Paranoid Security:

**Best for:** security researchers, systems under active threat, compliance requirements

**What it includes:**
Everything from High, plus:

* Maximum kernel hardening
* IPv6 disabled (unless explicitly needed)
* Minimal services
* Strictest password policies
* Maximum audit logging
* Most restrictive firewall rules
* USB ports can be disabled entirely

**Trade-offs:**

* Significant usability impact
* Many services require manual configuration
* Some applications may not work
* Frequent security prompts
* Requires deep Linux knowledge to maintain

### Comparison Table:

| Feature           | Low     | Moderate    | High         | Paranoid |
| ----------------- | ------- | ----------- | ------------ | -------- |
| Firewall          | Basic   | Standard    | Strict       | Maximum  |
| SSH Keys Required | No      | Recommended | Yes          | Yes      |
| Fail2Ban Attempts | 5       | 4           | 3            | 2        |
| File Integrity    | No      | Yes         | Yes          | Yes      |
| Audit Logging     | Minimal | Standard    | Detailed     | Maximum  |
| USB Protection    | No      | Optional    | Yes          | Strict   |
| IPv6              | Enabled | Enabled     | Configurable | Disabled |
| Desktop Features  | All     | Most        | Some         | Minimal  |
| Maintenance       | Low     | Low         | Medium       | High     |

---

## Available Modules

The script is modular. You can enable/disable specific components:

### Core Modules:

**system_update**

* Updates all packages to latest versions
* Fixes security vulnerabilities
* Dependency: None
* Runtime: 2-10 minutes (depends on updates available)

**firewall**

* Configures UFW (Uncomplicated Firewall)
* Blocks all except allowed services
* Desktop-aware (preserves gaming, KDE Connect, etc.)
* Dependency: system_update
* Runtime: 1 minute

**ssh_hardening**

* Disables root login
* Enforces strong ciphers
* Disables password auth (moderate+ levels)
* Changes default port (optional)
* Dependency: system_update
* Runtime: 1 minute

**fail2ban**

* Automatic IP banning after failed logins
* Protects SSH, web services, mail servers
* Configurable attempt threshold
* Dependency: system_update, firewall
* Runtime: 2 minutes

### Security Tools:

**clamav**

* Open-source antivirus
* Scans for malware, viruses, trojans
* Updates signatures automatically
* Dependency: system_update
* Runtime: 5 minutes (signature download)

**aide**

* File integrity monitoring
* Detects unauthorized file changes
* Creates baseline of system files
* Dependency: system_update
* Runtime: 10-20 minutes (initial database creation)

**rootkit_scanner**

* Installs rkhunter and chkrootkit
* Scans for known rootkits
* Weekly automated scans
* Dependency: system_update
* Runtime: 5 minutes

**audit**

* Comprehensive system auditing (auditd)
* Logs privileged operations
* Required for compliance (PCI-DSS, HIPAA)
* Dependency: system_update
* Runtime: 2 minutes

### System Hardening:

**sysctl**

* Kernel parameter hardening
* Enables ASLR, DEP, SYN cookies
* Protects against IP spoofing
* Networking stack hardening
* Dependency: None
* Runtime: 1 minute

**apparmor**

* Mandatory Access Control (MAC)
* Confines programs to limited resources
* Profiles for common services
* Dependency: system_update
* Runtime: 3 minutes

**boot_security**

* GRUB password protection
* Secures boot parameters
* Protects against boot-time attacks
* Dependency: None
* Runtime: 1 minute

**filesystems**

* Disables unused filesystems (cramfs, freevxfs, etc.)
* Reduces attack surface
* Prevents automatic mounting of dangerous filesystems
* Dependency: None
* Runtime: 1 minute

### Access Control:

**root_access**

* Disables direct root login
* Forces sudo usage (better audit trail)
* Dependency: None
* Runtime: 1 minute

**password_policy**

* Enforces strong passwords
* Minimum length, complexity requirements
* Password history and age
* Dependency: None
* Runtime: 1 minute

**usb_protection**

* Logs all USB device connections
* Optional: block USB storage devices
* Useful for corporate/compliance environments
* Dependency: None
* Runtime: 1 minute

### Maintenance:

**automatic_updates**

* Enables unattended-upgrades
* Automatic security patch installation
* Configurable update window
* Dependency: None
* Runtime: 2 minutes

**packages**

* Removes unnecessary packages
* Cleans up unused dependencies
* Reduces attack surface
* Dependency: None
* Runtime: 2-5 minutes

**ntp**

* Configure time synchronization
* Important for logging and certificates
* Uses systemd-timesyncd
* Dependency: system_update
* Runtime: 1 minute

### Additional Modules:

**ipv6**

* Configure IPv6 settings
* Can disable if not needed
* Reduces attack surface
* Dependency: None
* Runtime: 1 minute

**secure_shared_memory**

* Prevents execution from /dev/shm
* Blocks privilege escalation vectors
* Dependency: None
* Runtime: 1 minute

**lynis_audit**

* Comprehensive security audit
* Generates detailed security report
* Identifies additional improvements
* Dependency: None
* Runtime: 5 minutes

### Module Dependencies:

Most modules are independent, but some require others:

* fail2ban requires firewall
* ssh_hardening requires system_update
* Most security tools require system_update

The script handles dependencies automatically - you don't need to manually order them.

### Listing Available Modules:

```bash
sudo ./improved_harden_linux.sh --list-modules
```

### Running Specific Modules:

```bash
# Only firewall and SSH:
sudo ./improved_harden_linux.sh -e firewall,ssh_hardening

# Everything except AIDE (slow):
sudo ./improved_harden_linux.sh -x aide

# Only essential modules for a quick run:
sudo ./improved_harden_linux.sh -e system_update,firewall,fail2ban,ssh_hardening
```

---

## What Gets Hardened?

### Firewall Configuration:

* **UFW enabled** with default deny incoming, allow outgoing
* **Desktop exceptions:** Steam, Discord, KDE Connect, mDNS, Samba (if you choose)
* **Rate limiting** on SSH port
* **IPv6** firewall rules (if IPv6 enabled)
* **Logging** of blocked connections

### SSH Hardening:

* **Protocol 2 only** (SSHv1 disabled)
* **Root login disabled** (must use sudo)
* **Strong ciphers only** (modern algorithms)
* **Password authentication disabled** (moderate+ levels)
* **Key-based authentication required**
* **MaxAuthTries reduced** to 3
* **ClientAliveInterval** set to detect dead connections
* **X11Forwarding disabled** (security risk)
* **Optional:** change default port from 22

### Fail2Ban Protection:

* **SSH jail** enabled (4 failed attempts = temporary ban at moderate level)
* **Recidive jail** (repeated offenders get longer bans)
* **Email notifications** (if configured)
* **Aggressive mode** at high/paranoid levels

### Kernel Hardening (sysctl):

```
# Network security:
- IP forwarding disabled
- ICMP redirects blocked
- Source routing disabled
- SYN cookies enabled
- Reverse path filtering

# Memory protections:
- ASLR enabled (randomize memory addresses)
- DEP enabled (no-execute memory pages)
- kptr_restrict (hide kernel pointers)

# Process restrictions:
- dmesg_restrict (hide kernel messages)
- ptrace restrictions
```

### File System Protections:

* **Unused filesystems disabled:** cramfs, freevxfs, jffs2, hfs, hfsplus, udf
* **/dev/shm secured:** noexec, nosuid, nodev
* **Automatic mounting of suspicious filesystems prevented**

### Boot Security:

* **GRUB password protection** (prevents boot parameter tampering)
* **Kernel parameter protections**
* **Boot-time integrity checks**

### Password Policy:

* **Minimum length:** 12 characters (14 at high, 16 at paranoid)
* **Complexity:** must include upper, lower, numbers, special chars
* **History:** last 5 passwords remembered
* **Age:** maximum 90 days (60 at high, 30 at paranoid)
* **Retry:** 3 attempts before lockout

### Audit Logging (auditd):

Tracks:

* All privileged operations (sudo commands)
* Authentication attempts (successful and failed)
* File access to sensitive directories (/etc/passwd, /etc/shadow)
* User account modifications
* System time changes
* Kernel module loading

### AppArmor Profiles:

Enabled for:

* System services (systemd, dbus)
* Network services (Apache, Nginx, MySQL if installed)
* User applications (Firefox, Chromium, Thunderbird)
* Custom profiles for high-risk services

### File Integrity (AIDE):

* **Baseline** created of system files
* **Daily checks** for unauthorized changes
* **Email alerts** on modifications (if configured)
* **Checksums** of critical files stored securely

### Antivirus (ClamAV):

* **Signature updates:** automatic daily updates
* **Scheduled scans:** weekly full system scan (configurable)
* **Real-time protection:** optional (performance impact)
* **Quarantine:** infected files can be isolated

### USB Device Protection:

* **All USB events logged** (device connect/disconnect)
* **Optional:** block USB storage devices entirely
* **Whitelist mode:** only allow specific devices (paranoid level)

### Automatic Updates:

* **Security updates:** installed automatically
* **Update window:** configurable (default: daily at 6 AM)
* **Notifications:** email on updates (if configured)
* **Safety:** only security patches, not major version upgrades

---

## Emergency Recovery

### If Something Goes Wrong:

**The script automatically creates backups before making ANY changes.**

### Quick Restore:

```bash
# Restore all changes:
sudo ./improved_harden_linux.sh --restore

# Restore specific backup file:
sudo ./improved_harden_linux.sh --restore /root/security_backup_YYYYMMDD_HHMMSS.tar.gz
```

### Manual Recovery (If Script Isn't Working):

**Restore SSH Access:**

```bash
# From console or VNC (not SSH):
sudo cp /etc/ssh/sshd_config.backup.* /etc/ssh/sshd_config
sudo systemctl restart sshd
```

**Disable Firewall:**

```bash
sudo ufw disable
```

**Stop Fail2Ban:**

```bash
sudo systemctl stop fail2ban
sudo systemctl disable fail2ban
```

**Restore All Configs Manually:**

```bash
cd /root
tar -xzf security_backup_YYYYMMDD_HHMMSS.tar.gz
sudo cp -r backup/etc/ssh/* /etc/ssh/
sudo cp -r backup/etc/ufw/* /etc/ufw/
sudo cp backup/etc/sysctl.d/* /etc/sysctl.d/
# Restart affected services:
sudo systemctl restart sshd
sudo ufw reload
sudo sysctl --system
```

**Boot Issues (Recovery Mode):**

1. Reboot and select "Advanced options" in GRUB
2. Choose "Recovery mode"
3. Select "root - Drop to root shell prompt"
4. Remount filesystem as read-write:

   ```bash
   mount -o remount,rw /
   ```
5. Restore GRUB config:

   ```bash
   cp /etc/default/grub.backup.* /etc/default/grub
   update-grub
   ```
6. Reboot:

   ```bash
   reboot
   ```

### Backup Locations:

All backups are stored in `/root/`:

* Main backup: `/root/security_backup_YYYYMMDD_HHMMSS.tar.gz`
* SHA256 checksum: `/root/security_backup_YYYYMMDD_HHMMSS.tar.gz.sha256`
* Individual file backups: `/etc/config_file.backup.TIMESTAMP`

### Verify Backup Integrity:

```bash
sha256sum -c /root/security_backup_*.tar.gz.sha256
```

### List Backups:

```bash
ls -lht /root/security_backup_*.tar.gz
```

---

## Common Questions

### Will this break my system?

The script creates automatic backups and is designed to be reversible. If something does go wrong, restore with one command.

### Will games still work?

Yes. Steam, Lutris, Proton, Discord, and gaming services work normally. The firewall can allow gaming ports. There is no expected FPS impact.

### Can I run this on a production server?

Yes, but set up SSH keys FIRST, then run in dry-run mode to preview changes. Use high or paranoid security level for production.

### What about Docker/VMs/development tools?

They work. Docker, VirtualBox, QEMU, databases, and development tools are preserved.

### How long does it take?

Typically 5-15 minutes on most systems, depending on updates and AIDE initialization.

### Do I need to reboot?

Yes, to apply kernel parameter changes and ensure everything is working correctly.

### Can I undo everything?

Yes. Use `--restore` to revert changes.

### What if I use KDE Connect/Samba/mDNS?

The script can keep desktop features working. If you use KDE Connect, Samba, or network discovery, select the corresponding options.

### Is this safe for my home server?

Yes. Many users run this on Plex servers, NAS systems, and home automation setups.

### What about Raspberry Pi?

It should work on Raspberry Pi OS (Debian-based), but AIDE database creation may take longer on slower hardware.

### Can I run this multiple times?

Yes. It's safe to run repeatedly. The script detects existing configurations and updates them.

### What about SELinux vs AppArmor?

This script uses AppArmor (standard on Ubuntu/Debian). SELinux is different and not used here.

### Will automatic updates break things?

Automatic updates are security patches only, not major version upgrades.

### What if I don't have SSH?

The SSH hardening module only runs if SSH is installed.

### Can I use this on Arch/Fedora/other distros?

Not yet. Currently supports Ubuntu, Debian, Kubuntu, Mint, and Pop!_OS.

### Is this overkill for a desktop?

No. The "moderate" level provides essential security without usability impact.

---

## Troubleshooting

### General Debugging:

**Enable verbose mode:**

```bash
sudo ./improved_harden_linux.sh --verbose
```

**Check the log:**

```bash
sudo tail -f /var/log/security_hardening.log
```

**Run dry-run to see what would change:**

```bash
sudo ./improved_harden_linux.sh --dry-run -v
```

### Specific Issues:

#### SSH Connection Refused After Hardening:

**Symptom:** can't SSH into the server
**Cause:** SSH keys not set up or port changed

**Fix:**

```bash
# From console/VNC access:
sudo nano /etc/ssh/sshd_config
# Temporarily relax if needed:
#   PasswordAuthentication yes
#   PermitRootLogin yes
sudo systemctl restart sshd

# Test and fix key authentication
# Then re-run hardening with SSH keys working
```

#### Firewall Blocking Expected Services:

**Symptom:** can't access a service that should be working
**Cause:** port not allowed through firewall

**Fix:**

```bash
# List current rules:
sudo ufw status numbered

# Allow specific port:
sudo ufw allow PORT/tcp

# Allow specific service:
sudo ufw allow SERVICE
```

#### Fail2Ban Banned Your Own IP:

**Symptom:** can't connect after failed password attempts
**Cause:** Fail2Ban banned your IP

**Fix:**

```bash
# Check if you're banned:
sudo fail2ban-client status sshd

# Unban your IP:
sudo fail2ban-client set sshd unbanip YOUR_IP

# Whitelist your IP permanently:
sudo nano /etc/fail2ban/jail.local
# Add under [DEFAULT]:
#   ignoreip = 127.0.0.1/8 YOUR_IP
sudo systemctl restart fail2ban
```

#### AIDE Taking Too Long:

**Symptom:** initial AIDE database creation taking 30+ minutes
**Cause:** scanning entire filesystem on slow hardware

**Fix:**

```bash
# Skip AIDE initially:
sudo ./improved_harden_linux.sh -x aide

# Or reduce scope in /etc/aide/aide.conf:
sudo nano /etc/aide/aide.conf
# Comment out: /usr
# Focus on: /etc, /bin, /sbin, /lib
sudo aideinit
```

#### ClamAV High Memory Usage:

**Symptom:** system slow after ClamAV installation
**Cause:** ClamAV daemon uses significant RAM

**Fix:**

```bash
# Stop real-time scanning:
sudo systemctl stop clamav-daemon

# Use manual scans only:
sudo systemctl disable clamav-daemon

# Or skip ClamAV entirely:
sudo ./improved_harden_linux.sh -x clamav
```

#### USB Devices Not Working:

**Symptom:** USB storage not mounting
**Cause:** USB protection module blocked USB storage

**Fix:**

```bash
# Check current USB rules:
ls /etc/udev/rules.d/*usb*

# Temporarily disable:
sudo rm /etc/udev/rules.d/99-usb-authorization.rules
sudo udevadm control --reload-rules

# Or skip USB protection:
sudo ./improved_harden_linux.sh -x usb_protection
```

#### Audit Logs Filling Disk:

**Symptom:** /var/log/audit/ using too much space
**Cause:** audit logging set to maximum

**Fix:**

```bash
# Check current size:
du -sh /var/log/audit/

# Reduce audit logging:
sudo nano /etc/audit/rules.d/hardening.rules
# Comment out verbose rules

# Reload:
sudo service auditd restart

# Set up log rotation:
sudo nano /etc/audit/auditd.conf
# Set: max_log_file_action = ROTATE
```

#### Desktop Features Not Working:

**Symptom:** KDE Connect, Samba, or mDNS not working
**Cause:** firewall blocking required ports

**Fix:**

```bash
# KDE Connect:
sudo ufw allow 1714:1764/tcp
sudo ufw allow 1714:1764/udp

# Samba:
sudo ufw allow Samba

# mDNS (network discovery):
sudo ufw allow 5353/udp
```

#### Boot Taking Longer:

**Symptom:** system boots slower after hardening
**Cause:** GRUB timeout or audit logging

**Fix:**

```bash
# Reduce GRUB timeout:
sudo nano /etc/default/grub
# Change: GRUB_TIMEOUT=5 to GRUB_TIMEOUT=2
sudo update-grub

# Disable audit at boot (if not needed):
sudo nano /etc/default/grub
# Add to GRUB_CMDLINE_LINUX: audit=0
sudo update-grub
```

#### Script Hangs During system_update:

**Symptom:** script stuck during package updates (especially Debian 13)
**Cause:** package manager lock or hung apt process

**Fix:**

```bash
# In another terminal:
# Check for hung processes:
ps aux | grep apt
ps aux | grep dpkg

# If found, kill them:
sudo killall apt apt-get dpkg

# Remove locks:
sudo rm /var/lib/dpkg/lock-frontend
sudo rm /var/lib/dpkg/lock
sudo rm /var/cache/apt/archives/lock

# Configure dpkg:
sudo dpkg --configure -a

# Re-run the script
```

#### Dry-Run Not Working Properly (older versions):

**Fix:**

```bash
# Update to latest version:
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh
chmod +x improved_harden_linux.sh

# Verify version:
./improved_harden_linux.sh --version
# Should show: 3.7

# Run dry-run again:
sudo ./improved_harden_linux.sh --dry-run -v
```

---

## Advanced Usage

### Custom Configuration Files:

Create a custom configuration file to override defaults:

```bash
# Create config file:
sudo nano hardening.conf
```

Example `hardening.conf`:

```bash
# Security level
SECURITY_LEVEL="high"

# Module selection
ENABLE_MODULES="system_update,firewall,ssh_hardening,fail2ban"
DISABLE_MODULES="clamav,usb_protection"

# Interactive mode
INTERACTIVE=false

# Desktop mode
IS_DESKTOP=true

# SSH settings
SSH_PORT=2222
DISABLE_ROOT_LOGIN=true
PASSWORD_AUTH=false

# Firewall rules
ALLOW_PORTS="80,443,8080"

# Fail2Ban settings
FAIL2BAN_MAXRETRY=3
FAIL2BAN_BANTIME=3600

# AIDE settings
AIDE_SCAN_PATHS="/etc /bin /sbin"

# Email notifications
NOTIFICATION_EMAIL="admin@example.com"
```

Use it:

```bash
sudo ./improved_harden_linux.sh -c hardening.conf
```

### Module-Specific Configuration:

**Firewall Custom Rules:**

```bash
# After running script, add custom rules:
sudo ufw allow from 192.168.1.0/24 to any port 22
sudo ufw allow 8080/tcp comment 'Custom web server'
sudo ufw reload
```

**Fail2Ban Custom Jail:**

```bash
sudo nano /etc/fail2ban/jail.local

[custom-service]
enabled = true
port = 8080
logpath = /var/log/custom-service.log
maxretry = 3
bantime = 3600

sudo systemctl restart fail2ban
```

**AIDE Custom Configuration:**

```bash
sudo nano /etc/aide/aide.conf

# Add custom paths:
/home/user/important FullAccess
!/home/user/cache

# Reinitialize:
sudo aideinit
```

**AppArmor Custom Profile:**

```bash
sudo aa-complain /usr/bin/custom-app
# Test the app
sudo aa-enforce /usr/bin/custom-app
```

### Automation:

**Automated Deployment (Ansible):**

```yaml
- name: Harden Linux servers
  hosts: all
  become: yes
  tasks:
    - name: Download hardening script
      get_url:
        url: https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh
        dest: /tmp/harden.sh
        mode: '0755'
    
    - name: Run hardening script
      command: /tmp/harden.sh -l high -n
      args:
        creates: /var/log/security_hardening.log
```

**Cron for Regular Audits:**

```bash
# Run security checks weekly:
sudo crontab -e

# Add:
0 3 * * 0 /path/to/improved_harden_linux.sh --report
```

### Integration with Monitoring:

**Send Logs to Syslog Server:**

```bash
sudo nano /etc/rsyslog.d/50-security.conf

# Add:
$ModLoad imfile
$InputFileName /var/log/security_hardening.log
$InputFileTag security-hardening:
$InputFileStateFile stat-security-hardening
$InputFileSeverity info
$InputFileFacility local7
$InputRunFileMonitor

*.* @@syslog-server.example.com:514

sudo systemctl restart rsyslog
```

**Email Notifications:**

```bash
# Install mail utilities:
sudo apt install mailutils

# Configure in hardening.conf:
NOTIFICATION_EMAIL="admin@example.com"

# Test:
echo "Test" | mail -s "Security Alert" admin@example.com
```

### Security Scanning Schedule:

**Weekly Full Scan Script:**

```bash
sudo nano /etc/cron.weekly/security-scan

#!/bin/bash
# Weekly security scan
DATE=$(date +%Y%m%d)
REPORT="/var/log/security_scan_${DATE}.log"

echo "=== Weekly Security Scan - ${DATE} ===" > ${REPORT}

echo "--- RKHunter Scan ---" >> ${REPORT}
rkhunter --check --skip-keypress --report-warnings-only >> ${REPORT}

echo "--- ClamAV Scan ---" >> ${REPORT}
clamscan -r /home --infected --log=${REPORT}

echo "--- AIDE Check ---" >> ${REPORT}
aide --check >> ${REPORT}

echo "--- Lynis Audit ---" >> ${REPORT}
lynis audit system --quick >> ${REPORT}

# Email report if issues found:
if grep -q "Warning" ${REPORT}; then
    mail -s "Security Scan Warnings" admin@example.com < ${REPORT}
fi

chmod +x /etc/cron.weekly/security-scan
```

### Compliance Reporting:

**Generate Compliance Report:**

```bash
# Install SCAP tools:
sudo apt install libopenscap8 ssg-debian ssg-debderived

# Run SCAP scan:
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss \
  --results /root/compliance-scan.xml \
  --report /root/compliance-report.html \
  /usr/share/xml/scap/ssg/content/ssg-debian10-ds.xml
```

### Container Hardening:

**Docker Integration:**

```bash
# After running script, configure Docker:
sudo nano /etc/docker/daemon.json

{
  "icc": false,
  "userns-remap": "default",
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false
}

sudo systemctl restart docker
```

---

## Requirements

### System Requirements:

**Minimum:**

* Linux distribution: Ubuntu 22.04+, Debian 11+, Kubuntu 24.04+, Mint 21+, Pop!_OS 22.04+
* Disk space: 2GB free (for security tools and backups)
* Memory: 1GB RAM minimum (2GB recommended)
* Root/sudo access
* Internet connection (for package downloads)

**Recommended:**

* 4GB RAM (for ClamAV and AIDE)
* 5GB free disk space
* SSH key authentication configured (for servers)
* Console/VNC access available (for servers)

### Software Dependencies:

**Pre-installed on most systems:**

* bash 4.0+
* sudo
* systemd
* apt/apt-get (Debian/Ubuntu package manager)

**Automatically installed by script:**

* ufw (firewall)
* fail2ban (intrusion prevention)
* aide (file integrity)
* auditd (system auditing)
* apparmor (mandatory access control)
* clamav (antivirus)
* rkhunter (rootkit detection)
* chkrootkit (rootkit detection)
* lynis (security auditing)
* unattended-upgrades (automatic updates)

### Verified Distributions:

**Tested:**

* Ubuntu 22.04 LTS (Jammy)
* Ubuntu 24.04 LTS (Noble)
* Ubuntu 25.10 (Oracular)
* Kubuntu 24.04 LTS
* Debian 11 (Bullseye)
* Debian 12 (Bookworm)
* Debian 13 (Trixie)
* Linux Mint 21
* Pop!_OS 22.04

**Should Work (Community Tested):**

* Ubuntu derivatives (Xubuntu, Lubuntu, Ubuntu Budgie)
* MX Linux
* Kali Linux (limited - already hardened)
* Elementary OS

**Not Supported:**

* Fedora, CentOS, RHEL (different package manager)
* Arch, Manjaro (different package manager)
* openSUSE (different package manager)
* Alpine Linux (different init system)

---

## Security Compliance

### Compliance Frameworks Addressed:

**CIS Benchmarks:**
This script implements many recommendations from:

* CIS Ubuntu Linux Benchmark
* CIS Debian Linux Benchmark

**Specific CIS controls implemented:**

* 1.1.x - Filesystem configuration
* 1.4.x - Secure boot settings
* 1.5.x - Mandatory Access Control
* 1.7.x - Warning banners
* 3.x - Network configuration
* 4.x - Logging and auditing
* 5.x - Access, authentication, and authorization
* 6.x - System maintenance

**DISA STIG:**
Implements portions of:

* Application Security and Development STIG
* Operating System STIG (Linux)

**Specific STIG controls:**

* SRG-OS-000023 (Audit unsuccessful account access attempts)
* SRG-OS-000024 (Audit successful account access)
* SRG-OS-000032 (Session lock)
* SRG-OS-000033 (Remote session termination)
* SRG-OS-000037 (Limit concurrent sessions)
* SRG-OS-000042 (Audit account management events)
* SRG-OS-000057 (Screen lock)
* SRG-OS-000163 (Wireless disabled if not required)
* SRG-OS-000185 (Audit system startup/shutdown)

**PCI-DSS (Payment Card Industry):**
Addresses requirements:

* 1.1 - Firewall configuration standards
* 2.2 - Configuration standards for system components
* 2.3 - Encrypt non-console admin access
* 8.1 - User identification management
* 8.2 - Authentication management
* 8.3 - Multi-factor authentication for remote access
* 10.1 - Audit trail requirements
* 10.2 - Automated audit trails for security events
* 10.3 - Audit trail detail requirements

**HIPAA (Health Insurance Portability and Accountability Act):**
Supports:

* Access Control (§164.312(a)(1))
* Audit Controls (§164.312(b))
* Integrity (§164.312(c)(1))
* Person or Entity Authentication (§164.312(d))
* Transmission Security (§164.312(e)(1))

**SOC 2 (Service Organization Control 2):**
Supports trust service criteria:

* CC6.1 - Logical and physical access controls
* CC6.6 - Prevention and detection of security incidents
* CC6.7 - Security incident containment
* CC7.2 - System monitoring

**NIST (National Institute of Standards and Technology):**
Implements controls from:

* NIST SP 800-53 (Security and Privacy Controls)
* NIST Cybersecurity Framework

### Important Compliance Notes:

**This script provides a FOUNDATION, not complete compliance.**

**What it does:**

* Implements many technical controls from frameworks
* Creates audit logs required for compliance
* Hardens system configuration
* Enables security tools

**What it DOES NOT do:**

* Replace formal security assessment
* Implement application-specific security
* Configure backups or disaster recovery
* Provide encryption at rest
* Replace security awareness training
* Provide HIPAA Business Associate Agreement
* Configure network segmentation
* Implement role-based access control (RBAC)
* Configure intrusion detection systems (IDS)
* Provide security information and event management (SIEM)

**For full compliance, you also need:**

* Formal risk assessment
* Security policies and procedures
* Incident response plan
* Security awareness training
* Regular vulnerability assessments
* Penetration testing
* Third-party audit
* Ongoing monitoring and maintenance

**Professional Assessment Required:**
If you need compliance certification (PCI-DSS, HIPAA, SOC 2, etc.), hire a qualified security professional or compliance specialist. This script is a starting point, not a complete solution.

---

## License & Support

### License:

This project is licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**

**You are free to:**

* Share - copy and redistribute the material
* Adapt - remix, transform, and build upon the material

**Under the following terms:**

* **Attribution** - you must give appropriate credit, provide a link to the license, and indicate if changes were made
* **NonCommercial** - you may not use the material for commercial purposes

**Commercial Licensing:**
For commercial use, contact: [cyberjunk77@protonmail.com](mailto:cyberjunk77@protonmail.com)

### Support:

**Community Support (Free):**

* GitHub Issues: [https://github.com/captainzero93/security_harden_linux/issues](https://github.com/captainzero93/security_harden_linux/issues)
* Best-effort response time
* Community-driven Q&A

**Professional Support (Paid):**

* Email: [cyberjunk77@protonmail.com](mailto:cyberjunk77@protonmail.com)
* Custom script development
* Security consulting
* Training and workshops
* Priority response
* Commercial licensing

### Contributing:

**Want to improve this script?**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

**Contribution guidelines:**

* Follow existing code style
* Add comments for complex logic
* Test on multiple distributions
* Update documentation
* One feature per pull request

**What we're looking for:**

* Bug fixes
* Performance improvements
* Additional security modules
* Better error handling
* Documentation improvements
* Distribution compatibility

### Donations:

If this script saved you time or money, consider supporting development:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/captainzero)

**All donations go toward:**

* Continued development
* Testing on more distributions
* Documentation improvements
* Security research
* Community support

---

## Version History

### Version 4.1 (2025-11-07)

**Critical Fix:**

* Fixed script exiting at 4% after first module completion
* Added explicit return 0 statements to all 21 module functions
* Modules now properly signal successful completion to execution loop
* Script executes all modules sequentially without premature termination

**Technical Details:**

* All module functions were missing explicit return statements
* Functions returned unpredictable exit codes from log commands
* Execution loop misinterpreted module success/failure status
* Fixed by adding return 0 to end of every module function

**Improvements:**

* Maintained all v4.0 APT lock handling improvements
* Progress bar advances correctly through all modules
* Reliable module completion status checking
* No breaking changes from v4.0

### Version 4.0 (2025-11-06)

**Critical Fix:**

* Fixed wait_for_apt() hanging with stale APT locks
* Automatic detection and removal of stale lock files
* Interactive force-unlock option at 60 seconds
* Improved timeout handling and user feedback

**Improvements:**

* Enhanced Debian 13 (Trixie) compatibility
* Fixed progress bar display between modules
* Better terminal output flushing
* Improved error recovery
* Fixed readonly variable errors in OS detection

3.9 (2025-10-20)
- Critical bug fixes and fallback logic

3.7;

**Critical Bug Fixes:**

* Fixed system_update module hanging on Debian 13 (Trixie)
* Fixed dry-run mode not working properly
* Fixed progress bar in non-interactive sessions
* Improved timeout handling for apt operations
* Better error handling and recovery
* Fixed missing MODULE_DEPS entries
* Better handling of locked dpkg/apt states

**Improvements:**

* Enhanced compatibility with Debian 13
* Better TTY detection for progress bars
* Milestone-based progress logging in non-interactive mode
* Automatic retry mechanism for apt operations
* Improved dependency resolution
* Clearer error messages

**Compatibility:**

* Full support for Ubuntu 25.10 (Oracular)
* Complete Debian 13 (Trixie) compatibility verified
* Enhanced Kubuntu 24.04+ support

### Version 3.6 (2025-09-15)

**Major Features:**

* Complete refactoring of core execution engine
* Dependency resolution system for modules
* Circular dependency detection
* Progress tracking with visual progress bars
* Improved desktop environment detection
* Better backup and restore functionality

**Security Enhancements:**

* AppArmor profile management
* USB device protection module
* Lynis security audit integration
* Enhanced kernel hardening parameters
* Improved AIDE configuration

**Bug Fixes:**

* Fixed GRUB configuration on EFI systems
* Resolved Fail2Ban jail conflicts
* Fixed SSH port change issues
* Corrected sysctl parameter applications
* Fixed module dependency ordering

**Usability:**

* Colorized output for better readability
* Verbose logging option
* Non-interactive mode for automation
* Custom configuration file support
* Module selection (enable/disable specific modules)

### Version 3.5 (2025-07-10)

**Features:**

* Added support for Linux Mint 21+
* Added support for Pop!_OS 22.04+
* Rootkit scanner integration (rkhunter + chkrootkit)
* Automatic security update configuration
* Password policy enforcement module
* Secure shared memory implementation

**Improvements:**

* Better handling of desktop environments
* Improved firewall rule organization
* Enhanced SSH hardening options
* More comprehensive audit logging
* Better error handling and recovery

**Bug Fixes:**

* Fixed ClamAV signature update issues
* Resolved AppArmor profile conflicts
* Fixed AIDE database initialization on slow systems
* Corrected IPv6 disable functionality

### Version 3.0 (2025-04-22)

**Major Release:**

* Complete rewrite in bash with better error handling
* Modular architecture (enable/disable modules)
* Security level system (low/moderate/high/paranoid)
* Automatic backup before all changes
* One-command restore functionality
* HTML report generation

**Features:**

* UFW firewall configuration
* Fail2Ban intrusion prevention
* AIDE file integrity monitoring
* Auditd system auditing
* ClamAV antivirus
* Kernel hardening (sysctl)
* Boot security (GRUB)
* SSH hardening
* AppArmor enforcement

**Desktop Optimizations:**

* Automatic desktop detection
* Preservation of gaming functionality
* KDE Connect / mDNS support
* Samba compatibility
* Zero performance impact

### Version 2.0 (2025-01-15)

**Features:**

* Basic firewall setup
* SSH hardening
* Password policy
* Package updates
* Simple logging

### Version 1.0 (2024-10-01)

**Initial Release:**

* Proof of concept
* Basic hardening steps
* Manual configuration

---

## Additional Resources

### Official Documentation:

**Ubuntu Security:**

* [Ubuntu Security Guide](https://ubuntu.com/security)
* [Ubuntu Server Security Guide](https://ubuntu.com/server/docs/security)
* [AppArmor on Ubuntu](https://ubuntu.com/server/docs/security-apparmor)

**Debian Security:**

* [Debian Security Manual](https://www.debian.org/doc/manuals/securing-debian-manual/)
* [Debian Security FAQ](https://www.debian.org/security/faq)
* [Debian Security Tracker](https://security-tracker.debian.org/)

**Security Standards:**

* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [DISA STIGs](https://public.cyber.mil/stigs/)
* [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
* [PCI Security Standards](https://www.pcisecuritystandards.org/)

### Tools Documentation:

**Firewall:**

* [UFW Documentation](https://help.ubuntu.com/community/UFW)
* [UFW Man Page](https://manpages.ubuntu.com/manpages/focal/man8/ufw.8.html)

**Intrusion Prevention:**

* [Fail2Ban Manual](https://www.fail2ban.org/wiki/index.php/Main_Page)
* [Fail2Ban Configuration](https://github.com/fail2ban/fail2ban)

**File Integrity:**

* [AIDE Manual](https://aide.github.io/)
* [AIDE Configuration Guide](https://aide.github.io/doc/)

**Auditing:**

* [Auditd Documentation](https://github.com/linux-audit/audit-documentation)
* [Linux Audit Quickstart](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening)

**Mandatory Access Control:**

* [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
* [AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)

**Security Scanning:**

* [Lynis Documentation](https://cisofy.com/documentation/lynis/)
* [RKHunter README](http://rkhunter.sourceforge.net/)
* [ClamAV Documentation](https://docs.clamav.net/)

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
4. Run with `--verbose` and check logs at `/var/log/security_hardening.log`

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
Preview:      sudo ./improved_harden_linux.sh --dry-run -v
Apply:        sudo ./improved_harden_linux.sh
Restore:      sudo ./improved_harden_linux.sh --restore
Report:       sudo ./improved_harden_linux.sh --report
Help:         sudo ./improved_harden_linux.sh --help
List modules: sudo ./improved_harden_linux.sh --list-modules

SECURITY LEVELS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Desktop:      sudo ./improved_harden_linux.sh -l moderate
Server:       sudo ./improved_harden_linux.sh -l high -n
Maximum:      sudo ./improved_harden_linux.sh -l paranoid
Basic:        sudo ./improved_harden_linux.sh -l low

MODULE SELECTION:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Enable:       sudo ./improved_harden_linux.sh -e module1,module2
Disable:      sudo ./improved_harden_linux.sh -x module1,module2
Custom:       sudo ./improved_harden_linux.sh -c config.conf

MONITORING:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Firewall:     sudo ufw status
Blocked IPs:  sudo fail2ban-client status sshd
Unban IP:     sudo fail2ban-client set sshd unbanip IP
Audit:        sudo ausearch -m USER_LOGIN -ts recent
AppArmor:     sudo aa-status
Logs:         sudo tail -f /var/log/security_hardening.log

FILE CHECKS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AIDE:         sudo aide --check
Rootkits:     sudo rkhunter --check
ClamAV:       sudo clamscan -r /home

BACKUPS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Location:     /root/security_backup_*.tar.gz
List:         ls -lht /root/security_backup_*.tar.gz
Verify:       sha256sum -c /root/security_backup_*.tar.gz.sha256
Restore:      sudo ./improved_harden_linux.sh --restore [FILE]

EMERGENCY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SSH lockout:  Use console, restore /etc/ssh/sshd_config.backup.*
Firewall:     sudo ufw disable (from console)
Boot fail:    Recovery mode, restore /etc/default/grub.backup.*
Full restore: sudo ./improved_harden_linux.sh --restore

QUICK FIXES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Allow port:   sudo ufw allow PORT/tcp
Disable AIDE: sudo chmod -x /etc/cron.daily/aide-check
Stop ClamAV:  sudo systemctl stop clamav-daemon

RESOURCES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
GitHub:       https://github.com/captainzero93/security_harden_linux
Issues:       https://github.com/captainzero93/security_harden_linux/issues

```

---

**Star this repo if it helped you.**

**Version:** 4.1 | **Author:** captainzero93 |

**GitHub:** [https://github.com/captainzero93/security_harden_linux](https://github.com/captainzero93/security_harden_linux)

---
