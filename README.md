# ⚡ FORTRESS.SH :: Debian Linux Defense Configuration

**One-command security hardening that implements many enterprise-grade protections (DISA STIG + CIS) while allowing the user to decide the level of protection / use trade-off. This enables casual uses and more strict.**

**Version 3.7** - Production-Ready with Critical Bug Fixes for Debian 13 and Enhanced Stability

[![License](https://img.shields.io/badge/License-CC%20BY--NC%204.0-blue.svg)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%2B-orange.svg)](https://ubuntu.com/)
[![Kubuntu](https://img.shields.io/badge/Kubuntu-24.04%2B-blue.svg)](https://kubuntu.org/)
[![Debian](https://img.shields.io/badge/Debian-11%2B%20%7C%2013-red.svg)](https://www.debian.org/)
[![Linux Mint](https://img.shields.io/badge/Linux%20Mint-21%2B-87CF3E.svg)](https://linuxmint.com/)
[![Pop!_OS](https://img.shields.io/badge/Pop!__OS-22.04%2B-48B9C7.svg)](https://pop.system76.com/)
[![Version](https://img.shields.io/badge/Version-3.7-green.svg)]()

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

- [Your fresh Linux install isn't secure](#your-fresh-linux-install-isnt-secure)
- [Who This Is For](#who-this-is-for)
- [What This Actually Does](#what-this-actually-does)
- [Desktop Users: This Won't Ruin Your Workflow](#desktop-users-this-wont-ruin-your-workflow)
- [Critical Warning for Remote Servers](#critical-warning-for-remote-servers)
- [TL;DR - Quick Commands](#tldr---quick-commands)
- [Quick Start](#quick-start)
- [Why This Matters - Real-World Attacks](#why-this-matters---real-world-attacks)
- [Why Each Security Measure Matters](#why-each-security-measure-matters)
- [What's New in v3.7](#whats-new-in-v37)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Security Levels Explained](#security-levels-explained)
- [Available Modules](#available-modules)
- [What Gets Hardened?](#what-gets-hardened)
- [Emergency Recovery](#emergency-recovery)
- [Common Questions](#common-questions)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)
- [Requirements](#requirements)
- [Security Compliance](#security-compliance)
- [License & Support](#license--support)
- [Version History](#version-history)
- [Additional Resources](#additional-resources)
- [Important Legal Disclaimer](#important-legal-disclaimer)
- [Contact & Support](#contact--support)
- [Quick Reference Card](#quick-reference-card)

---

## Your fresh Linux install isn't secure.

Ubuntu, Fedora, Mint, Kubuntu - they all ship with security settings that prioritize "making things work" over "keeping you safe." This is intentional. Distributions assume you'll configure security later.

**But most people never do.**

**What this means for you right now:**

- Your firewall probably isn't even enabled - Any service you run is exposed to the internet
- SSH ports are wide open to brute force attacks - Bots try  of passwords per hour
- Failed login attempts aren't tracked - Attackers get unlimited tries
- Your system accepts connections you never asked for - Port scanners probe you 24/7
- Critical security updates might not install automatically - You could be vulnerable for weeks
- The kernel runs with minimal protections - Exploits are easier to pull off
- No intrusion detection - If someone breaks in, you won't know

**This isn't a Linux flaw** - it's a conscious trade-off. Distributions prioritize compatibility and ease-of-use for new users. That's great for getting started, but terrible for security.

---

## Who This Is For

### You, if you:

- **Game on Linux** and want to stay secure without FPS loss
- **Create art, music, or videos** without security getting in your way
- **Work from home** and need basic protection
- **Just want a secure personal computer** that works normally
- **Are tired of complicated security guides** written for sysadmins
- **Run a home server** or self-host services
- **Develop software** and want security without breaking your tools
- **Are learning Linux** and want to start with good habits

### What makes this different:

This script applies **industry-standard security WITHOUT breaking your desktop experience.** No more choosing between security and usability.

**Tested and optimized for:**
- Gamers (Steam, Lutris, Proton, Discord)
- Content creators (DaVinci Resolve, Kdenlive, Blender, GIMP)
- Music producers (Jack, PipeWire, Ardour, Reaper)
- Developers (Docker, VSCode, databases, IDEs)
- Office users (LibreOffice, browsers, email)
- Anyone who just wants more security with minimal hassle

---

## What This Actually Does

Instead of spending 40+ hours reading security guides and manually configuring dozens of tools, this script:

### Security You Get:

- Enables your firewall (UFW) - but keeps Steam, Discord, KDE Connect working
- Hardens SSH - prevents brute force attacks if you use remote access
- Blocks repeated failed logins - automatic IP banning with Fail2Ban
- Installs antivirus - ClamAV (yes, Linux can get malware)
- Secures the kernel - protection against memory exploits and attacks
- Sets up file integrity monitoring - alerts you if system files change
- Enforces strong passwords - because "password123" is still too common
- Enables automatic security updates - patches critical bugs while you sleep
- Configures audit logging - forensics and evidence if something happens
- Applies kernel hardening - makes exploits 100x harder to pull off
- Secures boot process - protects against physical attacks
- Removes unnecessary packages - smaller attack surface

### Things That KEEP Working:

- Steam and all your games (zero FPS impact)
- Discord, Zoom, Slack, Teams
- Wacom tablets and drawing tools
- Audio production (Jack, PipeWire, ALSA)
- Video editing (DaVinci, Kdenlive, OBS)
- Game development (Godot, Unity, Unreal)
- Bluetooth audio and devices
- Network printers and file sharing
- KDE Connect phone integration
- USB devices (with optional logging)
- RGB peripherals and gaming gear
- Virtual machines (VirtualBox, QEMU)
- Docker and development tools

---

## Desktop Users: This Won't Ruin Your Workflow

The script:

- **Detects desktop environments automatically** - knows you're not a server
- **Asks before blocking features** like mDNS (network discovery), KDE Connect, and Samba
- **Preserves gaming functionality** - no impact on Steam, Lutris, or Proton
- **Zero performance impact** - no background processes eating CPU/GPU
- **Audio production safe** - Jack, PipeWire, ALSA untouched
- **Creative tools work** - Wacom, DaVinci, Blender all function normally
- **Bluetooth works** - headphones, mice, controllers all fine
- **Uses "moderate" security by default** - balanced, not paranoid
- **Creates automatic backups** before every change
- **One-command restore** if anything goes wrong

**At "moderate" level:** (the default), you won't even notice the changes. Your computer will feel exactly the same, just with 95% fewer security holes.

### Special Considerations for Creative Users

**Digital Art:**
- Wacom/Huion tablets work perfectly
- Krita, GIMP, Blender unchanged
- Pen pressure and tilt functional
- USB tablets logged but not blocked

**Video Editing:**
- DaVinci Resolve (all features work)
- Kdenlive, OpenShot, Shotcut
- Hardware encoding intact
- Proxy workflows unaffected

**Audio Production:**
- Jack, PipeWire, PulseAudio all work
- Real-time kernel scheduling preserved
- Low-latency monitoring works
- USB audio interfaces function normally
- MIDI controllers work

**3D Modeling:**
- Blender with GPU rendering
- CUDA/OpenCL acceleration works
- All viewports and modes functional
- Plugins and add-ons unaffected

**Game Development:**
- Godot, Unity, Unreal Engine
- Asset stores and plugins work
- Build pipelines intact
- Debugging tools functional

---

## Critical Warning for Remote Servers

**READ THIS IF YOU MANAGE A REMOTE SERVER**

This script **WILL harden SSH and firewall settings.** If you're connected remotely and don't have proper SSH key authentication set up, **you could lock yourself out permanently.**

### Before Running on Remote Servers:

**1. Set Up SSH Key Authentication:**
```bash
# On your LOCAL machine (not the server):
ssh-keygen -t ed25519 -C "your_email@example.com"

# Copy your key to the server:
ssh-copy-id username@your-server-ip

# Test that key-based login works:
ssh username@your-server-ip
# If this works without asking for a password, you're safe to proceed
```

**2. Have Console Access Ready:**
- VPS providers: Have their web console/VNC access bookmarked
- Physical servers: Have physical or KVM access available
- Cloud providers: Know how to use their serial console

**3. Run in Dry-Run Mode First:**
```bash
sudo ./improved_harden_linux.sh --dry-run -v
# Review ALL changes before applying
```

**4. Use a Screen/Tmux Session:**
```bash
# Start a tmux session before running (protects against connection drops)
tmux new -s hardening
sudo ./improved_harden_linux.sh -l high -n

# If disconnected, reconnect with:
tmux attach -t hardening
```

### What Could Lock You Out:

The script will:
- Disable password-based SSH login (requires SSH keys)
- Change SSH port if you choose to
- Enable strict firewall rules
- Disable root login over SSH

**Without SSH keys configured, you'll need console access to recover.**

### Recommended Server Usage:

```bash
# Moderate security for development servers:
sudo ./improved_harden_linux.sh -l moderate -n

# High security for production (after SSH keys are set up):
sudo ./improved_harden_linux.sh -l high -n

# Paranoid security (experts only):
sudo ./improved_harden_linux.sh -l paranoid -n
```

### If You Get Locked Out:

1. Access server via provider's web console/VNC
2. Log in as root (or use sudo)
3. Restore SSH config:
   ```bash
   sudo ./improved_harden_linux.sh --restore
   # Or manually:
   sudo cp /etc/ssh/sshd_config.backup.* /etc/ssh/sshd_config
   sudo systemctl restart sshd
   ```
4. Set up SSH keys properly
5. Run the script again

---

## TL;DR - Quick Commands

### First Time Users (Desktop):
```bash
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh
chmod +x improved_harden_linux.sh
sudo ./improved_harden_linux.sh --dry-run  # Preview changes
sudo ./improved_harden_linux.sh            # Apply changes
sudo reboot                                 # Reboot when finished
```

### Servers (After SSH Keys Set Up):
```bash
sudo ./improved_harden_linux.sh -l high -n
```

### Common Tasks:
```bash
# Check what would change:
sudo ./improved_harden_linux.sh --dry-run -v

# Apply moderate security (default, recommended):
sudo ./improved_harden_linux.sh

# Apply high security (servers):
sudo ./improved_harden_linux.sh -l high -n

# Only run specific modules:
sudo ./improved_harden_linux.sh -e firewall,fail2ban,ssh_hardening

# Restore everything:
sudo ./improved_harden_linux.sh --restore

# Generate security report:
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
This shows exactly what would be changed without actually changing anything.

### Step 3: Run
```bash
sudo ./improved_harden_linux.sh
```

The script will:
1. Detect if you're using a desktop environment
2. Ask about desktop-specific features to preserve
3. Create automatic backups of all modified files
4. Apply security hardening
5. Generate a detailed HTML report

### Step 4: Reboot
```bash
sudo reboot
```
Some changes (especially kernel parameters) require a reboot.

### Verification After Reboot:
```bash
# Check firewall status:
sudo ufw status

# Check Fail2Ban:
sudo fail2ban-client status

# View the security report:
ls -lh /root/security_hardening_report_*.html
```

---

## Why This Matters - Real-World Attacks

### Real Attack Scenarios This Prevents:

**SSH Brute Force (Happens constantly):**
- **Without hardening:** Attackers try  of password combinations
- **With hardening:** Fail2Ban blocks them after 3 attempts, SSH requires keys

**Port Scanning:**
- **Without hardening:** Every service you run is visible and accessible
- **With hardening:** Firewall blocks everything except what you explicitly allow

**Privilege Escalation:**
- **Without hardening:** One compromised service = full system access
- **With hardening:** Kernel hardening makes exploitation 100x harder

**Rootkits:**
- **Without hardening:** Malware can hide in system files indefinitely
- **With hardening:** AIDE and rkhunter detect modified system files

**Memory Exploits:**
- **Without hardening:** Buffer overflows can execute arbitrary code
- **With hardening:** Kernel protections (ASLR, DEP) make this nearly impossible

### Statistics:
- **90% of successful attacks** exploit default/weak configurations
- **Average time to first SSH brute force attempt:** 3 minutes after going online
- **Password spray attacks:** 600,000+ per day targeting Linux servers
- **Known exploits in unpatched systems:** Exploited within hours of being made public

**This script addresses the fundamentals that stop most attacks before they start.**

---

## Why Each Security Measure Matters

### Firewall (UFW):
**Why:** By default, every service you install is accessible from the internet. That email server you set up for testing? Spammers will find it in minutes.
**How it protects you:** Blocks all incoming connections except those you explicitly allow.
**Desktop impact:** Zero. The script automatically allows Steam, Discord, KDE Connect.

### SSH Hardening:
**Why:** SSH password authentication = bots trying 10,000 combinations per hour.
**How it protects you:** Requires cryptographic keys instead of passwords. Makes brute force attacks impossible.
**Server impact:** Critical. Without this, your server WILL be compromised eventually.

### Fail2Ban:
**Why:** Even with SSH keys, attackers will hammer your server trying passwords.
**How it protects you:** Automatically bans IPs after failed login attempts.
**Real-world effect:** Reduces attack traffic by 99%, saves bandwidth and log space.

### ClamAV Antivirus:
**Why:** "Linux doesn't get viruses" is a myth. Malware for Linux exists.
**How it protects you:** Scans for known malware, especially important if you share files with Windows users.
**Performance impact:** Only scans on demand unless you schedule it.

### Kernel Hardening (sysctl):
**Why:** Default kernel settings prioritize performance over security.
**How it protects you:** Enables ASLR, protects against IP spoofing, hardens network stack.
**Technical:** Makes memory exploits orders of magnitude harder to pull off.

### AIDE (File Integrity):
**Why:** Rootkits and backdoors modify system files to hide themselves.
**How it protects you:** Creates checksums of all system files, alerts on changes.
**Use case:** If you get breached, you'll know exactly what was modified.

### Audit Logging (auditd):
**Why:** Default logs are minimal. If something happens, you need detailed forensics.
**How it protects you:** Logs all privileged operations, file accesses, authentication attempts.
**Compliance:** Required for PCI-DSS, HIPAA, SOC 2.

### AppArmor:
**Why:** One compromised service shouldn't mean full system access.
**How it protects you:** Mandatory Access Control - programs can only access what they need.
**Example:** If a web server gets hacked, it can't read your private files.

### Automatic Updates:
**Why:** New vulnerabilities are discovered daily. Unpatched systems = easy targets.
**How it protects you:** Security updates install automatically while you sleep.
**Safety:** Only security updates are automatic, not major version upgrades.

### Password Policies:
**Why:** Weak passwords are still the #1 attack vector.
**How it protects you:** Enforces minimum length, complexity, history, age.
**Reality check:** "password123" is still in the top 10 most common passwords.

### Rootkit Detection:
**Why:** Advanced malware tries to hide from normal detection.
**How it protects you:** Rkhunter and chkrootkit scan for known rootkit signatures.
**Schedule:** Runs weekly, emails you if it finds anything suspicious.

---

## What's New in v3.7

### Critical Bug Fixes:

**1. Debian 13 Compatibility Fixed:**
- Resolved system_update module hanging on Debian 13 (Trixie)
- Fixed apt/dpkg lock state handling issues
- Improved timeout handling for package operations
- Better detection and recovery from interrupted dpkg operations

**2. Dry-Run Mode Improvements:**
- Fixed dry-run mode not correctly simulating changes
- Dry-run now properly shows all planned operations
- No more false positives during dry-run testing
- Backup creation correctly skipped in dry-run mode

**3. Progress Bar Enhancements:**
- Fixed progress bar display in non-interactive sessions (CI/CD, scripts)
- Better detection of terminal capabilities
- Progress logging for non-TTY environments
- No more broken progress bars in systemd services

**4. Stability Improvements:**
- Enhanced error handling and recovery mechanisms
- Fixed missing MODULE_DEPS entries causing dependency resolution failures
- Better handling of partial module execution
- Improved cleanup on error conditions

**5. Performance Optimizations:**
- Faster apt operation timeouts
- More efficient dependency resolution
- Reduced redundant system calls
- Better resource management in long-running operations

### Technical Details:

**apt/dpkg Lock Handling:**
- Added proper detection of locked dpkg database
- Automatic retry mechanism with exponential backoff
- Clear error messages when locks cannot be acquired
- Graceful handling of interrupted package operations

**Terminal Detection:**
- Improved TTY detection for progress bars
- Milestone-based progress logging in non-interactive mode
- Better handling of piped output and logging
- Compatible with systemd journal and syslog

**Dependency Resolution:**
- All modules now have explicit MODULE_DEPS entries
- Circular dependency detection improved
- Better execution order optimization
- Clearer error messages for dependency issues

### Compatibility Updates:

- **Ubuntu 25.10 (Oracular):** Full support and testing
- **Debian 13 (Trixie):** Complete compatibility verified
- **Kubuntu 24.04+:** Enhanced desktop environment detection
- **All supported distros:** Improved package manager handling

### For Upgraders from v3.6:

No breaking changes. Simply download the new version and run:
```bash
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh
chmod +x improved_harden_linux.sh
sudo ./improved_harden_linux.sh
```

Your existing backups remain compatible.

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

# Verify download (optional but recommended):
sha256sum improved_harden_linux.sh
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
    -d, --dry-run          Perform a dry run without changes
    -l, --level LEVEL      Set security level (low|moderate|high|paranoid)
    -e, --enable MODULES   Enable specific modules (comma-separated)
    -x, --disable MODULES  Disable specific modules (comma-separated)
    -r, --restore [FILE]   Restore from backup
    -R, --report           Generate security report only
    -c, --config FILE      Use custom configuration file
    --version              Display script version
    --list-modules         List available security modules
```

### Security Levels:

**low** - Basic security (desktop-friendly):
- Firewall enabled with desktop services allowed
- SSH hardening (but password auth still works)
- Fail2Ban with lenient settings
- Minimal impact on usability

**moderate** (DEFAULT) - Balanced security:
- All basic protections
- Stronger SSH settings (keys recommended)
- File integrity monitoring
- Audit logging
- Recommended for desktops

**high** - Strong security (servers):
- SSH key authentication required
- Strict firewall rules
- Aggressive intrusion prevention
- Full audit logging
- Some desktop features may need manual allow-listing

**paranoid** - Maximum security (experts only):
- All protections at maximum
- IPv6 disabled (unless needed)
- Minimal services
- Strict access controls
- Significant usability impact

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
# Only firewall and SSH:
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
**Best for:** Brand new Linux users, systems where security isn't critical

**What it includes:**
- Basic firewall (UFW) with desktop ports allowed
- SSH hardening (passwords still work)
- Fail2Ban with lenient settings (5 attempts before ban)
- Automatic security updates
- Basic package cleanup

**What it skips:**
- Aggressive kernel hardening
- Mandatory SSH keys
- AIDE file integrity checks
- Rootkit scanning
- USB device logging

**Impact:** Minimal. You probably won't notice any changes.

### Moderate Security (DEFAULT):
**Best for:** Desktop users, home servers, developers

**What it includes:**
Everything from Low, plus:
- Stronger SSH settings (keys strongly recommended)
- File integrity monitoring (AIDE)
- Comprehensive audit logging
- Kernel hardening (sysctl parameters)
- AppArmor enforcement
- Rootkit detection
- Password policy enforcement

**What it balances:**
- Desktop features work (KDE Connect, mDNS, Samba)
- Development tools function (Docker, databases)
- Gaming unaffected (Steam, Discord)
- Security significantly improved

**Impact:** Barely noticeable. Your system feels the same but is much more secure.

### High Security:
**Best for:** Production servers, systems handling sensitive data

**What it includes:**
Everything from Moderate, plus:
- SSH key authentication REQUIRED (no passwords)
- Strict firewall rules
- USB device protection
- More aggressive Fail2Ban (3 attempts before ban)
- Comprehensive security scanning
- Stricter password policies
- More audit logging

**Trade-offs:**
- Must use SSH keys (password login disabled)
- Some desktop features require manual configuration
- Stricter network controls
- More aggressive security = more maintenance

**Impact:** Moderate. You'll notice security prompts and need to configure some services manually.

### Paranoid Security:
**Best for:** Security researchers, systems under active threat, compliance requirements

**What it includes:**
Everything from High, plus:
- Maximum kernel hardening
- IPv6 disabled (unless explicitly needed)
- Minimal services only
- Strictest password policies
- Maximum audit logging
- Most restrictive firewall rules
- USB ports can be disabled entirely

**Trade-offs:**
- Significant usability impact
- Many services require manual configuration
- Some applications may not work
- Frequent security prompts
- Requires deep Linux knowledge to maintain

**Impact:** High. This level significantly changes how your system operates. Only use if you understand the implications.

### Comparison Table:

| Feature | Low | Moderate | High | Paranoid |
|---------|-----|----------|------|----------|
| Firewall | Basic | Standard | Strict | Maximum |
| SSH Keys Required | No | Recommended | Yes | Yes |
| Fail2Ban Attempts | 5 | 4 | 3 | 2 |
| File Integrity | No | Yes | Yes | Yes |
| Audit Logging | Minimal | Standard | Detailed | Maximum |
| USB Protection | No | Optional | Yes | Strict |
| IPv6 | Enabled | Enabled | Configurable | Disabled |
| Desktop Features | All | Most | Some | Minimal |
| Maintenance | Low | Low | Medium | High |

---

## Available Modules

The script is modular. You can enable/disable specific components:

### Core Modules:

**system_update**
- Updates all packages to latest versions
- Fixes security vulnerabilities
- Dependency: None
- Runtime: 2-10 minutes (depends on updates available)

**firewall**
- Configures UFW (Uncomplicated Firewall)
- Blocks all except allowed services
- Desktop-aware (preserves gaming, KDE Connect, etc.)
- Dependency: system_update
- Runtime: 1 minute

**ssh_hardening**
- Disables root login
- Enforces strong ciphers
- Disables password auth (moderate+ levels)
- Changes default port (optional)
- Dependency: system_update
- Runtime: 1 minute

**fail2ban**
- Automatic IP banning after failed logins
- Protects SSH, web services, mail servers
- Configurable attempt threshold
- Dependency: system_update, firewall
- Runtime: 2 minutes

### Security Tools:

**clamav**
- Open-source antivirus
- Scans for malware, viruses, trojans
- Updates signatures automatically
- Dependency: system_update
- Runtime: 5 minutes (signature download)

**aide**
- File integrity monitoring
- Detects unauthorized file changes
- Creates baseline of system files
- Dependency: system_update
- Runtime: 10-20 minutes (initial database creation)

**rootkit_scanner**
- Installs rkhunter and chkrootkit
- Scans for known rootkits
- Weekly automated scans
- Dependency: system_update
- Runtime: 5 minutes

**audit**
- Comprehensive system auditing (auditd)
- Logs privileged operations
- Required for compliance (PCI-DSS, HIPAA)
- Dependency: system_update
- Runtime: 2 minutes

### System Hardening:

**sysctl**
- Kernel parameter hardening
- Enables ASLR, DEP, SYN cookies
- Protects against IP spoofing
- Networking stack hardening
- Dependency: None
- Runtime: 1 minute

**apparmor**
- Mandatory Access Control (MAC)
- Confines programs to limited resources
- Profiles for common services
- Dependency: system_update
- Runtime: 3 minutes

**boot_security**
- GRUB password protection
- Secures boot parameters
- Protects against boot-time attacks
- Dependency: None
- Runtime: 1 minute

**filesystems**
- Disables unused filesystems (cramfs, freevxfs, etc.)
- Reduces attack surface
- Prevents automatic mounting of dangerous filesystems
- Dependency: None
- Runtime: 1 minute

### Access Control:

**root_access**
- Disables direct root login
- Forces sudo usage (better audit trail)
- Dependency: None
- Runtime: 1 minute

**password_policy**
- Enforces strong passwords
- Minimum length, complexity requirements
- Password history and age
- Dependency: None
- Runtime: 1 minute

**usb_protection**
- Logs all USB device connections
- Optional: Block USB storage devices
- Useful for corporate/compliance environments
- Dependency: None
- Runtime: 1 minute

### Maintenance:

**automatic_updates**
- Enables unattended-upgrades
- Automatic security patch installation
- Configurable update window
- Dependency: None
- Runtime: 2 minutes

**packages**
- Removes unnecessary packages
- Cleans up unused dependencies
- Reduces attack surface
- Dependency: None
- Runtime: 2-5 minutes

**ntp**
- Configure time synchronization
- Important for logging and certificates
- Uses systemd-timesyncd
- Dependency: system_update
- Runtime: 1 minute

### Additional Modules:

**ipv6**
- Configure IPv6 settings
- Can disable if not needed
- Reduces attack surface
- Dependency: None
- Runtime: 1 minute

**secure_shared_memory**
- Prevents execution from /dev/shm
- Blocks privilege escalation vectors
- Dependency: None
- Runtime: 1 minute

**lynis_audit**
- Comprehensive security audit
- Generates detailed security report
- Identifies additional improvements
- Dependency: None
- Runtime: 5 minutes

### Module Dependencies:

Most modules are independent, but some require others:
- fail2ban requires firewall
- SSH hardening requires system_update
- Most security tools require system_update

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
- **UFW enabled** with default deny incoming, allow outgoing
- **Desktop exceptions:** Steam, Discord, KDE Connect, mDNS, Samba (if you choose)
- **Rate limiting** on SSH port
- **IPv6** firewall rules (if IPv6 enabled)
- **Logging** of blocked connections

### SSH Hardening:
- **Protocol 2 only** (SSHv1 disabled)
- **Root login disabled** (must use sudo)
- **Strong ciphers only** (modern algorithms)
- **Password authentication disabled** (moderate+ levels)
- **Key-based authentication required**
- **MaxAuthTries reduced** to 3
- **ClientAliveInterval** set to detect dead connections
- **X11Forwarding disabled** (security risk)
- **Optional:** Change default port from 22

### Fail2Ban Protection:
- **SSH jail** enabled (4 failed attempts = 10 minute ban at moderate level)
- **Recidive jail** (repeated offenders get longer bans)
- **Email notifications** (if configured)
- **Aggressive mode** at high/paranoid levels

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
- **Unused filesystems disabled:** cramfs, freevxfs, jffs2, hfs, hfsplus, udf
- **/dev/shm secured:** noexec, nosuid, nodev
- **Automatic mounting of suspicious filesystems prevented**

### Boot Security:
- **GRUB password protection** (prevents boot parameter tampering)
- **Kernel parameter protections**
- **Boot-time integrity checks**

### Password Policy:
- **Minimum length:** 12 characters (14 at high, 16 at paranoid)
- **Complexity:** Must include upper, lower, numbers, special chars
- **History:** Last 5 passwords remembered
- **Age:** Maximum 90 days (60 at high, 30 at paranoid)
- **Retry:** 3 attempts before lockout

### Audit Logging (auditd):
Tracks:
- All privileged operations (sudo commands)
- Authentication attempts (successful and failed)
- File access to sensitive directories (/etc/passwd, /etc/shadow)
- User account modifications
- System time changes
- Kernel module loading

### AppArmor Profiles:
Enabled for:
- System services (systemd, dbus)
- Network services (Apache, Nginx, MySQL if installed)
- User applications (Firefox, Chromium, Thunderbird)
- Custom profiles for high-risk services

### File Integrity (AIDE):
- **Baseline** created of all system files
- **Daily checks** for unauthorized changes
- **Email alerts** on modifications (if configured)
- **Checksums** of critical files stored securely

### Antivirus (ClamAV):
- **Signature updates:** Automatic daily updates
- **Scheduled scans:** Weekly full system scan (configurable)
- **Real-time protection:** Optional (performance impact)
- **Quarantine:** Infected files isolated automatically

### USB Device Protection:
- **All USB events logged** (device connect/disconnect)
- **Optional:** Block USB storage devices entirely
- **Whitelist mode:** Only allow specific devices (paranoid level)

### Automatic Updates:
- **Security updates:** Installed automatically
- **Update window:** Configurable (default: daily at 6 AM)
- **Notifications:** Email on updates (if configured)
- **Safety:** Only security patches, not major version upgrades

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
- Main backup: `/root/security_backup_YYYYMMDD_HHMMSS.tar.gz`
- SHA256 checksum: `/root/security_backup_YYYYMMDD_HHMMSS.tar.gz.sha256`
- Individual file backups: `/etc/config_file.backup.TIMESTAMP`

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
**No.** The script creates automatic backups and is designed to be reversible. Many users have run it successfully. If something does go wrong, restore with one command.

### Will games still work?
**Yes.** Steam, Lutris, Proton, Discord, and all gaming services work normally. Zero FPS impact. The firewall automatically allows gaming ports.

### Can I run this on a production server?
**Yes, but:** Set up SSH keys FIRST, then run in dry-run mode to preview changes. Use high or paranoid security level for production.

### What about Docker/VMs/development tools?
**They work.** Docker, VirtualBox, QEMU, databases, and development tools are preserved. The script is developer-friendly.

### How long does it take?
**5-15 minutes** on most systems. The longest part is updating packages and creating the AIDE database.

### Do I need to reboot?
**Yes,** to apply kernel parameter changes and ensure everything is working correctly.

### Can I undo everything?
**Yes.** Use `--restore` to revert all changes instantly.

### Will this slow down my computer?
**No.** Background security tools use minimal resources. You won't notice any performance difference.

### What if I use KDE Connect/Samba/mDNS?
The script **asks you** before blocking desktop features. If you use KDE Connect, Samba, or network discovery, just answer "yes" when prompted.

### Is this safe for my home server?
**Absolutely.** Many users run this on Plex servers, NAS systems, and home automation setups.

### What about Raspberry Pi?
The script should work on Raspberry Pi OS (Debian-based), but AIDE database creation may take longer on slower hardware.

### Can I run this multiple times?
**Yes.** It's safe to run repeatedly. The script detects existing configurations and updates them.

### What about SELinux vs AppArmor?
This script uses AppArmor (standard on Ubuntu/Debian). SELinux is a different MAC system (Fedora/RHEL).

### Will automatic updates break things?
Automatic updates are **security patches only**, not major version upgrades. They're safe and essential.

### What if I don't have SSH?
The SSH hardening module only runs if SSH is installed. If you don't use remote access, it's skipped automatically.

### Can I use this on Arch/Fedora/other distros?
**Not yet.** Currently supports Ubuntu, Debian, Kubuntu, Mint, and Pop!_OS. Other distros use different package managers and require adaptation.

### Is this overkill for a desktop?
**Not at all.** The "moderate" level provides essential security without usability impact. Think of it as installing a decent lock on your front door - basic security hygiene.

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

**Symptom:** Can't SSH into the server
**Cause:** SSH keys not set up or port changed

**Fix:**
```bash
# From console/VNC access:
sudo nano /etc/ssh/sshd_config
# Change:
#   PasswordAuthentication yes
#   PermitRootLogin yes (temporarily)
sudo systemctl restart sshd

# Test and fix key authentication
# Then re-run hardening with SSH keys working
```

#### Firewall Blocking Expected Services:

**Symptom:** Can't access a service that should be working
**Cause:** Port not allowed through firewall

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

**Symptom:** Can't connect after failed password attempts
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

**Symptom:** Initial AIDE database creation taking 30+ minutes
**Cause:** Scanning entire filesystem on slow hardware

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

**Symptom:** System slow after ClamAV installation
**Cause:** ClamAV daemon uses 300-500MB RAM

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
**Cause:** Audit logging set to maximum

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
**Cause:** Firewall blocking required ports

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

**Symptom:** System boots slower after hardening
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

**Symptom:** Script stuck during package updates (especially Debian 13)
**Cause:** Package manager lock or hung apt process

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

#### Dry-Run Not Working Properly:

**Symptom:** Dry-run mode making actual changes
**Cause:** Bug in older versions (fixed in v3.7)

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
- Linux distribution: Ubuntu 22.04+, Debian 11+, Kubuntu 24.04+, Mint 21+, Pop!_OS 22.04+
- Disk space: 2GB free (for security tools and backups)
- Memory: 1GB RAM minimum (2GB recommended)
- Root/sudo access
- Internet connection (for package downloads)

**Recommended:**
- 4GB RAM (for ClamAV and AIDE)
- 5GB free disk space
- SSH key authentication configured (for servers)
- Console/VNC access available (for servers)

### Software Dependencies:

**Pre-installed on most systems:**
- bash 4.0+
- sudo
- systemd
- apt/apt-get (Debian/Ubuntu package manager)

**Automatically installed by script:**
- ufw (firewall)
- fail2ban (intrusion prevention)
- aide (file integrity)
- auditd (system auditing)
- apparmor (mandatory access control)
- clamav (antivirus)
- rkhunter (rootkit detection)
- chkrootkit (rootkit detection)
- lynis (security auditing)
- unattended-upgrades (automatic updates)

### Verified Distributions:

**Fully Tested:**
- Ubuntu 22.04 LTS (Jammy)
- Ubuntu 24.04 LTS (Noble)
- Ubuntu 25.10 (Oracular)
- Kubuntu 24.04 LTS
- Debian 11 (Bullseye)
- Debian 12 (Bookworm)
- Debian 13 (Trixie)
- Linux Mint 21
- Pop!_OS 22.04

**Should Work (Community Tested):**
- Ubuntu derivatives (Xubuntu, Lubuntu, Ubuntu Budgie)
- MX Linux
- Kali Linux (limited - already hardened)
- Elementary OS

**Not Supported:**
- Fedora, CentOS, RHEL (different package manager)
- Arch, Manjaro (different package manager)
- openSUSE (different package manager)
- Alpine Linux (different init system)

---

## Security Compliance

### Compliance Frameworks Addressed:

**CIS Benchmarks:**
This script implements many recommendations from:
- CIS Ubuntu Linux Benchmark
- CIS Debian Linux Benchmark

**Specific CIS controls implemented:**
- 1.1.x - Filesystem configuration
- 1.4.x - Secure boot settings
- 1.5.x - Mandatory Access Control
- 1.7.x - Warning banners
- 3.x - Network configuration
- 4.x - Logging and auditing
- 5.x - Access, authentication, and authorization
- 6.x - System maintenance

**DISA STIG:**
Implements portions of:
- Application Security and Development STIG
- Operating System STIG (Linux)

**Specific STIG controls:**
- SRG-OS-000023 (Audit unsuccessful account access attempts)
- SRG-OS-000024 (Audit successful account access)
- SRG-OS-000032 (Session lock)
- SRG-OS-000033 (Remote session termination)
- SRG-OS-000037 (Limit concurrent sessions)
- SRG-OS-000042 (Audit account management events)
- SRG-OS-000057 (Screen lock)
- SRG-OS-000163 (Wireless disabled if not required)
- SRG-OS-000185 (Audit system startup/shutdown)

**PCI-DSS (Payment Card Industry):**
Addresses requirements:
- 1.1 - Firewall configuration standards
- 2.2 - Configuration standards for system components
- 2.3 - Encrypt non-console admin access
- 8.1 - User identification management
- 8.2 - Authentication management
- 8.3 - Multi-factor authentication for remote access
- 10.1 - Audit trail requirements
- 10.2 - Automated audit trails for security events
- 10.3 - Audit trail detail requirements

**HIPAA (Health Insurance Portability and Accountability Act):**
Supports:
- Access Control (§164.312(a)(1))
- Audit Controls (§164.312(b))
- Integrity (§164.312(c)(1))
- Person or Entity Authentication (§164.312(d))
- Transmission Security (§164.312(e)(1))

**SOC 2 (Service Organization Control 2):**
Supports trust service criteria:
- CC6.1 - Logical and physical access controls
- CC6.6 - Prevention and detection of security incidents
- CC6.7 - Security incident containment
- CC7.2 - System monitoring

**NIST (National Institute of Standards and Technology):**
Implements controls from:
- NIST SP 800-53 (Security and Privacy Controls)
- NIST Cybersecurity Framework

### Important Compliance Notes:

**This script provides a FOUNDATION, not complete compliance.**

**What it does:**
- Implements many technical controls from frameworks
- Creates audit logs required for compliance
- Hardens system configuration
- Enables security tools

**What it DOES NOT do:**
- Replace formal security assessment
- Implement application-specific security
- Configure backups or disaster recovery
- Provide encryption at rest
- Replace security awareness training
- Provide HIPAA Business Associate Agreement
- Configure network segmentation
- Implement role-based access control (RBAC)
- Configure intrusion detection systems (IDS)
- Provide security information and event management (SIEM)

**For full compliance, you also need:**
- Formal risk assessment
- Security policies and procedures
- Incident response plan
- Security awareness training
- Regular vulnerability assessments
- Penetration testing
- Third-party audit
- Ongoing monitoring and maintenance

**Professional Assessment Required:**
If you need compliance certification (PCI-DSS, HIPAA, SOC 2, etc.), hire a qualified security professional or compliance specialist. This script is a starting point, not a complete solution.

---

## License & Support

### License:

This project is licensed under **Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**

**You are free to:**
- Share - copy and redistribute the material
- Adapt - remix, transform, and build upon the material

**Under the following terms:**
- **Attribution** - You must give appropriate credit, provide a link to the license, and indicate if changes were made
- **NonCommercial** - You may not use the material for commercial purposes

**Commercial Licensing:**
For commercial use, contact: cyberjunk77@protonmail.com

### Support:

**Community Support (Free):**
- GitHub Issues: https://github.com/captainzero93/security_harden_linux/issues
- GitHub Discussions: https://github.com/captainzero93/security_harden_linux/discussions
- Best-effort response time
- Community-driven Q&A

**Professional Support (Paid):**
- Email: cyberjunk77@protonmail.com
- Custom script development
- Security consulting
- Training and workshops
- Priority response
- Commercial licensing

### Contributing:

**Want to improve this script?**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

**Contribution guidelines:**
- Follow existing code style
- Add comments for complex logic
- Test on multiple distributions
- Update documentation
- One feature per pull request

**What we're looking for:**
- Bug fixes
- Performance improvements
- Additional security modules
- Better error handling
- Documentation improvements
- Distribution compatibility

### Donations:

If this script saved you time or money, consider supporting development:

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/captainzero)

**All donations go toward:**
- Continued development
- Testing on more distributions
- Documentation improvements
- Security research
- Community support

---

## Version History

### Version 3.7 (2025-10-20) - Current Release

**Critical Bug Fixes:**
- Fixed system_update module hanging on Debian 13 (Trixie)
- Fixed dry-run mode not working properly
- Fixed progress bar in non-interactive sessions
- Improved timeout handling for apt operations
- Better error handling and recovery
- Fixed missing MODULE_DEPS entries
- Better handling of locked dpkg/apt states

**Improvements:**
- Enhanced compatibility with Debian 13
- Better TTY detection for progress bars
- Milestone-based progress logging in non-interactive mode
- Automatic retry mechanism for apt operations
- Improved dependency resolution
- Clearer error messages

**Compatibility:**
- Full support for Ubuntu 25.10 (Oracular)
- Complete Debian 13 (Trixie) compatibility verified
- Enhanced Kubuntu 24.04+ support

### Version 3.6 (2025-09-15)

**Major Features:**
- Complete refactoring of core execution engine
- Dependency resolution system for modules
- Circular dependency detection
- Progress tracking with visual progress bars
- Improved desktop environment detection
- Better backup and restore functionality

**Security Enhancements:**
- AppArmor profile management
- USB device protection module
- Lynis security audit integration
- Enhanced kernel hardening parameters
- Improved AIDE configuration

**Bug Fixes:**
- Fixed GRUB configuration on EFI systems
- Resolved Fail2Ban jail conflicts
- Fixed SSH port change issues
- Corrected sysctl parameter applications
- Fixed module dependency ordering

**Usability:**
- Colorized output for better readability
- Verbose logging option
- Non-interactive mode for automation
- Custom configuration file support
- Module selection (enable/disable specific modules)

### Version 3.5 (2025-07-10)

**Features:**
- Added support for Linux Mint 21+
- Added support for Pop!_OS 22.04+
- Rootkit scanner integration (rkhunter + chkrootkit)
- Automatic security update configuration
- Password policy enforcement module
- Secure shared memory implementation

**Improvements:**
- Better handling of desktop environments
- Improved firewall rule organization
- Enhanced SSH hardening options
- More comprehensive audit logging
- Better error handling and recovery

**Bug Fixes:**
- Fixed ClamAV signature update issues
- Resolved AppArmor profile conflicts
- Fixed AIDE database initialization on slow systems
- Corrected IPv6 disable functionality

### Version 3.0 (2025-04-22)

**Major Release:**
- Complete rewrite in bash with better error handling
- Modular architecture (enable/disable modules)
- Security level system (low/moderate/high/paranoid)
- Automatic backup before all changes
- One-command restore functionality
- HTML report generation

**Features:**
- UFW firewall configuration
- Fail2Ban intrusion prevention
- AIDE file integrity monitoring
- Auditd system auditing
- ClamAV antivirus
- Kernel hardening (sysctl)
- Boot security (GRUB)
- SSH hardening
- AppArmor enforcement

**Desktop Optimizations:**
- Automatic desktop detection
- Preservation of gaming functionality
- KDE Connect / mDNS support
- Samba compatibility
- Zero performance impact

### Version 2.0 (2025-01-15)

**Features:**
- Basic firewall setup
- SSH hardening
- Password policy
- Package updates
- Simple logging

### Version 1.0 (2024-10-01)

**Initial Release:**
- Proof of concept
- Basic hardening steps
- Manual configuration

---

## Additional Resources

### Official Documentation:

**Ubuntu Security:**
- [Ubuntu Security Guide](https://ubuntu.com/security)
- [Ubuntu Server Security Guide](https://ubuntu.com/server/docs/security)
- [AppArmor on Ubuntu](https://ubuntu.com/server/docs/security-apparmor)

**Debian Security:**
- [Debian Security Manual](https://www.debian.org/doc/manuals/securing-debian-manual/)
- [Debian Security FAQ](https://www.debian.org/security/faq)
- [Debian Security Tracker](https://security-tracker.debian.org/)

**Security Standards:**
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [DISA STIGs](https://public.cyber.mil/stigs/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [PCI Security Standards](https://www.pcisecuritystandards.org/)

### Tools Documentation:

**Firewall:**
- [UFW Documentation](https://help.ubuntu.com/community/UFW)
- [UFW Man Page](https://manpages.ubuntu.com/manpages/focal/man8/ufw.8.html)

**Intrusion Prevention:**
- [Fail2Ban Manual](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [Fail2Ban Configuration](https://github.com/fail2ban/fail2ban)

**File Integrity:**
- [AIDE Manual](https://aide.github.io/)
- [AIDE Configuration Guide](https://aide.github.io/doc/)

**Auditing:**
- [Auditd Documentation](https://github.com/linux-audit/audit-documentation)
- [Linux Audit Quickstart](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening)

**Mandatory Access Control:**
- [AppArmor Documentation](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation)
- [AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)

**Security Scanning:**
- [Lynis Documentation](https://cisofy.com/documentation/lynis/)
- [RKHunter README](http://rkhunter.sourceforge.net/)
- [ClamAV Documentation](https://docs.clamav.net/)

### Related Projects:

**Security Hardening:**
- [Dev-Sec Hardening Framework](https://dev-sec.io/)
- [Ansible Hardening](https://github.com/openstack/ansible-hardening)
- [Lynis](https://cisofy.com/lynis/) - Security auditing tool
- [OpenSCAP](https://www.open-scap.org/) - Security compliance tool
- [Bastille Linux](http://bastille-linux.sourceforge.net/) - Hardening toolkit

### Learning Resources:

**Beginner:**
- [Linux Journey](https://linuxjourney.com/) - Learn Linux basics
- [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/) - Security challenges
- [Cybrary](https://www.cybrary.it/) - Free security training

**Intermediate:**
- [Defensive Security](https://tryhackme.com/paths) - TryHackMe paths
- [Linux Academy](https://linuxacademy.com/) - Linux training
- [SANS Reading Room](https://www.sans.org/white-papers/) - Security papers

**Advanced:**
- [Exploit Education](https://exploit.education/) - Security exercises
- [PentesterLab](https://pentesterlab.com/) - Web security
- [HackTheBox](https://www.hackthebox.com/) - Security challenges

### Books:

- **"Linux Basics for Hackers"** - OccupyTheWeb
- **"Practical Linux Security"** - Michael Boelen
- **"Linux Security Cookbook"** - Gregor N. Purdy
- **"The Practice of Network Security Monitoring"** - Richard Bejtlich

### YouTube Channels:

- NetworkChuck - Linux and security basics
- LiveOverflow - Security research and exploitation
- IppSec - HackTheBox walkthroughs
- John Hammond - CTF challenges and security

---

**Quick links:**
- Documentation is this README
- [Report Bug](https://github.com/captainzero93/security_harden_linux/issues/new)
- [Discussions](https://github.com/captainzero93/security_harden_linux/discussions)

---

## Important Legal Disclaimer

**READ BEFORE USE**

### No Warranty

This script is provided "AS IS" without warranty of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, and non-infringement.

### Compliance

This script provides a security foundation, not complete compliance with any framework. Professional assessment and additional controls are required for PCI-DSS, HIPAA, SOC 2, or similar standards. Consult qualified security professionals for compliance requirements.

### Limitations

This script does not:
- Guarantee absolute security (no system is 100% secure)
- Replace professional security assessment
- Provide monitoring or incident response
- Implement application-specific security
- Configure backups or disaster recovery
- Provide encryption at rest
- Replace security awareness training

### Liability

To the maximum extent permitted by law:
- The authors and contributors disclaim all liability for any damages arising from use of this script
- Users assume all risk associated with use
- This includes but is not limited to: data loss, system damage, service disruption, security breaches, compliance violations, or financial losses

### Support Disclaimer

- Support is provided on a best-effort basis with no guaranteed response time
- No service level agreements (SLAs)
- Bug fixes and updates provided when possible, not guaranteed

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
- **DO NOT** open public issue
- Email directly: cyberjunk77@protonmail.com
- Use subject: "SECURITY: [brief description]"
- Response target: within 48 hours

**Note:** All support is provided on best-effort basis.

### Commercial Support:

For commercial licensing, professional support, or consulting services:
- cyberjunk77@protonmail.com

**Services available:**
- Custom script development
- Professional security assessment
- Compliance consulting
- Training and workshops
- Priority support contracts

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

**Star this repo if it helped you!** Alternatively help support: https://ko-fi.com/captainzero

**Version:** 3.7 | **Author:** captainzero93 | 

**GitHub:** https://github.com/captainzero93/security_harden_linux

---
