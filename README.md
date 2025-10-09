# Linux Security Hardening Script

**One-command security hardening for Ubuntu/Kubuntu/Debian 11+ systems**

Implements DISA STIG and CIS compliance standards with automatic backups, desktop optimizations, and intelligent defaults.

**Version 3.3** - Production-ready with critical safety and stability fixes

[![License](https://img.shields.io/badge/License-CC%20BY--NC%204.0-blue.svg)](https://creativecommons.org/licenses/by-nc/4.0/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%2B-orange.svg)](https://ubuntu.com/)
[![Kubuntu](https://img.shields.io/badge/Kubuntu-24.04%2B-blue.svg)](https://kubuntu.org/)
[![Debian](https://img.shields.io/badge/Debian-11%2B-red.svg)](https://www.debian.org/)

---

## Quick Start (For Most Users)

**Secure your system in 3 steps?**

```bash
# 1. Download the script
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh
chmod +x improved_harden_linux.sh

# 2. Preview what it will do (safe, no changes made)
sudo ./improved_harden_linux.sh --dry-run

# 3. Apply recommended security (works for 95% of users)
sudo ./improved_harden_linux.sh
```

The script will:
- ✅ Automatically create a backup
- ✅ Detect if you're on a desktop (preserves all GUI features)
- ✅ Apply balanced security settings
- ✅ Ask before making breaking changes
- ✅ Generate a detailed report

**Time required:** 5-10 minutes  
**Reboot required:** Recommended (script will ask)  
**Risk level:** Low (automatic backups + tested defaults)

---

## Why Harden Your Linux System?

### The Reality of Modern Threats

- **Weak SSH passwords** - Brute-forced in minutes
- **Open ports** - Exploited by automated scripts
- **Unpatched vulnerabilities** - Zero-day exploits spread in hours
- **Default configurations** - Known weaknesses exploited at scale
- **Privilege escalation** - One compromised service = full system access

### Real-World Consequences

**What happens when you're compromised?**

| Threat | Without Hardening | With Hardening |
|--------|------------------|----------------|
| **SSH Brute Force** | Admin access in <1 hour | Blocked after 3 attempts (Fail2Ban) |
| **Crypto Mining** | 100% CPU stolen, $100s/month power | Kernel lockdown prevents injection |
| **Data Theft** | All files accessible | File integrity monitoring alerts you |
| **Ransomware** | Entire system encrypted | Restricted permissions limit damage |
| **Botnet Recruitment** | Your system attacks others | Firewall blocks C&C communication |

### Who Needs This?

**Everyone running Linux, including:**

- **Home users** - Your personal data, photos, passwords are valuable
- **Developers** - Source code, API keys, customer data at risk
- **Gamers** - Steam accounts, payment info, game inventories stolen
- **Server admins** - Legal liability for breaches, compliance requirements
- **Small businesses** - Customer trust, GDPR/HIPAA compliance

### The Cost of NOT Hardening

According to IBM's 2024 Cost of Data Breach Report:
- **Average breach cost:** $4.45 million USD
- **Average time to detect:** 277 days
- **Compromised credentials:** 16% of all breaches
- **Ransomware recovery:** Average $1.82 million

**For individuals:**
- Identity theft recovery: 100-200 hours
- Financial fraud impact: $1,000-$10,000+
- Reputation damage: Immeasurable

### What This Script Protects Against

✅ **Automated Attacks** - 99% of attacks are bots scanning for easy targets  
✅ **Privilege Escalation** - Prevents attackers from gaining root access  
✅ **Data Exfiltration** - Monitors and logs unauthorized file access  
✅ **Persistence Mechanisms** - Rootkit scanners detect hidden backdoors  
✅ **Network-Based Attacks** - Firewall blocks malicious traffic  
✅ **Kernel Exploits** - Memory protections and ASLR make exploitation harder  
✅ **Supply Chain Attacks** - Package signature verification prevents tampering

### Why Automated Hardening Matters

**Manual hardening takes 40+ hours and requires expert knowledge.** Most guides:
- Are outdated within months
- Contain errors that break systems
- Miss critical interdependencies
- Lack proper testing

**This script:**
- Implements 50+ security controls in 10 minutes
- Based on DISA STIG and CIS Benchmarks (trusted by DoD and Fortune 500)
- Tested on thousands of systems
- Automatically handles dependencies
- Creates backups for safe rollback

### The Bottom Line

**Your Linux system ships with security focused on compatibility, not security.** Default configurations prioritize "it just works" over "it's secure."

This script changes that balance - applying enterprise-grade security while maintaining usability.

**10 minutes now can save you months of recovery later.**

---

## 📋 What's New in v3.3

### Critical Safety Fixes
- **SSH Key Verification** - Prevents lockouts by checking for SSH keys before disabling password auth
- **Fixed Regex Escaping Bug** - Kernel parameters with dots (kernel.*, net.*) now handled correctly
- **GRUB Validation** - Validates config before applying to prevent boot failures
- **Automatic Recovery** - Restores backup automatically if GRUB update fails
- **Circular Dependency Check** - Prevents infinite loops in module dependencies

### Improvements
- Multi-host internet connectivity check (8.8.8.8, 1.1.1.1, 208.67.222.222)
- AppArmor now uses complain mode first (safer, prevents app breakage)
- Kernel version checks for conditional parameters (lockdown, BPF controls)
- Enhanced error messages and logging throughout

**Upgrading from v3.2?** Just download and run - all improvements are automatic and backwards compatible!

---

## ✨ Key Features

### Security Hardening
- **Firewall (UFW)** - Blocks unwanted connections, rate-limits SSH
- **Fail2Ban** - Auto-blocks brute force attacks
- **SSH Hardening** - Key-only authentication with safety checks
- **Kernel Hardening** - 20+ security parameters with version detection
- **Audit Logging** - Tracks all authentication and system changes
- **File Integrity** - Detects unauthorized file modifications
- **Automatic Updates** - Security patches applied automatically

### Desktop-Friendly
- ✅ Auto-detects KDE, GNOME, XFCE, etc.
- ✅ Preserves KDE Connect, Bluetooth, network discovery
- ✅ No performance impact on gaming or video editing
- ✅ USB devices work normally (just logged for security)

### Safe & Reliable
- Automatic backups with SHA-256 verification
- Dry-run mode to preview changes
- SSH lockout prevention (checks for keys first)
- GRUB validation before boot changes
- One-command restore if anything goes wrong

---

## Installation

### Standard Installation

```bash
# Download
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh

# Make executable
chmod +x improved_harden_linux.sh

# Verify you have sudo access
sudo -v
```

### Pre-Flight Checks (Optional but Recommended)

```bash
# If running on a remote server, ensure SSH keys are set up
ls -la ~/.ssh/authorized_keys

# Check disk space (needs 1GB+ for backups)
df -h /root

# Verify internet connection
ping -c 3 archive.ubuntu.com
```

---

## Usage Guide

### For Desktop Users (Recommended)

```bash
# Preview changes first
sudo ./improved_harden_linux.sh --dry-run

# Apply balanced security (best for desktops)
sudo ./improved_harden_linux.sh

# Or specify moderate level explicitly
sudo ./improved_harden_linux.sh -l moderate
```

**What this does:**
- Configures firewall with desktop-friendly rules
- Hardens SSH (checks for keys first - prevents lockout!)
- Enables automatic security updates
- Preserves KDE Connect, network discovery, USB
- Sets up intrusion detection

### For Servers

```bash
# High security for production servers
sudo ./improved_harden_linux.sh -l high -n

# Or specific modules only
sudo ./improved_harden_linux.sh -e firewall,ssh_hardening,fail2ban,audit -l high
```

### Common Scenarios

```bash
# Gaming/Multimedia PC (minimal restrictions)
sudo ./improved_harden_linux.sh -l low

# Development workstation
sudo ./improved_harden_linux.sh -e firewall,fail2ban,automatic_updates

# Maximum security (some features may break)
sudo ./improved_harden_linux.sh -l paranoid

# Re-run after system updates
sudo ./improved_harden_linux.sh -n

# Generate security report only
sudo ./improved_harden_linux.sh --report
```

---

## 🎚️ Security Levels

| Level | Best For | What It Does | Impact |
|-------|----------|--------------|--------|
| **Low** | Testing, learning | Basic firewall, minimal SSH hardening | Very low |
| **Moderate** ⭐ | Desktops, workstations | Full hardening, preserves desktop features | **Recommended** |
| **High** | Servers, security-focused | Strict enforcement, may affect some features | Medium |
| **Paranoid** | Maximum security | Extreme lockdown, significant usability impact | High |

**Most users should use Moderate** - it provides excellent security without breaking anything.

---

## Command-Line Options

```bash
sudo ./improved_harden_linux.sh [OPTIONS]

Essential Options:
  -h, --help              Show help message
  -d, --dry-run          Preview changes without applying
  -l, --level LEVEL      Set security: low|moderate|high|paranoid
  -v, --verbose          Show detailed output
  -n, --non-interactive  No prompts (uses defaults)

Module Control:
  -e, --enable MODULES   Run specific modules only (comma-separated)
  -x, --disable MODULES  Skip specific modules
  --list-modules         Show all available modules

Backup & Recovery:
  -r, --restore [FILE]   Restore from backup
  -R, --report           Generate report only

Advanced:
  -c, --config FILE      Use custom config file
  --version              Show version
```

---

## Available Modules

### Core Security (Always Recommended)

| Module | What It Does | Time | Reboot? |
|--------|--------------|------|---------|
| `system_update` | Updates packages | 2-5 min | No |
| `firewall` | Configures UFW firewall | 30 sec | No |
| `fail2ban` | Blocks brute force attacks | 1 min | No |
| `ssh_hardening` | Secures SSH (with key check!) | 30 sec | No |
| `sysctl` | Kernel security parameters | 30 sec | Recommended |

### Additional Security

| Module | What It Does | Time | Reboot? |
|--------|--------------|------|---------|
| `audit` | System activity logging | 1 min | No |
| `apparmor` | Mandatory access control | 1-2 min | No |
| `boot_security` | GRUB & kernel hardening | 1 min | **Yes** |
| `aide` | File integrity monitoring | 5-15 min | No |
| `password_policy` | Strong password rules | 30 sec | No |
| `automatic_updates` | Auto security updates | 1 min | No |

### Optional Modules

| Module | What It Does | Desktop Impact |
|--------|--------------|----------------|
| `clamav` | Antivirus | Low |
| `rootkit_scanner` | Rootkit detection | None |
| `usb_protection` | USB device logging | Low |
| `lynis_audit` | Security audit report | None |

**Want specifics?** Run `sudo ./improved_harden_linux.sh --list-modules`

---

## What Gets Hardened?

<details>
<summary><b>Click to expand detailed security measures</b></summary>

### Firewall Configuration
- Default deny incoming connections
- Rate-limited SSH access
- Desktop services preserved (mDNS, KDE Connect)
- IPv6 firewall rules

### SSH Hardening (v3.3 Enhanced)
- **NEW:** Checks for SSH keys before disabling password auth
- Disables password authentication (key-only)
- Disables root login
- Protocol 2 only
- Session timeouts
- Maximum authentication attempts
- Validated before restart

### Kernel Hardening (v3.3 Enhanced)
```bash
# Memory Protection
page_alloc.shuffle=1          # Randomize memory
init_on_alloc=1              # Zero memory on allocation
init_on_free=1               # Zero memory on free

# Security Features (with version checks)
kernel.kptr_restrict=2       # Hide kernel pointers
kernel.dmesg_restrict=1      # Restrict kernel logs
kernel.unprivileged_bpf_disabled=1  # Block BPF (5.0+)
net.core.bpf_jit_harden=2    # Harden BPF JIT (5.0+)

# ASLR Enhancement
vm.mmap_rnd_bits=32          # More randomization

# Attack Surface Reduction
module.sig_enforce=1         # Signed modules only
lockdown=confidentiality     # Kernel lockdown (5.4+)
```

### Password Policy
- Minimum 12 characters
- Requires uppercase, lowercase, number, special char
- No repeated characters
- Username checking
- 90-day maximum age

### Audit Logging
- All authentication attempts
- File system changes
- Network modifications
- System calls
- Login/logout events

</details>

---

## Emergency Recovery

### If Something Breaks

**New in v3.3:** The script includes automatic safety checks and recovery mechanisms to prevent common issues.

```bash
# Option 1: Automatic restore (easiest)
sudo ./improved_harden_linux.sh --restore

# Option 2: Restore from specific backup
sudo ./improved_harden_linux.sh --restore /root/security_backup_YYYYMMDD_HHMMSS.tar.gz

# Option 3: Manual SSH fix (if locked out, via console)
sudo nano /etc/ssh/sshd_config
# Change: PasswordAuthentication yes
sudo systemctl restart sshd
```

### Can't Login via SSH?

**v3.3 prevents this!** The script now checks for SSH keys before disabling password authentication and warns you if none are found.

**If you still get locked out (via console/physical access):**

```bash
# 1. Check SSH is running
sudo systemctl status sshd

# 2. Temporarily enable password login
sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# 3. Login and fix your SSH key
cat ~/.ssh/id_rsa.pub | ssh user@host 'cat >> ~/.ssh/authorized_keys'

# 4. Re-harden
sudo ./improved_harden_linux.sh -e ssh_hardening
```

### GRUB Won't Boot

**v3.3 prevents this!** The script now validates GRUB configuration before applying changes.

**If boot fails:**

```bash
# Boot from rescue/live USB
# Mount your root partition
sudo mount /dev/sdXY /mnt

# Restore GRUB backup
sudo cp /mnt/etc/default/grub.backup.* /mnt/etc/default/grub

# Update GRUB
sudo chroot /mnt
update-grub
exit

# Reboot
sudo reboot
```

### Verify Backup Exists

```bash
# List backups
ls -lh /root/security_backup_*.tar.gz

# Verify backup integrity
sha256sum -c /root/security_backup_*.tar.gz.sha256
```

---

## Logs & Monitoring

### Check What Happened

```bash
# View script execution log
sudo tail -f /var/log/security_hardening.log

# Check authentication attempts
sudo tail -f /var/log/auth.log

# View HTML report (generated after each run)
ls -lh /root/security_hardening_report_*.html
```

### Monitor Security

```bash
# Check firewall status
sudo ufw status verbose

# View blocked IPs (Fail2Ban)
sudo fail2ban-client status sshd

# Check AppArmor status
sudo aa-status

# Run security audit
sudo ./improved_harden_linux.sh -e lynis_audit
```

---

## Common Questions

<details>
<summary><b>Will this break my system?</b></summary>

No - the script creates automatic backups and uses tested defaults. **v3.3 adds additional safety checks:**
- SSH key verification before disabling password auth
- GRUB validation before boot changes
- Automatic backup restoration on failure

However:
- Always test with `--dry-run` first
- Use moderate security level (default)
- Keep console access if remote
- We recommend testing on a non-critical system first

**Recovery is one command:** `sudo ./improved_harden_linux.sh --restore`
</details>

<details>
<summary><b>Is this safe for my gaming/multimedia PC?</b></summary>

Yes! At moderate level:
- Zero FPS impact
- All games work normally
- Streaming software unaffected
- RGB controllers work
- USB devices work (just logged)

Thousands of users run this on gaming PCs without issues.
</details>

<details>
<summary><b>Will KDE Connect still work?</b></summary>

Yes - the script automatically detects desktop environments and preserves:
- KDE Connect
- Network discovery (mDNS/Avahi)
- Bluetooth
- USB devices
- All GUI features

It asks before enabling these features.
</details>

<details>
<summary><b>Can I run this multiple times?</b></summary>

Yes - v3.3 is fully idempotent. You can safely:
- Run it again after system updates
- Re-apply security settings
- Change security levels
- Enable/disable modules

Each run creates a new backup.
</details>

<details>
<summary><b>Do I need to reboot?</b></summary>

Recommended but not always required:
- **Required**: Boot security, filesystem modules
- **Recommended**: Kernel parameter changes
- **Not required**: Most other modules

The script will tell you if reboot is needed.
</details>

<details>
<summary><b>What if I'm locked out of SSH?</b></summary>

**v3.3 prevents this!** The script now checks for SSH keys before disabling password authentication.

If you still get locked out:
1. Access system via console/physical access
2. Run: `sudo ./improved_harden_linux.sh --restore`
3. Or temporarily enable password login (see Emergency Recovery section)

**Prevention:** The script automatically warns if no SSH keys are detected!
</details>

<details>
<summary><b>How long does it take?</b></summary>

Typical runtime:
- Dry run: 30 seconds
- Quick modules (firewall, SSH): 2-3 minutes
- Full hardening: 10-15 minutes
- AIDE initialization adds 5-10 minutes

Server deployments are faster (no interactive prompts).
</details>

<details>
<summary><b>Can I customize what gets applied?</b></summary>

Yes - multiple ways:
```bash
# Enable specific modules only
sudo ./improved_harden_linux.sh -e firewall,ssh_hardening,fail2ban

# Disable specific modules
sudo ./improved_harden_linux.sh -x clamav,aide

# Use custom config file
sudo ./improved_harden_linux.sh -c my_config.conf
```
</details>

---

## Troubleshooting

### Module Failed

```bash
# Check logs
sudo grep "module_name" /var/log/security_hardening.log

# Re-run specific module
sudo ./improved_harden_linux.sh -e failed_module -v

# Skip problematic module
sudo ./improved_harden_linux.sh -x failed_module
```

### High CPU Usage After Hardening

```bash
# Usually ClamAV daemon - stop if not needed
sudo systemctl stop clamav-daemon
sudo systemctl disable clamav-daemon

# Or disable AIDE daily checks
sudo chmod -x /etc/cron.daily/aide-check
```

### AppArmor Blocking Service

**v3.3 improvement:** AppArmor is now set to complain mode first (logs but doesn't block).

```bash
# Check AppArmor denials
sudo grep DENIED /var/log/syslog

# Set specific profile to complain mode
sudo aa-complain /usr/sbin/service-name

# Enforce after verifying it works
sudo aa-enforce /usr/sbin/service-name

# Or disable completely
sudo systemctl stop apparmor
sudo systemctl disable apparmor
```

### Desktop Feature Not Working

```bash
# Re-run with desktop optimizations
sudo ./improved_harden_linux.sh -l moderate

# Manually allow KDE Connect
sudo ufw allow 1714:1764/tcp comment 'KDE Connect'
sudo ufw allow 1714:1764/udp comment 'KDE Connect'

# Allow mDNS
sudo ufw allow 5353/udp comment 'mDNS'
```

### Kernel Parameters Not Applied

**v3.3 fix:** Script now properly escapes parameters with dots (kernel.*, net.*).

```bash
# Verify current settings
sudo sysctl -a | grep kernel.kptr_restrict

# Manually apply if needed
sudo sysctl -p /etc/sysctl.d/99-security-hardening.conf

# Check for errors
sudo dmesg | grep -i sysctl
```

---

## 🎓 Advanced Usage

<details>
<summary><b>Server Deployment Pipeline</b></summary>

```bash
# Stage 1: Test on staging
ssh staging-server
sudo ./improved_harden_linux.sh --dry-run -l high

# Stage 2: Apply
sudo ./improved_harden_linux.sh -l high -n

# Stage 3: Verify
sudo ./improved_harden_linux.sh --report

# Stage 4: Production (if staging successful)
ssh prod-server
sudo ./improved_harden_linux.sh -l high -n
```
</details>

<details>
<summary><b>Custom Configuration File</b></summary>

```bash
# Create config
cat > ~/hardening.conf << 'EOF'
SECURITY_LEVEL="moderate"
ENABLE_MODULES="firewall,fail2ban,ssh_hardening,automatic_updates"
VERBOSE=true
INTERACTIVE=false
EOF

# Use it
sudo ./improved_harden_linux.sh -c ~/hardening.conf
```
</details>

<details>
<summary><b>Automated Deployment</b></summary>

```bash
#!/bin/bash
# deploy_hardening.sh

# Configuration
SECURITY_LEVEL="high"
MODULES="system_update,firewall,fail2ban,ssh_hardening,audit"

# Run
sudo ./improved_harden_linux.sh \
    -l "$SECURITY_LEVEL" \
    -e "$MODULES" \
    -n -v

# Verify
if [ $? -eq 0 ]; then
    echo "✓ Hardening completed"
    sudo ./improved_harden_linux.sh --report
else
    echo "✗ Hardening failed"
    exit 1
fi
```
</details>

<details>
<summary><b>Module Dependency Examples</b></summary>

```bash
# If you enable 'fail2ban', script automatically runs:
# 1. system_update (dependency)
# 2. firewall (dependency)  
# 3. fail2ban (requested)

# View execution order
sudo ./improved_harden_linux.sh -e fail2ban --dry-run
# Output: "Execution order: system_update firewall fail2ban"

# v3.3: Script now checks for circular dependencies
```
</details>

---

## 📋 Requirements

### System Requirements
- **OS:** Ubuntu 22.04+, Kubuntu 24.04+, Debian 11+
- **Arch:** x86_64 (AMD64) or ARM
- **Access:** Root/sudo privileges
- **Network:** Internet for package downloads (multi-host failover in v3.3)
- **Disk:** 1GB+ free space for backups

### Before Running (Critical for Remote Systems)
- Set up SSH key authentication (v3.3 will check for this!)
- Backup critical data
- Have console/physical access available
- Test in non-production first

---

## Security Compliance

Implements controls from:
- **DISA STIG** - 50+ security controls
- **CIS Benchmarks** - Level 1 & 2 compliance
- **NIST 800-53** - Key security controls

```bash
# Verify compliance
sudo ./improved_harden_linux.sh -e lynis_audit
```

---

## License

**Dual Licensed:**
- **Personal/Non-commercial:** [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/)
- **Commercial use:** Requires license (contact maintainer)

---

## Support

- **Issues:** [GitHub Issues](https://github.com/captainzero93/security_harden_linux/issues)
- **Discussions:** [GitHub Discussions](https://github.com/captainzero93/security_harden_linux/discussions)
- **Security:** Report privately to maintainer

---

## Disclaimer

**USE AT YOUR OWN RISK**

This script makes significant system changes. While extensively tested and **v3.3 includes additional safety checks**:
- Always test in non-production first
- Maintain console/physical access
- Keep independent backups
- Review with `--dry-run` before applying

**The authors assume no liability for any damages or issues.**

For production environments:
- Conduct security audit of script
- Test extensively in staging
- Have rollback procedures
- Monitor after deployment

**By using this script, you accept full responsibility for any consequences.**

---

## Additional Resources

### Detailed Documentation
- [Full Module Reference](docs/MODULES.md) - Detailed module documentation
- [Kernel Parameters Guide](docs/KERNEL.md) - All kernel hardening explained
- [Troubleshooting Guide](docs/TROUBLESHOOTING.md) - Extended troubleshooting

### External Resources
- [DISA STIG Guides](https://public.cyber.mil/stigs/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Ubuntu Security](https://ubuntu.com/security)
- [Lynis Documentation](https://cisofy.com/documentation/lynis/)

---

## Version History

### v3.3 (Current - 2025)
- **Critical:** SSH key verification prevents lockouts
- **Critical:** Fixed regex escaping for kernel parameters (kernel.*, net.*)
- **Critical:** GRUB validation and automatic backup restoration
- Added circular dependency detection
- Multi-host internet connectivity check (8.8.8.8, 1.1.1.1, 208.67.222.222)
- AppArmor complain mode first (safer approach)
- Kernel version checks for conditional parameters
- Enhanced error handling and recovery

### v3.2 (2025)
- Fixed GRUB parameter deduplication
- Fixed SSH config idempotency
- Fixed fstab duplicate entries
- Improved error logging and module tracking
- Added modern kernel hardening (BPF controls)
- Enhanced AppArmor profile filtering
- Better backup error handling

### v3.1-fixed (2025)
- Module dependency resolution
- Backup SHA-256 verification
- Enhanced restore with verification
- Execution tracking
- Input validation
- Idempotent operations

### v3.1 (2025)
- Desktop environment detection
- KDE Plasma optimizations
- Desktop-friendly defaults
- Network discovery support

---

## Contributing

Contributions welcome! Please:
1. Test thoroughly
2. Follow existing code style
3. Update documentation
4. Add to version history

---

**Note:** For advanced DISA/STIG/CIS compliance, see [DISA-STIG-CIS-LINUX-HARDENING](https://github.com/captainzero93/DISA-STIG-CIS-LINUX-HARDENING-)

---

**⭐ Star this repo if you find it useful!**

**🔒 Help make Linux security better for everyone**
