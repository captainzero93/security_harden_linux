# Linux Security Hardening Scripts

Security hardening scripts for Ubuntu/Kubuntu/Debian systems implementing DISA STIG and CIS compliance standards with enhanced error handling, dependency resolution, and desktop environment optimizations.

**Version 3.1-fixed** - Production-ready with comprehensive fixes, module dependency resolution, backup verification, and KDE Plasma optimizations!

**Note:** For advanced users, see [DISA-STIG-CIS-LINUX-HARDENING](https://github.com/captainzero93/DISA-STIG-CIS-LINUX-HARDENING-) for a more comprehensive solution.

## What's New in v3.1-fixed

### Critical Improvements
- **Automatic dependency resolution** - Modules execute in correct order
- **Backup checksum verification** - SHA-256 integrity checks for all backups
- **Enhanced restore functionality** - Detailed verification and error reporting
- **Kernel parameter deduplication** - Prevents duplicate boot parameters
- **Execution tracking** - Monitor which modules succeeded/failed
- **Input validation** - Validates all command-line arguments
- **Idempotent operations** - Safe to run multiple times

### Enhanced Error Handling
- Individual module failure tracking
- Interactive failure recovery options
- Comprehensive logging for all operations
- Better error messages with remediation steps
- Graceful degradation when modules fail

### Improved Reliability
- Package installation retries with exponential backoff
- SSH configuration validation before restart
- AppArmor profile enforcement feedback
- Firewall rule validation
- Mount point existence verification

## Features

### Core Security
- **Firewall (UFW)** - Advanced configuration with rate limiting and desktop-friendly exceptions
- **Fail2Ban** - Intelligent intrusion prevention with customized jail configurations
- **SSH Hardening** - Key-only authentication, protocol restrictions, session timeouts
- **Audit System (auditd)** - Comprehensive monitoring of authentication, network changes, and system calls
- **AppArmor** - Mandatory access control with profile enforcement and complaint mode handling
- **Kernel Hardening** - 20+ kernel parameters for memory protection, ASLR enhancement, and attack surface reduction
- **Boot Security** - GRUB hardening with kernel parameter validation and optional password protection
- **Password Policy** - 12+ character minimum with complexity requirements (PAM pwquality)
- **Rootkit Detection** - Automated scanning with rkhunter and chkrootkit
- **File Integrity** - AIDE monitoring with daily check reports
- **Automatic Updates** - Unattended security updates with kernel package management
- **USB Protection** - Intelligent logging/blocking based on environment and security level
- **Memory Security** - Secured shared memory with noexec/nosuid/nodev flags
- **Security Auditing** - Lynis integration with timestamped reports
- **Antivirus** - ClamAV with desktop-optimized configuration

### Desktop Environment Support
- **Automatic Detection** - Recognizes KDE, GNOME, XFCE, MATE, Cinnamon, and more
- **KDE Plasma Optimization** - Preserves KDE Connect, Bluetooth, and system integration
- **Network Discovery** - Optional mDNS/Avahi support for network browsing
- **Smart USB Policy** - Logging on desktops, optional blocking on servers
- **Performance Tuning** - No impact on GUI responsiveness or gaming performance
- **Service Preservation** - All desktop features work at moderate security level

### Advanced Features
- **Module Dependency Resolution** - Automatically resolves and executes prerequisites
- **Backup Verification** - SHA-256 checksums for backup integrity
- **Execution Tracking** - Real-time progress and success/failure monitoring
- **Comprehensive Reporting** - HTML reports with system info, executed modules, and recommendations
- **Flexible Configuration** - Security levels, module selection, custom configs
- **Dry Run Mode** - Preview all changes without applying them

## Requirements

### System Requirements
- **Operating System**: Ubuntu 22.04+, Kubuntu 24.04+, or Debian 11+
- **Architecture**: x86_64 (AMD64) or ARM (tested on Raspberry Pi)
- **Privileges**: Root/sudo access required
- **Network**: Internet connection for package installation
- **Disk Space**: 1GB+ free space recommended for backups

### Pre-requisites
- Active SSH key authentication (if running `ssh_hardening` module remotely)
- Backup of critical data
- Console/physical access or recovery method (if remote)
- Basic understanding of Linux security concepts

### Recommended
- Test VM or non-production environment
- Terminal multiplexer (screen/tmux) for remote execution
- Secondary admin user with sudo privileges

## Installation

### Standard Installation
```bash
# Download the script
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh

# Make it executable
chmod +x improved_harden_linux.sh

# Verify download (optional but recommended)
sha256sum improved_harden_linux.sh

# Run with dry-run first to preview changes
sudo ./improved_harden_linux.sh --dry-run -v
```

### Verification Steps
```bash
# Check script integrity
head -n 10 improved_harden_linux.sh

# Verify you have sudo access
sudo -v

# Ensure you have SSH keys set up (if hardening SSH)
ls -la ~/.ssh/authorized_keys

# Check available disk space
df -h /root

# Verify internet connectivity
ping -c 3 archive.ubuntu.com
```

## Usage

### Quick Start (Interactive Mode)
```bash
# Recommended for first-time users
sudo ./improved_harden_linux.sh

# The script will:
# 1. Detect your environment (desktop/server)
# 2. Create a backup automatically
# 3. Ask for confirmation on certain options
# 4. Execute all modules with dependency resolution
# 5. Generate an HTML report
# 6. Optionally restart your system
```

### Command-Line Options

```bash
Options:
  -h, --help              Display comprehensive help message
  -v, --verbose           Enable detailed operation logging
  -n, --non-interactive   Run without user prompts (uses defaults)
  -d, --dry-run          Preview all changes without applying
  -l, --level LEVEL      Set security level: low|moderate|high|paranoid
  -e, --enable MODULES   Run specific modules only (comma-separated)
  -x, --disable MODULES  Exclude specific modules (comma-separated)
  -r, --restore [FILE]   Restore from backup (uses latest if no file specified)
  -R, --report           Generate security report without changes
  -c, --config FILE      Use custom configuration file
  --version              Display script version
  --list-modules         Show all available modules with descriptions
```

### Common Usage Examples

#### First-Time Setup
```bash
# Preview what will happen
sudo ./improved_harden_linux.sh --dry-run -v

# Run with default moderate security (recommended)
sudo ./improved_harden_linux.sh -l moderate

# Run specific critical modules first
sudo ./improved_harden_linux.sh -e system_update,firewall,fail2ban,ssh_hardening
```

#### Desktop/Workstation
```bash
# Desktop-friendly configuration
sudo ./improved_harden_linux.sh -l moderate

# Gaming/multimedia system (exclude USB restrictions)
sudo ./improved_harden_linux.sh -l low -x usb_protection

# Development workstation
sudo ./improved_harden_linux.sh -e firewall,fail2ban,automatic_updates,password_policy
```

#### Server Deployments
```bash
# Production web server
sudo ./improved_harden_linux.sh -l high -n

# Database server (minimal modules)
sudo ./improved_harden_linux.sh -e firewall,ssh_hardening,audit,aide -l high

# Headless server (maximum security)
sudo ./improved_harden_linux.sh -l paranoid -n
```

#### Testing and Development
```bash
# Safe testing
sudo ./improved_harden_linux.sh --dry-run -v -l high

# Test specific module
sudo ./improved_harden_linux.sh -e firewall --dry-run

# Generate report only
sudo ./improved_harden_linux.sh --report
```

#### Maintenance Operations
```bash
# Re-run after system updates
sudo ./improved_harden_linux.sh -n

# Update specific modules
sudo ./improved_harden_linux.sh -e system_update,rootkit_scanner

# Audit current security
sudo ./improved_harden_linux.sh -e lynis_audit --report
```

## Security Levels Explained

### Low (Development/Testing)
**Use Case**: Development systems, testing environments, learning

**What It Does**:
- Basic firewall with essential rules only
- Minimal SSH hardening (keeps password auth as backup)
- Standard password policies
- No AppArmor enforcement
- No USB restrictions
- Kernel hardening disabled
- All desktop features preserved

**Impact**: Minimal security improvements, maximum compatibility

### Moderate (Recommended Default)
**Use Case**: Desktop workstations, development servers, general use

**What It Does**:
- Full firewall configuration with rate limiting
- SSH hardening with key-based auth
- Strong password policies (12+ chars)
- AppArmor in complain mode
- USB device logging (not blocking)
- Essential kernel hardening
- Desktop features fully preserved
- Network discovery maintained

**Impact**: Significant security improvement with zero desktop functionality loss

### High (Production Servers)
**Use Case**: Production servers, security-conscious environments

**What It Does**:
- Everything in Moderate, plus:
- AppArmor full enforcement
- Stricter kernel parameters
- USB boot restrictions (servers)
- Aggressive fail2ban settings
- File integrity monitoring
- GRUB password recommended
- Some desktop features may require manual allowlisting

**Impact**: Strong security with minimal usability trade-offs

### Paranoid (Maximum Security)
**Use Case**: Sensitive data systems, high-security requirements

**What It Does**:
- Everything in High, plus:
- Maximum kernel lockdown
- GRUB timeout disabled
- All USB disabled at boot (except explicitly allowed)
- Extremely strict network policies
- Full filesystem monitoring
- All services heavily restricted

**Impact**: Maximum security with significant usability restrictions

## Available Modules

### Core Modules (Auto-dependency)

| Module | Description | Dependencies | Time | Reboot Required |
|--------|-------------|--------------|------|-----------------|
| `system_update` | Updates all packages and repositories | None | 2-5 min | No |
| `firewall` | Configures UFW with intelligent rules | None | 30 sec | No |
| `fail2ban` | Intrusion prevention with SSH protection | system_update, firewall | 1 min | No |
| `ssh_hardening` | Disables password auth, enforces strong ciphers | system_update | 30 sec | No |
| `root_access` | Disables direct root login, restricts su | None | 10 sec | No |

### Security Modules

| Module | Description | Dependencies | Time | Impact |
|--------|-------------|--------------|------|--------|
| `audit` | Configures auditd for comprehensive logging | system_update | 1 min | Low |
| `apparmor` | Enforces mandatory access control | system_update | 1-2 min | Medium |
| `aide` | File integrity monitoring system | system_update | 5-15 min | Low |
| `clamav` | Antivirus installation and setup | system_update | 3-5 min | Low |
| `rootkit_scanner` | Installs rkhunter and chkrootkit | system_update | 2 min | Low |

### System Hardening Modules

| Module | Description | Dependencies | Time | Reboot Required |
|--------|-------------|--------------|------|-----------------|
| `boot_security` | GRUB and kernel parameter hardening | None | 1 min | **Yes** |
| `sysctl` | Kernel security parameters | None | 30 sec | No* |
| `filesystems` | Disables unused filesystem modules | None | 10 sec | **Yes** |
| `secure_shared_memory` | Secures /dev/shm and /run/shm | None | 10 sec | No* |
| `password_policy` | PAM and login.defs hardening | None | 30 sec | No |

### Optional Modules

| Module | Description | Dependencies | Time | Desktop Impact |
|--------|-------------|--------------|------|----------------|
| `ipv6` | IPv6 configuration/disable | None | 10 sec | Minimal |
| `usb_protection` | USB device logging/blocking | None | 10 sec | Medium (servers) |
| `packages` | Removes insecure packages | None | 1 min | Minimal |
| `ntp` | Time synchronization | None | 30 sec | None |
| `automatic_updates` | Unattended security updates | system_update | 1 min | None |
| `lynis_audit` | Security audit and report | system_update | 2-5 min | None |

*Changes take effect after sysctl reload or reboot for full effect

### Module Execution Order

The script automatically resolves dependencies. Example execution order:
```
User enables: fail2ban, aide, ssh_hardening
Actual order: system_update → firewall → fail2ban → ssh_hardening → aide
```

## Kernel Hardening Parameters Explained

The `boot_security` module adds comprehensive kernel hardening. Here's what each parameter does:

### Memory Protection
```bash
page_alloc.shuffle=1          # Randomizes page allocator freelists
slab_nomerge                  # Prevents slab cache merging attacks
init_on_alloc=1               # Zero memory on allocation
init_on_free=1                # Zero memory on free
randomize_kstack_offset=1     # Randomizes kernel stack offset (ASLR)
```

### Kernel Lockdown
```bash
kernel.unprivileged_bpf_disabled=1  # Blocks unprivileged BPF
net.core.bpf_jit_harden=2          # Hardens BPF JIT compiler
kernel.kptr_restrict=2              # Hides kernel pointers
kernel.dmesg_restrict=1             # Restricts dmesg access
kernel.perf_event_paranoid=3        # Disables performance monitoring
```

### ASLR Enhancement
```bash
vm.mmap_rnd_bits=32               # Increases ASLR entropy (64-bit)
vm.mmap_rnd_compat_bits=16        # Increases ASLR entropy (32-bit)
```

### Attack Surface Reduction
```bash
vsyscall=none                     # Disables legacy vsyscall
debugfs=off                       # Disables debug filesystem
oops=panic                        # Panics on kernel oops
module.sig_enforce=1              # Requires signed kernel modules
lockdown=confidentiality          # Enables kernel lockdown mode
```

### Optional (High/Paranoid)
```bash
nousb                             # Disables USB at boot (servers only)
```

## Backup and Recovery

### Automatic Backup

Every run creates a comprehensive backup:
```bash
Location: /root/security_backup_YYYYMMDD_HHMMSS.tar.gz
Checksum: /root/security_backup_YYYYMMDD_HHMMSS.tar.gz.sha256

Contents:
├── etc/
│   ├── default/grub
│   ├── ssh/sshd_config
│   ├── pam.d/
│   ├── security/
│   ├── sysctl.conf
│   ├── sysctl.d/
│   ├── audit/
│   ├── modprobe.d/
│   ├── fail2ban/
│   ├── ufw/
│   └── fstab
├── iptables.rules
├── ip6tables.rules
├── enabled_services.txt
├── installed_packages.txt
└── backup_info.txt
```

### Restore from Backup

```bash
# Restore from most recent backup
sudo ./improved_harden_linux.sh --restore

# Restore from specific backup with verification
sudo ./improved_harden_linux.sh --restore /root/security_backup_20241008_143022.tar.gz

# Verify backup integrity before restore
sha256sum -c /root/security_backup_20241008_143022.tar.gz.sha256

# Manual restore if script unavailable
cd /
sudo tar -xzf /root/security_backup_20241008_143022.tar.gz
sudo cp -a security_backup_*/etc/* /etc/
sudo iptables-restore < security_backup_*/iptables.rules
```

### Backup Best Practices

1. **Test Restores**: Regularly verify backups can be restored
2. **Off-System Storage**: Copy backups to separate system
3. **Version Control**: Keep multiple backup versions
4. **Document Changes**: Note any manual modifications after script runs

## Logs and Monitoring

### Primary Logs

```bash
# Script execution log
/var/log/security_hardening.log
- All operations logged with timestamps
- Error messages with remediation hints
- Module execution status

# Audit logs (if auditd enabled)
/var/log/audit/audit.log
- Authentication attempts
- File system changes
- Network modifications
- System call monitoring

# Firewall logs
/var/log/ufw.log
- Blocked connection attempts
- Rate limiting events
- Rule violations

# Authentication logs
/var/log/auth.log
- SSH login attempts
- Sudo command usage
- Failed authentications
- User account changes
```

### Reports

```bash
# HTML Security Report
/root/security_hardening_report_YYYYMMDD_HHMMSS.html
- System information
- Executed modules
- Failed modules (if any)
- Backup location
- Recommendations

# Lynis Audit Report
/var/log/lynis-YYYYMMDD_HHMMSS.log
- Security score
- Warnings and suggestions
- Compliance status
- Hardening index

# USB Device Log
/var/log/usb-devices.log
- Connected USB devices
- Vendor/Product IDs
- Connection timestamps
```

### Monitoring Commands

```bash
# Check script log
sudo tail -f /var/log/security_hardening.log

# Monitor authentication attempts
sudo tail -f /var/log/auth.log

# Check Fail2Ban status
sudo fail2ban-client status
sudo fail2ban-client status sshd

# View firewall status
sudo ufw status verbose
sudo ufw status numbered

# Check AppArmor status
sudo aa-status

# Review audit events
sudo ausearch -m USER_LOGIN -ts recent
sudo aureport --summary

# Check AIDE integrity
sudo aide --check

# View Lynis suggestions
sudo lynis show suggestions
```

## Testing and Validation

### Pre-Deployment Testing

```bash
# Phase 1: Dry Run
sudo ./improved_harden_linux.sh --dry-run -v -l moderate
# Review what will change

# Phase 2: Limited Modules
sudo ./improved_harden_linux.sh -e firewall,fail2ban
# Test with non-critical modules first

# Phase 3: Specific Security Level
sudo ./improved_harden_linux.sh -l moderate
# Apply with recommended level

# Phase 4: Verification
sudo ./improved_harden_linux.sh --report
# Generate status report

# Phase 5: Full Audit
sudo ./improved_harden_linux.sh -e lynis_audit
# Run comprehensive security audit
```

### Post-Deployment Validation

```bash
# Verify SSH still works (CRITICAL before disconnecting)
ssh -v user@localhost

# Check firewall rules
sudo ufw status verbose

# Verify services are running
sudo systemctl status sshd fail2ban auditd

# Test sudo access
sudo -v

# Check for errors in logs
sudo grep -i error /var/log/security_hardening.log

# Verify backup exists
ls -lh /root/security_backup_*.tar.gz

# Check AppArmor profiles
sudo aa-status

# Test AIDE
sudo aide --check

# Run quick security scan
sudo rkhunter --check --skip-keypress
```

### Testing Checklist

- [ ] Backup created successfully
- [ ] Can still login via SSH
- [ ] Sudo access works
- [ ] Desktop environment functional (if applicable)
- [ ] Network connectivity maintained
- [ ] KDE Connect works (if enabled)
- [ ] USB devices detected (if not restricted)
- [ ] Services start correctly
- [ ] No errors in security_hardening.log
- [ ] Firewall rules are correct
- [ ] Can restore from backup

## Troubleshooting

### SSH Access Issues

**Symptom**: Cannot connect via SSH after hardening

**Diagnosis**:
```bash
# Check SSH service status
sudo systemctl status sshd

# Review SSH configuration
sudo sshd -t

# Check SSH logs
sudo journalctl -u ssh -n 50

# Review firewall rules
sudo ufw status | grep ssh
```

**Solutions**:
```bash
# Option 1: Restore from backup
sudo ./improved_harden_linux.sh --restore

# Option 2: Fix SSH config (via console)
sudo nano /etc/ssh/sshd_config
# Temporarily enable PasswordAuthentication yes
sudo systemctl restart sshd

# Option 3: Add SSH key (if missing)
cat ~/.ssh/id_rsa.pub | ssh user@host 'cat >> ~/.ssh/authorized_keys'

# Option 4: Check UFW port
sudo ufw allow 22/tcp
sudo ufw reload
```

### Module Failed to Execute

**Symptom**: Module shows as failed in report

**Diagnosis**:
```bash
# Check detailed logs
sudo grep "module_name" /var/log/security_hardening.log

# Check system logs
sudo journalctl -xe | grep -i error

# Verify dependencies
sudo apt-cache policy package-name
```

**Solutions**:
```bash
# Re-run specific module
sudo ./improved_harden_linux.sh -e failed_module -v

# Run with dependencies
sudo ./improved_harden_linux.sh -e system_update,failed_module

# Skip problematic module
sudo ./improved_harden_linux.sh -x failed_module

# Check for conflicts
sudo dpkg --audit
sudo apt-get install -f
```

### AppArmor Blocking Services

**Symptom**: Services fail to start with AppArmor errors

**Diagnosis**:
```bash
# Check AppArmor status
sudo aa-status

# View denied operations
sudo journalctl -xe | grep apparmor

# Check specific profile
sudo aa-logprof
```

**Solutions**:
```bash
# Set profile to complain mode
sudo aa-complain /usr/sbin/service-name

# Disable specific profile
sudo ln -s /etc/apparmor.d/usr.sbin.service-name /etc/apparmor.d/disable/
sudo apparmor_parser -R /etc/apparmor.d/usr.sbin.service-name

# Update profile
sudo aa-logprof  # Interactive profile updates

# Restart AppArmor
sudo systemctl restart apparmor
```

### Firewall Blocking Legitimate Traffic

**Symptom**: Cannot access services that should be allowed

**Diagnosis**:
```bash
# Check firewall rules
sudo ufw status numbered

# Monitor firewall blocks
sudo tail -f /var/log/ufw.log

# Check specific port
sudo netstat -tlnp | grep :PORT
```

**Solutions**:
```bash
# Allow specific port
sudo ufw allow PORT/tcp comment 'Service description'

# Allow from specific IP
sudo ufw allow from IP_ADDRESS to any port PORT

# Allow application
sudo ufw app list
sudo ufw allow 'App Name'

# Insert rule at specific position
sudo ufw insert 1 allow from 192.168.1.0/24 to any

# Reload firewall
sudo ufw reload
```

### Desktop Features Not Working

**Symptom**: KDE Connect, network discovery, or USB devices not working

**Diagnosis**:
```bash
# Check desktop detection
echo $XDG_CURRENT_DESKTOP

# Verify KDE Connect ports
sudo ufw status | grep 1714

# Check mDNS
sudo ufw status | grep 5353

# Review USB logs
sudo tail -f /var/log/usb-devices.log
```

**Solutions**:
```bash
# Re-run with desktop optimizations
sudo ./improved_harden_linux.sh -l moderate

# Manually allow KDE Connect
sudo ufw allow 1714:1764/tcp comment 'KDE Connect'
sudo ufw allow 1714:1764/udp comment 'KDE Connect'

# Allow mDNS/Avahi
sudo ufw allow 5353/udp comment 'mDNS'

# Disable USB restrictions (desktops)
sudo rm /etc/udev/rules.d/90-usb-*.rules
sudo udevadm control --reload-rules
```

### High CPU/Memory Usage

**Symptom**: System performance degraded after hardening

**Diagnosis**:
```bash
# Check CPU usage
top
htop

# Check memory usage
free -h
vmstat 1

# Identify processes
ps aux --sort=-%cpu | head -20
ps aux --sort=-%mem | head -20
```

**Solutions**:
```bash
# Stop ClamAV daemon (if not needed)
sudo systemctl stop clamav-daemon
sudo systemctl disable clamav-daemon

# Reduce auditd logging
sudo systemctl stop auditd
# Edit /etc/audit/rules.d/hardening.rules to reduce rules

# Disable AIDE checks
sudo chmod -x /etc/cron.daily/aide-check

# Lower AppArmor to complain mode
sudo aa-complain /etc/apparmor.d/*

# Check for runaway processes
sudo systemctl list-units --failed
```

### Boot Issues After Hardening

**Symptom**: System fails to boot or boots slowly

**Diagnosis** (via recovery mode):
```bash
# Boot into recovery mode
# Select "root" shell

# Check GRUB config
cat /etc/default/grub | grep CMDLINE

# Review system logs
journalctl -xb

# Check kernel parameters
cat /proc/cmdline
```

**Solutions** (in recovery mode):
```bash
# Restore GRUB backup
cp /etc/default/grub.backup.* /etc/default/grub
update-grub

# Remove problematic kernel parameters
nano /etc/default/grub
# Edit GRUB_CMDLINE_LINUX_DEFAULT
update-grub

# Restore full system
cd /
tar -xzf /root/security_backup_*.tar.gz
cp -a security_backup_*/etc/* /etc/
reboot
```

### Cannot Restore from Backup

**Symptom**: Restore operation fails

**Solutions**:
```bash
# Verify backup integrity
sha256sum -c /root/security_backup_*.tar.gz.sha256

# Manual extraction
mkdir /tmp/restore
tar -xzf /root/security_backup_*.tar.gz -C /tmp/restore

# Check contents
ls -la /tmp/restore/security_backup_*/

# Selective restore
sudo cp -a /tmp/restore/security_backup_*/etc/ssh/sshd_config /etc/ssh/
sudo systemctl restart sshd

# Try older backup
ls -lt /root/security_backup_*.tar.gz
sudo ./improved_harden_linux.sh --restore /root/security_backup_OLDER.tar.gz
```

## Advanced Usage

### Custom Configuration File

Create a custom config to pre-set options:

```bash
# Create configuration file
cat > ~/hardening.conf << 'EOF'
# Security level
SECURITY_LEVEL="moderate"

# Enable/disable modules
ENABLE_MODULES="firewall,fail2ban,ssh_hardening,automatic_updates"

# Flags
VERBOSE=true
INTERACTIVE=false
EOF

# Use custom config
sudo ./improved_harden_linux.sh -c ~/hardening.conf
```

### Automated Deployment

```bash
#!/bin/bash
# deploy_hardening.sh - Automated security hardening

# Configuration
SECURITY_LEVEL="high"
MODULES="system_update,firewall,fail2ban,ssh_hardening,audit,aide"

# Pre-flight checks
if ! ssh-add -l &>/dev/null; then
    echo "Error: SSH key not loaded"
    exit 1
fi

# Run hardening
sudo ./improved_harden_linux.sh \
    -l "$SECURITY_LEVEL" \
    -e "$MODULES" \
    -n \
    -v

# Verify
if [ $? -eq 0 ]; then
    echo "Hardening completed successfully"
    sudo ./improved_harden_linux.sh --report
else
    echo "Hardening failed, check logs"
    exit 1
fi
```

### Module Dependency Chain Example

```bash
# If you enable 'fail2ban', the script automatically runs:
# 1. system_update (dependency)
# 2. firewall (dependency)
# 3. fail2ban (requested)

# You can see the execution order with:
sudo ./improved_harden_linux.sh -e fail2ban -v --dry-run
# Output shows: "Execution order: system_update firewall fail2ban"
```

### Scheduled Re-Hardening

```bash
# Create cron job for monthly re-hardening
sudo crontab -e

# Add line:
0 2 1 * * /path/to/improved_harden_linux.sh -n -l moderate >> /var/log/auto_harden.log 2>&1
```

### Production Server Deployment

```bash
# Stage 1: Test on staging server
ssh staging-server
sudo ./improved_harden_linux.sh --dry-run -v -l high

# Stage 2: Apply with specific modules
sudo ./improved_harden_linux.sh \
    -e system_update,firewall,ssh_hardening,fail2ban,audit \
    -l high \
    -n

# Stage 3: Verify
sudo ./improved_harden_linux.sh --report

# Stage 4: Deploy to production (if staging successful)
ssh prod-server
sudo ./improved_harden_linux.sh -l high -n

# Stage 5: Monitor
watch 'fail2ban-client status'
```

## Performance Impact Details

### Service-Specific Impact

```
auditd:     ~30MB RAM, <1% CPU, 5-10MB/day logs
fail2ban:   ~50MB RAM, <1% CPU
aide:       Scan: 2-5min (daily), minimal runtime impact
clamav:     ~100MB RAM (daemon off by default on desktop)
apparmor:   ~10MB RAM, <0.5% CPU
firewall:   ~5MB RAM, negligible CPU
```

### Desktop Performance

- **Gaming**: No FPS impact at moderate level
- **Video Editing**: No performance loss
- **Development**: IDE/compilation unaffected
- **Browsing**: No noticeable latency

## Security Compliance

### Standards Implemented

This script implements controls from:

#### DISA STIG Controls
- V-238197: Disable unused file systems
- V-238200: Configure audit logging
- V-238204: SSH protocol 2
- V-238207: Disable root login
- V-238209: Strong password policies
- V-238211: Account lockout policies (via fail2ban)
- V-238215: Session timeout configuration
- V-238220: Kernel parameter hardening
- And 50+ additional STIG controls

#### CIS Benchmarks (Level 1 & 2)
- 1.1.x: Filesystem configuration
- 1.3.x: Filesystem integrity checking
- 1.4.x: Secure boot settings
- 3.x: Network configuration
- 4.1.x: Configure auditd
- 5.2.x: SSH server configuration
- 5.3.x: PAM configuration
- 6.2.x: User accounts and environment

#### NIST 800-53 Controls
- AC-2: Account Management
- AC-7: Unsuccessful Logon Attempts
- AU-2: Audit Events
- CM-6: Configuration Settings
- IA-5: Authenticator Management
- SC-7: Boundary Protection
- SI-4: Information System Monitoring

### Compliance Verification

```bash
# Run Lynis compliance check
sudo lynis audit system

# Check specific compliance
sudo ./improved_harden_linux.sh -e lynis_audit
grep -i "compliance" /var/log/lynis-*.log

# OpenSCAP scanning (requires additional tools)
sudo oscap xccdf eval \
    --profile xccdf_org.ssgproject.content_profile_stig \
    /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
```

## FAQ

### General Questions

**Q: Will this script break my system?**  
A: The script creates automatic backups and has been tested extensively. However, always test in non-production first and use `--dry-run` to preview changes.

**Q: Can I run this on a desktop/laptop?**  
A: Yes! v3.1-fixed includes desktop detection and KDE/GNOME/XFCE optimizations. Use moderate security level for best balance.

**Q: Do I need to reboot after running?**  
A: Recommended but not always required. Boot security and kernel parameter changes require reboot. The script will prompt you.

**Q: Can I run this multiple times?**  
A: Yes, it's idempotent. Safe to run multiple times. It will update configurations and create new backups each time.

**Q: How do I undo all changes?**  
A: Use `sudo ./improved_harden_linux.sh --restore` to restore from the automatic backup.

**Q: Will this affect my gaming performance?**  
A: No. At moderate level, there's no impact on gaming, video editing, or other performance-intensive tasks.

### Technical Questions

**Q: What's the difference between v3.1 and v3.1-fixed?**  
A: v3.1-fixed adds critical improvements: module dependency resolution, backup checksum verification, better error handling, kernel parameter deduplication, and execution tracking.

**Q: How does module dependency resolution work?**  
A: The script automatically identifies and executes prerequisite modules. For example, if you enable `fail2ban`, it automatically runs `system_update` and `firewall` first.

**Q: Are backups verified?**  
A: Yes, v3.1-fixed generates SHA-256 checksums for all backups and verifies them during restore operations.

**Q: Can I create custom modules?**  
A: Yes, add `module_yourname()` function and register it in `SECURITY_MODULES` array. Follow the existing module pattern.

**Q: Does this work with Docker/Kubernetes?**  
A: Yes, but be cautious with `sysctl` and `apparmor` modules. Consider excluding them or testing thoroughly: `-x sysctl,apparmor`

**Q: Will this break Docker containers?**  
A: The moderate security level should not impact Docker. Some kernel parameters in high/paranoid levels may affect container networking. Test before production use.

**Q: Can I use this with configuration management tools?**  
A: Yes, the script works well with Ansible, Puppet, Chef, Salt. Use `-n` flag for non-interactive execution.

**Q: Does this support Wayland?**  
A: Yes, desktop detection is display-server agnostic. Works with both X11 and Wayland.

**Q: What about ARM/Raspberry Pi support?**  
A: Fully supported on Raspberry Pi OS (Debian-based). Some modules may need adjustment for specific ARM architectures.

### Troubleshooting Questions

**Q: SSH stopped working after hardening, what do I do?**  
A: 1) Access via console, 2) Restore backup: `sudo ./improved_harden_linux.sh --restore`, or 3) Temporarily enable password auth in `/etc/ssh/sshd_config`

**Q: A module failed, should I be concerned?**  
A: Check logs at `/var/log/security_hardening.log`. Most failures are non-critical. You can re-run specific modules or exclude problematic ones.

**Q: AppArmor is blocking my application, how do I fix it?**  
A: Set profile to complain mode: `sudo aa-complain /path/to/binary`, or disable specific profile. See Troubleshooting section.

**Q: High CPU usage after hardening, why?**  
A: Check if ClamAV daemon is running. Stop it if not needed: `sudo systemctl stop clamav-daemon`. Also check AIDE and auditd are not running excessive scans.

**Q: Can I restore just one specific config file?**  
A: Yes, extract backup and copy specific files: `tar -xzf backup.tar.gz` then `cp` individual files.

### Operational Questions

**Q: How often should I run this script?**  
A: Initially for hardening, then quarterly or after major updates. Enable `automatic_updates` module for ongoing security.

**Q: Should I run this on my main development machine?**  
A: Yes, with moderate security level. It won't interfere with development work and significantly improves security.

**Q: What's the recommended approach for production servers?**  
A: Test on staging with `--dry-run`, apply with high security level and `-n` flag, monitor for 24-48 hours, then deploy to production.

**Q: Can I schedule automatic hardening?**  
A: Yes, but be cautious. Consider cron job with specific modules only: `0 2 1 * * /path/to/script -e system_update,rootkit_scanner -n`

**Q: How do I monitor ongoing security?**  
A: Check logs regularly, run Lynis audits monthly, monitor fail2ban with `sudo fail2ban-client status`, review AIDE reports.

### Reporting Issues

When reporting issues, include:
- Operating system and version (`lsb_release -a`)
- Script version (`./script.sh --version`)
- Command used to run script
- Relevant log excerpts from `/var/log/security_hardening.log`
- Error messages
- Steps to reproduce

## Support and Resources

### Getting Help

- **Issues**: [GitHub Issues](https://github.com/captainzero93/security_harden_linux/issues) - Bug reports and feature requests
- **Discussions**: [GitHub Discussions](https://github.com/captainzero93/security_harden_linux/discussions) - Questions and community help
- **Security Issues**: Report privately to maintainer

### Useful Resources

- [DISA STIG Guides](https://public.cyber.mil/stigs/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [Ubuntu Security](https://ubuntu.com/security)
- [Lynis Documentation](https://cisofy.com/documentation/lynis/)
- [AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)
- [AIDE Documentation](https://aide.github.io/)

## License

**Dual Licensed:**

- **Non-commercial use**: [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/) (Creative Commons Attribution-NonCommercial 4.0)
- **Commercial use**: Requires separate license agreement. Contact maintainer for terms.

### Non-Commercial License (CC BY-NC 4.0)

You are free to:
- **Share** — copy and redistribute in any medium or format
- **Adapt** — remix, transform, and build upon the material

Under the following terms:
- **Attribution** — Give appropriate credit
- **NonCommercial** — Not for commercial use
- **No additional restrictions**

### Commercial License

Commercial use includes:
- Using in for-profit organizations
- Providing as a paid service
- Bundling with commercial products
- Using in commercial consulting

Contact for commercial licensing terms.

## Acknowledgments

- Community contributors
- Security researchers
- DISA STIG and CIS Benchmark teams
- Ubuntu/Debian security teams
- Testing volunteers

## Disclaimer

**IMPORTANT: USE AT YOUR OWN RISK**

This script makes significant changes to system security settings. While extensively tested:

### Before Running
- ✅ **Backup your data** independently of script backups
- ✅ **Test in non-production** environment first
- ✅ **Review changes** with `--dry-run` before applying
- ✅ **Maintain access** to recovery console if remote
- ✅ **Understand impact** of each module on your use case
- ✅ **Have SSH keys** set up if running SSH hardening remotely

### Liability
The authors and contributors are not responsible for:
- System issues or downtime
- Data loss or corruption
- Security breaches
- Service disruption
- Any damages direct or indirect

### Recommendations
- Always test in development environment
- Keep console/physical access available
- Maintain multiple admin accounts
- Document all customizations
- Monitor system after hardening
- Have rollback plan ready

### Professional Use
For production/enterprise environments:
- Conduct security audit of script
- Test extensively in staging
- Have dedicated security team review
- Implement monitoring and alerting
- Maintain disaster recovery procedures

**By using this script, you acknowledge these risks and accept full responsibility for any consequences.**

---

## Version History

### v3.1-fixed (Current - 2024)
- ✅ Module dependency resolution
- ✅ Backup checksum verification (SHA-256)
- ✅ Enhanced restore functionality with verification
- ✅ Kernel parameter deduplication
- ✅ Execution tracking (success/failure monitoring)
- ✅ Input validation for all parameters
- ✅ Idempotent operations
- ✅ Enhanced error handling with remediation hints
- ✅ AppArmor profile enforcement tracking
- ✅ SSH configuration validation before restart
- ✅ Firewall SSH port detection improvements
- ✅ AIDE initialization verification
- ✅ Package installation retry logic
- ✅ Comprehensive HTML reports with failed modules
- ✅ Better logging throughout all modules

### v3.1 (2024)
- Desktop environment detection
- KDE Plasma / Kubuntu optimizations
- Kubuntu 25.10 support
- Desktop-friendly USB policies
- KDE Connect firewall support
- Network discovery preservation
- Enhanced password policies
- All modules implemented
- Improved progress indicators

### v3.0 (2024)
- Initial modular architecture
- Security level selection
- Comprehensive backup system
- HTML reporting
- Multiple module support

### v2.0
- Enhanced error handling
- Package management improvements
- Configuration backups

### v1.0
- Initial release
- Basic hardening features

---

**Star this repository if you find it useful! ⭐**

**Report issues and contribute to make Linux security better for everyone.**
