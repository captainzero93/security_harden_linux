# Linux Security Hardening Scripts

Security hardening scripts for Ubuntu/Kubuntu/Debian systems implementing DISA STIG and CIS compliance standards.

**Version 3.1** - Now with desktop environment detection and KDE Plasma optimizations!

**Note:** For advanced users, see [DISA-STIG-CIS-LINUX-HARDENING](https://github.com/captainzero93/DISA-STIG-CIS-LINUX-HARDENING-) for a more comprehensive solution.

## Features

### Core Security
- Firewall (UFW) configuration with rate limiting
- Fail2Ban intrusion prevention system
- SSH hardening (key-only auth, strong ciphers, rate limiting)
- Audit system (auditd) with comprehensive monitoring rules
- AppArmor enforcement with profile management
- Kernel parameter hardening via sysctl
- Boot security (GRUB hardening)
- Password policy enforcement (12+ character minimum)
- Rootkit detection (rkhunter, chkrootkit)
- File integrity monitoring (AIDE)
- Automatic security updates
- USB device logging and restrictions
- Secure shared memory configuration
- Lynis security auditing
- ClamAV antivirus with desktop-friendly configuration

### Desktop Environment Support (NEW in v3.1)
- Automatic desktop environment detection
- KDE Plasma / Kubuntu optimizations
- KDE Connect firewall rules (optional)
- Network discovery (mDNS/Avahi) support
- Desktop-friendly USB policies (logging vs blocking)
- Preserved GUI functionality at moderate security levels
- No performance impact on daily desktop use

### System Hardening
- Disable unused filesystems
- Remove unnecessary packages
- Time synchronization (systemd-timesyncd)
- IPv6 configuration options
- Core dump prevention
- Comprehensive HTML security reports

## Requirements

- Ubuntu 22.04+, Kubuntu 24.04+, or Debian 11+
- Automatically detects and adapts to desktop environments
- Root/sudo access
- Internet connection for package installation
- Recommended: 1GB+ free disk space for backups

## Installation

```bash
wget https://raw.githubusercontent.com/captainzero93/security_harden_linux/main/improved_harden_linux.sh
chmod +x improved_harden_linux.sh
sudo ./improved_harden_linux.sh
```

## Usage

### Basic usage
```bash
sudo ./improved_harden_linux.sh
```

### Command-line options
```bash
-h, --help              Show help message
-v, --verbose           Enable verbose output
-n, --non-interactive   Run without user prompts (use defaults)
-d, --dry-run          Preview changes without applying them
-l, --level LEVEL      Set security level (low|moderate|high|paranoid)
-e, --enable MODULES   Enable specific modules only (comma-separated)
-x, --disable MODULES  Disable specific modules (comma-separated)
-r, --restore          Restore system from most recent backup
-R, --report           Generate security report only (no changes)
-c, --config FILE      Use custom configuration file
--version              Display script version
--list-modules         List all available security modules
```

### Examples

```bash
# Basic run with interactive prompts (recommended for first use)
sudo ./improved_harden_linux.sh

# Desktop-friendly moderate security (default)
sudo ./improved_harden_linux.sh -l moderate

# Run specific modules only
sudo ./improved_harden_linux.sh -e firewall,ssh_hardening,fail2ban,automatic_updates

# High security for production servers
sudo ./improved_harden_linux.sh -l high -n

# Preview all changes without applying
sudo ./improved_harden_linux.sh --dry-run -v

# Generate security report without making changes
sudo ./improved_harden_linux.sh --report

# Exclude certain modules
sudo ./improved_harden_linux.sh -x ipv6,usb_protection
```

## Security Levels

- **low**: Basic hardening for development systems and testing
- **moderate**: Balanced security (default, recommended for desktops)
- **high**: Strong security with minimal usability impact
- **paranoid**: Maximum security, may significantly affect usability

## Desktop Environment Support

**NEW in v3.1** - Automatically detects and adapts for desktop environments:

### KDE Plasma / Kubuntu Optimizations
- **KDE Connect**: Optional firewall rules for phone integration (ports 1714-1764)
- **Network Discovery**: mDNS/Avahi support maintained for network browsing
- **USB Devices**: Smart logging instead of blocking (desktop-friendly)
- **ClamAV**: Installed for manual scanning (no background scanning impact)
- **Bluetooth**: Preserved functionality
- **GUI Services**: All desktop features work normally at moderate security level

### Tested Desktop Environments
- KDE Plasma (Kubuntu)
- GNOME (Ubuntu)
- XFCE (Xubuntu)
- MATE
- Cinnamon

## Available Modules

| Module | Description |
|--------|-------------|
| system_update | Update and upgrade system packages |
| firewall | Configure UFW firewall with rate limiting |
| fail2ban | Setup Fail2Ban intrusion prevention |
| ssh_hardening | Harden SSH configuration |
| root_access | Disable direct root login |
| audit | Configure auditd logging system |
| apparmor | Setup and enforce AppArmor profiles |
| sysctl | Configure kernel security parameters |
| password_policy | Enforce strong password requirements |
| rootkit_scanner | Install rkhunter and chkrootkit |
| usb_protection | Configure USB device policies |
| aide | Setup AIDE file integrity monitoring |
| clamav | Install ClamAV antivirus |
| ntp | Configure time synchronization |
| lynis_audit | Run Lynis security audit |
| secure_shared_memory | Secure shared memory configuration |
| boot_security | Secure GRUB and boot settings |
| ipv6 | Configure IPv6 settings |
| filesystems | Disable unused filesystems |
| packages | Remove unnecessary packages |
| automatic_updates | Enable automatic security updates |

## Backup and Recovery

Backups are automatically created before any changes are made:
- Location: `/root/security_backup_[timestamp].tar.gz`
- Includes: Configuration files, service states, firewall rules, package lists

### Restore from Backup
```bash
# Restore from most recent backup
sudo ./improved_harden_linux.sh --restore

# Restore from specific backup
sudo ./improved_harden_linux.sh --restore /root/security_backup_20241008_143022.tar.gz
```

## Logs and Reports

- **Script log**: `/var/log/security_hardening.log`
- **HTML report**: `/root/security_hardening_report_[timestamp].html`
- **Audit logs**: `/var/log/audit/audit.log` (if auditd enabled)
- **USB device log**: `/var/log/usb-devices.log` (if USB protection enabled)
- **Lynis audit**: `/var/log/lynis-[date].log` (if Lynis module run)

## Testing

⚠️ **Always test in a non-production environment first!**

1. Use `--dry-run` to preview all changes
2. Test with `--verbose` to see detailed operations
3. Start with specific modules using `-e` flag
4. Verify SSH access works before disconnecting
5. Keep a backup terminal session open during testing

```bash
# Safe testing workflow
sudo ./improved_harden_linux.sh --dry-run -v
sudo ./improved_harden_linux.sh -e firewall,fail2ban
sudo ./improved_harden_linux.sh -l moderate
```

## Troubleshooting

### SSH Access Issues
**Problem**: Can't connect via SSH after running script

**Solution**:
- Ensure you have SSH key authentication set up before running
- Check `/var/log/security_hardening.log` for errors
- Restore from backup: `sudo ./improved_harden_linux.sh --restore`
- Use recovery console if locked out

### AppArmor Service Issues
**Problem**: Services fail to start after AppArmor enforcement

**Solution**:
```bash
# Check AppArmor status
sudo aa-status

# Set profile to complain mode for troubleshooting
sudo aa-complain /path/to/binary

# View AppArmor logs
sudo journalctl -xe | grep apparmor
```

### Firewall Issues
**Problem**: Can't access certain services

**Solution**:
```bash
# Review current firewall rules
sudo ufw status verbose

# Allow specific port
sudo ufw allow [port]/tcp

# Check firewall logs
sudo tail -f /var/log/ufw.log
```

### Desktop Features Not Working
**Problem**: Network discovery or KDE Connect broken

**Solution**:
- Re-run script and allow mDNS when prompted
- Manually allow KDE Connect: `sudo ufw allow 1714:1764/tcp && sudo ufw allow 1714:1764/udp`
- Check desktop detection worked: `echo $XDG_CURRENT_DESKTOP`

### ClamAV High CPU Usage
**Problem**: ClamAV consuming resources

**Solution**:
```bash
# Stop ClamAV daemon (script doesn't enable by default)
sudo systemctl stop clamav-daemon
sudo systemctl disable clamav-daemon

# Run manual scans only
clamscan -r /home/yourusername
```

## FAQ

**Q: Will this affect daily desktop use on Kubuntu/KDE?**  
A: v3.1 includes desktop detection and KDE-optimized defaults. The moderate security level preserves KDE Connect, network discovery, USB devices, and all desktop functionality while significantly hardening security. Gaming, browsing, development, and common applications work normally.

**Q: How do I undo changes?**  
A: Use the `--restore` option to restore from the automatic backup, or manually restore from `/root/security_backup_[timestamp].tar.gz`

**Q: Can I run this on production servers?**  
A: Yes, but test thoroughly first in a staging environment. Use `--dry-run` to preview changes, start with moderate security level, and consider excluding modules that might impact your specific services.

**Q: Do I need to reboot after running?**  
A: A reboot is recommended but not always required. The script will prompt you. Some changes (kernel parameters, boot security) require a reboot to take full effect.

**Q: Can I run this script multiple times?**  
A: Yes, it's idempotent and safe to run multiple times. It will update configurations and won't break existing settings.

**Q: Will this break Docker/containers?**  
A: The moderate security level should not break Docker. If you experience issues, disable the `sysctl` or `apparmor` modules: `-x sysctl,apparmor`

**Q: How often should I run this?**  
A: Run it initially for hardening, then periodically (quarterly) or after major system updates. The `automatic_updates` module keeps security patches current.

**Q: What about Wayland vs X11?**  
A: The script works with both. Desktop detection is display-server agnostic.

**Q: Does this work on Raspberry Pi?**  
A: Yes, it works on Raspberry Pi OS (Debian-based), though some modules may need adjustment for ARM architecture.

## Security Best Practices

After running the script:

1. **Review Generated Reports**: Check `/root/security_hardening_report_[timestamp].html`
2. **Monitor Logs Regularly**: 
   - Check `/var/log/auth.log` for authentication attempts
   - Review Fail2Ban activity: `sudo fail2ban-client status`
3. **Keep Updated**: Enable automatic updates or regularly run `apt update && apt upgrade`
4. **Run Lynis Audits**: Periodically run `sudo lynis audit system`
5. **Test Backups**: Verify you can restore from backups
6. **Document Changes**: Keep notes on any custom modifications
7. **Review Firewall**: Regularly audit firewall rules with `sudo ufw status numbered`
8. **Check File Integrity**: If using AIDE, review reports regularly

## Performance Impact

| Security Level | CPU Impact | Memory Impact | Disk I/O | Desktop Impact |
|---------------|------------|---------------|----------|----------------|
| Low | Minimal | <50MB | Minimal | None |
| Moderate | <2% | ~100MB | Low | None |
| High | <5% | ~150MB | Low-Medium | Minimal |
| Paranoid | <10% | ~200MB | Medium | Moderate |

*Note: Desktop environments are unaffected at low/moderate levels*

## Compliance Standards

This script implements security controls based on:
- DISA STIG (Defense Information Systems Agency Security Technical Implementation Guides)
- CIS Benchmarks (Center for Internet Security)
- NIST Guidelines (National Institute of Standards and Technology)

For full compliance auditing, see the advanced [DISA-STIG-CIS-LINUX-HARDENING](https://github.com/captainzero93/DISA-STIG-CIS-LINUX-HARDENING-) repository.

## Version History

### v3.1 (Current)
- Desktop environment detection with KDE Plasma optimizations
- Complete implementation of all modules (AppArmor, AIDE, auditd, ClamAV, etc.)
- Kubuntu 25.10 support
- Desktop-friendly defaults for USB, network discovery, KDE Connect
- Enhanced password policies (12+ character minimum)
- Modern Ubuntu 22.04+ compatibility
- Improved user experience with better progress indicators

### v3.0
- Initial modular architecture
- Security level selection
- Comprehensive backup system
- HTML reporting

## License

Dual licensed:
- **Non-commercial use**: CC BY-NC 4.0 (Creative Commons Attribution-NonCommercial 4.0)
- **Commercial use**: Requires separate license agreement (contact for terms)

## Contributing

Pull requests are welcome! Please:
1. Test changes thoroughly on both server and desktop environments
2. Document new features in code comments and README
3. Follow existing code style and conventions
4. Include example usage in commit messages
5. Test on Ubuntu/Kubuntu/Debian before submitting

## Support

- **Issues**: Report bugs via [GitHub Issues](https://github.com/captainzero93/security_harden_linux/issues)
- **Discussions**: Use [GitHub Discussions](https://github.com/captainzero93/security_harden_linux/discussions) for questions

## Acknowledgments

- Community contributors
- Based on DISA STIG and CIS Benchmark standards

## Disclaimer

**Use at your own risk.** This script makes significant changes to system security settings. While thoroughly tested, always:
- Backup your system before running
- Test in non-production environments first
- Review changes with `--dry-run` before applying
- Maintain access to recovery/console if remote
- Understand each module's impact on your specific use case

The authors and contributors are not responsible for any system issues, data loss, or security breaches that may occur from using this script.

---
