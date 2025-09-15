# Linux Security Hardening Scripts

Security hardening scripts for Ubuntu/Debian systems implementing DISA STIG and CIS compliance standards.

**Note:** For advanced users, see [DISA-STIG-CIS-LINUX-HARDENING](https://github.com/captainzero93/DISA-STIG-CIS-LINUX-HARDENING-) for a more comprehensive solution.

## Features

- Firewall (UFW) configuration with rate limiting
- Fail2Ban intrusion prevention
- SSH hardening (key-only auth, strong ciphers)
- Audit system (auditd) configuration
- AppArmor enforcement
- Kernel parameter hardening via sysctl
- Boot security (GRUB hardening)
- Password policy enforcement
- Rootkit detection (rkhunter, chkrootkit)
- File integrity monitoring (AIDE)
- Automatic security updates
- USB device restrictions
- Core dump prevention

## Requirements

- Ubuntu 20.04+ or Debian 11+
- Root/sudo access
- Internet connection for package installation

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
-h, --help              Show help
-v, --verbose           Enable verbose output
-n, --non-interactive   Run without prompts
-d, --dry-run          Preview changes without applying
-l, --level LEVEL      Set security level (low|moderate|high|paranoid)
-e, --enable MODULES   Enable specific modules (comma-separated)
-x, --disable MODULES  Disable specific modules (comma-separated)
-r, --restore          Restore from backup
-R, --report           Generate security report only
--list-modules         List available modules
```

### Examples

```bash
# Run specific modules only
sudo ./improved_harden_linux.sh -e firewall,ssh_hardening,fail2ban

# High security for production servers
sudo ./improved_harden_linux.sh -l high -n

# Preview changes
sudo ./improved_harden_linux.sh --dry-run

# Generate security report
sudo ./improved_harden_linux.sh --report
```

## Security Levels

- **low**: Basic hardening for development systems
- **moderate**: Balanced security (default)
- **high**: Strong security, minimal usability impact
- **paranoid**: Maximum security, may affect usability

## Available Modules

| Module | Description |
|--------|-------------|
| system_update | Update system packages |
| firewall | Configure UFW firewall |
| fail2ban | Setup Fail2Ban |
| ssh_hardening | Harden SSH configuration |
| root_access | Disable root login |
| audit | Configure auditd |
| apparmor | Setup AppArmor |
| sysctl | Configure kernel parameters |
| password_policy | Enforce strong passwords |
| rootkit_scanner | Install rootkit detection |
| usb_protection | Restrict USB devices |
| aide | Setup file integrity monitoring |

## Backup and Recovery

Backups are automatically created in `/root/security_backup_[timestamp].tar.gz`

To restore:
```bash
sudo ./improved_harden_linux.sh --restore
```

## Logs and Reports

- Script log: `/var/log/security_hardening.log`
- HTML report: `/root/security_hardening_report_[timestamp].html`

## Testing

Always test in a non-production environment first. Use `--dry-run` to preview changes.

## Troubleshooting

### SSH Access Issues
Ensure you have SSH key access before running the script if using ssh_hardening module.

### Service Issues
Check AppArmor profiles if services fail:
```bash
sudo aa-status
sudo aa-complain /path/to/binary  # To troubleshoot
```

### Firewall Issues
Review UFW rules:
```bash
sudo ufw status verbose
```

## FAQ

**Q: Will this affect daily desktop use?**  
A: The moderate security level is designed to balance security with usability. Gaming, browsing, and common applications should work normally.

**Q: How do I undo changes?**  
A: Use `--restore` option or manually restore from backup files.

**Q: Can I run this on production servers?**  
A: Test thoroughly first. Use `--dry-run` and review the changes for your specific environment.

## License

Dual licensed:
- Non-commercial: CC BY-NC 4.0
- Commercial use requires separate license (contact for terms)

## Contributing

Pull requests welcome. Please test changes thoroughly and document any new features.

## Issues

Report bugs and feature requests via [GitHub Issues](https://github.com/captainzero93/security_harden_linux/issues).

## Disclaimer

Use at your own risk. Always backup your system before applying security changes.
