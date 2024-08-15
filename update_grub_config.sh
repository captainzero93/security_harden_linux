#!/bin/bash

# Global variables
VERSION="2.0"
GRUB_CONFIG="/etc/default/grub"
BACKUP_FILE="${GRUB_CONFIG}.bak.$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/grub_config_update.log"

# Function to log messages
log() {
    local message="$(date '+%Y-%m-%d %H:%M:%S'): $1"
    echo "$message" | tee -a "$LOG_FILE"
}

# Function to display help
display_help() {
    echo "Usage: sudo $0 [OPTIONS]"
    echo "Options:"
    echo "  -h, --help     Display this help message"
    echo "  --version      Display script version"
    echo "  --dry-run      Perform a dry run without making changes"
    exit 0
}

# Function to display version
display_version() {
    echo "Enhanced GRUB Configuration Script v$VERSION"
    exit 0
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    log "Error: This script must be run as root. Please use sudo."
    exit 1
fi

# Parse command line arguments
dry_run=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            display_help
            ;;
        --version)
            display_version
            ;;
        --dry-run)
            dry_run=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            display_help
            ;;
    esac
done

# Backup the original file
if [ -f "$GRUB_CONFIG" ]; then
    if ! $dry_run; then
        cp "$GRUB_CONFIG" "$BACKUP_FILE"
        log "Backup created: $BACKUP_FILE"
    else
        log "Dry run: Would create backup: $BACKUP_FILE"
    fi
else
    log "Error: $GRUB_CONFIG not found. Exiting."
    exit 1
fi

# Parameters to add
PARAMS=(
    "page_alloc.shuffle=1"
    "slab_nomerge"
    "init_on_alloc=1"
    "init_on_free=1"
    "randomize_kstack_offset=1"
    "kernel.unprivileged_bpf_disabled=1"
    "net.core.bpf_jit_harden=2"
    "kernel.kptr_restrict=2"
    "kernel.dmesg_restrict=1"
    "kernel.perf_event_paranoid=3"
    "vm.mmap_rnd_bits=32"
    "vm.mmap_rnd_compat_bits=16"
    "vsyscall=none"
    "debugfs=off"
    "oops=panic"
    "module.sig_enforce=1"
)

# Read the current GRUB_CMDLINE_LINUX_DEFAULT value
CURRENT_VALUE=$(grep GRUB_CMDLINE_LINUX_DEFAULT "$GRUB_CONFIG" | cut -d'"' -f2)

# Add new parameters
for param in "${PARAMS[@]}"; do
    if [[ $CURRENT_VALUE != *"$param"* ]]; then
        CURRENT_VALUE="$CURRENT_VALUE $param"
        log "Added parameter: $param"
    else
        log "Parameter already present: $param"
    fi
done

# Update the GRUB configuration file
if ! $dry_run; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=".*"/GRUB_CMDLINE_LINUX_DEFAULT="'"$CURRENT_VALUE"'"/' "$GRUB_CONFIG"
    log "Updated GRUB_CMDLINE_LINUX_DEFAULT in $GRUB_CONFIG"
else
    log "Dry run: Would update GRUB_CMDLINE_LINUX_DEFAULT in $GRUB_CONFIG"
fi

# Ensure GRUB_ENABLE_CRYPTODISK is set to y
if ! $dry_run; then
    if grep -q "^GRUB_ENABLE_CRYPTODISK=" "$GRUB_CONFIG"; then
        sed -i 's/^GRUB_ENABLE_CRYPTODISK=.*/GRUB_ENABLE_CRYPTODISK=y/' "$GRUB_CONFIG"
    else
        echo "GRUB_ENABLE_CRYPTODISK=y" >> "$GRUB_CONFIG"
    fi
    log "Enabled GRUB_ENABLE_CRYPTODISK"
else
    log "Dry run: Would enable GRUB_ENABLE_CRYPTODISK"
fi

# Update GRUB
if ! $dry_run; then
    if command -v update-grub &> /dev/null; then
        update-grub
        log "GRUB configuration updated using update-grub"
    elif command -v grub2-mkconfig &> /dev/null; then
        grub2-mkconfig -o /boot/grub2/grub.cfg
        log "GRUB configuration updated using grub2-mkconfig"
    else
        log "Warning: Neither update-grub nor grub2-mkconfig found. Please update GRUB manually."
    fi
else
    log "Dry run: Would update GRUB configuration"
fi

log "Script execution completed. Please reboot your system for changes to take effect."
