#!/bin/bash

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    log "Error: This script must be run as root. Please use sudo."
    exit 1
fi

# Backup the original file
GRUB_CONFIG="/etc/default/grub"
BACKUP_FILE="${GRUB_CONFIG}.bak.$(date +%Y%m%d_%H%M%S)"

if [ -f "$GRUB_CONFIG" ]; then
    cp "$GRUB_CONFIG" "$BACKUP_FILE"
    log "Backup created: $BACKUP_FILE"
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
sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=".*"/GRUB_CMDLINE_LINUX_DEFAULT="'"$CURRENT_VALUE"'"/' "$GRUB_CONFIG"
log "Updated GRUB_CMDLINE_LINUX_DEFAULT in $GRUB_CONFIG"

# Ensure GRUB_ENABLE_CRYPTODISK is set to y
if grep -q "^GRUB_ENABLE_CRYPTODISK=" "$GRUB_CONFIG"; then
    sed -i 's/^GRUB_ENABLE_CRYPTODISK=.*/GRUB_ENABLE_CRYPTODISK=y/' "$GRUB_CONFIG"
else
    echo "GRUB_ENABLE_CRYPTODISK=y" >> "$GRUB_CONFIG"
fi
log "Enabled GRUB_ENABLE_CRYPTODISK"

# Update GRUB
if command -v update-grub &> /dev/null; then
    update-grub
    log "GRUB configuration updated using update-grub"
elif command -v grub2-mkconfig &> /dev/null; then
    grub2-mkconfig -o /boot/grub2/grub.cfg
    log "GRUB configuration updated using grub2-mkconfig"
else
    log "Warning: Neither update-grub nor grub2-mkconfig found. Please update GRUB manually."
fi

log "Script execution completed. Please reboot your system for changes to take effect."
