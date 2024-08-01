#!/bin/bash

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Backup the original file
if [ -f /etc/default/grub ]; then
    sudo cp /etc/default/grub /etc/default/grub.bak
    log "Backup created: /etc/default/grub.bak"
else
    log "Error: /etc/default/grub not found. Exiting."
    exit 1
fi

# Parameters to add
PARAMS=(
    "page_alloc.shuffle=1"
    "slab_nomerge"
    "init_on_alloc=1"
    "kernel.unprivileged_bpf_disabled=1"
    "net.core.bpf_jit_harden=2"
    "vm.mmap_rnd_bits=32"
    "vm.mmap_rnd_compat_bits=16"
)

# Read the current GRUB_CMDLINE_LINUX_DEFAULT value
CURRENT_VALUE=$(grep GRUB_CMDLINE_LINUX_DEFAULT /etc/default/grub | cut -d'"' -f2)

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
sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=".*"/GRUB_CMDLINE_LINUX_DEFAULT="'"$CURRENT_VALUE"'"/' /etc/default/grub
log "Updated GRUB_CMDLINE_LINUX_DEFAULT in /etc/default/grub"

# Update GRUB
if command -v update-grub &> /dev/null; then
    sudo update-grub
    log "GRUB configuration updated using update-grub"
elif command -v grub2-mkconfig &> /dev/null; then
    sudo grub2-mkconfig -o /boot/grub2/grub.cfg
    log "GRUB configuration updated using grub2-mkconfig"
else
    log "Warning: Neither update-grub nor grub2-mkconfig found. Please update GRUB manually."
fi

log "Script execution completed. Please reboot your system for changes to take effect."
