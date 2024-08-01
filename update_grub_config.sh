#!/bin/bash

# Backup the original file
sudo cp /etc/default/grub /etc/default/grub.bak

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
    fi
done

# Update the GRUB configuration file
sudo sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT=".*"/GRUB_CMDLINE_LINUX_DEFAULT="'"$CURRENT_VALUE"'"/' /etc/default/grub

# Update GRUB
sudo update-grub

echo "GRUB configuration updated. Please reboot your system for changes to take effect."
