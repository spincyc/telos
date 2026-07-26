#!/usr/bin/env bash
# Homelab provisioning environment --- Archiso profile (ADR 0049).
#
# A netboot image whose only purpose is to run bin/homelab-install. It carries
# the tools that installer shells out to and nothing else: no desktop, no
# browser, no compiler.
#
# The image is a public artifact. It contains administrator PUBLIC keys only.
# No private key, token, passphrase or credential is ever baked in.

iso_name="homelab-install"
iso_label="HOMELAB_INSTALL"
iso_publisher="Homelab <https://github.com/spincyc/telos>"
iso_application="Homelab provisioning environment"
iso_version="$(date +%Y.%m.%d)"
install_dir="arch"

# UEFI only. ADR 0019 makes the Controller profile UEFI-only and the installer
# refuses a BIOS-booted target, so shipping a BIOS boot path would only create
# a way to reach a refusal slowly.
buildmodes=('netboot')
bootmodes=('uefi-x64.systemd-boot.esp' 'uefi-x64.systemd-boot.eltorito')

arch="x86_64"
pacman_conf="pacman.conf"
airootfs_image_type="erofs"
airootfs_image_tool_options=('-zlz4hc,12' -E ztailpacking)
bootstrap_tarball_compression=('zstd' '-c' '-T0' '--auto-threads=logical' '--long' '-19')

file_permissions=(
  ["/etc/shadow"]="0:0:400"
  ["/root"]="0:0:750"
  ["/root/.ssh"]="0:0:700"
  ["/root/.ssh/authorized_keys"]="0:0:600"
  ["/usr/local/bin/homelab-install"]="0:0:755"
)
