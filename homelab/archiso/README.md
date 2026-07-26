# Provisioning image

An Archiso netboot profile whose only job is to run `bin/homelab-install`
(ADR 0049).

## Build

    cd homelab/archiso
    sudo mkarchiso -v -w /tmp/homelab-work -o out .

Requires the `archiso` package. `buildmodes=('netboot')` produces the kernel,
initramfs and rootfs the iPXE script in `lib/artifacts.py` expects, rather than
an ISO.

## Publish

Copy the output into the artifact root and regenerate the checksum manifest:

    homelab/bin/homelab-artifacts publish out/ /srv/http/boot

The installer verifies every artifact against that manifest before using it
(ADR 0043, ADR 0048).

## What is deliberately absent

No private keys, tokens or passphrases: the image is a public artifact
published with its checksum. No BIOS boot path: ADR 0019 makes the Controller
profile UEFI-only. No unattended install path: ADR 0058.
