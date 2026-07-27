# Provisioning image

An Archiso netboot profile whose only job is to run `bin/homelab-install`
(ADR 0049).

## Build

    cd homelab/archiso
    sudo mkarchiso -v -w /tmp/homelab-work -o out .

Requires the `archiso` package. `buildmodes=('netboot')` produces the kernel,
initramfs and rootfs the iPXE script in `lib/artifacts.py` expects, rather than
an ISO.

## Stage an immutable PXE release

Treat the completed `out/` tree as a local build input. Stage it through the
Controller target so every copied byte and the source-tree provenance are
bound to the versioned release:

    make homelab-pxe-controller \
      SOURCE="$PWD/out" \
      VERSION=YYYYMMDD.NNN \
      BASE_URL=http://controller.example/controller/YYYYMMDD.NNN

The target accepts the mkarchiso root image as either `airootfs.erofs` (the
current profile output) or the older `airootfs.sfs`, but requires exactly one.
It verifies the generated `airootfs.sha512`, refuses links, special files,
missing or empty boot payloads, and an existing release directory. The iPXE
entrypoint enables Archiso's HTTP `checksum=y` verification. Publication to a
Controller is a separate, explicit step after release-set verification.

The profile does not currently produce or pin a CMS signing identity, so its
iPXE entrypoint does not claim `cms_verify=y`. Every served byte remains bound
to the release SHA-256 manifest. Add CMS verification only together with a
defined signing-key custody and verification contract.

## What is deliberately absent

No private keys, tokens or passphrases: the image is a public artifact
published with its checksum. No BIOS boot path: ADR 0019 makes the Controller
profile UEFI-only. No unattended install path: ADR 0058.
