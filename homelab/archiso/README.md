# Provisioning image

An Archiso netboot profile whose only job is to run `bin/homelab-install`
(ADR 0049).

## Build

Run from the repository root on an Arch build host with `archiso` installed.
Use a dedicated unused `/tmp/homelab-image` work tree and stage the profile
before building:

```sh
make homelab-image
sudo mkarchiso -v -w /tmp/homelab-image/work \
  -o /tmp/homelab-image/out /tmp/homelab-image/profile
```

The first command stages the installer and module closure and audits the
profile; proceed only after its audit succeeds. The raw tracked profile is
incomplete and must not be passed directly to `mkarchiso`. Public
`authorized_keys` is optional: without it, staging disables SSH and leaves
console access. To choose another work tree, run
`python3 homelab/bin/homelab-image --work <absolute-path>` and follow its
printed build command. `--check` also stages; it is not read-only.

Build during online preparation, before the factory's offline boundary.
Require `mkarchiso` to exit successfully. `buildmodes=('netboot')` produces the kernel,
initramfs and rootfs the iPXE script in `lib/artifacts.py` expects, rather than
an ISO.

## Stage an immutable PXE release

Treat the completed `/tmp/homelab-image/out/` tree as a local build input,
not `profile/`, `out/arch/`, the seed ISO or a stock Arch ISO. From repository
root, stage it through the
Controller target so every copied byte and the source-tree provenance are
bound to the versioned release:

    make homelab-pxe-controller \
      SOURCE=/tmp/homelab-image/out \
      VERSION=YYYYMMDD.NNN \
      BASE_URL=http://controller.example/controller/YYYYMMDD.NNN

The target accepts the mkarchiso root image as either `airootfs.erofs` (the
current profile output) or the older `airootfs.sfs`, but requires exactly one.
It verifies the generated `airootfs.sha512`, refuses links, special files,
missing or empty boot payloads, and an existing release directory. The iPXE
entrypoint enables Archiso's HTTP `checksum=y` verification. Publication to a
Controller is a separate, explicit step after release-set verification.

For the three-leaf factory release, pass
`CONTROLLER_SOURCE=/tmp/homelab-image/out` to `homelab-factory-pxe`; see the
[operator runbook](../docs/operator-runbook.md#12-build-the-immutable-release-set)
for media-seal prerequisites and release verification. The aggregate still
requires this leaf, but [ADR 0079](../decisions/0079-drop-the-controller-pxe-mint.md)
drops replacement-Controller PXE mint acceptance. The canonical Controller is
installed from Arch plus the offline seed.

The profile does not currently produce or pin a CMS signing identity, so its
iPXE entrypoint does not claim `cms_verify=y`. Every served byte remains bound
to the release SHA-256 manifest. Add CMS verification only together with a
defined signing-key custody and verification contract.

## What is deliberately absent

No private keys, tokens or passphrases: the image is a public artifact
published with its checksum. No BIOS boot path: ADR 0019 makes the Controller
profile UEFI-only. No unattended install path: ADR 0058.
