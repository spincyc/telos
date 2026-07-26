# ADR 0049: Build the installer as an Archiso netboot image driving a Python installer

- Status: Accepted
- Date: 2026-07-25

## Context

ADR 0004 requires an interactive environment that collects inputs, validates
them, shows a preflight summary and demands explicit confirmation. ADR 0045 adds
a validated network plan. Nothing selected what that environment actually is.

## Decision

Build the provisioning environment as a custom Archiso profile, booted over the
network, running a Python installer from this repository.

- The image carries the tools the installer needs and nothing else: `parted`,
  `cryptsetup`, `btrfs-progs`, `dosfstools`, `arch-install-scripts`,
  `systemd-ukify`, `python`, `nginx`-less, no desktop.
- The installer is ordinary Python 3 using only the standard library, so it can
  be unit-tested off-target. `homelab/lib/` holds the logic; `homelab/bin/`
  holds the entry points.
- Only administrator **public** SSH keys are baked into the image, enabling a
  parallel SSH session for observation. No private key, token or credential is
  ever placed in an image.
- The image is built reproducibly from a pinned package list and a recorded
  mirror snapshot, and its SHA-256 is published in the artifact manifest.

Do not use WDS, MDT, or a vendor deployment suite.

## Consequences

- Installer logic is testable without hardware, which is what makes ADR 0056's
  acceptance matrix possible.
- Archiso is a first-class Arch workflow, so the image and the installed system
  share package provenance.
- The image is a public artifact and must remain secret-free.
- Image build requires a machine with `archiso`; ADR 0052 names it.
