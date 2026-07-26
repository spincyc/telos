# ADR 0048: Serve boot and installation artifacts over HTTP with nginx

- Status: Accepted
- Date: 2026-07-25

## Context

ADR 0044 restricts TFTP to the first-stage loader and requires kernels,
initramfs images, root filesystems and installer payloads to travel over
HTTP(S), but does not select an implementation. Milestone A cannot network boot
without one, so this is a hard blocker rather than a refinement.

## Decision

Use the Arch `nginx` package as the Controller's artifact service.

- Serve a single read-only document root, `/srv/http/boot`.
- Bind only to the managed interface and the Controller service address.
- Serve plain HTTP on the isolated proof network. iPXE's HTTPS support depends
  on build options and an embedded trust store, and the proof network has no
  certificate authority; artifact integrity comes from published checksums
  verified by the installer, not from transport.
- Publish a `manifest.json` beside the artifacts listing every file with its
  SHA-256. The installer verifies each artifact against it before use.
- Run as a distinct system user with no write access to the document root.

Do not use a general-purpose application server, and do not enable directory
autoindex on the published root.

## Consequences

- Milestone A's boot chain is complete: dnsmasq for DHCP, DNS, PXE selection and
  the first-stage loader; nginx for everything substantial.
- Artifact integrity is checksum-based during the proof, which ADR 0043 already
  permits and requires to be labelled.
- Introducing HTTPS later is an nginx configuration change plus an iPXE build
  with a trust store; it does not change the artifact layout.
- nginx and dnsmasq are separate units, so an artifact-service failure does not
  stop DHCP or DNS.
