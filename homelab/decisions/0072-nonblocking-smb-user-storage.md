# ADR 0072: Mount optional SMB user storage without blocking logon

- Status: Accepted
- Date: 2026-07-27

## Context

The primary NAS supports SMB and NFS, but earlier NFS use exposed UID and
timestamp problems. Storage availability must not become an identity
dependency. Its hostname belongs in the private overlay.

## Decision

Keep each operating system profile local. After login, optionally connect the
user's AD-authorized SMB storage:

- Windows maps a user drive;
- Arch mounts it beneath the local home; and
- short timeouts turn DNS, network, NAS and permission failures into visible
  warnings, never failed logons.

Integrate the primary NAS with `identity_dns_domain` and verify whether its
supported interface automatically provisions imported AD users. Do not
automate an undocumented private API. The private `backup_nas_fqdn` is backup
infrastructure, not an automatic read/write failover.

## Consequences

- Numeric NFS UID/GID mapping is outside phase one.
- NAS-unavailable acceptance tests are mandatory.
- A manual share-assignment step may remain until a supported automation path
  is proven.
