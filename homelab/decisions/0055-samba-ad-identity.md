# ADR 0055: Use Samba AD DC for shared Windows and Linux identity

- Status: Accepted
- Date: 2026-07-25

## Context

Users and groups must be central across Arch Workstations, Windows
Workstations, the Controller and ideally the NAS, with cached logon for laptops
away from home. FreeIPA has the better Linux story but cannot serve Windows
domain join; a minimal LDAP has neither Kerberos nor a Windows story.

## Decision

Use Samba Active Directory Domain Services as the directory.

- Run it in a dedicated VM, not on the Controller host. It is a distinct trust
  boundary, it needs its own restart and upgrade cadence, and ADR 0014 permits a
  VM exactly when those conditions hold.
- Arch clients use SSSD's AD provider with credential caching.
- Windows Pro clients domain-join. Windows Home cannot and keeps local accounts.
- Home directories stay local; `pam_mkhomedir` creates them on first login.
- Every managed machine keeps a separately named local break-glass administrator
  with its own sudo rule, and that account is never a directory account.
- UID and GID come from the directory. The existing local `ksh` at UID 1000 is
  migrated deliberately and only after piloting with a separate test identity.
- Set an explicit offline credential lifetime longer than a normal trip rather
  than relying on a default.

A second domain controller on separate physical hardware is required before the
directory is considered production, and is deferred until the first one works.

## Consequences

- One identity serves Windows, Linux and an AD-capable NAS.
- The directory is a bootstrap dependency: while it is down, only cached and
  break-glass logins work. Local break-glass accounts are therefore mandatory,
  not optional.
- A single domain controller is a single point of failure until the replica
  exists.
- Offline machines cannot receive revocations promptly; that is inherent to
  cached credentials and must be stated in the operations manual.
- Samba AD upgrades are their own operational burden, separate from Arch.
