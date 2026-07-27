# ADR 0069: Use plain disks for phase-one workstations

- Status: Accepted
- Date: 2026-07-27

## Context

The first pilots optimize for a short, observable installation loop. Their
owner explicitly deferred disk encryption and Secure Boot.

## Decision

Phase-one workstations use:

- Windows NTFS without BitLocker;
- an unencrypted Arch filesystem without LUKS;
- Secure Boot disabled;
- no TPM enrollment or custom boot keys; and
- no sensitive or irreplaceable data.

Every manifest and manual labels this state `development-proof`. Reconsider
BitLocker and Arch encryption after several pilots. BitLocker may be enabled
later; Arch encryption may require rebuilding and must not be promised as an
in-place conversion.

This is a scoped workstation-pilot exception to ADRs 0020 and 0043. It does
not weaken Controller or final-production acceptance requirements.

## Consequences

- Physical disk access exposes local data and cached credentials.
- The pilot is unsuitable for sensitive college or mobile use.
- Security hardening remains a recorded gate rather than hidden backlog.
