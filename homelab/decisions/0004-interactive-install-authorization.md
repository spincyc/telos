# ADR 0004: Interactive install authorization

- Status: Accepted
- Date: 2026-07-24

## Context

Network provisioning must be able to wipe and reinstall a computer without
making an accidental profile selection destructive. A pre-staged,
machine-specific deployment record would provide strong centralized control,
but it would add enrollment and staging work before each installation.

## Decision

Do not require a pre-staged deployment record. The network-boot environment
will collect and validate several operator inputs at the target computer,
display a complete preflight summary, and perform no destructive operation
until the operator gives a final explicit confirmation.

Physical-console and boot-path access, together with this interactive
confirmation workflow, are the authorization boundary.

## Consequences

- A computer can be installed directly from the network-boot environment
  without prior enrollment.
- Profile selection alone never authorizes a disk wipe.
- The workflow must identify and validate the target disk before confirmation.
- All supplied values must be validated before any partition table, filesystem,
  or boot configuration is changed.
- The final prompt must state exactly which disk will be destroyed and what
  profile and hostname will be installed.
- ADR 0045 subsequently defines the four explicit Controller managed-network
  inputs and requires the entered and derived network plan in that summary.
- This protects against operator mistakes, but not against a malicious person
  who controls the physical console and network-boot path.
- The remaining prompt sequence, validation rules, and confirmation mechanism
  remain open.
