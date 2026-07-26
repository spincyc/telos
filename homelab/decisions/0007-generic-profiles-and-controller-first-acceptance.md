# ADR 0007: Design generic profiles and build a Controller first

- Status: Accepted
- Date: 2026-07-24

## Context

The current Polycarp installation could be inventoried and reproduced as a
machine-specific design. The intended system is instead a generic provisioner
that installs reusable computer profiles on compatible target hardware.

The first meaningful verification should exercise the same path intended for
future machines rather than manually constructing special infrastructure
before testing it.

## Decision

Design reusable Controller and Workstation profiles without using an inventory
of the current Polycarp installation as an architecture input.

The first end-to-end acceptance test will network boot a target and use the
generated provisioning system to build a Controller from bare metal. The
acceptance sequence will then validate Controller-owned DHCP and DNS on an
isolated network whose only permanent network infrastructure is a switch.

## Consequences

- Do not inspect Polycarp as a prerequisite for profile design.
- Host-specific values, including the Controller hostname, are instance
  parameters rather than constants embedded in a profile.
- Hardware requirements must be stated generically and validated against the
  selected target during installation.
- Existing Polycarp services and layout do not constrain the Controller
  profile.
- The first Controller installation cannot depend on DNS, PXE, HTTP, Git,
  artifact, identity, or configuration services hosted by that target
  Controller.
- The initial test therefore needs an off-Controller source for the boot chain,
  configuration, artifacts, and reconstruction instructions.
- For the first acceptance sequence, provisioning occurs on the existing full
  network before the installed Controller is powered off and moved to the
  isolated validation network under ADR 0010.
- The exact test machine and authorization to wipe it remain separate
  decisions.
- Profile documentation and per-machine instance inventory must be separated;
  their exact repository layout remains open.
