# ADR 0009: Activate Controller network services automatically

- Status: Accepted
- Date: 2026-07-24

## Context

The Controller is provisioned on a network with existing DHCP and DNS, then
moved to an isolated switch network where it must provide those services. A
manual post-move activation step would make the resulting installation less
reproducible and less autonomous.

Starting Controller DHCP while it is still attached to the provisioning
network would create competing DHCP authorities and could disrupt that network.

## Decision

When the Controller is provisioned for Controller-owned DHCP and DNS, activate
those services automatically on its first boot after provisioning. Do not
require a separate manual activation command.

The activation path must fail closed: if its required transition conditions
cannot be verified, Controller DHCP must remain stopped.

## Consequences

- Provisioning must leave a durable, one-shot first-boot activation state.
- The first-boot process must apply and validate the Controller's static network
  configuration before starting DHCP or advertising itself as DNS.
- Successful activation must clear or complete the one-shot state so ordinary
  subsequent reboots do not repeat a transition.
- Failed activation must leave DHCP disabled and provide an observable
  diagnostic and recovery path.
- ADR 0010 requires the installer to power off before the first
  installed-system boot.
- Detection of an existing DHCP authority, retry behavior, and rollback
  procedure remain open.
