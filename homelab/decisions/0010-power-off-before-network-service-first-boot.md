# ADR 0010: Power off before the network-service first boot

- Status: Accepted
- Date: 2026-07-24

## Context

The Controller is provisioned on a full network that already has DHCP and DNS.
It will provide those services only after it is moved to an isolated switch
network. Automatically booting the installed system while it remains on the
provisioning network could start a competing DHCP authority.

## Decision

When Controller-owned DHCP and DNS are selected, a successful installation
must end with a clean poweroff rather than rebooting into the installed
operating system.

The operator relocates the powered-off Controller to the isolated switch and
powers it on. That power-on is the first boot of the installed system, and ADR
0009 automatically activates the configured network services after validation.

## Consequences

- Provisioning must synchronize persistent storage and verify completion before
  powering off.
- No manual DHCP/DNS activation command is required after relocation.
- Physical relocation while powered off is the primary DHCP-conflict safety
  boundary.
- First-boot checks must still fail closed if they detect another DHCP
  authority, a duplicate service address, the wrong interface, or invalid
  configuration.
- If validation fails, DHCP remains stopped and the Controller exposes a local
  diagnostic and documented recovery procedure.
