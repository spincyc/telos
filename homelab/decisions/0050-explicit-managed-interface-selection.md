# ADR 0050: Select the managed interface explicitly and pin it by MAC address

- Status: Accepted
- Date: 2026-07-25

## Context

ADR 0044 binds dnsmasq to one managed interface and ADR 0045 left the selection
open. A Controller may have several NICs. Kernel interface names are stable per
firmware enumeration but not across hardware changes, and binding DHCP to the
wrong link would put a second DHCP authority on a network the Controller does
not own -- the exact outcome ADR 0008 forbids.

## Decision

Select the managed interface as an explicit installation input.

- Preflight enumerates every physical Ethernet interface with its kernel name,
  permanent MAC address, current link state and observed speed.
- The operator selects one. There is no default and no automatic choice.
- The installer records the **permanent MAC address** as the identity and writes
  a systemd `.link` file pinning a stable name, `lan0`, to that MAC.
- dnsmasq, nginx and the static address configuration all reference `lan0`.
- First-boot activation verifies that `lan0` exists, carries the expected MAC and
  has carrier before starting network services, and fails closed otherwise.
- Wireless interfaces are not offered.

## Consequences

- The managed interface survives a kernel or firmware change that reorders
  enumeration.
- Replacing the NIC is a deliberate re-provisioning or a recorded manifest
  amendment, not a silent behaviour change.
- ADR 0009's fail-closed first boot gains a concrete, checkable condition.
- A Controller with exactly one Ethernet interface still requires the operator
  to confirm it. Selection is never implicit.
