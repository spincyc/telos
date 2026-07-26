# ADR 0014: Use a host-first hybrid Controller

- Status: Accepted
- Date: 2026-07-24

## Context

The physical machine is dedicated exclusively to the Controller role. Putting
every service in a VM would isolate software failures and dependencies but
would not protect against failure of the only physical host. It would also add
bridging, boot ordering, guest-image, resource, and recovery complexity to
foundational DHCP, DNS, and network provisioning.

Some future services may still require a different operating system or a
stronger trust boundary.

## Decision

Use a host-first hybrid architecture:

- The Controller host operating system directly owns boot, storage, physical networking,
  first-boot safety, bundled DHCP/DNS, PXE control, and local recovery.
- Use containers when they materially simplify packaging or independent
  service lifecycle.
- Use VMs only when a service requires a separate kernel, different operating
  system, or stronger trust boundary.
- Do not require virtualization for every service.

## Consequences

- Foundational network startup and troubleshooting avoid a mandatory bridge and
  guest-boot dependency.
- Host package or configuration changes have a larger potential blast radius,
  so foundational configurations require declarative source, validation, and
  rollback procedures.
- Containers provide packaging and process isolation but share the host kernel;
  they are not equivalent to a VM trust boundary.
- VMs remain available for future identity, certificate, Windows-only, or
  experimental services when justified individually.
- Virtualization support is not a baseline hardware prerequisite until an
  accepted service requires it.
- The Controller remains one physical failure domain regardless of container or
  VM placement.
