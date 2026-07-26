# ADR 0056: Prove every change in a QEMU/OVMF matrix before hardware

- Status: Accepted
- Date: 2026-07-25

## Context

ADR 0043 requires a functional proof and the handoff requires virtual-machine
testing before physical deployment, but no mechanism existed. Without one, the
first test of any change is the real Controller.

## Decision

Maintain a QEMU/OVMF acceptance matrix in `homelab/qemu/`, runnable with one
command.

The matrix builds a virtual isolated network with no router and boots:

- a virtual **bootstrap** host serving ProxyDHCP, TFTP and HTTP;
- a virtual **Controller** target, installed from the real installer with no
  human present; ADR 0058 defines the mechanism, which drives the genuine
  interactive prompts through a pseudo-terminal rather than adding an
  unattended code path; and
- a virtual **Workstation** target that pivots on the Controller's FQDN.

It then asserts, automatically:

- the installer refuses every invalid network plan in its rejection corpus;
- the Controller installs, powers off, and activates services on first boot;
- a client receives a lease inside the configured pool and never the Controller
  address;
- `home.arpa` resolves the Controller;
- **no default route is advertised**, per ADR 0011;
- the artifact manifest checksums verify;
- Ansible converge is idempotent -- a second run reports no changes; and
- a checkpoint can be created, rolled back to, and validated.

Physical installation is permitted only after the matrix passes. UEFI variables
use a per-run OVMF variable store so firmware state never leaks between runs.

## Consequences

- The loop from edit to evidence is minutes, not a reinstall.
- Regressions in validation logic are caught by the rejection corpus rather than
  by a wiped disk.
- QEMU cannot prove firmware quirks, NIC behaviour, TPM or Secure Boot on real
  hardware. Passing the matrix is necessary, never sufficient.
- The matrix is the executable form of the acceptance criteria in the
  reconstruction manuals.
