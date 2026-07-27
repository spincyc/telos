# ADR 0070: Standardize a configurable dual-boot layout

- Status: Accepted
- Date: 2026-07-27

## Context

Minted laptops need predictable Windows 11 Pro and Arch installations while
allowing reasonable per-machine disk policy.

## Decision

Use UEFI/GPT and install Windows before Arch. The default profile provides:

- a 1 GiB EFI System Partition;
- the required 16 MiB Microsoft Reserved partition;
- Windows: minimum 160 GiB;
- Arch: minimum 64 GiB;
- Windows recovery space derived from the selected image; and
- a five-second boot menu with Windows as default.

First reserve GPT margin, ESP, MSR and recovery space. Then reserve both OS
minimums. In ratio mode, distribute all capacity above those minima 75 percent
to Windows and 25 percent to Arch; the percentage never reduces either
minimum. In fixed mode, explicit sizes take precedence and any remainder stays
unallocated.

Reject automatic installation if both minimums and the fixed allowances do not
fit. An approved manifest may override the surplus ratio, fixed sizes or
default OS.
The operator must confirm the target disk identity and final layout before any
write.

## Consequences

- About 256 GiB is the practical minimum target.
- Independent firmware boot entries provide a recovery path.
- Layout policy is data, not installer branching.
