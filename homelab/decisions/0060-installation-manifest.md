# ADR 0060: Record a non-secret manifest on the installed system

- Status: Accepted
- Date: 2026-07-26

## Context

Several accepted decisions require the installer to record what it did. ADR 0045
requires the confirmed network inputs and derived plan; ADR 0043 requires the
`development-proof` label to be recorded in the installation manifest rather
than remembered; ADR 0050 requires the managed interface's permanent MAC as its
identity; ADR 0031 and ADR 0034 will eventually require signing-identity
fingerprints. Nothing decided where the manifest lives.

The first Controller is built before any artifact, inventory or configuration
service exists to receive a record, so the manifest cannot depend on one.

## Decision

Write one JSON manifest to `/etc/homelab/manifest.json` on the installed root,
and echo it to the console at the end of the run.

- The machine carries its own provenance. A Controller found in a cupboard in
  three years can state what it is, when it was built, and from what.
- The console copy is how the acceptance harness under ADR 0056 captures the
  manifest without mounting an encrypted filesystem.
- Nothing is uploaded during installation. There is no service to upload to when
  the first Controller is built, and adding one would make provisioning depend
  on it.
- The manifest is **non-secret by construction** and is validated against that
  before being written. It records identities, not credentials: no passphrase,
  no recovery key, no private key, no token, no LUKS header, no password hash.
- It is not written to the ESP. ADR 0020 keeps the ESP minimal and secret-free,
  and interface MACs, disk serials and network plans are exactly the instance
  data ADR 0046 keeps out of anything published or casually readable.

Recorded: schema version; installer version and the artifact checksums it
verified; timestamp; profile; hostname; whether this was a `development-proof`
installation; firmware mode, Secure Boot state and TPM presence as *observed*;
target disk path, model, serial and size; managed interface name and permanent
MAC; the confirmed network inputs and every derived value; and the partition
layout actually written.

## Consequences

- Every installed machine is self-describing without a central database.
- ADR 0043's requirement that `development-proof` be a recorded project state,
  not a silent one, is satisfied by a field that later tooling can refuse to
  treat as production.
- A central inventory, if one is ever wanted, is built by collecting these files
  from machines rather than by making installation write to a service.
- The manifest is readable by anyone who can unlock the root, which is why the
  no-secrets rule is enforced in code rather than trusted to reviewers.
- Losing the disk loses the manifest. That is acceptable: it describes a machine
  that no longer exists.
