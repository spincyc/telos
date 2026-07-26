# ADR 0043: Prove the functional environment before boot hardening

- Status: Accepted
- Date: 2026-07-24

## Context

The custom Secure Boot, signed-UKI, TPM policy, offline-signing, and signing-key
custody design has grown into a substantial subsystem before the core
provisioning and Controller environment has been exercised end to end.

The user wants to prove the network, installation, storage, service, and profile
concepts first, then revisit the signing design with operational experience.
Authenticated boot and unattended restart remain desired final properties, but
the present signing design must not block the functional proof.

## Decision

Split delivery into two explicit milestones.

### Milestone A: functional proof

Build and test the non-production provisioning path first:

- network boot into the interactive installer;
- collect, validate, summarize, and explicitly confirm all destructive inputs;
- record UEFI mode, Secure Boot capability and state, and TPM 2.0 availability
  without changing firmware trust or enrolling a TPM token;
- install the generic Controller profile with Arch, LUKS2, Btrfs, systemd-boot,
  the two normal kernels, and the accepted shared-ESP layout;
- exercise the permanent Windows maintenance installation and its independent
  UEFI entry far enough to validate the functional dual-boot layout;
- power off after installation, relocate to the isolated switch, and perform
  the first installed boot;
- after manual LUKS2 unlock, start Controller DHCP and DNS automatically;
- verify isolated-network leases, `home.arpa` resolution, PXE service, and the
  no-routing/no-NAT boundary;
- exercise the Workstation profile's Controller-FQDN pivot; and
- prove checkpoint, rollback, rebuild, and health-validation concepts without
  depending on an offline signer.

Continue to verify the provenance and published checksums of downloaded
installer and package artifacts even though Milestone A does not prove the
final authenticated-boot chain.

Milestone A does not create, enroll, or use a custom lab Secure Boot identity,
TPM policy identity, TPM unlock token, signing medium, or signing credential.
It does not clear factory firmware keys, enter firmware Setup Mode, alter
firmware `db`, or implement TPM automatic LUKS2 unlock.

If the Arch or network-boot path cannot use an already trusted upstream chain,
Milestone A may run with Secure Boot disabled only under an explicit
`development-proof` mode. That mode must:

- display and record that authenticated boot is not being tested;
- require a separate explicit operator acknowledgement before destructive
  authorization;
- use a manually entered LUKS2 passphrase at every Arch boot;
- contain no production secrets or irreplaceable data; and
- never be reported as a production-ready or fully accepted profile.

`development-proof` is a temporary project state recorded in the installation
manifest, not a permanent profile option that can be selected to avoid
hardening.

Windows installation and direct UEFI boot may be tested in Milestone A, but
final BitLocker, Secure Boot, TPM, and recovery behavior belongs to Milestone B.

### Milestone B: security hardening and final acceptance

After Milestone A passes, revisit ADRs 0029 through 0042 as a group. They are
design input, not an instruction to enroll TPM state or manufacture keys,
credentials, or signing media now. Simplify, change, or replace them based on
the proven update and provisioning workflow.

Milestone B must then:

- enforce ADR 0020's Secure Boot and encryption requirements;
- establish and test the selected network-boot, installed-boot, and recovery
  trust chains;
- implement and test the selected signing and recovery-key custody;
- implement TPM automatic unlock only after its recovery path works;
- complete Windows BitLocker and recovery acceptance; and
- prove that an unattended cold restart restores Controller DHCP, DNS, and PXE
  service; and
- reprovision from the proven installer for final acceptance rather than
  treating the development-proof installation as production.

No system passes final Controller or Workstation acceptance until Milestone B
is complete.

## Consequences

- Core provisioning, DHCP/DNS, isolated-network transition, storage, profile,
  and recovery concepts can be validated without first operating an offline
  signing ceremony.
- The functional proof requires an operator at each Arch boot and does not
  provide unattended recovery after a power loss.
- Secure Boot-disabled proof boots have weaker pre-boot integrity and are
  explicitly disposable and non-production.
- Some boot and Windows acceptance tests must be repeated during Milestone B.
- Reprovisioning after proof adds work but also validates that the installer is
  reproducible and prevents development exceptions from silently becoming
  permanent.
- ADRs 0029 through 0042 are deferred for post-proof revalidation.
