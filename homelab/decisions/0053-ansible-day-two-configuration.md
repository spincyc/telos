# ADR 0053: Own day-two configuration with Ansible from this repository

- Status: Accepted
- Date: 2026-07-25

## Context

The design specified provisioning in detail and day-two configuration not at
all. Every service, tuning change or new role would have required reinstalling
the machine. That makes iteration impossibly slow and guarantees that running
systems drift from the record.

## Decision

Split the lifecycle in two.

**Install time** does only what cannot be done later: partition, encrypt, create
the filesystem, install the base system and kernels, write the boot artifacts,
configure the managed interface and static address, install `sshd` with the
administrator public key, and record the manifest. Nothing else.

**Converge time** is Ansible, run over SSH from this repository, and owns
everything else: package sets, dnsmasq and nginx configuration, the services
role, identity client configuration, users, sudo policy, health checks and
update orchestration.

- Inventory lives in the private overlay; roles and playbooks are public.
- Every role must be idempotent and must pass `--check` cleanly against a
  converged host.
- No secret is stored in a playbook. Secret material is referenced, and the
  mechanism is chosen in a later ADR.
- The Controller converges itself the same way a Workstation does. There is no
  privileged manual path.

## Consequences

- A change is a commit plus a converge run, not a reinstall.
- The installed system's configuration is reviewable as a diff.
- Provisioning stays small enough to reason about and to test.
- Ansible becomes a hard dependency of the workflow and needs its own version
  and collection pinning.
- ADR 0016's guarded update workflow becomes an Ansible-driven playbook with
  the checkpoint and validation steps it already requires.
