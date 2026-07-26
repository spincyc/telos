# ADR 0063: Use a dedicated key pair for the break-glass administrator

- Status: Accepted
- Date: 2026-07-26

## Context

ADR 0055 makes a local break-glass administrator mandatory on every managed
machine: while the directory is down, it and cached logins are the only ways in.
That account is reached over SSH with a public key, and the obvious key to use
is the one already in `~/.ssh` on the daily-driver workstation.

That is also the key with the widest exposure. It is loaded into an agent all
day, forwarded to other hosts, and present on the machine most likely to be
compromised. Reusing it means the account that exists specifically to survive a
bad day is protected by the credential most likely to be part of one.

## Decision

The break-glass administrator is authorized by a **dedicated key pair used for
nothing else**.

- The operator generates it. Nothing in this repository handles the private
  half, generates it, copies it, or knows where it lives.
- The public key is recorded in the gitignored instance overlay
  (`group_vars/all.yml`), never in Git and never in a published document.
- The private key is stored where the operator keeps private keys and backed up
  somewhere that does not depend on the homelab being reachable. A break-glass
  key stored only on a homelab machine is not a break-glass key.
- The `common` role refuses to converge a machine when no break-glass key is
  configured, and `identity_client` refuses to join a machine to the directory
  for the same reason. Both are assertions, not warnings.
- The key is not used for ordinary administration. Ordinary administration is
  Ansible convergence under a directory identity once one exists.

## Consequences

- Compromising the daily-driver key does not hand over the recovery account.
- There is one more key to keep safe, and losing it while the directory is also
  down means physical console access is the only remaining route. That is the
  accepted trade-off; it is why the backup requirement is part of the decision
  rather than advice.
- The key is rarely exercised, so it can rot unnoticed. Verifying break-glass
  access belongs in the periodic recovery drill alongside restoring a
  checkpoint, not in the convergence run.
