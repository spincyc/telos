# ADR 0081: Back up and restore persistent directories with Samba's own tools

- Status: Accepted
- Date: 2026-09-30

## Context

The domain, not the machine, is the asset that cannot be rebuilt (ADR 0079).
On 2026-09-30 the owner decided that backup and restore of persistent
directory instances must be built and proven before the keeper, the
unrebuildable domain (aiq TASK-21), is minted. Backups go to `BACKUP_ROOT`,
by default the gitignored `homelab/var/backups/`, with 0700 directories and
0600 files.

The constraints already in force:

- ADR 0067 forbids duplicating, renaming or restoring a live DC's disk; ADR
  0068 forbids powering on a stale DC snapshot and names a tested Samba domain
  backup as the recovery path. An image-level copy is therefore never the
  disaster-recovery path.
- Lifecycle Gate 7 (`homelab/LOCAL-FACTORY-LIFECYCLE.md`) requires same-realm
  reconstruction from a tested, encrypted Samba AD backup that preserves the
  domain SID, object identities, machine trust, DNS and Kerberos secrets.
- A persistent instance reaches the host only through its serial console, and
  `simulated_topology.audit_persistent_controller` is a closed allowlist that
  refuses every medium.

What Samba documents (the wiki page "Back up and Restoring a Samba AD DC",
and `python/samba/netcmd/domain/backup.py`):

- `samba-tool domain backup offline` (Samba 4.10 and later) copies the local
  DC's database files "with proper locking of the DB to ensure consistency".
  Despite its name the DC does not need to be stopped. It must run as root.
  The tarball holds every secret of the domain.
- `samba-tool domain backup restore` is the only supported way back; samba
  cannot run on an untarred backup. Its target directory must be empty or
  absent. It adds a new DC named by `--newservername`, removes every other DC
  from the restored database, seizes the FSMO roles and rotates the `krbtgt`
  password twice.
- The new server name must not already exist in the domain. The restore adds
  the new DC's computer and server objects while the backed-up DC's still
  exist, so naming the backed-up DC fails with `Entry
  CN=<name>,OU=Domain Controllers,... already exists`. Samba's documented way
  back to the original name is to restore onto a temporary DC, join a DC with
  the original name to it ("You can re-use the same server-name ... during
  the join"), and demote the temporary DC.

## Decision

1. **Backup is `samba-tool domain backup offline`**, run as root inside the
   instance booted in place exactly as `homelab-factory-persistent-probe`
   boots it (the per-run fabric, under the instance lock, a clean console
   poweroff), with samba running as Samba documents. Before it, the run
   proves the live realm and domain SID are the bound directory's and
   requires `samba-tool dbcheck --cross-ncs` to be clean, because an offline
   backup copies the raw files and any hidden defect with them.
2. **The backup disk is the one exception to the closed allowlist.** A
   backup or restore run may attach exactly one more device: a raw disk the
   run itself creates, virtio-blk with a fixed serial (`TELOS-BACKUP-OUT`,
   writable, for a backup; `TELOS-BACKUP-IN`, read-only, for a restore), no
   boot index, at the exact path the run named. The audit admits it only in
   those two modes. It carries a Samba tarball behind a 4 KiB header of the
   tarball's length, its SHA-256 and the run's token, and nothing else; it is
   never a disk image of a DC. The guest verifies what it wrote and prints
   the SHA-256; the host verifies the disk against both after a clean
   poweroff, and shreds the disk.
3. **A backup set** is `BACKUP_ROOT/<instance>/<run id>/` holding the
   tarball, a `manifest.json` (instance, realm, DNS domain, NetBIOS name,
   domain SID, the backed-up DC's name, a digest of every non-DC security
   principal's SID, and the SHA-256 of every file) and a copy of the
   instance marker. For a throwaway instance under agent custody only, it
   also holds a copy of the instance's custody store, because those account
   passwords exist nowhere else. An owner-custody set never holds one, and a
   restore refuses one that does. The realm and SID are stored because the
   tarball holds them anyway; they are never printed. The marker records the
   latest set as `last_backup`.
4. **Restore is `samba-tool domain backup restore`** into a freshly created
   instance, never an image clone. It refuses unless the target instance is
   absent (the disaster is a lost or destroyed instance; a separate name is
   a restore drill), the set verifies, and its realm agrees with the owner's
   directory identity. It seeds the instance from the canonical image under
   the custody the backup records (agent: a new console credential, with the
   domain Administrator's and every staged account's passwords carried from
   the backup's store; owner: the canonical image's console password, typed
   at the terminal), boots it with **no network device** and the backup
   disk read-only, restores into `/var/lib/samba` so `sam.ldb` lands where
   convergence looks for it, installs the restore's `smb.conf` as
   `/etc/samba/smb.conf`, starts samba, and proves the realm, the domain SID
   and the principal digest equal the backup's. Only then are the backup's
   convergence, account, password-policy and reset records written into the
   new marker, with a `restored` record. The same instance name may be
   restored once it is destroyed: that is disaster recovery.
5. **The restored DC keeps its new name, and everything follows the
   recorded name** (owner decision 2026-09-30, aiq TASK-42). Because Samba
   cannot restore a DC under a name the domain has held, the restored DC
   takes a new name (`RESTORE_DC_NAME`, default `dr-<UTC minute>`; never the
   backed-up DC's, never `bootstrap-dc`, which every persistent directory
   began with). The restore renames the guest to it, and the instance marker
   records it as the convergence record's `dc_hostname`; a record without
   one means `bootstrap-dc`, which covers every instance converged earlier.
   The console prompt, the binding's controller FQDN, the probe's A and SRV
   checks, the Windows control disc's controller, and -- on reconvergence --
   `/etc/hostname`, `/etc/hosts` and the role's SPN aliases all use the
   recorded name. Kept Arch workstations find the DC by DNS SRV first:
   a durable render writes `ad_server = _srv_, <recorded DC FQDN>`, so the
   named controller is only the fallback. A kept workstation whose Arch side
   asks SRV first is accepted under any DC name in its realm; one installed
   before this decision names its controller alone and is refused, with that
   reason, once the instance's DC is no longer that name. Windows needs
   nothing: its join names the domain, and its DC locator uses SRV.
   The disposable acceptance render stays pinned (8906d83): its simulated
   segment showed SSSD's SRV discovery failing where Samba's NetBIOS
   fallback joined, and it only ever has one controller.
   Samba's own route back to an original DC name -- join a DC with that name
   to the restored one, then demote the temporary DC -- is not needed and
   not built. This item was amended before ADR 0081 left its branch; it
   records the owner's answer rather than leaving the question open.
6. **Retention and sensitivity.** Nothing is pruned automatically; deleting
   a set is the owner's act, and it should be shredded. Destroying a
   throwaway instance does not remove its sets; they are as disposable as
   the instance. Sets are not encrypted at rest: they are protected only by
   0700/0600 permissions in an ignored directory on the owner's machine.
   Gate 7's "encrypted" clause stays open: no set may leave the host
   unencrypted, and encryption for an off-host copy is not built.

## Consequences

- `make homelab-factory-persistent-backup` and
  `make homelab-factory-persistent-restore` exist (`homelab/vm/persistent_backup.py`,
  `homelab/vm/samba_backup_disk.py`); both are dry runs unless `APPLY=1`,
  and the restore also needs `CONFIRM='RESTORE <instance>'`.
- The live proof is a disaster recovery: back up an instance with an
  SRV-first kept workstation, destroy the instance, restore it into the same
  name under a new DC name, reconverge it (`RECONVERGE=1`, which lays down
  the network the canonical image lacks and skips provisioning because a
  directory exists), then probe it and keep-verify the workstation.
- Kept workstations installed before the decision (for example
  `rehearsal-auto-ws1`) cannot survive a DC rename; they are refused with a
  message naming that reason, and their Arch side must be installed again.
- Restoring under a new DC name rotates `krbtgt` and removes the old DC's
  DNS records, as Samba documents; joined machines keep their accounts and
  secrets, which is the machine trust Gate 7 asks for.

## References

- https://wiki.samba.org/index.php/Back_up_and_Restoring_a_Samba_AD_DC
- https://github.com/samba-team/samba/blob/master/python/samba/netcmd/domain/backup.py
- ADR 0067, ADR 0068, ADR 0079; `homelab/LOCAL-FACTORY-LIFECYCLE.md` Gate 7
