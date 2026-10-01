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
   new marker, with a `restored` record.
5. **The restored DC's name.** Because Samba cannot restore a DC under a
   name the domain still holds, the restored DC takes a new name
   (`RESTORE_DC_NAME`, default `dr-<UTC minute>`), recorded in the marker.
   Every durable stage expects the DC named `bootstrap-dc` -- the console
   protocol, the domain-controller role's SPN aliases, Arch's pinned
   `ad_server`, the probe's A and SRV checks -- so the durable binding
   refuses a restored instance. **Not decided here: how a restored domain
   regains the bootstrap DC's name.** Samba's documented route is to join a
   DC named `bootstrap-dc` to the restored one and demote the temporary DC,
   which needs two Controllers on one fabric and the DC join and demotion
   ADR 0068's migration also needs; nothing of it is built. Until it is, a
   restore proves the backup and the domain's identity but cannot serve a
   kept workstation.
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
- A live proof can show that a backup restores with its realm, domain SID
  and principals intact. It cannot yet show a restored directory serving the
  kept workstations; that needs the name decision above.
- Restoring under a new DC name rotates `krbtgt` and removes the old DC's
  DNS records, as Samba documents; joined machines keep their accounts and
  secrets, which is the machine trust Gate 7 asks for.

## References

- https://wiki.samba.org/index.php/Back_up_and_Restoring_a_Samba_AD_DC
- https://github.com/samba-team/samba/blob/master/python/samba/netcmd/domain/backup.py
- ADR 0067, ADR 0068, ADR 0079; `homelab/LOCAL-FACTORY-LIFECYCLE.md` Gate 7
