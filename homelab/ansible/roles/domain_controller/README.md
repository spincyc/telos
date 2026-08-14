# Domain controller role

This role provisions the first host-level Samba AD DC with Samba's internal
DNS. It is intentionally not included in a playbook by default.

Before the first run, place the initial Administrator password in a root-owned
`0600` file on the target, preferably:

```text
/run/secrets/samba-ad-admin
```

Set `homelab_ad_admin_password_file` to that path in the untracked instance
overlay and explicitly set `homelab_ad_provision_enabled: true` for that run.
Remove the file and return the switch to false after provisioning succeeds.
The role neither copies nor reads the secret through Ansible; a temporary local
driver feeds it to Samba's terminal prompt so it never appears in process
arguments.

The role is idempotent around `/var/lib/samba/private/sam.ldb`. If a directory
already exists, its realm and NetBIOS domain must match the declared permanent
identity. It will not rename, replace, or re-provision a directory.

The host must already have its final static address, hostname, forward and
reverse DNS plan, and synchronized clock. Clients must use AD DNS. Those
network decisions belong to the deployment gate rather than this role.
Set `homelab_ad_expected_hostname` to the intended short hostname; the role
refuses to provision if the running host has a different name.

The role publishes the required TCP, UDP, and dynamic RPC ranges as defaults
for a surrounding firewall implementation. It deliberately makes no firewall
changes itself.

## Durable directory accounts

Optional, off by default, and only meaningful on a **persistent** instance: one
whose `/var/lib/samba` survives a bring-up. A run that declares no roster
behaves exactly as a run of this role did before this section existed, which is
what keeps the disposable acceptance Controller — whose synthetic roster is
staged over the serial console by `homelab/vm/controller_principals.py` —
untouched.

Declare the roster in the untracked instance overlay:

```yaml
# homelab/instance/group_vars/controllers.yml
homelab_ad_directory_accounts:
  - name: <standard-account>
    role: standard
    password_file: /run/secrets/homelab-ad-<standard-account>
  - name: <admin-account>
    role: administrator            # a Domain Admins member
    password_file: /run/secrets/homelab-ad-<admin-account>
```

Before the run that first creates an account, place its initial credential in a
root-owned `0600` file at that path, one file per account, one non-empty first
line each. Delete the files afterwards: an account the directory already has
keeps its own credential, its SID and its group memberships across every later
convergence, so no secret needs to exist on the target again. The role is never
given a value, only a path; a temporary root-owned `0700` driver opens each file
and hands what it reads to Samba's in-process API, so nothing ever appears in a
process argument list, an Ansible variable, a template, or a log.

Each account receives the rfc2307 attributes an SSSD client running with
`ldap_id_mapping = False` requires — without them the account cannot log in at
all — allocated by the rule `homelab/vm/controller_principals.py` already
implements for the acceptance roster:

| Attribute           | Value                                            |
| ------------------- | ------------------------------------------------ |
| `uidNumber`         | `homelab_ad_posix_base` + position in the roster |
| `gidNumber`         | the Domain Users gid, `base` + RID 513           |
| `loginShell`        | `homelab_ad_posix_login_shell`                   |
| `unixHomeDirectory` | `homelab_ad_posix_home_root/<name>`              |

Position is the identifier, so **append to the roster; never reorder or remove
an entry.** Reordering renumbers accounts and orphans everything they own.
Domain Users and Domain Admins are given `base` + their well-known RIDs
(10513 and 10512) so a client with directory-provided identifiers can resolve
both groups.

Rotating a credential that is already set takes two keys: set
`homelab_ad_account_password_reset_enabled: true` for that one run *and*
`reset_password: true` on the individual account, then return both to false.
Nothing else ever rewrites a stored credential, and nothing in this role ever
deletes a durable account: doing so would destroy its SID and silently
invalidate every ACL that references it.

The administrator is a Domain Admins member and nothing more. Its passworded
`sudo` on a workstation is the identity client's business (ADR 0055, ADR 0063
keep the local break-glass account out of the directory and out of `root`).

Convergence fails closed on a half-provisioned account: each one must carry all
four POSIX attributes in the directory, resolve through this Controller's own
name service with its own `uidNumber`, own a private
`homelab_ad_account_share_root/<name>` directory for the per-user share, and —
for an administrator — appear in Domain Admins. The live check this role cannot
perform for itself is persistence: bring the instance up, confirm both accounts
exist with their attributes, shut it down, bring it up again, and confirm the
accounts and the domain SID survived.

## Backup boundary

Backups and restores are operator procedures, not convergence. Take a supported
online backup to storage outside Samba's database tree:

```sh
sudo install -d -m 0700 /var/backups/samba-ad
sudo samba-tool domain backup online \
  --targetdir=/var/backups/samba-ad \
  --server="$(hostname -f)"
```

Copy the archive off the DC and test restoration on an isolated machine. Never
restore a filesystem snapshot over a running directory, and never automate a
restore from this role.

## Human acceptance

The role performs non-secret structural checks. An operator separately proves
that Kerberos accepts a real account without placing its password in Ansible:

```sh
kinit "administrator@${AD_REALM}"
klist
kdestroy
```

Set `AD_REALM` from the private instance overlay and run that prompt
interactively. Never add a password flag, pipe a password from inventory, or
retain the resulting credential cache in a release artifact.
