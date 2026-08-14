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

### One declaration

Accounts are named **once**, in the owner's gitignored private overlay
(ADR 0046), which is also what names the accounts baked onto an installed
workstation disk:

    homelab/instance/identity/principals.json

This role is told only *which* of that contract's directory roles the instance
keeps as durable directory accounts:

```yaml
# homelab/instance/group_vars/controllers.yml
homelab_ad_directory_accounts:
  - standard_user
  - daily_administrator
  - domain_administrator
```

Order is immaterial and no account name appears here. `local_rescue` is refused
outright: ADR 0055/0063 keep the break-glass administrator a **local** account
at UID 1000 on the workstation, never a directory principal.

The names, the directory roles and the POSIX identifiers are rendered from that
one declaration by `files/resolve-directory-accounts.py`, which runs on the
Ansible **control host** (`delegate_to: localhost`) because that is where the
repository — and therefore the one roster loader
(`homelab/workstations/arch_second.identity_roster`) and the one allocation rule
(`homelab/vm/controller_principals.directory_account_plan`) — actually is. The
guest receives only the finished plan: the in-guest driver has just
`homelab/ansible` staged and is never handed the private overlay.

### Credentials

Before the run that first creates an account, place its initial credential in a
root-owned `0600` file with one non-empty first line, at the path
`homelab_ad_account_password_file_template` gives it — `{name}` is replaced with
the account's own resolved name, so no name is restated here either. Delete the
files afterwards: an account the directory already has keeps its own credential,
its SID and its group memberships across every later convergence, so no secret
needs to exist on the target again. The role is never given a value, only a
path; a temporary root-owned `0700` driver opens each file and hands what it
reads to Samba's in-process API, so nothing ever appears in a process argument
list, an Ansible variable, a template, or a log.

Rotating a credential that is already set takes two keys: set
`homelab_ad_account_password_reset_enabled: true` for that one run *and* name
the contract role in `homelab_ad_account_password_reset_roles`, then return both
to their defaults. Nothing else ever rewrites a stored credential, and nothing
in this role ever deletes a durable account: doing so would destroy its SID and
silently invalidate every ACL that references it.

### The POSIX allocation

Each account receives the rfc2307 attributes an SSSD client running with
`ldap_id_mapping = False` requires — without them the account cannot log in at
all. **The rule is not in this role.** It lives once, in
`homelab/vm/controller_principals.directory_account_plan`, which is the same
function that numbers the disposable acceptance roster, so the workstation can
never be handed different UIDs than the acceptance path proves:

| Attribute           | Value                                                    |
| ------------------- | -------------------------------------------------------- |
| `uidNumber`         | `POSIX_BASE` + the role's position in `DIRECTORY_ROLES`   |
| `gidNumber`         | the Domain Users gid, `POSIX_BASE` + RID 513              |
| `loginShell`        | `POSIX_LOGIN_SHELL`                                       |
| `unixHomeDirectory` | `POSIX_HOME_ROOT/<name>`                                  |

The identifier belongs to the **role**, so renaming an account in the overlay
moves no UID, and declaring one more role appends one UID without moving any
existing one. Domain Users and Domain Admins are given `POSIX_BASE` + their
well-known RIDs (10513 and 10512) so a client with directory-provided
identifiers can resolve both groups; `homelab_ad_posix_group_rids` declares
*which* groups this role verifies and the resolver refuses to render a plan if
it disagrees with the allocation.

Convergence **refuses to move** a uidNumber the directory already allocated —
files on every workstation, the per-user share directory and every ACL keyed on
that number could not follow it. Re-owning them and setting
`homelab_ad_account_renumber_enabled` for one run is a deliberate migration.

Only `domain_administrator` becomes a Domain Admins member. `daily_administrator`
is a `standard` directory account on purpose: ADR 0055 makes the everyday
elevated account a **passworded-sudo** administrator on the workstation and
deliberately *not* a directory administrator, which is exactly what gate 8's
`domain-admin-separate` check proves from this group's member list. Membership is
asserted in both directions, here and in the driver, so an extra member fails
convergence instead of quietly defeating that separation.

Convergence fails closed on a half-provisioned account: each one must carry all
four POSIX attributes in the directory, resolve through this Controller's own
name service with its own `uidNumber`, own a private
`homelab_ad_account_share_root/<name>` directory for the per-user share, and
appear in Domain Admins if and only if its role is `administrator`. The live
check this role cannot
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
