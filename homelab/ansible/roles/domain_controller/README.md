# Domain controller role

This role provisions the first host-level Samba AD DC with Samba's internal
DNS. It is intentionally not included in a playbook by default.

## How it is run

One play carries this role: `ansible/playbooks/bootstrap-controller.yml`, which
targets the inventory group `bootstrap_controllers`.

```sh
make homelab-bootstrap-controller INVENTORY=homelab/instance/inventory/hosts.yml
make homelab-bootstrap-controller INVENTORY=homelab/instance/inventory/hosts.yml APPLY=1
```

Without `APPLY=1` that is `--check --diff`. Read what check mode does and does
not prove under "Check mode" below before relying on it.

Two properties of the private overlay decide whether this works at all, and
both used to be wrong in the shipped template:

* the Controller must be a member of **`bootstrap_controllers`** (declare it as
  a parent of `controllers`, which is what `instance-example` now does), or the
  play matches zero hosts and merely warns;
* `group_vars/` must sit **inside** `inventory/`, beside `hosts.yml`. Ansible
  resolves group variables relative to the inventory source, so an
  `instance/group_vars/` one level up is read by nothing and every variable in
  it silently falls back to its role default.

Check both before converging anything:

```sh
ansible-inventory -i homelab/instance/inventory/hosts.yml --list
```

The Controller's variables must appear under `_meta.hostvars`. If the only key
there is `ansible_user`, the layout is wrong.

The durable accounts travel this host-side path and no other. The in-guest
factory payload (`homelab/vm/controller_factory.py`) deliberately declares an
empty roster: only a control host has the private identity overlay, the one
roster loader, and an operator who can stage a credential file out of band.

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
# homelab/instance/inventory/group_vars/controllers.yml
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

`local_rescue` is not the only refused name. The roster may not name a reserved
directory object either — `Administrator`, `Guest`, `krbtgt`, the per-DC
`dns-*` service account, or a local UNIX system account such as `root` — because
an account that already exists needs no credential and would simply be adopted:
its POSIX attributes and its `userPrincipalName` rewritten before any
fail-closed check ran. The refusal is case-insensitive, is made on the control
host (before anything is installed on the target) and again in the driver
(before Samba is even imported).

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

Stage the file at the moment of use and delete it immediately afterwards.
`/run` is tmpfs, so a reboot removes it whether or not you do:

```sh
ssh <controller> 'sudo install -d -m 0700 /run/secrets'
ssh <controller> 'sudo install -m 0600 /dev/null /run/secrets/homelab-ad-<name>'
ssh <controller> 'sudo tee /run/secrets/homelab-ad-<name> >/dev/null'   # type it
ssh <controller> 'sudo shred -u /run/secrets/homelab-ad-<name>'
```

Never put the value on a command line: argv is readable in the process table by
every local account. `tee` reads it from your terminal.

There is deliberately no way to have Ansible carry the value. `vars_prompt`, a
lookup and a vaulted variable all end with the credential in an Ansible
variable, which is what this shape exists to avoid.

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
| `uidNumber`         | the overlay's `uid_number` pin for the role, else `POSIX_BASE` + the role's position in `DIRECTORY_ROLES` |
| `gidNumber`         | the Domain Users gid, `POSIX_BASE` + RID 513              |
| `loginShell`        | `POSIX_LOGIN_SHELL`                                       |
| `unixHomeDirectory` | `POSIX_HOME_ROOT/<name>`                                  |

The identifier belongs to the **role**, so renaming an account in the overlay
moves no UID, and declaring one more role appends one UID without moving any
existing one. A pin, and every number's range and distinctness, is judged by the
roster loader; the rules are in
`homelab/instance-example/identity/README.md`. Domain Users and Domain Admins
are given `POSIX_BASE` + their well-known RIDs (10513 and 10512) so a client
with directory-provided identifiers can resolve both groups;
`homelab_ad_posix_group_rids` declares *which* groups this role verifies and the
resolver refuses to render a plan if it disagrees with the allocation.

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
`homelab_ad_share_root/<name>` directory for the per-user share, and
appear in Domain Admins if and only if its role is `administrator`. The live
check this role cannot
perform for itself is persistence: bring the instance up, confirm both accounts
exist with their attributes, shut it down, bring it up again, and confirm the
accounts and the domain SID survived.

### Additional standard users

The overlay may also list `additional_standard_users`: people with no contract
role. They are not declared here. Whenever `homelab_ad_directory_accounts` is
non-empty, the resolver plans every one the overlay lists, after the declared
roles, as a plain `standard` account with its own required `uid_number`, under
the name-free label `additional_standard_user_<uidNumber>` in the
`contract_role` field every loop label and driver message uses. The resolver
also reports those labels separately, and the role requires the plan to hold
exactly the declared roles plus exactly those labels, each `standard`; the
driver refuses such an account as anything but `standard`. Stage each one's
password file from the same template; rotate one by naming its label in
`homelab_ad_account_password_reset_roles`. The disposable acceptance Controller
never stages them.

### Diagnosing a failure

Two tasks in this section carry `no_log`, and only two: the per-account `stat`,
whose loop item is the account's own plan entry, and the driver invocation,
whose argv is the whole plan. Both would otherwise put resolved account names
into a retained transcript (ADR 0046).

Everything else about a failure is readable, and names accounts by their
**contract role**:

* a password file that is missing, not a regular file, not root-owned, not
  `0600` or empty is reported as `<contract role>: <reason>`, for every account
  at once, before anything is installed on the target;
* any failure inside the driver is reported from the driver's own diagnostic,
  `/run/homelab-provision-accounts.status` — root-owned `0600`, bounded to
  16 KiB, with every credential it read replaced by `[REDACTED]`. A `rescue`
  reads that file and fails the run with its contents.

Resolve a path yourself from `homelab_ad_account_password_file_template` and
`homelab/instance/identity/principals.json`; the role will not print it.

### Check mode

`--check` stops this role at its eighth task, immediately after the identity,
FQDN-resolution and clock preflight, because nothing below it can be evaluated
safely against a host where the packages and the directory do not exist yet.

That means a dry run proves the permanent identity is coherent and the host is
reachable, resolvable and in time. It does **not** reach the durable-account
roster validation, the control-host resolver, or the password-file precheck:
those live inside the durable-account block, which is deliberately gated and
sits last. A misdeclared roster or a missing credential file is therefore
caught on the first `APPLY=1` run, before any account is created, but not by
`--check`.

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

A simulated persistent instance, which only its serial console reaches, has
its own targets instead: `make homelab-factory-persistent-backup` takes
`samba-tool domain backup offline` inside the instance and
`make homelab-factory-persistent-restore` runs `samba-tool domain backup
restore` into a freshly created instance under a new DC name, as Samba
requires (ADR 0081).

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
