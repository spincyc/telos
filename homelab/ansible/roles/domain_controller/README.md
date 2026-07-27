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
