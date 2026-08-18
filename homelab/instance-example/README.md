# Instance overlay template

Copy this directory to `homelab/instance/` and fill it in. That path is
gitignored (ADR 0046): real hostnames, addresses, interface MACs, disk serials
and per-machine inventory never enter Git or the published site.

    make homelab-instance      copies this template if instance/ does not exist

## Where the variables live

`group_vars/` is **inside `inventory/`**, beside `hosts.yml`. Ansible looks for
group and host variables in the directory the inventory source lives in and
nowhere else, so an `instance/group_vars/` one level up is parsed by nothing:
every variable in it silently falls back to its role default. An overlay
created before 2026-08-17 has that layout — move it:

    mv homelab/instance/group_vars homelab/instance/inventory/group_vars

Check it took, before converging anything:

    ansible-inventory -i homelab/instance/inventory/hosts.yml --list

Every variable you filled in must appear under `_meta.hostvars`. If the only
key there is `ansible_user`, the layout is still wrong.

Every value here is a `<placeholder>`. Nothing in this template is a real
address, and nothing that is a secret belongs in the overlay at all — see
"What does not go here" below.

## The break-glass administrator key

Every managed machine keeps a separately named local administrator with its own
sudo rule, and that account is never a directory account (ADR 0055). While the
directory is down, it and cached logins are the only ways in.

Its key is a **dedicated key pair, used for nothing else** (ADR 0063). Generate
it yourself; nothing in this repository ever handles the private half:

    ssh-keygen -t ed25519 -f ~/.ssh/homelab-breakglass -C "homelab break-glass"

Then put the **public** key — the `.pub` file, one line — into
`inventory/group_vars/all.yml`. Keep the private key where you keep your other
private keys, and back it up somewhere that does not depend on the homelab being
up. A break-glass key stored only on a homelab machine is not a break-glass key.

## The real account names

`identity/principals.json` names the real directory and break-glass accounts the
workstation factory creates. It is optional, and absent it every account keeps
the synthetic name in the tracked contract, which is what the acceptance gates
expect. See [`identity/README.md`](identity/README.md).

## What does not go here

The overlay is gitignored, not encrypted, and it sits in a working tree that
gets copied around. Passphrases, private keys, directory-administrator
credentials and Kerberos keytabs stay out of it:

- The LUKS2 passphrase is typed at the console at every boot (Milestone A) and
  is not recorded anywhere in this repository.
- The domain join is performed by a person, once, with credentials that are
  never stored — the identity role stops and tells you to run it.
- Directory account passwords — the domain Administrator's and each durable
  account's — are typed into a root-owned `0600` file **on the Controller**,
  under `/run` (tmpfs, so a reboot clears it), immediately before the run and
  deleted immediately after. The Controller role and its drivers are given the
  PATH of that file and never its contents, so no password reaches a variable,
  an argv, a log or a transcript. `inventory/group_vars/controllers.yml` spells
  out the exact commands.
- Private SSH keys stay in your own key store.
