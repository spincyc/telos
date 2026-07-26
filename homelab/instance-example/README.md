# Instance overlay template

Copy this directory to `homelab/instance/` and fill it in. That path is
gitignored (ADR 0046): real hostnames, addresses, interface MACs, disk serials
and per-machine inventory never enter Git or the published site.

    make homelab-instance      copies this template if instance/ does not exist

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
`group_vars/all.yml`. Keep the private key where you keep your other private
keys, and back it up somewhere that does not depend on the homelab being up. A
break-glass key stored only on a homelab machine is not a break-glass key.

## What does not go here

The overlay is gitignored, not encrypted, and it sits in a working tree that
gets copied around. Passphrases, private keys, directory-administrator
credentials and Kerberos keytabs stay out of it:

- The LUKS2 passphrase is typed at the console at every boot (Milestone A) and
  is not recorded anywhere in this repository.
- The domain join is performed by a person, once, with credentials that are
  never stored — the identity role stops and tells you to run it.
- Private SSH keys stay in your own key store.
