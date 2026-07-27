# Offline Controller seed

`build.py` creates an ignored data ISO containing a fresh Arch package closure,
a `repo-add` database, the committed public Telos source, an installer, and a
hash receipt. It archives `HEAD`, never the working tree, so a private sibling
repository and untracked instance data cannot enter the image.

Build on Arch Linux:

```sh
python homelab/seed/build.py
```

The default output is
`homelab/var/seed/telos-controller-seed.iso`. The builder synchronizes isolated
pacman databases on every run and downloads the full closure even when a
package is installed on the build host. Pacman runs under `fakeroot`; staging
and final publication remain owned by the caller. The ISO is
written under a temporary name and atomically replaces the prior output only
after `xorriso` succeeds.

On an Arch live system, mount the data ISO and run:

```sh
sudo /path/to/seed/install-controller-deps /path/to/seed
```

The seed deliberately contains no inventory, credentials, domain name, host
name, address plan, or other instance value. Apply the separately held private
overlay only after the public bootstrap completes.
