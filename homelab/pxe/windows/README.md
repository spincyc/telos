# Windows 11 PXE payload

This target stages a locally supplied Windows 11 ISO for a `wimboot`-based
WinPE boot. It does not download, commit, publish, or license Microsoft media.
The operator is responsible for obtaining a genuine Windows 11 ISO and for
licensing every installed workstation.

Microsoft's supported consumer flow creates an expiring link after interactive
product and language selection. The repository acquisition target downloads
everything with a stable official source and stops here with an exact
continuation. After downloading the ISO from Microsoft's page, import it with:

```sh
homelab/bin/homelab-fetch-windows \
  --source ~/Downloads/Win11_English_x64.iso \
  --expected-sha256 <SHA-256-published-by-Microsoft> \
  --output homelab/var/downloads/windows-11.iso
```

Copy the digest Microsoft displays for the selected download. The importer
refuses a mismatch; the ISO and its verification receipt stay under ignored
`homelab/var/`. PXE staging independently confirms that the image advertises
Windows 11 Pro.

## Inputs

- a local Windows 11 x86-64 ISO;
- a local `wimboot` binary obtained from the official iPXE project;
- `7z` and `wimlib-imagex` (the Microsoft image is UDF); and
- a release name containing only letters, digits, dots, underscores, or
  hyphens.

Keep the ISO, extracted files, `wimboot`, answer files, passwords, domain-join
material, and generated release outside Git. The repository ignore rules cover
the default `homelab/var/` workspace, but an operator must still inspect
`git status` before committing.

## Stage and verify

```sh
python homelab/pxe/windows/stage.py \
  --iso /absolute/path/to/Win11_English_x64.iso \
  --wimboot /absolute/path/to/wimboot \
  --output homelab/var/pxe/windows \
  --release 20260727.001
```

The command refuses an ISO that does not advertise Windows 11 Pro in
`sources/install.wim` or `sources/install.esd`. It extracts the ISO into a
temporary sibling directory, copies only the WinPE boot inputs into a
versioned release, hashes every staged file, writes `release.json` last, and
then renames the complete directory into place.

The generated `boot.ipxe` loads:

1. `wimboot`;
2. Windows Boot Manager;
3. the ISO's BCD store;
4. the WinPE RAM-disk image; and
5. `sources/boot.wim`.

This proves that the supplied media can reach WinPE. It does **not** silently
claim that Windows installation is unattended. A later target must inject a
reviewed WinPE startup script and an answer file, provide the installation
image through an authenticated local source, select the approved disk by
serial, and stop before erasure for explicit authorization.

## Acceptance

Run `verify.py` against the staged directory before publishing:

```sh
python homelab/pxe/windows/verify.py \
  homelab/var/pxe/windows/20260727.001
```

Pass means every required file exists, its digest and size match the manifest,
the release contains no tracked secret-bearing answer files, and the iPXE
script references the immutable release URL. A QEMU/OVMF boot to WinPE remains
a separate integration proof.
