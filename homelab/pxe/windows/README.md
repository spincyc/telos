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
- the repository-pinned official `wimboot` binary;
- `7z` and `wimlib-imagex` (the Microsoft image is UDF); and
- a release name containing only letters, digits, dots, underscores, or
  hyphens.

Keep the ISO, extracted files, `wimboot`, answer files, passwords, domain-join
material, and generated release outside Git. The repository ignore rules cover
the default `homelab/var/` workspace, but an operator must still inspect
`git status` before committing.

## Local installation source

Stage the complete Microsoft UDF tree for the isolated factory:

```sh
make homelab-stage-windows-source
```

The target verifies the cached ISO digest, UEFI/WinPE chain, and exact Windows
11 Pro edition before extraction. It inventories every extracted file, rejects
answer files and unsafe file types, makes the complete tree read-only, and
atomically promotes it beneath ignored `homelab/var/`. Repeated runs verify and
reuse the cache; they do not trust its directory name. A changed byte or mode
stops the factory rather than silently refreshing evidence.

Read-only modes prevent accidental edits; they are not a security boundary
against another process running as the same Unix user. Staging holds a lock,
copies the ISO into a private work directory, and verifies and extracts only
that copy, closing the verify/extract replacement window. Keep the build
account single-operator during staging and do not run untrusted same-UID
processes. Stronger multi-user isolation requires a dedicated account or VM.

Fetch `wimboot` from the pinned official iPXE release before staging:

```sh
make homelab-media-wimboot
```

The fetch is fresh on every invocation. It downloads to a temporary file,
requires the recorded byte size and SHA-256 digest, then atomically replaces
`homelab/var/media/wimboot`. The Windows release manifest retains its upstream
project, release, URL, size, and digest so the published PXE payload remains
auditable without committing the binary.

## Stage and verify

The transactional factory release consumes the already verified, read-only
installation source created by `homelab-stage-windows-source`. It verifies that
tree against the sealed Windows ISO digest, then copies only the WinPE boot
payload into the immutable HTTP release. This offline path does not re-extract
the ISO and therefore does not require `7z` or `wimlib-imagex` after the media
seal has been created.

Direct ISO staging remains available as a diagnostic and compatibility path:

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

For an already sealed source tree, the equivalent low-level form is:

```sh
python homelab/pxe/windows/stage.py \
  --install-source homelab/var/media/windows/install-source \
  --source-iso-sha256 <sealed-ISO-SHA-256> \
  --wimboot homelab/var/media/wimboot \
  --output homelab/var/pxe/windows \
  --release 20260727.001
```

The aggregate factory command supplies the sealed digest itself; operators
should normally use `make homelab-factory-pxe` instead of invoking this form.

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
