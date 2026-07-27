# Media from a fresh clone

Installation media is deliberately not committed to `telos-public`. A fresh
clone contains the fetchers, pinned trust information, and tests needed to
obtain every external boot artifact. The default cache is
`homelab/var/media/`, which Git ignores and which may be deleted at any time.

## One-command flow

On the supported Arch Linux build host:

```sh
git clone https://github.com/spincyc/telos.git
cd telos
make homelab-bootstrap-deps
make homelab-media
```

For an existing checkout, update the public instructions first:

```sh
git pull --ff-only
make homelab-media
```

`make homelab-media` performs a fresh upstream metadata lookup on every run.
It may reuse a large cached file only after recalculating its digest and
matching the currently selected upstream release. No ISO, signature, checksum
file, `wimboot` binary, receipt, or private repository is required before the
command starts.

The aggregate target obtains, or starts acquisition of:

- the current official Arch Linux x86-64 installation ISO;
- the pinned official iPXE `wimboot` release; and
- the current official Windows 11 x64 multi-edition ISO.

Individual targets are useful when resuming a failed or interactive download:

```sh
make homelab-media-arch
make homelab-media-wimboot
make homelab-media-windows
```

The Windows step deliberately pauses with a nonzero status when Microsoft
requires a browser. Follow the continuation it prints, then rerun the target.
A partially downloaded or failed-verification file is never promoted to the
usable path.

## What “verified” means

The Arch result is accepted only when its SHA-256 matches Arch's current
official checksum manifest and its detached OpenPGP signature is valid under
the pinned Arch release-signing fingerprint. The key is resolved from Arch's
official Web Key Directory into an isolated keyring; a same-name key from a
general-purpose keyserver is not sufficient.

`wimboot` is downloaded from the pinned release asset in the official
`ipxe/wimboot` GitHub repository. Its byte count and SHA-256 must match the
tracked public metadata. Redirects outside GitHub's release infrastructure are
rejected.

The Windows ISO must come from Microsoft's software-download service. Microsoft
does not offer a stable, supported unattended URL for the consumer
multi-edition download, so the repository does not scrape the page or silently
replace it with Enterprise evaluation, Insider, UUP-reconstructed, or
third-party media. The importer requires the exact SHA-256 shown in Microsoft's
current per-language verification table and refuses a mismatch. PXE staging
independently refuses media that does not advertise Windows 11 Pro.

The Windows import writes a machine-readable provenance receipt beside the
artifact. The Arch fetcher can emit its verified source, selected image, and
digest as JSON; `wimboot` is checked against tracked release metadata. Retain
those records and the command output with acceptance evidence. They contain no
credentials.

## Windows interactive fallback

Microsoft issues short-lived ISO URLs and may require an interactive browser.
If the Windows target reports that automatic resolution is unavailable:

1. Open Microsoft's official **Download Windows 11 Disk Image (ISO) for x64
   devices)** page.
2. Select the current multi-edition x64 release and the deployment language.
3. Download the ISO using the Microsoft-generated link. Do not rename a
   partial browser download to `.iso`.
4. Copy the SHA-256 from Microsoft's **Verify your download** table for that
   exact language.
5. Resume acquisition:

```sh
make homelab-media-windows \
  WINDOWS_ISO=/absolute/path/to/downloaded.iso \
  WINDOWS_SHA256=<digest-copied-from-Microsoft>
```

The importer rejects missing, non-ISO, and implausibly small inputs, copies the
file atomically, matches its full SHA-256 to Microsoft's value, and emits a
provenance record. Confirm the browser remained on Microsoft domains; never
fill the hash field with a digest copied from an unofficial site.

Microsoft links normally expire quickly. Keep the generated receipt with the
download used for a particular acceptance run, and repeat the Microsoft
selection when a fresh release is required.

## Evidence and cleanup

Before staging PXE payloads, record:

```sh
find homelab/var/media -maxdepth 3 -type f -print
git status --short
```

Acceptance requires all requested artifacts and their available provenance
records to exist, every verifier to report success, Windows staging to identify
Windows 11 Pro, and `git status --short` to show no media files.
The generated cache is disposable:

```sh
rm -r homelab/var/media
```

That removal does not affect reproducibility: the same Make targets rebuild
the cache from the public repository's tracked trust metadata and fresh
official upstream metadata.
