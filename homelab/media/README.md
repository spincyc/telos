# Installation media

`fetch-arch` refreshes official release metadata, downloads the current Arch
installation ISO when it is not already cached, and refuses to return it until
both checks pass:

1. SHA-256 matches the release manifest.
2. The detached OpenPGP signature matches Pierre Schmitz's pinned Arch
   developer key fingerprint.

The signing key is obtained through Arch Linux's official Web Key Directory and
kept in an isolated cache keyring. By default, media is stored beneath
`homelab/var/media/arch`; that generated directory is not source material.

```sh
homelab/media/fetch-arch
homelab/media/fetch-arch --json
```

See [Media from a fresh clone](FRESH-CLONE.md) for the aggregate Make workflow,
Windows browser continuation, trust boundaries, and acceptance evidence.
