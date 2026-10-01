# Samba SRV serialization compatibility library

Samba 4.24.5 compresses the TARGET name in DNS SRV records. RFC 2782 forbids
that encoding, and c-ares 1.34.7 and later reject it. With c-ares 1.34.8,
the directory's SRV discovery fails even though direct LDAP and Kerberos
operations work.

This vendor patch adds `NDR_NO_COMP` to `dns_srv_record`. It changes outgoing
SRV TARGET serialization only. Owner names can still be compressed, and
incoming compressed SRV records still parse. The existing internal DNS
backend, dynamic update handling, directory data, and client identities remain
in place. The serializer resides in `libndr-nbt.so.0`, supplied by Arch's
`smbclient` package.

## Build and admission

```sh
homelab/bin/homelab-samba-dns build --cache homelab/var/media/samba-dns
homelab/bin/homelab-samba-dns verify --cache homelab/var/media/samba-dns
```

Build first reuses pinned archives from the cache or workstation package
repository, then acquires missing inputs from official Samba/Arch locations.
Every archive and signature has a SHA-256 pin. Samba's detached signature
is verified over the uncompressed tar, against its pinned distribution key.
Arch signatures require the pinned packager key and the host's Arch keyring.
No host packages are installed.

The compiler runs in bubblewrap with the host mounted read-only, a private
temporary directory, and no network. `build.sh` disables unused executables
and builds only `ndr_nbt` and its DNS/NBT unit test. It sets explicit hardening
flags, a fixed source date, a canonical source path, and the installed
`/usr/lib/samba:/usr/lib` RUNPATH. Two clean builds must produce identical
stripped bytes. The receipt records the actual host package inventory and
compiler. This proves reproducibility on that recorded build host; it does
not claim an independent hermetic compiler sysroot.

The host needs an Arch build environment with GCC, binutils, Python, Perl,
pkgconf, bubblewrap, patch, tar, curl, GnuPG, and development headers for
the configure checks (including GnuTLS, Kerberos and libarchive). The only
additional tools needed on the prototype host were Parse::Yapp and rpcgen;
their signed packages are privately extracted. The source includes cmocka.
All configure/build output is retained under the ignored cache's `evidence/`.

Admission requires the exact original defined and undefined symbol/version
sets, SONAME, DT_NEEDED list, RUNPATH and ELF hardening properties. Thus this
build cannot quietly introduce newer GLIBC symbol requirements. The patched
library is also loaded with the sealed package's Samba libraries and tested
against the pinned c-ares 1.34.8 binary, whose hash matches the kept client's
parser. Both compressed and uncompressed synthetic inputs must round trip to
the exact conforming packet. The original library must fail the new Samba
regression test and emit a packet rejected by c-ares; the replacement must
pass that test plus the four existing DNS/NBT tests and c-ares parsing.

Offline `verify()` rechecks the ELF, resource pins, receipt and library bytes;
it does not download, rebuild or execute the library. `stage()` verifies
before and after copying and publishes exactly `libndr-nbt.so.0` and
`receipt.json`. The media seal binds this pair. A Samba service override must
check the installed `smbclient`/Samba version and the original library hash
from the receipt before adding the private override directory to the service's
`LD_LIBRARY_PATH`. Never overwrite the packaged library or apply a global
loader override.

The pin is deliberately specific to `smbclient 2:4.24.5-1`. Upgrade the vendor
patch, source/package pins and ABI baseline together, or remove the override
after a verified upstream package fixes the serializer. Do not relax the
c-ares parser or migrate DNS backends as part of this compatibility patch.

## Sources

- [RFC 2782 SRV TARGET format](https://www.rfc-editor.org/rfc/rfc2782.html)
- [c-ares change rejecting forbidden compressed RDATA](https://github.com/c-ares/c-ares/pull/1190)
- [Reported SSSD/Samba interoperability failure](https://bugzilla.redhat.com/show_bug.cgi?id=2510945)
- [Samba 4.24.5 DNS IDL](https://github.com/samba-team/samba/blob/samba-4.24.5/librpc/idl/dns.idl)
- [Samba distribution archive and signatures](https://download.samba.org/pub/samba/stable/)
