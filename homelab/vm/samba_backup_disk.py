"""The raw disk that carries a Samba backup tarball in or out of an instance.

ADR 0081.  A persistent instance has one channel to the host, its serial
console, and the argv audit refuses every medium.  A backup or restore run
therefore attaches exactly one more device, a raw disk this run creates
(``simulated_topology.backup_disk_args``), and moves the tarball across it
behind a small self-describing header:

* bytes ``0..4095``: ``TELOS-SAMBA-BACKUP-V1\\nlength=<n>\\nsha256=<hex>\\n
  token=<hex>\\n`` padded with NUL bytes to 4096 -- the tarball's length, its
  SHA-256, and the run's token, so a disk from another run is refused;
* bytes ``4096..4096+n``: the tarball itself; everything after is unused.

Both sides write and read exactly this, and each verifies the other: the
guest checks what it wrote by reading it back and prints the SHA-256 on the
console; the host reads the disk after a clean poweroff and refuses a header,
token, length or checksum that does not agree.  The guest commands are built
here, beside the host's reader, so one format has one definition; tests run
them under ``bash`` against an ordinary file standing in for the device.

Standard library only.  Nothing here reads or prints the tarball's contents.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path

HEADER_SIZE = 4096
MAGIC = "TELOS-SAMBA-BACKUP-V1"
#: The output disk's size.  Sparse: only what the guest writes is allocated.
#: A home domain's tarball is a few megabytes; the guest refuses a tarball
#: that does not fit rather than truncating it.
OUTPUT_CAPACITY = 512 * 1024 * 1024
#: A restore's input disk is rounded up to this boundary.
INPUT_ALIGNMENT = 1024 * 1024
#: Where the guest finds each disk: virtio-blk exposes its serial here.
DEVICE_BY_ID = "/dev/disk/by-id/virtio-{serial}"
TOKEN = re.compile(r"^[0-9a-f]{32}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
#: The single console line a backup command prints: the tarball's SHA-256
#: and length, or the step that failed.
BACKUP_PROOF = rb"FAIL:[a-z-]+|[0-9a-f]{64}:[0-9]{1,12}"
#: The single console line a restore command prints.
RESTORE_PROOF = rb"FAIL:[a-z-]+|RESTORED"
#: A DC name a restore may take: what ``samba-tool`` accepts as a NetBIOS
#: computer name, in the lower case the harness writes host names in.
NEW_SERVER_NAME = re.compile(r"^[a-z](?:[a-z0-9-]{0,13}[a-z0-9])?$")


class BackupDiskError(RuntimeError):
    """A backup disk, or its header, cannot be trusted.  Never carries data."""


@dataclass(frozen=True)
class Header:
    length: int
    sha256: str
    token: str


def new_token() -> str:
    return secrets.token_hex(16)


def header_text(length: int, sha256: str, token: str) -> str:
    """The header's text, before its NUL padding."""
    return f"{MAGIC}\nlength={length}\nsha256={sha256}\ntoken={token}\n"


def encode_header(length: int, sha256: str, token: str) -> bytes:
    if not isinstance(length, int) or isinstance(length, bool) or length < 1:
        raise BackupDiskError("a backup tarball must not be empty")
    if not SHA256.fullmatch(sha256 or ""):
        raise BackupDiskError("a backup header needs a lowercase SHA-256")
    if not TOKEN.fullmatch(token or ""):
        raise BackupDiskError("a backup header needs a 32-digit hex token")
    text = header_text(length, sha256, token).encode("ascii")
    return text + b"\0" * (HEADER_SIZE - len(text))


def decode_header(block: bytes, *, capacity: int) -> Header:
    """Parse one header strictly, or refuse it without quoting it."""
    if len(block) != HEADER_SIZE:
        raise BackupDiskError("the backup disk is shorter than its header")
    text, _, padding = block.partition(b"\0")
    if padding.strip(b"\0"):
        raise BackupDiskError("the backup header has bytes after its end")
    try:
        lines = text.decode("ascii").split("\n")
    except UnicodeDecodeError as error:
        raise BackupDiskError("the backup header is not text") from error
    if len(lines) != 5 or lines[0] != MAGIC or lines[4] != "":
        raise BackupDiskError(
            "the backup disk carries no Telos Samba backup header")
    fields = {}
    for line, key in zip(lines[1:4], ("length", "sha256", "token")):
        name, separator, value = line.partition("=")
        if name != key or not separator:
            raise BackupDiskError(f"the backup header has no {key}")
        fields[key] = value
    if not re.fullmatch(r"[1-9][0-9]{0,11}", fields["length"]):
        raise BackupDiskError("the backup header's length is not a size")
    length = int(fields["length"])
    if length > capacity - HEADER_SIZE:
        raise BackupDiskError(
            "the backup header claims more data than the disk holds")
    if not SHA256.fullmatch(fields["sha256"]):
        raise BackupDiskError("the backup header's SHA-256 is malformed")
    if not TOKEN.fullmatch(fields["token"]):
        raise BackupDiskError("the backup header's token is malformed")
    return Header(length, fields["sha256"], fields["token"])


def _open_new(path: Path) -> int:
    return os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)


def create_blank(path: Path, capacity: int = OUTPUT_CAPACITY) -> Path:
    """A fresh, empty, sparse raw disk; refuses a path that already exists."""
    if capacity <= HEADER_SIZE or capacity % HEADER_SIZE:
        raise BackupDiskError("a backup disk's size must be whole 4 KiB blocks")
    path = Path(path)
    descriptor = _open_new(path)
    try:
        os.ftruncate(descriptor, capacity)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return path


def write_image(path: Path, payload: bytes, token: str) -> Header:
    """A restore's input disk: header, tarball, padded to whole MiB."""
    if not payload:
        raise BackupDiskError("a backup tarball must not be empty")
    digest = hashlib.sha256(payload).hexdigest()
    header = encode_header(len(payload), digest, token)
    used = HEADER_SIZE + len(payload)
    size = -(-used // INPUT_ALIGNMENT) * INPUT_ALIGNMENT
    descriptor = _open_new(Path(path))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(header)
            stream.write(payload)
            stream.truncate(size)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return Header(len(payload), digest, token)


def read_payload(path: Path, *, token: str) -> tuple[bytes, Header]:
    """The tarball on *path*, refused unless header, token and SHA-256 agree."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise BackupDiskError(f"the backup disk cannot be opened: {path}") \
            from error
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise BackupDiskError("the backup disk is not a regular file")
        header = decode_header(stream.read(HEADER_SIZE),
                               capacity=info.st_size)
        if not secrets.compare_digest(header.token, token):
            raise BackupDiskError(
                "the backup disk was written by another run (token mismatch)")
        payload = stream.read(header.length)
    if len(payload) != header.length:
        raise BackupDiskError("the backup disk ends before its tarball does")
    if hashlib.sha256(payload).hexdigest() != header.sha256:
        raise BackupDiskError(
            "the tarball on the backup disk does not match its SHA-256")
    return payload, header


def shred_disk(path: Path) -> None:
    """Overwrite every allocated byte of a backup disk, fsync, unlink.

    The disk is sparse, so only the extents the guest wrote are overwritten
    (``SEEK_DATA``/``SEEK_HOLE``); a filesystem that cannot report them gets
    the whole file overwritten.  Best effort by nature, like
    ``credential_custody.shred_file``: copy-on-write storage can keep old
    blocks.
    """
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise BackupDiskError(f"refusing to shred a non-regular file: {path}")
        size = info.st_size
        try:
            extents = []
            offset = 0
            while offset < size:
                try:
                    start = os.lseek(descriptor, offset, os.SEEK_DATA)
                except OSError as error:
                    if error.errno == 6:  # ENXIO: no data after offset
                        break
                    raise
                end = os.lseek(descriptor, start, os.SEEK_HOLE)
                extents.append((start, end))
                offset = end
        except (OSError, AttributeError):
            extents = [(0, size)]
        for start, end in extents:
            position = start
            while position < end:
                chunk = secrets.token_bytes(min(end - position, 1024 * 1024))
                written = os.pwrite(descriptor, chunk, position)
                position += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.unlink(path)


# -- guest commands ----------------------------------------------------------
def _cleanup_trap(directory_variable: str = "d") -> str:
    """Shred every file of the guest's temporary directory, then remove it."""
    body = (f'/usr/bin/find "${directory_variable}" -type f -exec '
            f'/usr/bin/shred -u {{}} + 2>/dev/null; '
            f'/usr/bin/rm -rf "${directory_variable}"')
    return f"trap {shlex.quote(body)} EXIT"


def device_path(serial: str) -> str:
    return DEVICE_BY_ID.format(serial=serial)


def backup_command(
    device: str, token: str, *, capacity: int = OUTPUT_CAPACITY,
    samba_tool: str = "/usr/bin/samba-tool", tmp_root: str = "/var/tmp",
    require_block_device: bool = True,
) -> str:
    """One root shell line: back up, write the disk, prove it, print the proof.

    ``samba-tool domain backup offline`` (Samba 4.10+) copies the local DC's
    database with the locking it needs; Samba does not need to be stopped
    for it.  Its output goes to stderr, so stdout carries exactly one line:
    ``<sha256>:<length>``, or ``FAIL:<step>``.  The guest's copy of the
    tarball is shredded on every exit.
    """
    if not TOKEN.fullmatch(token):
        raise BackupDiskError("a backup command needs a 32-digit hex token")
    dev = shlex.quote(device)
    tool = shlex.quote(samba_tool)
    template = shlex.quote(f"{tmp_root}/telos-backup-XXXXXXXX")
    header = shlex.quote(MAGIC + r"\nlength=%s\nsha256=%s\ntoken=%s\n")
    steps = [
        "f=device",
        *([f"test -b {dev}"] if require_block_device else []),
        "f=tempdir", f"d=$(/usr/bin/mktemp -d {template})", _cleanup_trap(),
        "f=samba-tool",
        f'{tool} domain backup offline --targetdir="$d" </dev/null >&2',
        "f=tarball", 'set -- "$d"/samba-backup-*.tar.bz2', '[ "$#" -eq 1 ]',
        '[ -f "$1" ]', 't=$1', 's=$(/usr/bin/stat -c %s "$t")',
        'h=$(/usr/bin/sha256sum "$t")', 'h=${h%% *}',
        "f=capacity", '[ "$s" -gt 0 ]',
        f'[ $((s + {HEADER_SIZE})) -le {int(capacity)} ]',
        "f=write",
        f'/usr/bin/printf {header} "$s" "$h" {token} > "$d/.header"',
        f'/usr/bin/truncate -s {HEADER_SIZE} "$d/.header"',
        f'/usr/bin/dd if="$d/.header" of={dev} bs={HEADER_SIZE} count=1 '
        'conv=fsync,notrunc status=none',
        f'/usr/bin/dd if="$t" of={dev} bs={HEADER_SIZE} seek=1 '
        'conv=fsync,notrunc status=none',
        "f=verify",
        f'r=$(/usr/bin/dd if={dev} bs={HEADER_SIZE} skip=1 '
        f'count=$(( (s + {HEADER_SIZE - 1}) / {HEADER_SIZE} )) status=none '
        '| /usr/bin/head -c "$s" | /usr/bin/sha256sum)',
        '[ "${r%% *}" = "$h" ]',
        "/usr/bin/printf '%s:%s' \"$h\" \"$s\"",
    ]
    return " && ".join(steps) + " || /usr/bin/printf 'FAIL:%s' \"$f\""


def restore_command(
    device: str, header: Header, new_server_name: str, *,
    samba_tool: str = "/usr/bin/samba-tool",
    state_root: str = "/var/lib/samba", smb_conf: str = "/etc/samba/smb.conf",
    tmp_root: str = "/var/tmp", require_block_device: bool = True,
) -> str:
    """One root shell line: read the disk, prove it, restore with Samba.

    Refuses a guest that already holds a directory or a Samba
    configuration: a restore only fills a freshly created instance.  The
    package's empty ``/var/lib/samba`` is moved aside, because
    ``samba-tool domain backup restore`` requires an empty or absent
    target; restoring into ``/var/lib/samba`` itself puts ``sam.ldb`` at
    ``/var/lib/samba/private/sam.ldb``, where convergence looks for it, and
    the rewritten ``smb.conf`` the restore leaves in ``etc/`` is installed
    as ``/etc/samba/smb.conf``.  Prints ``RESTORED`` or ``FAIL:<step>``.
    """
    if not NEW_SERVER_NAME.fullmatch(new_server_name or ""):
        raise BackupDiskError(
            "a restored DC name must be 1-15 lowercase letters, digits or "
            "hyphens, starting with a letter")
    if not (TOKEN.fullmatch(header.token) and SHA256.fullmatch(header.sha256)
            and header.length > 0):
        raise BackupDiskError("a restore command needs a verified header")
    dev = shlex.quote(device)
    tool = shlex.quote(samba_tool)
    state = shlex.quote(state_root)
    aside = shlex.quote(state_root + ".pre-restore")
    conf = shlex.quote(smb_conf)
    template = shlex.quote(f"{tmp_root}/telos-restore-XXXXXXXX")
    # The console takes one line only, so the expected header is rebuilt by
    # printf in the guest rather than quoted with its newlines.
    expected = (
        '"$(/usr/bin/printf '
        + shlex.quote(MAGIC + r"\nlength=%s\nsha256=%s\ntoken=%s")
        + f' {header.length} {header.sha256} {header.token})"')
    blocks = -(-header.length // HEADER_SIZE)
    steps = [
        "f=device",
        *([f"test -b {dev}"] if require_block_device else []),
        "f=precondition", f"[ ! -e {conf} ]",
        f"[ ! -e {state}/private/sam.ldb ]", f"[ ! -e {aside} ]",
        "f=tempdir", f"d=$(/usr/bin/mktemp -d {template})", _cleanup_trap(),
        "f=header",
        f"x=$(/usr/bin/dd if={dev} bs={HEADER_SIZE} count=1 status=none "
        "| /usr/bin/tr -d '\\000')",
        f'[ "$x" = {expected} ]',
        "f=extract",
        f'/usr/bin/dd if={dev} bs={HEADER_SIZE} skip=1 count={blocks} '
        f'status=none | /usr/bin/head -c {header.length} '
        '> "$d/backup.tar.bz2"',
        "f=checksum", 'r=$(/usr/bin/sha256sum "$d/backup.tar.bz2")',
        f'[ "${{r%% *}}" = {header.sha256} ]',
        "f=set-aside", f"{{ [ ! -e {state} ] || /usr/bin/mv {state} {aside}; }}",
        "f=samba-tool",
        f'{tool} domain backup restore --backup-file="$d/backup.tar.bz2" '
        f'--newservername={new_server_name} --targetdir={state} '
        '</dev/null >&2',
        "f=install", f"[ -f {state}/private/sam.ldb ]",
        f"/usr/bin/install -D -m 0644 {state}/etc/smb.conf {conf}",
        "/usr/bin/printf RESTORED",
    ]
    return " && ".join(steps) + " || /usr/bin/printf 'FAIL:%s' \"$f\""
