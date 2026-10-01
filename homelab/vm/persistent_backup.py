#!/usr/bin/env python3
"""Back up a persistent directory with Samba, and restore it with Samba.

ADR 0081.  ``make homelab-factory-persistent-backup`` and
``make homelab-factory-persistent-restore``.  The domain is the asset that
cannot be rebuilt (ADR 0079), and ADR 0067 forbids cloning or restoring a
live DC's disk, so both directions go through Samba's own tooling and never
through a disk image:

* **backup** boots the instance in place on the per-run fabric, exactly as
  the probe does, with ONE extra audited device: a blank raw disk this run
  creates (``samba_backup_disk``).  Over the console, as root, it proves the
  realm and domain SID are the bound directory's, reads the DC's name, runs
  ``samba-tool dbcheck --cross-ncs``, then ``samba-tool domain backup
  offline`` -- which Samba documents as safe while samba runs, with the
  locking a consistent copy needs -- and writes the tarball onto the raw disk
  behind a header carrying its length and SHA-256.  After a clean poweroff
  the host reads the tarball off the disk, verifies it against the header and
  the guest's console proof, writes a backup set (tarball, manifest, marker
  copy and, for a throwaway agent-custody instance only, its custody store)
  into ``BACKUP_ROOT/<instance>/<run id>/`` (0700 directories, 0600 files),
  shreds the raw disk, and records ``last_backup`` in the instance marker.
* **restore** refuses unless the target instance is absent (the disaster:
  the instance is lost or destroyed) and the backup set verifies, creates the
  instance from the canonical image under the custody the backup records,
  boots it in place with NO network device and the backup disk attached
  read-only, and runs ``samba-tool domain backup restore`` into
  ``/var/lib/samba``, the layout convergence expects.  It starts samba,
  proves the realm, the domain SID and the digest of every security
  principal's SID equal the backup's, powers off cleanly, and only then
  copies the backup's directory records into the new marker.

Samba restores a DC only under a name the domain never held: its restore adds
the new DC's objects while the backed-up DC's still exist, so the backed-up
DC's own name fails.  A restored instance therefore runs a DC with a new name
(``RESTORE_DC_NAME``, default ``dr-<UTC minute>``).  The restore renames the
guest to it and records it as the convergence record's ``dc_hostname``, and
every durable stage follows the recorded name (owner decision 2026-09-30,
aiq TASK-42): the console prompt, the binding's controller FQDN, the probe's
DNS checks, the role's SPN aliases on reconvergence.  Kept workstations whose
Arch side asks DNS SRV first find the new DC; one that names its controller
alone is refused with the reason (ADR 0081).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

if not __package__:  # Direct execution by the Make recipe (PEP 366).
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "homelab.vm"

from .bootstrap_dc import (  # noqa: E402
    CONSOLE_ACCOUNT,
    DEFAULT_PERSISTENT_ROOT,
    DEFAULT_STATE,
    DOMAIN_SID_COMMAND,
    DOMAIN_SID_VALUE,
    NAME,
    PERSISTENT_CONSOLE_TIMEOUT,
    SOCKET_MAC,
    _agent_console_init,
    _console_root,
    _persistent_running,
    _persistent_state,
    _typed_secret,
    ovmf_pair,
    paths,
)
from .controller_image import (  # noqa: E402
    ControllerImageError, assert_installed)
from .credential_custody import (  # noqa: E402
    AGENT,
    OWNER,
    CustodyError,
    OwnerCredentialSource,
    credential_source,
    instance_custody,
    instance_store,
    marker_custody,
    marker_throwaway,
    validate_marker,
    validated_instance_document,
)
from .directory_identity import (  # noqa: E402
    DirectoryIdentityError,
    directory_identity_source,
    durable_directory_identity,
)
from .durable_workstation import (  # noqa: E402
    DurableBinding,
    durable_binding,
)
from .factory_runner import wait_for_switch_port  # noqa: E402
from .persistent_controller_session import (  # noqa: E402
    CUSTODY_CONSOLE_LINE,
    REALM_COMMAND,
    REALM_VALUE,
    PersistentControllerSession,
    PersistentControllerSessionError,
    _finish_session,
    _start_fabric,
    session_command,
)
from .samba_backup_disk import (  # noqa: E402
    BACKUP_PROOF,
    NEW_SERVER_NAME,
    OUTPUT_CAPACITY,
    RESTORE_PROOF,
    BackupDiskError,
    backup_command,
    create_blank,
    device_path,
    new_token,
    read_payload,
    restore_command,
    shred_disk,
    write_image,
)
from .secure_artifacts import atomic_write, private_directory  # noqa: E402
from .signal_cleanup import SignalGuard, terminate_children  # noqa: E402
from .simulated_topology import (  # noqa: E402
    BACKUP_DISK_MODES, BACKUP_INPUT, BACKUP_OUTPUT)
from .simulation_overlay import (  # noqa: E402
    DC_SERVER_NAME,
    DOMAIN_SID,
    PERSISTENT_ACCOUNTS_KEY,
    PERSISTENT_CONVERGENCE_KEY,
    PERSISTENT_MARKER_NAME,
    PERSISTENT_MARKER_SCHEMA,
    PERSISTENT_MODE,
    PERSISTENT_PASSWORD_POLICY_KEY,
    PERSISTENT_PASSWORD_RESETS_KEY,
    PERSISTENT_PROVISIONING_KEY,
    SHA256_HEX,
    PersistentControllerInstance,
    assert_installed_controller_image,
)


#: Backup sets live here (ADR 0081): under the gitignored ``homelab/var``,
#: never in the instance directory, whose destroy refuses unexpected files.
DEFAULT_BACKUP_ROOT = Path("homelab/var/backups")
#: Retained run evidence, beside the probe's.
DEFAULT_BACKUP_EVIDENCE_ROOT = Path("homelab/var/factory/persistent-backup")
DEFAULT_RESTORE_EVIDENCE_ROOT = Path("homelab/var/factory/persistent-restore")
#: Bounds on the in-guest backup and restore commands.  A home domain takes
#: seconds; a restore also waits for ``network-online.target`` on a guest
#: with no network before samba starts.
BACKUP_TIMEOUT = 1800.0
RESTORE_TIMEOUT = 1800.0
#: The backup set's file names.
TARBALL_NAME = "samba-backup.tar.bz2"
MANIFEST_NAME = "manifest.json"
MARKER_COPY_NAME = PERSISTENT_MARKER_NAME
CUSTODY_COPY_NAME = "custody-credentials.json"
OUTPUT_DISK_NAME = "backup-output.raw"
INPUT_DISK_NAME = "backup-input.raw"
MANIFEST_SCHEMA = 1
MANIFEST_KIND = "telos-samba-ad-backup"
RESTORE_CONFIRMATION_PREFIX = "RESTORE"
#: The directory records a restore carries from the backed-up marker.
CARRIED_RECORDS = (
    PERSISTENT_CONVERGENCE_KEY, PERSISTENT_PROVISIONING_KEY,
    PERSISTENT_ACCOUNTS_KEY, PERSISTENT_PASSWORD_POLICY_KEY,
    PERSISTENT_PASSWORD_RESETS_KEY,
)
#: The DC's own NetBIOS name, from the loader samba itself uses.
DC_NAME_COMMAND = (
    "/usr/bin/python3 -c 'from samba.param import LoadParm; "
    "lp = LoadParm(); lp.load_default(); "
    "print(str(lp.get(\"netbios name\") or \"NONE\").upper())' 2>/dev/null "
    "|| echo NONE")
DC_NAME_VALUE = rb"NONE|[A-Z0-9](?:[A-Z0-9-]{0,13}[A-Z0-9])?"
#: ``samba-tool dbcheck`` over every partition; its tail stays in the
#: transcript, and any ERROR line fails it even when the tool exits zero.
DBCHECK_COMMAND = (
    "o=$(/usr/bin/samba-tool dbcheck --cross-ncs 2>&1); c=$?; "
    "/usr/bin/printf '%s' \"$o\" | /usr/bin/tail -n 20 >&2; "
    "[ \"$c\" -eq 0 ] && ! /usr/bin/printf '%s' \"$o\" | "
    "/usr/bin/grep -q ERROR")
#: How many security principals the directory holds, and the SHA-256 of
#: their sorted SIDs: every user, computer and group, except domain
#: controllers, whose accounts a restore replaces by design.  It names no
#: account and carries no SID.
PRINCIPAL_DIGEST_COMMAND = (
    "/usr/bin/python3 -c 'import hashlib; "
    "from samba.param import LoadParm; from samba.auth import system_session; "
    "from samba.samdb import SamDB; from samba.ndr import ndr_unpack; "
    "from samba.dcerpc import security; "
    "lp = LoadParm(); lp.load_default(); "
    "db = SamDB(url=lp.private_path(\"sam.ldb\"), "
    "session_info=system_session(), lp=lp); "
    "res = db.search(base=db.domain_dn(), scope=2, expression="
    "\"(&(objectSid=*)(|(objectClass=user)(objectClass=group))"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))\", "
    "attrs=[\"objectSid\"]); "
    "sids = sorted(str(ndr_unpack(security.dom_sid, m[\"objectSid\"][0])) "
    "for m in res); "
    "print(\"%d:%s\" % (len(sids), "
    "hashlib.sha256(\"\\n\".join(sids).encode()).hexdigest()))' "
    "2>/dev/null || echo NONE")
PRINCIPAL_VALUE = rb"NONE|[0-9]{1,7}:[0-9a-f]{64}"
# The seed masks samba.service until convergence unmasks it, and a restored
# instance is a fresh canonical copy that has never converged: the first live
# drill (2026-10-01) failed "Unit /etc/systemd/system/samba.service is masked".
SAMBA_START_COMMAND = (
    "/usr/bin/systemctl unmask samba.service >&2 && "
    "/usr/bin/systemctl enable --now samba.service >&2")
#: Every boolean a backup must prove before its set is kept.
BACKUP_CHECKS = (
    "fabric_started", "controller_attached", "live_argv_audited",
    "console_login", "ad_service_live", "realm_matches", "domain_sid_matches",
    "dc_name_read", "dbcheck_clean", "backup_written", "clean_poweroff",
    "lock_released", "transcript_secret_free", "disk_verified",
    "backup_set_written", "marker_recorded",
)
#: Every boolean a restore must prove before the marker records it.
RESTORE_CHECKS = (
    "instance_created", "live_argv_audited", "console_login", "restore_ran",
    "ad_service_live", "realm_matches", "domain_sid_matches",
    "principals_match", "clean_poweroff", "lock_released",
    "transcript_secret_free", "marker_recorded",
)


class PersistentBackupError(RuntimeError):
    """A backup or restore cannot proceed safely.  Never carries a value."""


def _say(prefix: str, message: str) -> None:
    print(f"{prefix}: {message}", flush=True)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _run_id() -> str:
    return (datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
            + f"-{os.getpid()}-{secrets.token_hex(4)}")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@contextlib.contextmanager
def _console_timeout(console, seconds: float):
    """A longer bound for one long command; the console's own afterwards."""
    previous = console.timeout
    console.timeout = max(previous, seconds)
    try:
        yield
    finally:
        console.timeout = previous


def _console_text(console, command: str, label: str, value: bytes) -> str:
    raw = _console_root(console, command, label, value=value)
    return "" if raw is None else raw.decode("ascii")


def _prove_directory(console, realm: str, sid: str, checks: dict,
                     label: str) -> None:
    """The live realm and domain SID are exactly *realm* and *sid*.

    Exact, unlike the probe: a backup of a truncated record, or a restore
    that brought back a different directory, is refused, never repaired.
    """
    live_realm = _console_text(
        console, REALM_COMMAND, f"{label}-realm", REALM_VALUE)
    checks["realm_matches"] = live_realm.upper() == realm.upper()
    if not checks["realm_matches"]:
        raise PersistentBackupError(
            "the live directory does not serve the expected realm; values "
            "are not printed")
    live_sid = _console_text(
        console, DOMAIN_SID_COMMAND, f"{label}-domain-sid", DOMAIN_SID_VALUE)
    checks["domain_sid_matches"] = (
        bool(DOMAIN_SID.fullmatch(live_sid)) and live_sid == sid)
    if not checks["domain_sid_matches"]:
        raise PersistentBackupError(
            "the live directory's domain SID is not the expected one; a "
            "truncated recorded SID is repaired by "
            "homelab-factory-persistent-probe REPAIR_SID=1 first. Values "
            "are not printed")


def _shred_tree(directory: Path) -> None:
    """Shred every regular file under *directory*, then remove it."""
    if not directory.exists():
        return
    for path in sorted(directory.rglob("*"), reverse=True):
        if path.is_symlink():
            path.unlink()
        elif path.is_file():
            with contextlib.suppress(OSError):
                shred_disk(path)
            path.unlink(missing_ok=True)
        elif path.is_dir():
            path.rmdir()
    directory.rmdir()


def _write_private(path: Path, data: bytes) -> None:
    atomic_write(path, data)
    path.chmod(0o600)


# -- the backup set ------------------------------------------------------------
@dataclass(frozen=True, repr=False)
class BackupSet:
    """One verified backup set.  ``repr`` names only its directory."""

    path: Path
    manifest: dict
    tarball: bytes
    marker: dict
    custody_document: dict | None

    def __repr__(self) -> str:
        return f"BackupSet({str(self.path)!r})"

    @property
    def instance(self) -> str:
        return self.manifest["instance"]

    @property
    def directory(self) -> dict:
        return self.manifest["directory"]

    @property
    def custody(self) -> str:
        return self.manifest["custody"]["credential_custody"]

    @property
    def throwaway(self) -> bool:
        return self.manifest["custody"]["throwaway"]


def _private_regular(path: Path, label: str) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        raise PersistentBackupError(
            f"the backup set has no readable {label}: {path}") from error
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077):
            raise PersistentBackupError(
                f"the backup set's {label} must be a regular file owned by "
                f"this user, mode 0600: {path}")
        return stream.read()


def _json(data: bytes, label: str) -> dict:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PersistentBackupError(
            f"the backup set's {label} is not JSON") from error
    if not isinstance(value, dict):
        raise PersistentBackupError(
            f"the backup set's {label} is not an object")
    return value


def _file_entry(entry: object, name: str, label: str) -> dict:
    if (not isinstance(entry, dict) or entry.get("name") != name
            or not isinstance(entry.get("sha256"), str)
            or not SHA256_HEX.fullmatch(entry["sha256"])):
        raise PersistentBackupError(
            f"the backup manifest does not describe its {label}")
    return entry


def load_backup_set(path: Path) -> BackupSet:
    """Read and verify one backup set, or refuse it without printing values.

    Every file is regular, owner-only and matches the manifest's SHA-256; the
    marker copy is a persistent marker for the manifest's instance whose
    convergence record states exactly the manifest's realm, DNS domain,
    NetBIOS name and domain SID; and a custody store is present exactly when
    the backed-up instance was a throwaway under agent custody.
    """
    path = Path(path)
    try:
        info = path.lstat()
    except OSError as error:
        raise PersistentBackupError(f"there is no backup set at {path}") \
            from error
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise PersistentBackupError(
            f"a backup set must be a directory owned by this user, mode "
            f"0700: {path}")
    manifest = _json(
        _private_regular(path / MANIFEST_NAME, "manifest"), "manifest")
    if (manifest.get("schema") != MANIFEST_SCHEMA
            or manifest.get("kind") != MANIFEST_KIND):
        raise PersistentBackupError(
            f"{path / MANIFEST_NAME} is not a Telos Samba backup manifest")
    instance = manifest.get("instance")
    if not PersistentControllerInstance.valid_instance_name(instance):
        raise PersistentBackupError("the backup manifest names no instance")
    tar_entry = _file_entry(manifest.get("tarball"), TARBALL_NAME, "tarball")
    tarball = _private_regular(path / TARBALL_NAME, "tarball")
    if (_sha256(tarball) != tar_entry["sha256"]
            or len(tarball) != tar_entry.get("bytes")):
        raise PersistentBackupError(
            "the backup tarball does not match its manifest: the set is "
            "corrupt")
    marker_entry = _file_entry(
        manifest.get("marker"), MARKER_COPY_NAME, "marker copy")
    marker_bytes = _private_regular(path / MARKER_COPY_NAME, "marker copy")
    if _sha256(marker_bytes) != marker_entry["sha256"]:
        raise PersistentBackupError(
            "the backup's marker copy does not match its manifest")
    marker = _json(marker_bytes, "marker copy")
    if (marker.get("schema") != PERSISTENT_MARKER_SCHEMA
            or marker.get("mode") != PERSISTENT_MODE
            or marker.get("instance") != instance):
        raise PersistentBackupError(
            "the backup's marker copy is not the backed-up instance's marker")
    try:
        validate_marker(marker)
    except CustodyError as error:
        raise PersistentBackupError(str(error)) from error
    directory = manifest.get("directory")
    if not isinstance(directory, dict):
        raise PersistentBackupError("the backup manifest names no directory")
    convergence = marker.get(PERSISTENT_CONVERGENCE_KEY)
    if not isinstance(convergence, dict):
        raise PersistentBackupError(
            "the backup's marker copy records no converged directory")
    mismatched = [
        key for key, marker_key in (
            ("realm", "realm"), ("dns_domain", "dns_domain"),
            ("netbios", "netbios"), ("domain_sid", "domain_sid"))
        if directory.get(key) != convergence.get(marker_key)]
    if mismatched or not DOMAIN_SID.fullmatch(
            str(directory.get("domain_sid") or "")):
        raise PersistentBackupError(
            "the backup manifest and its marker copy disagree on "
            + (", ".join(mismatched) or "domain_sid")
            + ": the set is not one directory's. Values are not printed")
    if not DC_SERVER_NAME.fullmatch(str(directory.get("dc_server_name"))):
        raise PersistentBackupError(
            "the backup manifest does not name the backed-up DC")
    principals = directory.get("principals")
    if principals is not None and not (
            isinstance(principals, str)
            and principals.partition(":")[0].isdigit()
            and SHA256_HEX.fullmatch(principals.partition(":")[2])):
        raise PersistentBackupError(
            "the backup manifest's principal digest is malformed")
    custody = manifest.get("custody")
    if not isinstance(custody, dict):
        raise PersistentBackupError("the backup manifest records no custody")
    try:
        recorded = (marker_custody(marker), marker_throwaway(marker))
    except CustodyError as error:
        raise PersistentBackupError(str(error)) from error
    if (custody.get("credential_custody"), custody.get("throwaway")) \
            != recorded:
        raise PersistentBackupError(
            "the backup manifest's custody is not its marker copy's")
    store_path = path / CUSTODY_COPY_NAME
    document = None
    if recorded[0] == AGENT:
        store_entry = _file_entry(
            custody.get("store"), CUSTODY_COPY_NAME, "custody store")
        store_bytes = _private_regular(store_path, "custody store")
        if _sha256(store_bytes) != store_entry["sha256"]:
            raise PersistentBackupError(
                "the backup's custody store does not match its manifest")
        try:
            document = validated_instance_document(
                _json(store_bytes, "custody store"), instance)
        except CustodyError as error:
            raise PersistentBackupError(str(error)) from error
    elif custody.get("store") is not None or os.path.lexists(store_path):
        raise PersistentBackupError(
            "an owner-custody backup holds a custody store; owner custody "
            "never stores a credential, so this set is refused")
    return BackupSet(path, manifest, tarball, marker, document)


# -- backup ------------------------------------------------------------------
def _backup_set_files(
    staging: Path, *, binding: DurableBinding, target, payload: bytes,
    run_id: str, facts: dict,
) -> dict:
    """Write the set into *staging*; returns the manifest written."""
    marker_bytes = target.marker.read_bytes()
    marker = json.loads(marker_bytes.decode("utf-8"))
    custody = marker_custody(marker)
    store_entry = None
    if custody == AGENT:
        document = instance_store(target).read()
        store_bytes = (json.dumps(document, indent=2, sort_keys=True)
                       + "\n").encode("utf-8")
        _write_private(staging / CUSTODY_COPY_NAME, store_bytes)
        store_entry = {"name": CUSTODY_COPY_NAME,
                       "sha256": _sha256(store_bytes)}
    _write_private(staging / TARBALL_NAME, payload)
    _write_private(staging / MARKER_COPY_NAME, marker_bytes)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "kind": MANIFEST_KIND,
        "instance": binding.instance,
        "run_id": run_id,
        "created_utc": _now(),
        "method": "samba-tool domain backup offline",
        "note": (
            "the whole directory, every domain secret included; keep this "
            "set private (0700/0600), never copy it off this host "
            "unencrypted, and restore it only with "
            "make homelab-factory-persistent-restore (ADR 0081)"),
        "tarball": {"name": TARBALL_NAME, "bytes": len(payload),
                    "sha256": _sha256(payload)},
        "marker": {"name": MARKER_COPY_NAME,
                   "sha256": _sha256(marker_bytes)},
        "custody": {"credential_custody": custody,
                    "throwaway": marker_throwaway(marker),
                    "store": store_entry},
        "directory": {
            "realm": binding.kerberos_realm,
            "dns_domain": binding.dns_domain,
            "netbios": binding.netbios_name,
            "domain_sid": binding.domain_sid,
            "dc_server_name": facts["dc_server_name"],
            "principals": facts["principals"],
        },
    }
    _write_private(
        staging / MANIFEST_NAME,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    return manifest


def _passed(checks: dict, required: tuple[str, ...]) -> bool:
    return (all(checks.get(key) is True for key in required)
            and checks.get("terminated_fallback") is False)


def _run_backup(
    binding: DurableBinding, target: PersistentControllerInstance,
    password: bytes, *, canonical_state: Path, backup_root: Path,
    evidence_root: Path,
) -> int:
    run_id = _run_id()
    prefix = "backup"
    evidence_parent = Path(evidence_root).absolute()
    private_directory(evidence_parent, parents=True)
    private_directory(evidence_parent / binding.instance)
    evidence = private_directory(evidence_parent / binding.instance / run_id)
    sets = Path(backup_root).absolute()
    private_directory(sets, parents=True)
    private_directory(sets / binding.instance)
    staging = private_directory(sets / binding.instance / f".staging-{run_id}")
    final = sets / binding.instance / run_id
    disk = staging / OUTPUT_DISK_NAME
    token = new_token()
    switch_log = evidence / "switch.jsonl"
    checks: dict[str, object] = {key: False for key in BACKUP_CHECKS}
    checks.update(terminated_fallback=False, lock_released=True)
    facts: dict[str, object] = {"dc_server_name": None, "principals": None}
    result: dict[str, object] = {
        "schema": 1, "kind": "persistent-backup", "run_id": run_id,
        "instance": binding.instance, "started_utc": _now(),
        "method": "samba-tool domain backup offline", "samba_running": True,
        "backup_set": None, "tarball_sha256": None, "tarball_bytes": None,
        "principals_recorded": False, "checks": checks,
    }
    _say(prefix, f"evidence: {evidence}")
    children: list[subprocess.Popen[bytes]] = []
    session: PersistentControllerSession | None = None
    failure: BaseException | None = None
    transcript: bytes | None = None
    proof = ""
    step = "fabric"

    def attached() -> None:
        wait_for_switch_port(switch_log, "controller", SOCKET_MAC, timeout=60.0)
        checks["controller_attached"] = True

    with SignalGuard():
        try:
            step = "disk"
            create_blank(disk)
            step = "fabric"
            port = _start_fabric(switch_log, evidence / "fabric.log", children)
            checks["fabric_started"] = True
            step = "session"
            session = PersistentControllerSession(
                target, port=port, password=password,
                canonical_state=canonical_state, backup_disk=disk,
                backup_mode=BACKUP_OUTPUT)
            password = b""
            _say(prefix, f"booting {binding.instance} in place with a blank "
                 f"backup disk; waiting up to {PERSISTENT_CONSOLE_TIMEOUT:g}s "
                 "for its login prompt")
            console = session.start(attached=attached)
            checks["live_argv_audited"] = bool(
                session.facts["live_argv_audited"])
            checks["console_login"] = checks["ad_service_live"] = True
            _say(prefix, "logged in; samba is live")
            step = "directory"
            _prove_directory(console, binding.kerberos_realm,
                             binding.domain_sid, checks, "backup")
            _say(prefix, "realm and domain SID are the bound directory's")
            step = "dc-name"
            name = _console_text(
                console, DC_NAME_COMMAND, "backup-dc-name", DC_NAME_VALUE)
            if not DC_SERVER_NAME.fullmatch(name) or name == "NONE":
                raise PersistentBackupError(
                    "the directory's own DC name could not be read")
            facts["dc_server_name"] = name
            checks["dc_name_read"] = True
            step = "dbcheck"
            with _console_timeout(console, BACKUP_TIMEOUT):
                _console_root(console, DBCHECK_COMMAND, "backup-dbcheck")
            checks["dbcheck_clean"] = True
            _say(prefix, "samba-tool dbcheck --cross-ncs is clean")
            step = "principals"
            digest = _console_text(
                console, PRINCIPAL_DIGEST_COMMAND, "backup-principals",
                PRINCIPAL_VALUE)
            facts["principals"] = None if digest == "NONE" else digest
            result["principals_recorded"] = facts["principals"] is not None
            step = "backup"
            serial = BACKUP_DISK_MODES[BACKUP_OUTPUT][0]
            with _console_timeout(console, BACKUP_TIMEOUT):
                proof = _console_text(
                    console, backup_command(
                        device_path(serial), token,
                        capacity=OUTPUT_CAPACITY),
                    "backup-write", BACKUP_PROOF)
            if proof.startswith("FAIL:"):
                raise PersistentBackupError(
                    f"the in-guest backup failed at {proof[5:]}")
            checks["backup_written"] = True
            _say(prefix, f"backup written and read back in the guest: "
                 f"sha256 {proof.partition(':')[0]}")
            step = "poweroff"
            session.stop()
        except BaseException as error:  # noqa: BLE001 - evidence still lands
            failure = error
        finally:
            password = b""
            if session is not None:
                transcript, stopped = _finish_session(session, checks, [])
                failure = failure or stopped
            problems = terminate_children(
                children, terminate_timeout=10.0, kill_timeout=2.0)
            if problems and failure is None:
                failure = PersistentBackupError("; ".join(problems))
        checks["transcript_secret_free"] = transcript is not None
        if failure is None and _passed(
                checks, BACKUP_CHECKS[:BACKUP_CHECKS.index("disk_verified")]):
            try:
                step = "verify-disk"
                payload, header = read_payload(disk, token=token)
                if f"{header.sha256}:{header.length}" != proof:
                    raise PersistentBackupError(
                        "the tarball on the backup disk is not the one the "
                        "guest proved")
                checks["disk_verified"] = True
                step = "backup-set"
                manifest = _backup_set_files(
                    staging, binding=binding, target=target, payload=payload,
                    run_id=run_id, facts=facts)
                payload = b""
                shred_disk(disk)
                staging.rename(final)
                checks["backup_set_written"] = True
                result.update(backup_set=str(final),
                              tarball_sha256=header.sha256,
                              tarball_bytes=header.length)
                step = "marker"
                target.record_last_backup({
                    "utc": manifest["created_utc"], "path": str(final),
                    "sha256": header.sha256, "run_id": run_id})
                checks["marker_recorded"] = True
            except (BackupDiskError, PersistentBackupError, CustodyError,
                    RuntimeError, OSError, ValueError) as error:
                failure = error
        if failure is None and not _passed(checks, BACKUP_CHECKS):
            failure = PersistentBackupError(
                "the run did not prove: " + ", ".join(
                    key for key in BACKUP_CHECKS
                    if checks.get(key) is not True))
        passed = failure is None
        if not checks["backup_set_written"]:
            # Nothing of a failed run is kept: the disk and any partial set
            # hold the whole directory's secrets.
            with contextlib.suppress(OSError):
                _shred_tree(staging)
        result["verdict"] = "pass" if passed else "fail"
        result["finished_utc"] = _now()
        if failure is not None:
            result["failure"] = {"step": step, "type": type(failure).__name__}
        if transcript is not None:
            atomic_write(evidence / "console-transcript.log", transcript)
        atomic_write(
            evidence / "result.json",
            (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    if failure is not None:
        print(f"error: the backup failed at {step}: {failure}",
              file=sys.stderr)
        if checks["backup_set_written"] and not checks["marker_recorded"]:
            print(f"error: the backup set {final} was written and verified, "
                  f"but {binding.instance}'s marker could not record it",
                  file=sys.stderr)
    if passed:
        print(f"{binding.instance}: backup set {final} (tarball sha256 "
              f"{result['tarball_sha256']}); recorded as last_backup")
    print(f"{binding.instance}: backup {'PASS' if passed else 'FAIL'}; "
          f"evidence {evidence}")
    return 0 if passed else 2


def _console_plan_line(target) -> str:
    if instance_custody(target) == AGENT:
        return CUSTODY_CONSOLE_LINE
    return (f"console: this asks at your terminal for the {CONSOLE_ACCOUNT} "
            "password once, before anything starts; it is held in memory "
            "only and never written to a file, argv, the environment or the "
            "evidence")


def backup(
    root: Path,
    instance: str,
    apply: bool,
    *,
    canonical_state: Path = DEFAULT_STATE,
    identity_path: Path | None = None,
    overlay_path: Path | None = None,
    backup_root: Path = DEFAULT_BACKUP_ROOT,
    evidence_root: Path = DEFAULT_BACKUP_EVIDENCE_ROOT,
) -> int:
    """Plan, or take, one Samba backup of a persistent instance."""
    try:
        binding = durable_binding(
            root, instance, canonical_state=canonical_state,
            identity_path=identity_path, overlay_path=overlay_path)
        target = PersistentControllerInstance(binding.state, instance=instance)
        sets = Path(backup_root).absolute()
        preview_disk = sets / instance / ".staging-<run id>" / OUTPUT_DISK_NAME
        preview = session_command(
            target, 65535, canonical_state=canonical_state,
            backup_disk=preview_disk, backup_mode=BACKUP_OUTPUT)
        console_line = _console_plan_line(target)
        last = target.last_backup()
    except (RuntimeError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    serial = BACKUP_DISK_MODES[BACKUP_OUTPUT][0]
    print(f"persistent directory backup: {instance}")
    print(f"state: {binding.state}")
    print(f"binding: the convergence record agrees with "
          f"{binding.identity_source}; the declared Controller address, "
          "prefix and gateway are the per-run fabric's; the staged roster "
          "fingerprint is current (values are compared, not printed)")
    print("last backup: " + (f"{last['utc']} at {last['path']}" if last
                             else "none recorded"))
    print("method: samba-tool domain backup offline, run as root inside the "
          "instance with samba running, as Samba documents (ADR 0081); "
          "never a disk image")
    print(f"backup disk: one blank sparse raw disk this run creates "
          f"({OUTPUT_CAPACITY // (1024 * 1024)} MiB, virtio-blk serial "
          f"{serial}, not bootable), the only device beyond the instance's "
          "own; the tarball crosses it behind a header of its length and "
          "SHA-256, and the disk is shredded afterwards")
    print("steps: log in; prove samba live; prove the realm and domain SID "
          "are the bound directory's; read the DC's name; samba-tool dbcheck "
          "--cross-ncs; digest every principal's SID; samba-tool domain "
          "backup offline; write and read back the disk; power off over the "
          "console; verify the tarball host-side")
    print(f"backup set: {sets / instance}/<run id>/ ({TARBALL_NAME}, "
          f"{MANIFEST_NAME}, {MARKER_COPY_NAME}"
          + (f", {CUSTODY_COPY_NAME}" if instance_custody(target) == AGENT
             else "")
          + "; 0700 directories, 0600 files). It holds every domain secret")
    print(console_line)
    print(f"evidence: {Path(evidence_root) / instance}/<run id>/ "
          "(console-transcript.log, redacted; switch.jsonl; fabric.log; "
          "result.json of secret-free facts)")
    print(" ".join(preview).replace(
        "127.0.0.1:65535", "127.0.0.1:<per-run port>"))
    if not apply:
        print("dry run; repeat with APPLY=1")
        return 0

    problems = [f"{tool} is not installed" for tool in ("qemu-system-x86_64",)
                if not shutil.which(tool)]
    if ovmf_pair() is None:
        problems.append("OVMF firmware was not found")
    if _persistent_running(target) is not False:
        problems.append(f"{instance} is already running or its lock cannot "
                        "be probed; a backup boots it, so power it off first")
    if not problems:
        try:
            assert_installed(
                target.disk, subject=f"the persistent instance disk "
                f"{target.disk}", remedy="Recreate and converge the instance.")
        except ControllerImageError as error:
            problems.append(str(error))
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    try:
        password = credential_source(target, prompt=_typed_secret).console(
            f"{CONSOLE_ACCOUNT} console password: ")
    except (ValueError, RuntimeError, EOFError, KeyboardInterrupt) as error:
        print(f"error: {error or type(error).__name__}", file=sys.stderr)
        return 2
    try:
        return _run_backup(
            binding, target, password, canonical_state=canonical_state,
            backup_root=backup_root, evidence_root=evidence_root)
    except (PersistentControllerSessionError, BackupDiskError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    finally:
        password = b""


# -- restore ------------------------------------------------------------------
def default_restore_dc_name(now: datetime | None = None) -> str:
    """A DC name the domain never held: ``dr-`` and the UTC minute."""
    return f"dr-{(now or datetime.now(UTC)):%y%m%d%H%M}"


def _restore_dc_name(requested: str | None, backup_set: BackupSet) -> str:
    name = requested or default_restore_dc_name()
    if not NEW_SERVER_NAME.fullmatch(name):
        raise PersistentBackupError(
            "RESTORE_DC_NAME must be 1-15 lowercase letters, digits or "
            "hyphens, starting with a letter and not ending with a hyphen")
    if name.upper() == backup_set.directory["dc_server_name"].upper():
        raise PersistentBackupError(
            f"RESTORE_DC_NAME {name} is the backed-up DC's own name. Samba "
            "restores a DC only under a name the domain never held: its "
            "restore adds the new DC's objects while the backed-up DC's "
            "still exist, and that name fails with 'already exists' "
            "(ADR 0081)")
    # Every persistent directory began with the canonical image's DC, and a
    # restored one also replaced the DC its own backup named: Samba's
    # documentation asks for a name that never existed in the domain.
    held = {NAME.upper()}
    restored = backup_set.marker.get("restored")
    if isinstance(restored, dict) and isinstance(
            restored.get("replaced_dc_server_name"), str):
        held.add(restored["replaced_dc_server_name"].upper())
    if name.upper() in held:
        raise PersistentBackupError(
            f"RESTORE_DC_NAME {name} is a DC name this domain has already "
            "held; Samba documents that a restored DC must take a name that "
            "never existed in the domain (ADR 0081)")
    return name


def _create_instance(
    target: PersistentControllerInstance, canonical: dict[str, Path],
    backup_set: BackupSet,
) -> dict:
    """Seed the instance from the canonical image under the backup's custody."""
    if backup_set.custody == AGENT:
        init = _agent_console_init()
        return target.create(
            canonical["disk"], canonical["vars"], custody=AGENT,
            throwaway=True, initialize=init.initializer(
                str(target.instance),
                forbidden=(canonical["disk"], canonical["vars"])))
    if backup_set.throwaway:
        return target.create(canonical["disk"], canonical["vars"],
                             custody=OWNER, throwaway=True)
    return target.create(canonical["disk"], canonical["vars"])


def _carry_custody(target: PersistentControllerInstance,
                   backup_set: BackupSet) -> None:
    """The directory's own credentials, back into the new custody store.

    The new store keeps the console credential its creation set, because
    that is the new disk's ``local-rescue`` password; the domain
    Administrator and every staged account come from the backup, because
    their passwords are in the restored directory and nowhere else.
    """
    document = backup_set.custody_document or {}

    def carry(store: dict) -> None:
        store["administrator"] = document.get("administrator")
        store["accounts"] = json.loads(json.dumps(
            document.get("accounts", {})))
    instance_store(target).update(carry)


def _carried_records(backup_set: BackupSet, dc_name: str) -> dict:
    """The backed-up marker's directory records, under the restored DC name.

    The convergence record keeps its realm, NetBIOS name, DNS domain and
    domain SID, and records the DC the directory now runs as
    ``dc_hostname`` (TASK-42).
    """
    records = {key: json.loads(json.dumps(backup_set.marker[key]))
               for key in CARRIED_RECORDS
               if backup_set.marker.get(key) is not None}
    records[PERSISTENT_CONVERGENCE_KEY]["dc_hostname"] = dc_name
    return records


def _run_restore(
    target: PersistentControllerInstance, backup_set: BackupSet,
    password: bytes | None, *, canonical_state: Path, dc_name: str,
    evidence_root: Path,
) -> int:
    run_id = _run_id()
    prefix = "restore"
    instance = str(target.instance)
    parent = Path(evidence_root).absolute()
    private_directory(parent, parents=True)
    private_directory(parent / instance)
    evidence = private_directory(parent / instance / run_id)
    staging = private_directory(parent / instance / f".input-{run_id}")
    directory = backup_set.directory
    checks: dict[str, object] = {key: False for key in RESTORE_CHECKS}
    checks.update(terminated_fallback=False, lock_released=True,
                  principals="not-compared")
    result: dict[str, object] = {
        "schema": 1, "kind": "persistent-restore", "run_id": run_id,
        "instance": instance, "started_utc": _now(),
        "method": "samba-tool domain backup restore",
        "backup_set": str(backup_set.path),
        "backup_sha256": backup_set.manifest["tarball"]["sha256"],
        "source_instance": backup_set.instance,
        "dc_server_name": dc_name,
        "replaced_dc_server_name": directory["dc_server_name"],
        "custody": backup_set.custody, "network": "none",
        "checks": checks,
    }
    _say(prefix, f"evidence: {evidence}")
    session: PersistentControllerSession | None = None
    failure: BaseException | None = None
    transcript: bytes | None = None
    step = "create"
    created = False
    try:
        with SignalGuard():
            try:
                marker = _create_instance(
                    target, paths(canonical_state), backup_set)
                created = True
                checks["instance_created"] = True
                _say(prefix, f"created {instance} from "
                     f"{marker['seeded_from']['disk_sha256']}")
                if backup_set.custody == AGENT:
                    step = "custody"
                    _carry_custody(target, backup_set)
                    password = credential_source(
                        target, prompt=_typed_secret).console()
                    _say(prefix, "the directory's credentials are back in "
                         "the new custody store; the console credential is "
                         "the one creation set")
                step = "input-disk"
                header = write_image(
                    staging / INPUT_DISK_NAME, backup_set.tarball,
                    new_token())
                step = "session"
                session = PersistentControllerSession(
                    target, port=65535, password=password or b"",
                    canonical_state=canonical_state,
                    backup_disk=staging / INPUT_DISK_NAME,
                    backup_mode=BACKUP_INPUT)
                password = None
                _say(prefix, f"booting {instance} in place with no network "
                     "and the backup disk read-only; waiting up to "
                     f"{PERSISTENT_CONSOLE_TIMEOUT:g}s for its login prompt")
                console = session.start(require_ad=False)
                checks["live_argv_audited"] = bool(
                    session.facts["live_argv_audited"])
                checks["console_login"] = True
                step = "restore"
                serial = BACKUP_DISK_MODES[BACKUP_INPUT][0]
                with _console_timeout(console, RESTORE_TIMEOUT):
                    proof = _console_text(
                        console, restore_command(
                            device_path(serial), header, dc_name),
                        "restore-run", RESTORE_PROOF)
                if proof != "RESTORED":
                    raise PersistentBackupError(
                        "the in-guest restore failed at "
                        f"{proof[5:] or 'an unknown step'}")
                checks["restore_ran"] = True
                _say(prefix, f"samba-tool domain backup restore finished as "
                     f"DC {dc_name}")
                step = "samba"
                with _console_timeout(console, RESTORE_TIMEOUT):
                    _console_root(console, SAMBA_START_COMMAND,
                                  "restore-samba-start")
                console._wait_controller_ad()
                checks["ad_service_live"] = True
                step = "directory"
                _prove_directory(console, directory["realm"],
                                 directory["domain_sid"], checks, "restore")
                _say(prefix, "realm and domain SID are the backup's")
                step = "principals"
                if directory.get("principals") is None:
                    checks["principals_match"] = True
                    checks["principals"] = "not-recorded"
                else:
                    live = _console_text(
                        console, PRINCIPAL_DIGEST_COMMAND,
                        "restore-principals", PRINCIPAL_VALUE)
                    checks["principals_match"] = (
                        live == directory["principals"])
                    checks["principals"] = (
                        "match" if checks["principals_match"] else "mismatch")
                    if not checks["principals_match"]:
                        raise PersistentBackupError(
                            "the restored directory's security principals "
                            "are not the backup's")
                step = "poweroff"
                session.stop()
            except BaseException as error:  # noqa: BLE001 - evidence lands
                failure = error
            finally:
                password = None
                if session is not None:
                    transcript, stopped = _finish_session(session, checks, [])
                    failure = failure or stopped
            checks["transcript_secret_free"] = transcript is not None
            if failure is None and _passed(
                    checks, RESTORE_CHECKS[:RESTORE_CHECKS.index(
                        "marker_recorded")]):
                try:
                    step = "marker"
                    target.record_restoration(
                        _carried_records(backup_set, dc_name), {
                        "utc": _now(), "run_id": run_id,
                        "backup_path": str(backup_set.path),
                        "backup_sha256":
                            backup_set.manifest["tarball"]["sha256"],
                        "backup_created_utc": str(
                            backup_set.manifest.get("created_utc") or "?"),
                        "source_instance": backup_set.instance,
                        "dc_server_name": dc_name,
                        "replaced_dc_server_name":
                            directory["dc_server_name"],
                    })
                    checks["marker_recorded"] = True
                except (RuntimeError, OSError, ValueError) as error:
                    failure = error
            if failure is None and not _passed(checks, RESTORE_CHECKS):
                failure = PersistentBackupError(
                    "the run did not prove: " + ", ".join(
                        key for key in RESTORE_CHECKS
                        if checks.get(key) is not True))
    finally:
        with contextlib.suppress(OSError):
            _shred_tree(staging)
    passed = failure is None
    result["verdict"] = "pass" if passed else "fail"
    result["finished_utc"] = _now()
    if failure is not None:
        result["failure"] = {"step": step, "type": type(failure).__name__}
    if transcript is not None:
        atomic_write(evidence / "console-transcript.log", transcript)
    atomic_write(
        evidence / "result.json",
        (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    if failure is not None:
        print(f"error: the restore failed at {step}: {failure}",
              file=sys.stderr)
        if created:
            print(f"error: {instance} was created but its marker records no "
                  "restored directory, and every durable stage refuses it. "
                  f"Destroy it (make homelab-factory-persistent-destroy "
                  f"PERSISTENT_DC={instance} APPLY=1 CONFIRM='DESTROY "
                  f"{instance}') before restoring again", file=sys.stderr)
    else:
        print(f"{instance}: restored {backup_set.instance}'s directory from "
              f"{backup_set.path} as DC {dc_name}; realm, domain SID and "
              "principals are the backup's, and the guest is now named "
              f"{dc_name}")
        print(f"{instance}: it has no network yet. Next: make "
              f"homelab-factory-persistent-converge PERSISTENT_DC={instance} "
              f"APPLY=1 RECONVERGE=1 (convergence lays down the network and "
              f"the DC's name; provisioning is skipped because a directory "
              f"exists), then homelab-factory-persistent-probe")
    print(f"{instance}: restore {'PASS' if passed else 'FAIL'}; evidence "
          f"{evidence}")
    return 0 if passed else 2


def restore(
    root: Path,
    instance: str,
    backup_path: Path,
    apply: bool,
    *,
    confirm: str | None = None,
    dc_name: str | None = None,
    canonical_state: Path = DEFAULT_STATE,
    identity_path: Path | None = None,
    evidence_root: Path = DEFAULT_RESTORE_EVIDENCE_ROOT,
) -> int:
    """Plan, or run, one Samba restore into a freshly created instance."""
    try:
        state = _persistent_state(root, instance)
        target = PersistentControllerInstance(state, instance=instance)
        canonical = paths(canonical_state)
        target.assert_separate(canonical["disk"])
        backup_set = load_backup_set(Path(backup_path))
        name = _restore_dc_name(dc_name, backup_set)
        identity = durable_directory_identity(identity_path)
    except (PersistentBackupError, DirectoryIdentityError, RuntimeError,
            OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    directory = backup_set.directory
    source = directory_identity_source(identity.source)
    disagreeing = [
        key for key, declared in (
            ("realm", identity.kerberos_realm),
            ("dns_domain", identity.dns_domain),
            ("netbios", identity.netbios_name))
        if directory.get(key) != declared]
    if disagreeing:
        print(f"error: the backup's directory disagrees with {source} on "
              f"{', '.join(disagreeing)}: it is not the domain the overlay "
              "declares. Values are not printed", file=sys.stderr)
        return 2
    if identity.hostname != NAME:
        print(f"error: {source} names a bootstrap controller whose host name "
              f"is not {NAME!r}; the persistent console protocol matches on "
              "it", file=sys.stderr)
        return 2
    existing = state.exists() and (not state.is_dir() or any(state.iterdir()))
    agent = backup_set.custody == AGENT
    print(f"persistent directory restore: {instance}")
    print(f"state: {state}")
    print(f"backup set: {backup_set.path} (instance {backup_set.instance}, "
          f"taken {backup_set.manifest.get('created_utc')}, tarball sha256 "
          f"{backup_set.manifest['tarball']['sha256']}); it verifies, and "
          f"its realm, DNS domain and NetBIOS name agree with {source} "
          "(values are compared, not printed)")
    print("scenario: " + (
        "disaster recovery into the lost instance's own name"
        if instance == backup_set.instance else
        f"a restore drill into a separate instance; {backup_set.instance} "
        "is not touched. Destroy the drill instance afterwards"))
    print(f"instance: {'EXISTS' if existing else 'absent'}; it is created "
          "from the canonical image "
          f"{canonical['disk']} (read-only, under the strict fence), never "
          "from a disk image of the backed-up DC (ADR 0067)")
    print("credential custody: " + (
        "agent (throwaway), as the backup records; creation sets a new "
        f"{CONSOLE_ACCOUNT} password in a new custody store, and the domain "
        "Administrator's and every staged account's passwords come back "
        "from the backup's copy of the store" if agent else
        "owner" + (" (throwaway)" if backup_set.throwaway else "")
        + f", as the backup records; the {CONSOLE_ACCOUNT} password is the "
        "canonical image's, typed at this terminal once before anything "
        "is created; the directory's own passwords come back with it"))
    print(f"DC name: {name}. Samba restores a DC only under a name the domain "
          f"never held, so it is not the backed-up "
          f"{directory['dc_server_name']}; the guest is renamed to it and the "
          "marker records it, and every durable stage follows the recorded "
          "name (TASK-42). Kept workstations whose Arch side asks SRV first "
          "find it; one that names its controller alone is refused")
    print("steps: create the instance; boot it in place with NO network "
          "device and the backup disk read-only; verify the disk's header "
          "and SHA-256 in the guest; move the package's empty /var/lib/samba "
          "aside; samba-tool domain backup restore --newservername="
          f"{name} --targetdir=/var/lib/samba; install its smb.conf as "
          f"/etc/samba/smb.conf; name the guest {name}; enable and start "
          "samba; prove the realm, the domain SID and the principal digest "
          "are the backup's; power off over the console; record the backup's "
          "directory records under the new DC name and the restore in the "
          "new marker. Then reconverge (RECONVERGE=1) for the network")
    print(f"evidence: {Path(evidence_root) / instance}/<run id>/ "
          "(console-transcript.log, redacted; result.json of secret-free "
          "facts)")
    expected = f"{RESTORE_CONFIRMATION_PREFIX} {instance}"
    if existing:
        print(f"error: {instance} exists and is not destroyed. A restore only "
              f"fills a freshly created instance: destroy it first with make "
              f"homelab-factory-persistent-destroy PERSISTENT_DC={instance} "
              f"APPLY=1 CONFIRM='DESTROY {instance}'", file=sys.stderr)
        return 2
    if not apply:
        print(f"dry run; repeat with APPLY=1 CONFIRM='{expected}'")
        return 0

    if confirm != expected:
        print(f"error: refusing to create a directory server from a backup; "
              f"pass the exact confirmation: {expected}", file=sys.stderr)
        return 2
    tools = ("qemu-system-x86_64", "qemu-img") + (
        tuple(_agent_console_init().REQUIRED_TOOLS) if agent else ())
    problems = [f"{tool} is not installed" for tool in dict.fromkeys(tools)
                if not shutil.which(tool)]
    if ovmf_pair() is None:
        problems.append("OVMF firmware was not found")
    for key in ("disk", "vars"):
        if not canonical[key].is_file() or canonical[key].is_symlink():
            problems.append(f"{canonical[key]} is missing")
    if not problems:
        try:
            assert_installed_controller_image(
                canonical["disk"],
                subject=f"the canonical image {canonical['disk']}")
        except ControllerImageError as error:
            problems.append(str(error))
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    password: bytes | None = None
    if not agent:
        try:
            password = OwnerCredentialSource(_typed_secret).console(
                f"{CONSOLE_ACCOUNT} console password (the canonical "
                "image's): ")
        except (ValueError, RuntimeError, EOFError, KeyboardInterrupt) \
                as error:
            print(f"error: {error or type(error).__name__}", file=sys.stderr)
            return 2
    try:
        return _run_restore(
            target, backup_set, password, canonical_state=canonical_state,
            dc_name=name, evidence_root=evidence_root)
    except (PersistentControllerSessionError, BackupDiskError,
            CustodyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    finally:
        password = None


# -- the command line -----------------------------------------------------------
def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Back up a persistent Controller instance's directory "
                    "with Samba, or restore one into a new instance (ADR "
                    "0081); a dry run unless --apply")
    result.add_argument(
        "--state-dir", type=Path, default=DEFAULT_STATE,
        help="the disposable acceptance canonical: the seed of a restored "
             "instance, and refused as a persistent target")
    commands = result.add_subparsers(dest="command", required=True)
    for name in ("backup", "restore"):
        sub = commands.add_parser(name)
        sub.add_argument("--instance", required=True)
        sub.add_argument(
            "--persistent-root", type=Path, default=DEFAULT_PERSISTENT_ROOT)
        sub.add_argument(
            "--directory-identity", type=Path, default=None,
            help="the permanent directory identity instead of "
                 "homelab/instance/identity/directory.json")
        sub.add_argument("--apply", action="store_true")
        if name == "backup":
            sub.add_argument(
                "--identity-overlay", type=Path, default=None,
                help="the durable roster instead of "
                     "homelab/instance/identity/principals.json")
            sub.add_argument(
                "--backup-root", type=Path, default=DEFAULT_BACKUP_ROOT)
            sub.add_argument(
                "--evidence-root", type=Path,
                default=DEFAULT_BACKUP_EVIDENCE_ROOT)
        else:
            sub.add_argument("--backup", type=Path, required=True,
                             help="one backup set directory")
            sub.add_argument(
                "--restore-dc-name", default=None,
                help="the restored DC's name; never the backed-up DC's")
            sub.add_argument(
                "--confirm",
                help="required with --apply: 'RESTORE <instance>'")
            sub.add_argument(
                "--evidence-root", type=Path,
                default=DEFAULT_RESTORE_EVIDENCE_ROOT)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "backup":
        return backup(
            args.persistent_root, args.instance, args.apply,
            canonical_state=args.state_dir,
            identity_path=args.directory_identity,
            overlay_path=args.identity_overlay,
            backup_root=args.backup_root, evidence_root=args.evidence_root)
    return restore(
        args.persistent_root, args.instance, args.backup, args.apply,
        confirm=args.confirm, dc_name=args.restore_dc_name,
        canonical_state=args.state_dir,
        identity_path=args.directory_identity,
        evidence_root=args.evidence_root)


if __name__ == "__main__":
    raise SystemExit(main())
