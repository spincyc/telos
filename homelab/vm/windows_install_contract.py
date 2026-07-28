"""Fail-closed contract for a disposable Windows-first QEMU installation."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
from typing import Any
from xml.sax.saxutils import escape

from homelab.workstations.layout import GIB, build_record
from homelab.vm.simulated_topology import MACS, _base, audit_qemu_argv


MIN_DISK_BYTES = 256 * GIB
SAFE_SERIAL = re.compile(r"[A-Z0-9][A-Z0-9._-]{7,31}")
RUN_ROOT = Path("homelab/var/factory/windows-runs")
PRIVATE_INPUT_NAMES = frozenset({
    "boot.ipxe", "install.bat", "winpeshl.ini", "windows-layout.txt",
    "Autounattend.xml", "install-password.txt",
})


class WindowsInstallContractError(RuntimeError):
    """The proposed run cannot prove a narrow disposable-disk boundary."""


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def inspect_qcow2(path: Path) -> dict[str, Any]:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise WindowsInstallContractError(
            "workstation disk must be a regular non-symlink file")
    result = subprocess.run(
        ["qemu-img", "info", "--output=json", str(path)],
        check=True, capture_output=True, text=True)
    try:
        info = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise WindowsInstallContractError(
            "qemu-img returned invalid disk metadata") from error
    if info.get("format") != "qcow2" or info.get("backing-filename"):
        raise WindowsInstallContractError(
            "workstation disk must be standalone qcow2")
    virtual_size = info.get("virtual-size")
    if not isinstance(virtual_size, int) or virtual_size < MIN_DISK_BYTES:
        raise WindowsInstallContractError(
            "workstation disk is below the 256 GiB disposable minimum")
    return {
        "path": str(path.resolve()),
        "virtual_size": virtual_size,
        "format": "qcow2",
        "sha256": sha256(path),
    }


def audit_qemu_disk_boundary(
    command: list[str], *, disk: Path, serial: str,
) -> None:
    if not SAFE_SERIAL.fullmatch(serial):
        raise WindowsInstallContractError(
            "synthetic disk serial is not safely representable")
    expected = str(Path(disk).resolve())
    writable = []
    joined = " ".join(command)
    for index, argument in enumerate(command):
        if argument != "-drive" or index + 1 >= len(command):
            continue
        drive = command[index + 1]
        fields = dict(
            item.split("=", 1) for item in drive.split(",") if "=" in item)
        if (
            fields.get("media") == "cdrom"
            or fields.get("readonly") == "on"
            or fields.get("if") == "pflash"
        ):
            continue
        writable.append(fields)
    if len(writable) != 1:
        raise WindowsInstallContractError(
            "QEMU must expose exactly one writable disk")
    exposed = writable[0].get("file")
    if exposed is None or str(Path(exposed).resolve()) != expected:
        raise WindowsInstallContractError(
            "QEMU writable disk differs from the authorized disk")
    if f"serial={serial}" not in joined:
        raise WindowsInstallContractError(
            "QEMU disk does not expose the authorized synthetic serial")


def qemu_install_command(
    *,
    disk: Path,
    variables: Path,
    qmp_socket: Path,
    switch_port: int,
    serial: str,
) -> list[str]:
    """Build the persistent UEFI/NVMe/e1000e Windows installation command."""
    if not 1 <= switch_port <= 65535:
        raise WindowsInstallContractError("switch port is invalid")
    if Path(variables).is_symlink():
        raise WindowsInstallContractError(
            "OVMF variables must not be a symlink")
    command = _base("windows-install", variables, 8192)
    command[command.index("-serial") + 1] = "stdio"
    command += [
        "-monitor", "none",
        "-qmp", f"unix:{Path(qmp_socket).resolve()},server=on,wait=off",
        "-device", "VGA",
        "-drive",
        (
            "if=none,id=osdisk,format=qcow2,cache=none,"
            f"file={Path(disk).resolve()}"
        ),
        "-device", f"nvme,drive=osdisk,serial={serial},bootindex=2",
        "-netdev",
        f"socket,id=factory,connect=127.0.0.1:{switch_port}",
        "-device",
        f"e1000e,netdev=factory,mac={MACS['client']},bootindex=1",
    ]
    audit_qemu_argv("client", command, allowed_nic_models=("e1000e",))
    audit_qemu_disk_boundary(command, disk=disk, serial=serial)
    return command


@dataclass(frozen=True)
class Authorization:
    schema: int
    release_version: str
    release_manifest_sha256: str
    disk: dict[str, Any]
    disk_serial: str
    layout: dict[str, Any]
    qemu_argv_sha256: str


@dataclass(frozen=True)
class SyntheticIdentity:
    computer_name: str
    local_user: str
    local_password: str
    install_user: str
    install_password: str


def _partition_sizes(authorization: Authorization) -> dict[str, int]:
    try:
        partitions = authorization.layout["layout"]["partitions"]
        return {item["type"]: item["size_mib"] for item in partitions}
    except (KeyError, TypeError) as error:
        raise WindowsInstallContractError(
            "authorization layout has no partition sizes") from error


def render_diskpart(authorization: Authorization) -> str:
    """Render Windows-first GPT with an explicit unallocated Arch extent."""
    sizes = _partition_sizes(authorization)
    required = {
        "esp", "msr", "basic-data", "linux-root", "windows-recovery"}
    if set(sizes) != required:
        raise WindowsInstallContractError(
            "authorization layout has unexpected partition roles")
    recovery_start_kib = (
        1 + sizes["esp"] + sizes["msr"]
        + sizes["basic-data"] + sizes["linux-root"]
    ) * 1024
    return "\r\n".join((
        "select disk 0",
        "clean",
        "convert gpt",
        f"create partition efi size={sizes['esp']}",
        'format quick fs=fat32 label="SYSTEM"',
        "assign letter=S",
        f"create partition msr size={sizes['msr']}",
        f"create partition primary size={sizes['basic-data']}",
        'format quick fs=ntfs label="Windows"',
        "assign letter=W",
        "rem Leave the exact planned Arch extent unallocated.",
        f"create partition primary offset={recovery_start_kib} "
        f"size={sizes['windows-recovery']}",
        'format quick fs=ntfs label="Recovery"',
        "set id=de94bba4-06d1-4d40-a16a-bfd50179d6ac",
        "gpt attributes=0x8000000000000001",
        "exit",
        "",
    ))


def render_startup(
    authorization: Authorization, *, install_source_unc: str,
    install_user: str,
) -> str:
    """Render capacity checks around the only destructive diskpart call."""
    if not re.fullmatch(r"\\\\[A-Za-z0-9.-]+\\[A-Za-z0-9$_.-]+",
                        install_source_unc):
        raise WindowsInstallContractError("install source UNC is unsafe")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\\[A-Za-z0-9_.-]+", install_user):
        raise WindowsInstallContractError("install user is unsafe")
    gib = authorization.disk["virtual_size"] // GIB
    if authorization.disk["virtual_size"] != gib * GIB:
        raise WindowsInstallContractError(
            "WinPE capacity boundary requires a whole-GiB disk")
    # The password is read interactively by `net use *`; it is never placed in
    # this file, a process argument, or retained evidence.
    check = (
        'set "disk_count=0"\r\n'
        'for /f "tokens=2,4,5" %%A in ('
        "'findstr /R /C:\"^  Disk [0-9][0-9]* *Online\" X:\\\\disk-list.txt'"
        ') do (\r\n'
        "  set /a disk_count+=1\r\n"
        '  set "disk_number=%%A"\r\n'
        '  set "disk_size=%%B"\r\n'
        '  set "disk_unit=%%C"\r\n'
        ")\r\n"
        'if not "!disk_count!"=="1" exit /b 20\r\n'
        'if not "!disk_number!"=="0" exit /b 21\r\n'
        f'if not "!disk_size! !disk_unit!"=="{gib} GB" exit /b 22\r\n'
    )
    return (
        "@echo off\r\nsetlocal EnableExtensions EnableDelayedExpansion\r\n"
        "wpeinit || exit /b 10\r\n"
        '(echo list disk&echo exit)>X:\\disk-list-script.txt\r\n'
        "diskpart /s X:\\disk-list-script.txt >X:\\disk-list.txt || exit /b 11\r\n"
        + check
        + f'net use W: "{install_source_unc}" * /user:"{install_user}" '
        "/persistent:no < X:\\install-password.txt || exit /b 30\r\n"
        'if not exist W:\\setup.exe exit /b 31\r\n'
        'if not exist W:\\sources\\install.wim exit /b 32\r\n'
        "diskpart /s X:\\disk-list-script.txt >X:\\disk-list.txt || exit /b 40\r\n"
        + check
        + "diskpart /s X:\\windows-layout.txt || exit /b 41\r\n"
        "W:\\setup.exe /InstallFrom W:\\sources\\install.wim "
        "/Unattend:X:\\Autounattend.xml || exit /b 50\r\n"
    )


def render_unattend(identity: SyntheticIdentity) -> str:
    """Render explicit Pro/en-US Setup answers for one private run."""
    fields = (
        identity.computer_name, identity.local_user, identity.local_password)
    if any(not re.fullmatch(r"[A-Za-z0-9._-]{8,32}", value) for value in fields):
        raise WindowsInstallContractError(
            "synthetic Windows identity is not safely representable")
    computer = escape(identity.computer_name)
    user = escape(identity.local_user)
    password = escape(identity.local_password)
    return f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE"
      processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
      language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64"
      publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ImageInstall><OSImage>
        <InstallFrom><MetaData wcm:action="add"
          xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <Key>/IMAGE/NAME</Key><Value>Windows 11 Pro</Value>
        </MetaData></InstallFrom>
        <InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo>
        <WillShowUI>OnError</WillShowUI>
      </OSImage></ImageInstall>
      <UserData><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
      publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>{computer}</ComputerName>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64"
      publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE><HideEULAPage>true</HideEULAPage>
        <ProtectYourPC>3</ProtectYourPC></OOBE>
      <UserAccounts><LocalAccounts><LocalAccount
        xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
        wcm:action="add"><Name>{user}</Name><Group>Administrators</Group>
        <Password><Value>{password}</Value><PlainText>true</PlainText></Password>
      </LocalAccount></LocalAccounts></UserAccounts>
    </component>
  </settings>
</unattend>
"""


def render_winpeshl() -> str:
    """Launch the injected private startup script instead of interactive Setup."""
    return '[LaunchApps]\r\n"install.bat"\r\n'


def render_ipxe_overlay(version: str, private_base_url: str) -> str:
    """Load immutable WinPE plus per-run files using wimboot injection."""
    if not re.fullmatch(r"\d{8}\.\d{3}", version):
        raise WindowsInstallContractError("release version is invalid")
    if not re.fullmatch(
            r"http://10\.1\.31\.2/private/[A-Za-z0-9._-]+",
            private_base_url.rstrip("/")):
        raise WindowsInstallContractError(
            "private input URL must remain on the isolated Controller")
    release = f"http://10.1.31.2/windows/{version}"
    private = private_base_url.rstrip("/")
    return "\n".join((
        "#!ipxe",
        f"kernel {release}/wimboot",
        f"initrd {private}/install.bat install.bat",
        f"initrd {private}/winpeshl.ini winpeshl.ini",
        f"initrd {private}/windows-layout.txt windows-layout.txt",
        f"initrd {private}/Autounattend.xml Autounattend.xml",
        f"initrd {private}/install-password.txt install-password.txt",
        f"initrd {release}/bootmgr bootmgr",
        f"initrd {release}/boot/BCD BCD",
        f"initrd {release}/boot/boot.sdi boot.sdi",
        f"initrd {release}/sources/boot.wim boot.wim",
        "boot",
        "",
    ))


def authorize(
    *,
    disk: Path,
    serial: str,
    command: list[str],
    release_version: str,
    release_manifest_sha256: str,
    layout_profile: Path,
    workstation_profile: Path,
) -> Authorization:
    if not re.fullmatch(r"\d{8}\.\d{3}", release_version):
        raise WindowsInstallContractError("release version is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", release_manifest_sha256):
        raise WindowsInstallContractError("release manifest digest is invalid")
    disk_record = inspect_qcow2(disk)
    audit_qemu_disk_boundary(command, disk=disk, serial=serial)
    layout = build_record(
        disk_record["virtual_size"], layout_profile, workstation_profile)
    partitions = layout["layout"]["partitions"]
    start_mib = 1
    windows_first = []
    arch_extent = None
    for partition in partitions:
        extent = {
            "role": partition["type"],
            "start_mib": start_mib,
            "size_mib": partition["size_mib"],
        }
        if partition["type"] == "linux-root":
            arch_extent = {
                **extent, "role": "reserved-arch", "state": "unallocated"}
        else:
            windows_first.append(extent)
        start_mib += partition["size_mib"]
    if arch_extent is None:
        raise WindowsInstallContractError(
            "layout has no reserved Arch extent")
    layout["windows_first_layout"] = {
        "partitioned_extents": windows_first,
        "reserved_arch_extent": arch_extent,
    }
    argv_digest = hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()
    return Authorization(
        schema=1,
        release_version=release_version,
        release_manifest_sha256=release_manifest_sha256,
        disk=disk_record,
        disk_serial=serial,
        layout=layout,
        qemu_argv_sha256=argv_digest,
    )


class PrivateRun(AbstractContextManager["PrivateRun"]):
    """Own generated secret inputs and guarantee their recursive teardown."""

    def __init__(self, root: Path = RUN_ROOT) -> None:
        self.root = Path(root)
        self.path: Path | None = None
        self.known_secrets: tuple[str, ...] = ()

    def __enter__(self) -> "PrivateRun":
        if self.root.is_symlink():
            raise WindowsInstallContractError("private run root is a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.path = self.root / ("run-" + secrets.token_hex(12))
        self.path.mkdir(mode=0o700)
        return self

    def write_secret(self, name: str, content: str) -> Path:
        if self.path is None or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise WindowsInstallContractError("invalid private run filename")
        output = self.path / name
        descriptor = os.open(
            output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        return output

    def remember_secrets(self, *values: str) -> None:
        if any(not value for value in values):
            raise WindowsInstallContractError("known secrets must be nonempty")
        self.known_secrets += tuple(values)

    def render_windows_inputs(
        self,
        authorization: Authorization,
        identity: SyntheticIdentity,
        *,
        install_source_unc: str,
    ) -> list[Path]:
        if self.path is None:
            raise WindowsInstallContractError("private run is not active")
        self.remember_secrets(
            identity.local_password, identity.install_password)
        base = f"http://10.1.31.2/private/{self.path.name}"
        values = {
            "boot.ipxe": render_ipxe_overlay(
                authorization.release_version, base),
            "install.bat": render_startup(
                authorization,
                install_source_unc=install_source_unc,
                install_user=identity.install_user),
            "winpeshl.ini": render_winpeshl(),
            "windows-layout.txt": render_diskpart(authorization),
            "Autounattend.xml": render_unattend(identity),
            "install-password.txt": identity.install_password + "\r\n",
        }
        if set(values) != PRIVATE_INPUT_NAMES:
            raise WindowsInstallContractError(
                "private Windows input set is incomplete")
        return [
            self.write_secret(name, values[name])
            for name in sorted(values)
        ]

    def public_receipt(
        self, authorization: Authorization, generated: list[Path],
    ) -> dict[str, Any]:
        if self.path is None:
            raise WindowsInstallContractError("private run is not active")
        return {
            "schema": 1,
            "authorization": asdict(authorization),
            "generated_inputs": [
                {"name": path.name, "sha256": sha256(path)}
                for path in generated
            ],
        }

    def assert_secret_free(self, evidence: Path) -> None:
        raw = Path(evidence).read_bytes()
        for value in self.known_secrets:
            if value.encode() in raw:
                raise WindowsInstallContractError(
                    "retained evidence contains a known secret")

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self.path is not None:
            shutil.rmtree(self.path)
            self.path = None
