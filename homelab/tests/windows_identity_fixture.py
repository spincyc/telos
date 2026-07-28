import hashlib
import json
from pathlib import Path

from homelab.vm.windows_identity_contract import qemu_identity_command


def write_prepared_authorization(
    attempt: Path, controller_state: Path,
) -> None:
    command = qemu_identity_command(
        disk=attempt / "windows.qcow2",
        variables=attempt / "OVMF_VARS.fd",
        qmp_socket=attempt / "windows.qmp",
        switch_port=31415,
    )
    command_path = attempt / "qemu-command.json"
    command_path.write_text(json.dumps({
        "schema": 1, "argv": command}), encoding="utf-8")
    command_path.chmod(0o600)
    digest = hashlib.sha256(
        json.dumps(command, separators=(",", ":")).encode()).hexdigest()
    authorization = {
        "status": "prepared",
        "external_access": False,
        "installation_media_attached": False,
        "pxe_boot_enabled": False,
        "qemu_argv_sha256": digest,
        "controller_state": str(controller_state.resolve()),
        "overlay": {
            "path": str((attempt / "windows.qcow2").resolve()),
            "format": "qcow2",
        },
        "firmware_copy": {
            "path": str((attempt / "OVMF_VARS.fd").resolve()),
        },
    }
    marker = attempt / "authorization.json"
    marker.write_text(json.dumps(authorization), encoding="utf-8")
    marker.chmod(0o600)
