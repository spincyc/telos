"""Prepare one verified selected release set for a disposable Controller."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from homelab.lib import pxe_release_set, windows_install_source
    from homelab.vm.controller_factory import (
        FactorySpec, nginx_config, tftp_unit)
except ModuleNotFoundError as error:
    if error.name != "homelab":
        raise
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
    import pxe_release_set
    import windows_install_source
    from controller_factory import FactorySpec, nginx_config, tftp_unit


class PublicationError(RuntimeError):
    """Selected release material is absent, altered, or unsafe."""


TFTP_PACKAGE = re.compile(
    r"^packages/(tftp-hpa-[A-Za-z0-9.+_-]+-x86_64\.pkg\.tar\.zst)$")
PRIVATE_WINDOWS_FILES = frozenset({
    "boot.ipxe", "install.bat", "winpeshl.ini", "windows-layout.txt",
    "Autounattend.xml", "install-password.txt",
})


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise PublicationError(f"{path} must contain a JSON object")
    return value


def _ipxe_binary(explicit: Path | None) -> Path:
    candidates = (
        (Path(explicit),) if explicit is not None else (
            Path("/usr/share/ipxe/x86_64/ipxe.efi"),
            Path("/usr/share/ipxe/ipxe.efi"),
        )
    )
    matches = [
        path for path in candidates
        if path.is_file() and not path.is_symlink() and path.stat().st_size > 0
    ]
    if len(matches) != 1:
        raise PublicationError(
            "exactly one nonempty regular x86_64 ipxe.efi is required")
    return matches[0]


def extract_tftp_repair(seed_iso: Path, destination: Path) -> dict:
    """Extract one receipt-bound signed tftp-hpa archive without mounting."""
    seed_iso = Path(seed_iso)
    if (
        not seed_iso.is_file() or seed_iso.is_symlink()
        or seed_iso.stat().st_size <= 0
    ):
        raise PublicationError("Controller seed ISO is not a nonempty regular file")
    if shutil.which("xorriso") is None:
        raise PublicationError("xorriso is required to inspect the Controller seed")
    with tempfile.TemporaryDirectory(prefix="telos-seed-repair-") as temp_name:
        temporary = Path(temp_name)
        receipt_path = temporary / "receipt.json"
        subprocess.run([
            "xorriso", "-osirrox", "on", "-indev", str(seed_iso),
            "-extract", "/receipt.json", str(receipt_path),
        ], check=True, capture_output=True)
        try:
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            entries = receipt["payload_files"]
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError,
                TypeError) as error:
            raise PublicationError("Controller seed receipt is invalid") from error
        by_path = {
            item.get("path"): item for item in entries if isinstance(item, dict)
        }
        matches = [
            (path, TFTP_PACKAGE.fullmatch(str(path)))
            for path in by_path
            if TFTP_PACKAGE.fullmatch(str(path))
        ]
        if len(matches) != 1:
            raise PublicationError(
                "Controller seed must contain exactly one x86_64 tftp-hpa archive")
        package_path, match = matches[0]
        assert match is not None
        signature_path = str(package_path) + ".sig"
        if signature_path not in by_path:
            raise PublicationError(
                "Controller seed tftp-hpa detached signature is missing")
        destination.mkdir(parents=True)
        extracted = {}
        for logical in (str(package_path), signature_path):
            record = by_path[logical]
            output = destination / Path(logical).name
            subprocess.run([
                "xorriso", "-osirrox", "on", "-indev", str(seed_iso),
                "-extract", "/" + logical, str(output),
            ], check=True, capture_output=True)
            if (
                output.stat().st_size != record.get("bytes")
                or digest(output) != record.get("sha256")
            ):
                raise PublicationError(
                    f"Controller seed receipt mismatch: {logical}")
            extracted[logical] = {
                "name": output.name,
                "size": output.stat().st_size,
                "sha256": digest(output),
            }
        return {
            "seed_iso_sha256": digest(seed_iso),
            "seed_receipt_sha256": digest(receipt_path),
            "package": extracted[str(package_path)],
            "signature": extracted[signature_path],
            "install": "pacman --noconfirm -U (local archive only, if absent)",
        }


def stage(
    releases: Path, destination: Path, *, seed_iso: Path,
    ipxe_binary: Path | None = None, target: str = "arch-workstation",
    private_windows_inputs: Path | None = None,
    windows_source: Path | None = None,
) -> dict:
    """Copy only manifest-verified selected bytes into a private staging tree."""
    releases = Path(releases).resolve()
    destination = Path(destination)
    selected_path = releases / pxe_release_set.SELECTED
    selected = _json(selected_path)
    if set(selected) != {"schema", "version", "manifest_sha256"}:
        raise PublicationError("selected release descriptor has invalid fields")
    if selected.get("schema") != pxe_release_set.SCHEMA:
        raise PublicationError("selected release descriptor has invalid schema")
    version = selected.get("version")
    if not isinstance(version, str) or not pxe_release_set.VERSION.fullmatch(version):
        raise PublicationError("selected release version is invalid")
    release_set = releases / "release-sets" / version
    problems = pxe_release_set.verify(release_set, expected_version=version)
    if problems:
        raise PublicationError(
            "selected release set failed verification: " + "; ".join(problems))
    aggregate = release_set / pxe_release_set.MANIFEST
    if digest(aggregate) != selected.get("manifest_sha256"):
        raise PublicationError("selected descriptor does not match release-set manifest")
    if destination.exists():
        raise PublicationError(f"publication destination already exists: {destination}")
    ipxe = _ipxe_binary(ipxe_binary)
    if target not in ("arch-workstation", "windows"):
        raise PublicationError(f"unsupported PXE publication target: {target}")
    private_source = None
    if private_windows_inputs is not None:
        private_source = Path(private_windows_inputs)
        if target != "windows":
            raise PublicationError(
                "private Windows inputs require the windows target")
        if private_source.is_symlink() or not private_source.is_dir():
            raise PublicationError(
                "private Windows inputs must be a non-symlink directory")
        if not re.fullmatch(r"run-[A-Za-z0-9._-]+", private_source.name):
            raise PublicationError("private Windows run name is unsafe")
        entries = {path.name for path in private_source.iterdir()}
        if entries != PRIVATE_WINDOWS_FILES:
            raise PublicationError(
                "private Windows input set is incomplete or unexpected")
        if any(path.is_symlink() or not path.is_file()
               for path in private_source.iterdir()):
            raise PublicationError(
                "private Windows inputs must be regular non-symlink files")
    verified_windows_source = None
    if windows_source is not None:
        if private_source is None:
            raise PublicationError(
                "Windows install source requires private Windows inputs")
        windows_manifest = _json(
            release_set / "targets" / "windows" / version / "release.json")
        expected_iso = windows_manifest.get("source_iso_sha256")
        try:
            verified_windows_source = windows_install_source.verify_cache(
                Path(windows_source), expected_iso)
        except (OSError, RuntimeError) as error:
            raise PublicationError(
                f"Windows install source verification failed: {error}") from error

    www = destination / "www"
    try:
        www.mkdir(parents=True)
        controller = destination / "controller"
        controller.mkdir()
        spec = FactorySpec()
        (controller / "factory-nginx.conf").write_text(
            nginx_config(spec), encoding="utf-8")
        (controller / "telos-factory-tftp.service").write_text(
            tftp_unit(spec), encoding="utf-8")
        tftp = destination / "tftp"
        tftp.mkdir()
        shutil.copy2(ipxe, tftp / "ipxe.efi")
        repair = extract_tftp_repair(seed_iso, destination / "repair")
        shutil.copy2(aggregate, destination / pxe_release_set.MANIFEST)
        for release_target in pxe_release_set.TARGETS:
            source = release_set / "targets" / release_target / version
            shutil.copytree(source, www / release_target / version)
        bootstrap = www / "boot" / "boot.ipxe"
        bootstrap.parent.mkdir()
        selected_boot = f"{target}/{version}/boot.ipxe"
        if private_source is not None:
            private_destination = www / "private" / private_source.name
            shutil.copytree(private_source, private_destination)
            selected_boot = f"private/{private_source.name}/boot.ipxe"
        if verified_windows_source is not None:
            shutil.copytree(Path(windows_source), destination / "windows-source")
        bootstrap.write_text(
            "#!ipxe\n"
            f"chain http://10.1.31.2/{selected_boot}"
            " || goto failed\n"
            ":failed\n"
            f"echo Selected {target} release failed to load.\n"
            "shell\n",
            encoding="utf-8",
        )
        checksummed = [
            path for path in sorted(destination.rglob("*"))
            if path.is_file()
        ]
        (destination / "SHA256SUMS").write_text(
            "".join(
                f"{digest(path)}  {path.relative_to(destination).as_posix()}\n"
                for path in checksummed
            ),
            encoding="ascii",
        )
        windows_publish = ""
        if verified_windows_source is not None:
            windows_publish = (
                "command -v smbd >/dev/null || { "
                "echo 'TELOS PXE READINESS FAIL missing smbd' >/dev/ttyS0; "
                "exit 1; }\n"
                "test ! -e /etc/samba/smb.conf || { "
                "echo 'TELOS PXE READINESS FAIL existing smb.conf' >/dev/ttyS0; "
                "exit 1; }\n"
                "install -d -m 0755 /srv/windows-source /etc/samba\n"
                "cp -a -- windows-source/. /srv/windows-source/\n"
                "chmod -R a+rX /srv/windows-source\n"
                "id -u pxe-install >/dev/null 2>&1 || "
                "useradd --system --no-create-home --shell /usr/bin/nologin "
                "pxe-install\n"
                f"password=www/private/{private_source.name}/install-password.txt\n"
                "test -s \"$password\" || exit 1\n"
                "{ cat \"$password\"; cat \"$password\"; } | "
                "smbpasswd -s -a pxe-install >/dev/null\n"
                "cat >/etc/samba/smb.conf <<'EOF'\n"
                "[global]\nserver role = standalone server\n"
                "interfaces = 10.1.31.2/28\nbind interfaces only = yes\n"
                "map to guest = never\nlogging = file\n"
                "[windows-release]\npath = /srv/windows-source\n"
                "read only = yes\nguest ok = no\nvalid users = pxe-install\n"
                "EOF\n"
                "systemctl enable smb.service\n"
            )
        readiness_units = (
            "telos-factory-http.service telos-factory-tftp.service"
            + (" smb.service" if verified_windows_source is not None else "")
        )
        readiness_smb = (
            " && systemctl is-active --quiet smb.service"
            if verified_windows_source is not None else ""
        )
        publisher = destination / "publish"
        publisher.write_text(
            "#!/usr/bin/bash\n"
            "set -euo pipefail\n"
            "root=$(cd -- \"$(dirname -- \"$0\")\" && pwd)\n"
            "cd \"$root\"\n"
            "command -v sha256sum >/dev/null || { "
            "echo 'TELOS PXE READINESS FAIL missing sha256sum' >/dev/ttyS0; "
            "exit 1; }\n"
            "sha256sum --check --strict SHA256SUMS\n"
            "for binary in nginx; do\n"
            "  command -v \"$binary\" >/dev/null || { "
            "echo \"TELOS PXE READINESS FAIL missing $binary\" >/dev/ttyS0; "
            "exit 1; }\n"
            "done\n"
            "if ! command -v in.tftpd >/dev/null; then\n"
            "  command -v pacman >/dev/null || { "
            "echo 'TELOS PXE READINESS FAIL missing pacman' >/dev/ttyS0; exit 1; }\n"
            "  archives=(repair/tftp-hpa-*-x86_64.pkg.tar.zst)\n"
            "  [[ ${#archives[@]} -eq 1 && -f ${archives[0]} && "
            "-f ${archives[0]}.sig ]] || { "
            "echo 'TELOS PXE READINESS FAIL invalid tftp repair set' "
            ">/dev/ttyS0; exit 1; }\n"
            "  pacman --noconfirm -U \"${archives[0]}\" || { "
            "echo 'TELOS PXE READINESS FAIL tftp signature/install' "
            ">/dev/ttyS0; exit 1; }\n"
            "fi\n"
            "command -v in.tftpd >/dev/null || { "
            "echo 'TELOS PXE READINESS FAIL missing in.tftpd after repair' "
            ">/dev/ttyS0; exit 1; }\n"
            "test -s tftp/ipxe.efi || { "
            "echo 'TELOS PXE READINESS FAIL missing ipxe.efi' >/dev/ttyS0; "
            "exit 1; }\n"
            + windows_publish
            + "install -d -m 0755 /etc/homelab /srv/tftp\n"
            "install -m 0644 controller/factory-nginx.conf "
            "/etc/homelab/factory-nginx.conf\n"
            "install -m 0644 controller/telos-factory-tftp.service "
            "/etc/systemd/system/telos-factory-tftp.service\n"
            "install -m 0644 tftp/ipxe.efi /srv/tftp/ipxe.efi\n"
            "install -d -m 0755 /srv/http/homelab\n"
            "cp -a -- www/. /srv/http/homelab/\n"
            "# Release builders use private staging directories; published "
            "HTTP copies must remain immutable but traversable by nginx.\n"
            "chmod -R a+rX /srv/http/homelab\n"
            "install -d -m 0755 /etc/systemd/network\n"
            "cat >/etc/systemd/network/20-telos-factory.network <<'EOF'\n"
            "[Match]\nMACAddress=52:54:00:31:11:12\n"
            "[Network]\nAddress=10.1.31.2/28\nGateway=10.1.31.1\n"
            "DNS=127.0.0.1\nEOF\n"
            "# The disposable Controller is statically addressed and must not "
            "consume the workstation DHCP lease.\n"
            "ln -sfn /dev/null /etc/systemd/system/NetworkManager.service\n"
            "ln -sfn /dev/null "
            "/etc/systemd/system/NetworkManager-wait-online.service\n"
            "cat >/etc/systemd/system/telos-factory-http.service <<'EOF'\n"
            "[Unit]\nAfter=network-online.target\nWants=network-online.target\n"
            "[Service]\nType=simple\n"
            "ExecStart=/usr/bin/nginx -c /etc/homelab/factory-nginx.conf "
            "-g 'daemon off;'\n"
            "ExecReload=/usr/bin/nginx -s reload -c /etc/homelab/factory-nginx.conf\n"
            "[Install]\nWantedBy=multi-user.target\nEOF\n"
            "cat >/etc/systemd/system/telos-pxe-evidence.service <<'EOF'\n"
            f"[Unit]\nAfter={readiness_units}\n"
            f"Requires={readiness_units}\n"
            "[Service]\nType=simple\n"
            "ExecStart=/usr/bin/tail -n 0 -F /var/log/nginx/factory-access.log\n"
            "StandardOutput=tty\nTTYPath=/dev/ttyS0\n"
            "[Install]\nWantedBy=multi-user.target\nEOF\n"
            "cat >/usr/local/sbin/telos-pxe-ready <<'EOF'\n"
            "#!/usr/bin/bash\nset -u\n"
            "for attempt in {1..60}; do\n"
            "  if systemctl is-active --quiet telos-factory-http.service && "
            "systemctl is-active --quiet telos-factory-tftp.service && "
            "ip -4 address show | grep -q '10.1.31.2/28'"
            f"{readiness_smb}; then\n"
            f"    selected=/srv/http/homelab/{selected_boot}\n"
            f"    source=/run/telos-pxe-release/www/{selected_boot}\n"
            "    test -s \"$selected\" && cmp -s \"$source\" \"$selected\" || "
            "{ sleep 1; continue; }\n"
            f"    python -c \"import pathlib,urllib.request; "
            f"expected=pathlib.Path('$selected').read_bytes(); "
            f"actual=urllib.request.urlopen("
            f"'http://10.1.31.2/{selected_boot}',"
            f"timeout=2).read(); "
            f"assert actual == expected\" || {{ sleep 1; continue; }}\n"
            "    if ss -H -lun | grep -Eq ':(67|4011)[[:space:]]'; then\n"
            "      echo 'TELOS PXE READINESS FAIL rogue DHCP listener' >/dev/ttyS0\n"
            "      exit 1\n"
            "    fi\n"
            "    echo 'TELOS PXE SERVICES READY' >/dev/ttyS0\n"
            "    exit 0\n"
            "  fi\nsleep 1\ndone\n"
            "{ echo 'TELOS PXE READINESS FAIL timeout'; "
            "systemctl --no-pager --full status telos-factory-http.service "
            "telos-factory-tftp.service; ip -4 address show; ss -H -lntup; "
            f"ls -ld /srv/http/homelab/{Path(selected_boot).parent} "
            f"/srv/http/homelab/{selected_boot}; "
            "tail -50 /var/log/nginx/factory-error.log 2>/dev/null || true; "
            "} >/dev/ttyS0 2>&1\nexit 1\nEOF\n"
            "chmod 0755 /usr/local/sbin/telos-pxe-ready\n"
            "cat >/etc/systemd/system/telos-pxe-ready.service <<'EOF'\n"
            f"[Unit]\nAfter={readiness_units}\n"
            "[Service]\nType=oneshot\n"
            "ExecStart=/usr/local/sbin/telos-pxe-ready\n"
            "[Install]\nWantedBy=multi-user.target\nEOF\n"
            "install -d -m 0755 /etc/systemd/system/multi-user.target.wants\n"
            "ln -sfn /usr/lib/systemd/system/systemd-networkd.service "
            "/etc/systemd/system/multi-user.target.wants/systemd-networkd.service\n"
            "ln -sfn ../telos-factory-http.service "
            "/etc/systemd/system/multi-user.target.wants/telos-factory-http.service\n"
            "ln -sfn ../telos-factory-tftp.service "
            "/etc/systemd/system/multi-user.target.wants/telos-factory-tftp.service\n"
            "ln -sfn ../telos-pxe-evidence.service "
            "/etc/systemd/system/multi-user.target.wants/telos-pxe-evidence.service\n"
            "ln -sfn ../telos-pxe-ready.service "
            "/etc/systemd/system/multi-user.target.wants/telos-pxe-ready.service\n"
            + (
                "ln -sfn /usr/lib/systemd/system/smb.service "
                "/etc/systemd/system/multi-user.target.wants/smb.service\n"
                if verified_windows_source is not None else ""
            )
            + "echo 'TELOS PXE PUBLICATION PASS'\n",
            encoding="utf-8",
        )
        publisher.chmod(0o755)
        artifacts = {
            path.relative_to(destination).as_posix(): {
                "size": path.stat().st_size,
                "sha256": digest(path),
            }
            for path in sorted(destination.rglob("*"))
            if path.is_file()
        }
        receipt = {
            "schema": 1,
            "version": version,
            "target": target,
            "private_windows_run": (
                private_source.name if private_source is not None else None),
            "windows_install_source": (
                {
                    "receipt_sha256": digest(
                        Path(windows_source) / "receipt.json"),
                    "bytes": verified_windows_source["bytes"],
                    "file_count": verified_windows_source["file_count"],
                } if verified_windows_source is not None else None),
            "selected_manifest_sha256": selected["manifest_sha256"],
            "bootstrap": "www/boot/boot.ipxe",
            "offline_repair": repair,
            "artifacts": artifacts,
        }
        (destination / "publication.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return receipt
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
