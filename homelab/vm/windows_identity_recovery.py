"""Consume the retained one-run Windows local credential without retaining it."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET


class WindowsIdentityRecoveryError(RuntimeError):
    """The retained bootstrap credential cannot be consumed safely."""


class RecoveredLocalCredential(AbstractContextManager[str]):
    """Extract one unique unattend password into private transient storage."""

    def __init__(self, publication: Path, private_parent: Path) -> None:
        self.publication = Path(publication)
        self.private_parent = Path(private_parent)
        self._temporary: Path | None = None
        self._value: str | None = None

    def __enter__(self) -> str:
        if self.publication.is_symlink() or not self.publication.is_file():
            raise WindowsIdentityRecoveryError(
                "private publication must be a regular non-symlink file")
        if self.publication.stat().st_mode & 0o077:
            raise WindowsIdentityRecoveryError(
                "private publication must be mode 0600")
        if (self.private_parent.is_symlink()
                or not self.private_parent.is_dir()
                or self.private_parent.stat().st_mode & 0o077):
            raise WindowsIdentityRecoveryError(
                "recovery parent must be a private real directory")
        self._temporary = Path(tempfile.mkdtemp(
            prefix=".credential-", dir=self.private_parent))
        self._temporary.chmod(0o700)
        destination = self._temporary / "Autounattend.xml"
        try:
            listing = subprocess.run([
                "xorriso", "-indev", str(self.publication), "-find", "/",
                "-name", "Autounattend.xml", "-exec", "lsdl",
            ], check=True, capture_output=True, text=True)
            matches = []
            for line in listing.stdout.splitlines():
                match = re.search(r"'(/[^']*/Autounattend\.xml)'$", line)
                if match:
                    matches.append(match.group(1))
            if len(matches) != 1:
                raise WindowsIdentityRecoveryError(
                    "private publication must contain one unattend file")
            subprocess.run([
                "xorriso", "-osirrox", "on", "-indev",
                str(self.publication), "-extract", matches[0], str(destination),
            ], check=True, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            destination.chmod(0o600)
            root = ET.parse(destination).getroot()
            values = set()
            for password in root.iter():
                if password.tag.rsplit("}", 1)[-1] != "Password":
                    continue
                for node in password:
                    if (node.tag.rsplit("}", 1)[-1] == "Value"
                            and node.text is not None
                            and re.fullmatch(
                                r"[A-Za-z0-9._-]{8,64}", node.text)):
                        values.add(node.text)
            if len(values) != 1:
                raise WindowsIdentityRecoveryError(
                    "unattend must contain one unique local credential")
            self._value = values.pop()
            destination.write_bytes(b"\0" * destination.stat().st_size)
            destination.unlink()
            return self._value
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def destroy_publication(self) -> None:
        """Destroy the credential-bearing ISO only after guest rotation."""
        if self._value is None:
            raise WindowsIdentityRecoveryError(
                "credential was not recovered in the active context")
        if self.publication.is_symlink():
            raise WindowsIdentityRecoveryError(
                "private publication became a symlink")
        self.publication.unlink()

    def __exit__(self, *_exc: object) -> None:
        self._value = None
        if self._temporary is not None:
            shutil.rmtree(self._temporary, ignore_errors=True)
            self._temporary = None
