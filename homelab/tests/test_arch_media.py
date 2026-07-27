from __future__ import annotations

import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).parents[1] / "media" / "fetch_arch.py"
SPEC = importlib.util.spec_from_file_location("fetch_arch", MODULE_PATH)
assert SPEC and SPEC.loader
fetch_arch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch_arch)

FetchError = fetch_arch.FetchError
RELEASE_FINGERPRINT = fetch_arch.RELEASE_FINGERPRINT
ensure_release_key = fetch_arch.ensure_release_key
fetch = fetch_arch.fetch
release_from_sums = fetch_arch.release_from_sums
verify_checksum = fetch_arch.verify_checksum


class ArchMediaTests(unittest.TestCase):
    def test_release_from_sums_selects_versioned_iso(self) -> None:
        digest = "a" * 64
        filename, checksum = release_from_sums(
            f"{digest}  archlinux-2026.07.01-x86_64.iso\n"
            f"{'b' * 64}  archlinux-bootstrap-2026.07.01-x86_64.tar.zst\n"
        )
        self.assertEqual(filename, "archlinux-2026.07.01-x86_64.iso")
        self.assertEqual(checksum, digest)

    def test_release_from_sums_rejects_ambiguous_manifest(self) -> None:
        digest = "a" * 64
        line = f"{digest}  archlinux-2026.07.01-x86_64.iso\n"
        with self.assertRaises(FetchError):
            release_from_sums(line + line)

    def test_checksum_mismatch_is_fatal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "image.iso"
            image.write_bytes(b"wrong")
            with self.assertRaises(FetchError):
                verify_checksum(image, "0" * 64)

    def test_fetch_refreshes_metadata_and_reuses_valid_image(self) -> None:
        payload = b"arch image"
        digest = hashlib.sha256(payload).hexdigest()
        filename = "archlinux-2026.07.01-x86_64.iso"
        downloads: list[str] = []

        def downloader(url: str, destination: Path) -> None:
            downloads.append(url)
            if url.endswith("sha256sums.txt"):
                destination.write_text(f"{digest}  {filename}\n", encoding="utf-8")
            elif url.endswith(".sig"):
                destination.write_bytes(b"signature")
            else:
                destination.write_bytes(payload)

        def runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            if "--fingerprint" in command:
                output = f"fpr:::::::::{RELEASE_FINGERPRINT}:\n"
            else:
                output = f"[GNUPG:] VALIDSIG {RELEASE_FINGERPRINT} 2026 0 0 0 0 0 0 0\n"
            return subprocess.CompletedProcess(command, 0, output, "")

        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            first = fetch(cache, "https://example.invalid/iso/latest", downloader, runner)
            second = fetch(cache, "https://example.invalid/iso/latest", downloader, runner)

        self.assertEqual(first["cached"], "false")
        self.assertEqual(second["cached"], "true")
        self.assertEqual(sum(url.endswith("sha256sums.txt") for url in downloads), 2)
        self.assertEqual(sum(url.endswith(filename) for url in downloads), 1)
        self.assertEqual(sum(url.endswith(".sig") for url in downloads), 2)

    def test_release_key_retrieval_requires_pinned_fingerprint(self) -> None:
        calls = 0

        def runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise subprocess.CalledProcessError(2, command)
            return subprocess.CompletedProcess(command, 0, "fpr:::::::::BAD:\n", "")

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(FetchError):
                ensure_release_key(Path(temporary), runner)

    def test_download_failure_does_not_replace_cached_image(self) -> None:
        payload = b"known good"
        digest = hashlib.sha256(payload).hexdigest()
        filename = "archlinux-2026.07.01-x86_64.iso"

        def downloader(url: str, destination: Path) -> None:
            if url.endswith("sha256sums.txt"):
                destination.write_text(f"{digest}  {filename}\n", encoding="utf-8")
            elif url.endswith(filename):
                raise OSError("network down")
            else:
                destination.write_bytes(b"signature")

        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            with patch.object(fetch_arch, "sha256", return_value="bad"):
                with self.assertRaises(OSError):
                    fetch(cache, "https://example.invalid", downloader)
            self.assertFalse((cache / filename).exists())


if __name__ == "__main__":
    unittest.main()
