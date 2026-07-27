from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).parents[1] / "media" / "fetch_arch.py"
SPEC = importlib.util.spec_from_file_location("fetch_arch_edges", MODULE_PATH)
assert SPEC and SPEC.loader
fetch_arch = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fetch_arch)

FetchError = fetch_arch.FetchError
RELEASE_FINGERPRINT = fetch_arch.RELEASE_FINGERPRINT
download = fetch_arch.download
ensure_release_key = fetch_arch.ensure_release_key
fetch = fetch_arch.fetch
release_from_sums = fetch_arch.release_from_sums
verify_signature = fetch_arch.verify_signature


class _Response(io.BytesIO):
    def geturl(self) -> str:
        return "https://geo.mirror.pkgbuild.com/iso/latest/image.iso"

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *unused: object) -> None:
        self.close()


def _trusted_runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    output = (
        f"fpr:::::::::{RELEASE_FINGERPRINT}:\n"
        if "--fingerprint" in command
        else f"[GNUPG:] VALIDSIG {RELEASE_FINGERPRINT} 2026 0 0 0 0 0 0 0\n"
    )
    return subprocess.CompletedProcess(command, 0, output, "")


class AtomicDownloadEdgeTests(unittest.TestCase):
    def test_download_rejects_non_official_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(FetchError, "non-official"):
                download(
                    "https://example.invalid/image.iso",
                    Path(temporary) / "image.iso",
                )

    def test_download_rejects_redirect_off_official_origin(self) -> None:
        class RedirectedResponse(_Response):
            def geturl(self) -> str:
                return "https://example.invalid/image.iso"

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "image.iso"
            with patch.object(
                fetch_arch.urllib.request,
                "urlopen",
                return_value=RedirectedResponse(b"untrusted"),
            ):
                with self.assertRaisesRegex(FetchError, "non-official"):
                    download(
                        "https://geo.mirror.pkgbuild.com/iso/latest/image.iso",
                        destination,
                    )
            self.assertFalse(destination.exists())

    def test_download_refuses_symlink_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "outside"
            target.write_bytes(b"preserve")
            destination = root / "image.iso"
            destination.symlink_to(target)
            with self.assertRaisesRegex(FetchError, "unsafe cache entry"):
                download(
                    "https://geo.mirror.pkgbuild.com/iso/latest/image.iso",
                    destination,
                )
            self.assertEqual(target.read_bytes(), b"preserve")

    def test_download_replaces_destination_only_after_complete_response(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "image.iso"
            destination.write_bytes(b"old")
            with patch.object(
                fetch_arch.urllib.request,
                "urlopen",
                return_value=_Response(b"new image"),
            ) as urlopen:
                download("https://geo.mirror.pkgbuild.com/iso/latest/image.iso", destination)

            self.assertEqual(destination.read_bytes(), b"new image")
            self.assertEqual(list(destination.parent.glob("*.part")), [])
            request = urlopen.call_args.args[0]
            self.assertEqual(request.get_header("User-agent"), "telos-media-fetch/1")
            self.assertEqual(urlopen.call_args.kwargs["timeout"], 60)

    def test_interrupted_download_preserves_existing_destination_and_cleans_part(self) -> None:
        class BrokenResponse(_Response):
            def read(self, size: int = -1) -> bytes:
                raise TimeoutError("connection stalled")

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "image.iso"
            destination.write_bytes(b"known good")
            with patch.object(
                fetch_arch.urllib.request,
                "urlopen",
                return_value=BrokenResponse(b"partial"),
            ):
                with self.assertRaises(TimeoutError):
                    download("https://geo.mirror.pkgbuild.com/iso/latest/image.iso", destination)

            self.assertEqual(destination.read_bytes(), b"known good")
            self.assertEqual(list(destination.parent.glob("*.part")), [])


class ManifestEdgeTests(unittest.TestCase):
    def test_manifest_rejects_missing_iso(self) -> None:
        with self.assertRaisesRegex(FetchError, "exactly one"):
            release_from_sums(f"{'a' * 64}  archlinux-bootstrap.tar.zst\n")

    def test_manifest_rejects_uppercase_digest(self) -> None:
        with self.assertRaises(FetchError):
            release_from_sums(
                f"{'A' * 64}  archlinux-2026.07.01-x86_64.iso\n"
            )

    def test_manifest_rejects_path_traversal_filename(self) -> None:
        with self.assertRaises(FetchError):
            release_from_sums(
                f"{'a' * 64}  ../archlinux-2026.07.01-x86_64.iso\n"
            )

    def test_manifest_rejects_noncanonical_separator(self) -> None:
        with self.assertRaises(FetchError):
            release_from_sums(
                f"{'a' * 64} *archlinux-2026.07.01-x86_64.iso\n"
            )


class FetchWorkflowEdgeTests(unittest.TestCase):
    def test_corrupt_cached_iso_is_removed_and_downloaded_again(self) -> None:
        payload = b"fresh official media"
        digest = hashlib.sha256(payload).hexdigest()
        filename = "archlinux-2026.07.01-x86_64.iso"
        image_downloads = 0

        def downloader(url: str, destination: Path) -> None:
            nonlocal image_downloads
            if url.endswith("sha256sums.txt"):
                destination.write_text(f"{digest}  {filename}\n", encoding="utf-8")
            elif url.endswith(".sig"):
                destination.write_bytes(b"signature")
            else:
                image_downloads += 1
                self.assertFalse(destination.exists())
                destination.write_bytes(payload)

        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            (cache / filename).write_bytes(b"corrupt cache")
            result = fetch(cache, "https://example.invalid/latest", downloader, _trusted_runner)

            self.assertEqual(image_downloads, 1)
            self.assertEqual((cache / filename).read_bytes(), payload)
            self.assertEqual(result["cached"], "false")

    def test_changed_release_does_not_reuse_previous_release(self) -> None:
        old_name = "archlinux-2026.06.01-x86_64.iso"
        new_name = "archlinux-2026.07.01-x86_64.iso"
        payload = b"july"
        digest = hashlib.sha256(payload).hexdigest()
        downloads: list[str] = []

        def downloader(url: str, destination: Path) -> None:
            downloads.append(url)
            if url.endswith("sha256sums.txt"):
                destination.write_text(f"{digest}  {new_name}\n", encoding="utf-8")
            elif url.endswith(".sig"):
                destination.write_bytes(b"signature")
            else:
                destination.write_bytes(payload)

        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            (cache / old_name).write_bytes(b"june")
            result = fetch(cache, "https://example.invalid/latest/", downloader, _trusted_runner)

            self.assertEqual(result["source"], f"https://example.invalid/latest/{new_name}")
            self.assertIn(f"https://example.invalid/latest/{new_name}", downloads)
            self.assertEqual((cache / "archlinux-x86_64.iso").readlink(), Path(new_name))
            receipt = json.loads(
                (cache / "archlinux-x86_64.iso.receipt.json").read_text(encoding="utf-8")
            )
            self.assertEqual(receipt["sha256"], digest)
            self.assertEqual(receipt["signing_fingerprint"], RELEASE_FINGERPRINT)
            self.assertEqual(
                stat.S_IMODE((cache / new_name).stat().st_mode),
                0o600,
            )

    def test_checksum_failure_does_not_publish_current_symlink(self) -> None:
        filename = "archlinux-2026.07.01-x86_64.iso"

        def downloader(url: str, destination: Path) -> None:
            if url.endswith("sha256sums.txt"):
                destination.write_text(f"{'0' * 64}  {filename}\n", encoding="utf-8")
            else:
                destination.write_bytes(b"untrusted")

        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            with self.assertRaisesRegex(FetchError, "SHA-256 mismatch"):
                fetch(cache, downloader=downloader, runner=_trusted_runner)
            self.assertFalse((cache / "archlinux-x86_64.iso").exists())

    def test_signature_failure_does_not_publish_current_symlink(self) -> None:
        payload = b"correct checksum, bad signature"
        digest = hashlib.sha256(payload).hexdigest()
        filename = "archlinux-2026.07.01-x86_64.iso"

        def downloader(url: str, destination: Path) -> None:
            if url.endswith("sha256sums.txt"):
                destination.write_text(f"{digest}  {filename}\n", encoding="utf-8")
            elif url.endswith(".sig"):
                destination.write_bytes(b"bad signature")
            else:
                destination.write_bytes(payload)

        def runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            if "--fingerprint" in command:
                return _trusted_runner(command)
            raise subprocess.CalledProcessError(1, command)

        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary)
            with self.assertRaisesRegex(FetchError, "signature verification failed"):
                fetch(cache, downloader=downloader, runner=runner)
            self.assertFalse((cache / "archlinux-x86_64.iso").exists())


class AuthenticationEdgeTests(unittest.TestCase):
    def test_goodsig_without_exact_validsig_is_rejected(self) -> None:
        def runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 0, "[GNUPG:] GOODSIG test\n", "")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(FetchError, "pinned"):
                verify_signature(root / "image.iso", root / "image.sig", root / "keys", runner)

    def test_validsig_from_different_key_is_rejected(self) -> None:
        def runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            output = f"[GNUPG:] VALIDSIG {'A' * 40} 2026 0 0 0 0 0 0 0\n"
            return subprocess.CompletedProcess(command, 0, output, "")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(FetchError, "pinned"):
                verify_signature(root / "image.iso", root / "image.sig", root / "keys", runner)

    def test_missing_gpg_during_signature_verification_is_not_silently_accepted(self) -> None:
        def runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            raise FileNotFoundError("gpg")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(FileNotFoundError):
                verify_signature(root / "image.iso", root / "image.sig", root / "keys", runner)

    def test_key_lookup_failure_has_domain_specific_error(self) -> None:
        calls = 0

        def runner(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                return subprocess.CompletedProcess(command, 0, "", "")
            raise subprocess.CalledProcessError(2, command)

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(FetchError, "official WKD"):
                ensure_release_key(Path(temporary), runner)


if __name__ == "__main__":
    unittest.main()
