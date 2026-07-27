from pathlib import Path
import subprocess
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PUBLICATION_ROOT = REPOSITORY_ROOT / "doc"
MAX_PUBLISHED_PDF_BYTES = 50_000_000
INSTALLATION_MEDIA_SUFFIXES = {
    ".esd",
    ".img",
    ".iso",
    ".qcow2",
    ".vdi",
    ".vhd",
    ".vhdx",
    ".vmdk",
    ".wim",
}


class PublicationSizeTests(unittest.TestCase):
    def tracked_files(self):
        result = subprocess.run(
            ["git", "-C", REPOSITORY_ROOT, "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
        return [
            REPOSITORY_ROOT / path.decode()
            for path in result.stdout.split(b"\0")
            if path
        ]

    def test_tracked_publications_fit_github_without_lfs(self):
        oversized = []
        for publication in sorted(PUBLICATION_ROOT.rglob("*.pdf")):
            size = publication.stat().st_size
            if size > MAX_PUBLISHED_PDF_BYTES:
                oversized.append(
                    f"{publication.relative_to(REPOSITORY_ROOT)}: {size} bytes"
                )

        self.assertEqual(
            oversized,
            [],
            "Published PDFs must remain directly cloneable without Git LFS:\n"
            + "\n".join(oversized),
        )

    def test_installation_media_is_never_tracked(self):
        media = [
            path.relative_to(REPOSITORY_ROOT).as_posix()
            for path in self.tracked_files()
            if path.suffix.lower() in INSTALLATION_MEDIA_SUFFIXES
        ]
        self.assertEqual(
            media,
            [],
            "Installation media must be fetched into the disposable cache, "
            "not committed:\n" + "\n".join(media),
        )

    def test_disposable_media_cache_is_gitignored(self):
        candidates = (
            "homelab/var/media/arch/archlinux-x86_64.iso",
            "homelab/var/media/windows/windows-11-x64.iso",
            "homelab/var/media/wimboot",
            "homelab/var/media/download.partial",
        )
        result = subprocess.run(
            [
                "git",
                "-C",
                REPOSITORY_ROOT,
                "check-ignore",
                "--no-index",
                *candidates,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.stdout.splitlines(),
            list(candidates),
            "Every fetched media artifact and temporary download must remain ignored",
        )


if __name__ == "__main__":
    unittest.main()
