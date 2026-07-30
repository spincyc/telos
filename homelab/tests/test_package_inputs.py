"""Executable parity checks between package policy and image/build inputs."""

from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from package_contract import (  # noqa: E402
    PROFILE_OVERLAYS,
    load_registry,
    merge_contract,
)


def package_names(path: Path) -> tuple[str, ...]:
    packages = tuple(
        value
        for raw in path.read_text(encoding="utf-8").splitlines()
        if (value := raw.split("#", 1)[0].strip())
    )
    duplicates = sorted(
        package for package in set(packages) if packages.count(package) > 1
    )
    if duplicates:
        raise ValueError(
            f"{path} repeats package entries: {', '.join(duplicates)}"
        )
    return packages


def ansible_package_tasks(path: Path) -> tuple[frozenset[str], ...]:
    """Extract literal names from package and pacman task blocks."""
    lines = path.read_text(encoding="utf-8").splitlines()
    tasks: list[frozenset[str]] = []
    for module_index, raw in enumerate(lines):
        content = raw.split("#", 1)[0].rstrip()
        if content.lstrip() not in (
            "ansible.builtin.package:",
            "community.general.pacman:",
        ):
            continue
        module_indent = len(content) - len(content.lstrip())
        names: list[str] = []
        index = module_index + 1
        while index < len(lines):
            child = lines[index].split("#", 1)[0].rstrip()
            index += 1
            if not child.strip():
                continue
            child_indent = len(child) - len(child.lstrip())
            if child_indent <= module_indent:
                break
            stripped = child.strip()
            if stripped.startswith("name:"):
                scalar = stripped.removeprefix("name:").strip()
                if scalar:
                    names.append(scalar)
                    continue
                while index < len(lines):
                    item = lines[index].split("#", 1)[0].rstrip()
                    if not item.strip():
                        index += 1
                        continue
                    item_indent = len(item) - len(item.lstrip())
                    if item_indent <= child_indent:
                        break
                    item_value = item.strip()
                    if not item_value.startswith("- "):
                        raise ValueError(
                            f"{path}:{index + 1}: package name must be literal"
                        )
                    names.append(item_value.removeprefix("- ").strip())
                    index += 1
        if not names:
            raise ValueError(
                f"{path}:{module_index + 1}: package task has no literal names"
            )
        if len(names) != len(set(names)):
            raise ValueError(
                f"{path}:{module_index + 1}: package task repeats a name"
            )
        tasks.append(frozenset(names))
    return tuple(tasks)


class PackageInputParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = load_registry(ROOT / "package-contract.json")

    def required(self, *overlays: str) -> set[str]:
        return set(merge_contract(self.registry, list(overlays)).packages)

    def test_archiso_contains_exact_installer_profile(self):
        actual = set(package_names(ROOT / "archiso/packages.x86_64"))
        self.assertEqual(
            actual, self.required(*PROFILE_OVERLAYS["installer-live"]))

    def test_seed_contains_controller_and_build_profiles(self):
        actual = set(package_names(ROOT / "seed/packages.txt"))
        required = self.required(*PROFILE_OVERLAYS["controller-seed"])
        self.assertLessEqual(required, actual)
        self.assertEqual(
            actual - required,
            {"dosfstools", "linux-firmware", "linux-lts", "networkmanager"},
        )

    def test_domain_ansible_list_covers_domain_overlay(self):
        tasks = ansible_package_tasks(
            ROOT / "ansible/roles/domain_controller/tasks/main.yml"
        )
        overlay = frozenset(
            self.registry.overlays["controller-domain"].packages
        )
        self.assertIn(overlay, tasks)

    def test_identity_ansible_list_covers_directory_client_packages(self):
        tasks = ansible_package_tasks(
            ROOT / "ansible/roles/identity_client/tasks/main.yml"
        )
        required = frozenset({"krb5", "pam", "samba", "sssd"})
        self.assertIn(required, tasks)

    def test_update_ansible_list_covers_automatic_update_overlay(self):
        tasks = ansible_package_tasks(
            ROOT / "ansible/roles/arch_updates/tasks/main.yml"
        )
        required = frozenset(
            self.registry.overlays["automatic-updates"].packages
        )
        self.assertTrue(any(required <= task for task in tasks))

    def test_services_ansible_list_covers_services_overlay(self):
        tasks = ansible_package_tasks(
            ROOT / "ansible/roles/services/tasks/main.yml"
        )
        self.assertIn(frozenset({"podman"}), tasks)

    def test_package_input_rejects_duplicate_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "packages"
            path.write_text("curl\ncurl  # duplicate\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "repeats package entries"):
                package_names(path)


if __name__ == "__main__":
    unittest.main()
