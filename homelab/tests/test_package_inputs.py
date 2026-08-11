"""Executable parity checks between package policy and image/build inputs."""

from pathlib import Path
import re
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


ENABLING_MODULES = (
    "ansible.builtin.systemd:",
    "ansible.builtin.systemd_service:",
    "ansible.builtin.service:",
    "systemd:",
    "service:",
)
TRUE_LITERALS = frozenset({"true", "yes", "on"})
FALSE_LITERALS = frozenset({"false", "no", "off"})


class ExtractionError(AssertionError):
    """The source uses a form this extractor cannot honestly interpret."""


def ansible_enabled_units(path: Path) -> frozenset[str]:
    """Extract literal units an ansible role unconditionally enables.

    A templated name, a templated or conditional `enabled` value, and a task
    that disables a unit are all excluded: none is an unconditional promise.
    systemd resolves a bare name to `.service`; the contract records that
    resolved form.

    The extractor fails closed. A form it cannot interpret — a flow-style
    mapping, an unrecognized boolean spelling, or `systemctl enable` behind a
    shell module — raises rather than silently reporting nothing, because a
    silent miss would let an undeclared requirement pass this gate.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    units: set[str] = set()
    for module_index, raw in enumerate(lines):
        content = raw.split("#", 1)[0].rstrip()
        stripped = content.lstrip()
        if stripped.startswith(("ansible.builtin.command:", "ansible.builtin.shell:",
                                "command:", "shell:")):
            body = stripped.partition(":")[2]
            if "systemctl enable" in body:
                raise ExtractionError(
                    f"{path}:{module_index + 1}: systemctl enable behind a shell "
                    f"module is invisible to this gate")
            continue
        if stripped not in ENABLING_MODULES:
            if any(stripped.startswith(module.rstrip(":") + ": {")
                   for module in ENABLING_MODULES):
                raise ExtractionError(
                    f"{path}:{module_index + 1}: flow-style service mapping is "
                    f"not interpretable")
            continue
        module_indent = len(content) - len(content.lstrip())
        fields: dict[str, str] = {}
        index = module_index + 1
        while index < len(lines):
            child = lines[index].split("#", 1)[0].rstrip()
            index += 1
            if not child.strip():
                continue
            child_indent = len(child) - len(child.lstrip())
            if child_indent <= module_indent:
                break
            key, separator, value = child.strip().partition(":")
            if separator:
                fields[key] = value.strip().strip('"').strip("'")
        name = fields.get("name", "")
        enabled = fields.get("enabled")
        if enabled is None or "{{" in enabled:
            continue
        if enabled.lower() in FALSE_LITERALS:
            continue
        if enabled.lower() not in TRUE_LITERALS:
            raise ExtractionError(
                f"{path}:{module_index + 1}: unrecognized enabled value: {enabled}")
        if not name or "{{" in name:
            continue
        units.add(name if "." in name else f"{name}.service")
    return frozenset(units)


def role_enabled_units(role: Path) -> frozenset[str]:
    """Every unit a role enables, across its task and handler files."""
    units: set[str] = set()
    for name in ("tasks/main.yml", "handlers/main.yml"):
        path = role / name
        if path.is_file():
            units |= ansible_enabled_units(path)
    return frozenset(units)


def shell_enabled_units(path: Path) -> frozenset[str]:
    """Units enabled by `systemctl enable` inside a generated shell payload."""
    units: set[str] = set()
    for match in re.finditer(
        r"systemctl enable ((?:[A-Za-z0-9@._-]+ ?)+)",
        path.read_text(encoding="utf-8"),
    ):
        for unit in match.group(1).split():
            units.add(unit if "." in unit else f"{unit}.service")
    return frozenset(units)


def wants_linked_units(path: Path) -> frozenset[str]:
    """Units installed by symlink into a systemd `.wants` directory."""
    return frozenset(
        match.group(1)
        for match in re.finditer(
            r"\.wants/([A-Za-z0-9@._-]+\.(?:service|socket|timer))",
            path.read_text(encoding="utf-8"),
        )
    )


class NonAnsibleServiceParityTests(unittest.TestCase):
    """Roles whose units are enabled by code rather than by an ansible role."""

    @classmethod
    def setUpClass(cls):
        cls.registry = load_registry(ROOT / "package-contract.json")

    def declared(self, overlay: str) -> frozenset[str]:
        return frozenset(self.registry.overlays[overlay].services)

    def test_installer_live_declares_its_required_networkd_links(self):
        source = (ROOT / "bin/homelab-image").read_text(encoding="utf-8")
        required = frozenset(
            match.group(1)
            for match in re.finditer(
                r'\.wants/"?\s*\n?\s*"?([A-Za-z0-9@._-]+\.(?:service|socket))',
                source,
            )
        )
        self.assertTrue(required, "no required networkd links were found")
        self.assertEqual(self.declared("installer-live"), required)

    def test_workstation_profile_declares_what_the_installer_enables(self):
        # The installer enables identity and console units beyond networking,
        # so parity is judged against the whole workstation-install profile,
        # not the workstation overlay alone.
        enabled = shell_enabled_units(ROOT / "workstations/arch_second.py")
        self.assertEqual(enabled, frozenset({
            "NetworkManager.service",
            "sssd.service",
            "serial-getty@ttyS0.service",
        }))
        profile_declared = frozenset().union(*(
            self.declared(overlay)
            for overlay in PROFILE_OVERLAYS["workstation-install"]
        ))
        self.assertEqual(profile_declared, enabled)

    def test_controller_factory_declares_its_unconditional_units(self):
        linked = wants_linked_units(ROOT / "vm/factory_publication.py")
        declared = self.declared("controller-factory")
        self.assertTrue(declared <= linked)
        # smb.service is enabled only for a verified Windows source, so it is
        # deliberately absent from the unconditional declaration.
        self.assertEqual(linked - declared, frozenset({"smb.service"}))


class ServiceInputParityTests(unittest.TestCase):
    """Every unconditionally enabled unit is declared, and nothing more."""

    ROLE_OVERLAYS = (
        ("common", None),
        ("controller_network", "controller-network"),
        ("domain_controller", "controller-domain"),
        ("identity_client", "identity-client"),
        ("arch_updates", "automatic-updates"),
        ("services", "services"),
    )

    @classmethod
    def setUpClass(cls):
        cls.registry = load_registry(ROOT / "package-contract.json")

    def test_every_ansible_role_is_mapped_to_a_layer(self):
        """An unmapped role could enable a unit no layer ever declares."""
        present = {
            path.name for path in (ROOT / "ansible/roles").iterdir()
            if path.is_dir()
        }
        self.assertEqual(present, {role for role, _ in self.ROLE_OVERLAYS})

    def test_declared_services_match_enabled_ansible_units(self):
        for role, overlay in self.ROLE_OVERLAYS:
            with self.subTest(role=role):
                layer = (
                    self.registry.common if overlay is None
                    else self.registry.overlays[overlay]
                )
                enabled = role_enabled_units(ROOT / f"ansible/roles/{role}")
                self.assertEqual(enabled, frozenset(layer.services))

    def test_disabled_and_templated_units_are_not_requirements(self):
        enabled = ansible_enabled_units(
            ROOT / "ansible/roles/domain_controller/tasks/main.yml")
        self.assertEqual(enabled, frozenset({"ntpd.service", "samba.service"}))
        self.assertTrue(
            enabled.isdisjoint({"smb.service", "nmb.service", "winbind.service"}))
        self.assertEqual(
            ansible_enabled_units(ROOT / "ansible/roles/services/tasks/main.yml"),
            frozenset(),
        )

    def test_controller_seed_merges_every_layer_deterministically(self):
        merged = merge_contract(
            self.registry, PROFILE_OVERLAYS["controller-seed"])
        self.assertEqual(
            merged.services,
            (
                "homelab-first-boot.service", "ntpd.service", "samba.service",
                "sshd.service", "sssd.service", "systemd-networkd.service",
                "telos-factory-http.service", "telos-factory-tftp.service",
                "telos-pxe-evidence.service", "telos-pxe-ready.service",
            ),
        )


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
