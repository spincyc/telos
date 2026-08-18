"""Executable parity checks between package policy and image/build inputs."""

import ast
from importlib import import_module
from pathlib import Path
import re
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

from package_contract import (  # noqa: E402
    EXPECTED_OVERLAYS,
    PROFILE_OVERLAYS,
    load_registry,
    merge_contract,
    parse_registry,
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
    """Units enabled by `systemctl enable` inside a generated shell payload.

    A unit name interpolated from a module constant (``{JOIN_ONCE_UNIT_NAME}``)
    is resolved against that module rather than skipped: the old pattern
    silently matched nothing there, so an enabled unit could stay undeclared
    while the parity test still passed.
    """
    text = path.read_text(encoding="utf-8")
    units: set[str] = set()
    for match in re.finditer(
        r"systemctl enable ((?:\{?[A-Za-z0-9@._-]+\}? ?)+)", text
    ):
        for unit in match.group(1).split():
            if unit.startswith("{") and unit.endswith("}"):
                unit = _module_constant(path, unit[1:-1])
            units.add(unit if "." in unit else f"{unit}.service")
    return frozenset(units)


def _module_constant(path: Path, name: str) -> str:
    """The value of a module-level string constant, by import.

    The rendered payload interpolates a local binding (``{join_once_unit_name}``)
    whose value comes from the module constant of the same name in upper case,
    so both spellings are tried before giving up.
    """
    module = import_module(f"homelab.{path.parent.name}.{path.stem}")
    for candidate in (name, name.upper()):
        value = getattr(module, candidate, None)
        if isinstance(value, str) and value:
            return value
    raise AssertionError(
        f"{path.name} interpolates {{{name}}} into `systemctl enable` but "
        f"exposes no matching string constant to resolve it")


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
            # The one-shot in-run domain join: gate 8 boots into a freshly
            # provisioned domain, so the disk must re-join before sssd starts.
            "telos-arch-join-once.service",
            # The one-shot login-readiness gate: sssd.service reaching active
            # does not mean its AD backend is online, so this holds user
            # sessions -- and the ttyS0 getty -- until the domain is usable.
            "telos-arch-domain-online.service",
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


# ---------------------------------------------------------------------------
# Required python modules, derived from the python this repository delivers.
#
# Declaring imports per role is only worth anything if the declaration is held
# to the source. A hand-maintained list rots exactly the way `ldb` did: it is
# imported by `provision-accounts.py`, it survives only as a transitive pacman
# dependency of samba, and nothing noticed.
#
# So the required names are derived rather than restated, from every place this
# repository puts python inside a guest:
#
#   * a role file copied into the guest (`ansible.builtin.copy`);
#   * a `python3 -c` payload the serial console runs in the Controller;
#   * a program held as a module-level source constant and shipped to the
#     Controller's interpreter over the console.
#
# Guest python outside that set is stdlib-only and is covered elsewhere:
# `bin/homelab-install` and its `lib/` closure by `test_image.py`,
# `seed/verify-seed`, `vm/arch_install_prepare.py` (deliberately stdlib-only by
# its own docstring), the `workstations/arch_second.py` heredoc, and the
# `vm/factory_publication.py` inline payload (`pathlib`, `urllib.request`).

STDLIB = frozenset(sys.stdlib_module_names)
# A single-quoted, single-line shell payload. The escaped and line-split forms
# in `vm/factory_publication.py` and `vm/controller_principals.py` are not
# reconstructible from source text, so they are not guessed at: the first is
# stdlib-only, and the second is a base64 loader whose real program is a module
# constant that `embedded_program_modules` reads directly.
INLINE_PYTHON_RE = re.compile(r"python3?\s+-c\s+'([^']*)'")
ROLE_PATH_REFERENCE = "{{ role_path }}/files/"


def imported_modules(source: str, where: str) -> frozenset[str]:
    """Every non-stdlib module name a python program imports.

    `import samba.samdb` and `from samba.samdb import SamDB` both require
    `samba/samdb` to exist, so both are recorded under the dotted name rather
    than under the top-level package: proving `samba` is installed says nothing
    about whether the submodule that actually runs is there.

    Fail-closed. A relative import, an unparseable program, or a dynamic import
    raises instead of quietly contributing nothing, because a silent miss would
    let an undeclared requirement through this gate.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise ExtractionError(f"{where}: is not parseable python: {error}")
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                raise ExtractionError(
                    f"{where}: relative import is not resolvable to a package")
            names.add(node.module)
        elif isinstance(node, ast.Call):
            function = node.func
            dynamic = (
                (isinstance(function, ast.Name)
                 and function.id == "__import__")
                or (isinstance(function, ast.Attribute)
                    and function.attr == "import_module")
            )
            if dynamic:
                raise ExtractionError(
                    f"{where}: a dynamic import is invisible to this gate")
    return frozenset(
        name for name in names if name.split(".")[0] not in STDLIB)


def role_python_files(role: Path) -> tuple[tuple[Path, str], ...]:
    """Each python file a role ships, paired with where it runs.

    A file copied into the managed node is a guest requirement. A file the role
    runs through `{{ role_path }}` with `delegate_to: localhost` is a host
    requirement -- `resolve-directory-accounts.py` reads the operator's own
    checkout and never reaches an image.

    Fail-closed on anything else: a role file that is both, or neither, is a
    delivery this extractor cannot classify, and guessing would either invent a
    requirement or lose one.
    """
    directory = role / "files"
    if not directory.is_dir():
        return ()
    yaml = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(role.rglob("*.yml"))
    )
    lines = yaml.splitlines()
    classified: list[tuple[Path, str]] = []
    for path in sorted(directory.iterdir()):
        if not path.is_file():
            continue
        first = path.read_text(encoding="utf-8").splitlines()[:1]
        if path.suffix != ".py" and not (
                first and first[0].startswith("#!") and "python" in first[0]):
            continue
        copied = re.search(
            rf"(?m)^\s*src:\s*{re.escape(path.name)}\s*$", yaml) is not None
        reference = ROLE_PATH_REFERENCE + path.name
        delegated = [
            index for index, line in enumerate(lines) if reference in line]
        local = any(
            "delegate_to: localhost" in line
            for index in delegated
            for line in lines[index:index + 40]
        )
        if copied == bool(delegated) or (delegated and not local):
            raise ExtractionError(
                f"{path}: is not unambiguously delivered to a guest or run on "
                f"the host by {role.name}")
        classified.append((path, "guest" if copied else "host"))
    return tuple(classified)


def role_guest_modules(role: Path) -> frozenset[str]:
    """Non-stdlib modules the python a role copies into a guest imports."""
    names: set[str] = set()
    for path, where in role_python_files(role):
        if where == "guest":
            names |= imported_modules(
                path.read_text(encoding="utf-8"), str(path))
    return frozenset(names)


def inline_guest_modules(path: Path) -> frozenset[str]:
    """Non-stdlib modules an inline `python3 -c` guest payload imports."""
    text = path.read_text(encoding="utf-8")
    names: set[str] = set()
    for match in INLINE_PYTHON_RE.finditer(text):
        names |= imported_modules(match.group(1), f"{path}: {match.group(1)}")
    return frozenset(names)


def embedded_program_modules(path: Path) -> frozenset[str]:
    """Non-stdlib modules a module-level guest program constant imports.

    A string constant counts as a program when it parses as python and contains
    an import. That finds `_STAGE_PROGRAM_TEMPLATE` and `_DESTROY_PROGRAM_TEMPLATE`
    without naming them, so a third program shipped the same way is picked up
    rather than missed, and it leaves ordinary string constants alone.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if not (isinstance(value, ast.Constant)
                and isinstance(value.value, str)):
            continue
        try:
            program = ast.parse(value.value)
        except SyntaxError:
            continue
        if not any(isinstance(inner, (ast.Import, ast.ImportFrom))
                   for inner in ast.walk(program)):
            continue
        target = node.targets[0]
        label = target.id if isinstance(target, ast.Name) else "?"
        names |= imported_modules(value.value, f"{path}:{label}")
    return frozenset(names)


class PythonModuleParityTests(unittest.TestCase):
    """Every module the delivered python imports is declared, and nothing more."""

    # Guest python that does not come from an ansible role. Both target the
    # Controller, so both answer to the controller-domain layer.
    EXTRA_GUEST_PYTHON = {
        "controller-domain": (
            (Path("vm/serial_automation.py"), inline_guest_modules),
            (Path("vm/controller_principals.py"), embedded_program_modules),
        ),
    }

    @classmethod
    def setUpClass(cls):
        cls.registry = load_registry(ROOT / "package-contract.json")

    @staticmethod
    def derived() -> dict[str, frozenset[str]]:
        """The required module names, per layer, from the sources themselves."""
        names = {overlay: set() for overlay in EXPECTED_OVERLAYS}
        names[None] = set()
        for role, overlay in ServiceInputParityTests.ROLE_OVERLAYS:
            names[overlay] |= role_guest_modules(ROOT / f"ansible/roles/{role}")
        for overlay, sources in (
                PythonModuleParityTests.EXTRA_GUEST_PYTHON.items()):
            for relative, extract in sources:
                names[overlay] |= extract(ROOT / relative)
        return {key: frozenset(value) for key, value in names.items()}

    def declared(self, origin: str) -> dict[str, frozenset[str]]:
        layers = {None: self.registry.common, **self.registry.overlays}
        return {
            key: frozenset(
                module.name for module in layer.modules
                if module.origin == origin)
            for key, layer in layers.items()
        }

    def test_declared_repository_modules_match_the_delivered_python(self):
        self.assertEqual(self.declared("repository"), self.derived())

    def test_the_derivation_actually_finds_the_controller_imports(self):
        """A derivation that quietly stopped finding anything would agree with
        an empty declaration, so the expected content is asserted directly."""
        self.assertEqual(
            self.derived()["controller-domain"],
            frozenset({
                "dns", "dns.resolver", "ldb",
                "samba.auth", "samba.param", "samba.provision", "samba.samdb",
            }),
        )

    def test_dropping_a_declared_module_breaks_parity(self):
        """`ldb` went undeclared for exactly as long as nothing checked."""
        for name in ("ldb", "dns.resolver", "samba.samdb"):
            with self.subTest(module=name):
                raw = self.raw_registry()
                modules = raw["overlays"]["controller-domain"]["modules"]
                raw["overlays"]["controller-domain"]["modules"] = [
                    entry for entry in modules if entry["name"] != name]
                self.assertNotEqual(
                    self.repository_modules(parse_registry(raw)),
                    self.derived(),
                )

    def test_an_undeclared_role_import_breaks_parity(self):
        with tempfile.TemporaryDirectory() as directory:
            role = Path(directory) / "invented_role"
            (role / "files").mkdir(parents=True)
            (role / "tasks").mkdir()
            (role / "tasks/main.yml").write_text(
                "---\n- name: Install it\n  ansible.builtin.copy:\n"
                "    src: agent.py\n    dest: /usr/local/libexec/agent\n",
                encoding="utf-8",
            )
            (role / "files/agent.py").write_text(
                "import json\nimport nowhere_near_stdlib\n", encoding="utf-8")
            self.assertEqual(
                role_guest_modules(role), frozenset({"nowhere_near_stdlib"}))

    def test_a_host_delegated_role_file_is_not_a_guest_requirement(self):
        classified = dict(
            role_python_files(ROOT / "ansible/roles/domain_controller"))
        self.assertEqual(
            {path.name: where for path, where in classified.items()},
            {
                "provision-accounts.py": "guest",
                "provision-domain.py": "guest",
                "resolve-directory-accounts.py": "host",
            },
        )

    def test_the_extractor_refuses_what_it_cannot_read(self):
        with self.assertRaisesRegex(ExtractionError, "relative import"):
            imported_modules("from . import sibling\n", "<test>")
        with self.assertRaisesRegex(ExtractionError, "dynamic import"):
            imported_modules(
                "import importlib\nimportlib.import_module('x')\n", "<test>")
        with self.assertRaisesRegex(ExtractionError, "not parseable"):
            imported_modules("def (\n", "<test>")

    def test_upstream_modules_are_owner_assertions_no_source_makes(self):
        """python-cryptography and python-markdown are samba's own runtime
        dependencies. Nothing in this repository imports them, so they are
        recorded as owner assertions rather than dressed up as a derivation --
        and marking them that way is only honest while it stays underivable."""
        upstream = self.declared("upstream")
        self.assertEqual(
            upstream["controller-domain"],
            frozenset({"cryptography", "markdown"}))
        self.assertEqual(
            frozenset().union(*(
                names for key, names in upstream.items()
                if key != "controller-domain")),
            frozenset(),
        )
        derived = frozenset().union(*self.derived().values())
        self.assertTrue(derived.isdisjoint(upstream["controller-domain"]))

    def test_every_declared_module_names_an_installed_owner(self):
        """The owner is what the root gate matches ALPM ownership against, so a
        name that no package in the profile could supply is a dead declaration."""
        merged = merge_contract(self.registry, PROFILE_OVERLAYS["controller-seed"])
        self.assertEqual(
            {module.name: module.owner for module in merged.modules},
            {
                "cryptography": "python-cryptography",
                "dns": "python-dnspython",
                "dns.resolver": "python-dnspython",
                "ldb": "ldb",
                "markdown": "python-markdown",
                "samba.auth": "samba",
                "samba.param": "samba",
                "samba.provision": "samba",
                "samba.samdb": "samba",
            },
        )

    def test_roles_deliver_python_only_through_forms_this_gate_reads(self):
        """`ansible.builtin.script`, an inline payload, or a templated program
        would each put python in a guest that the derivation never sees."""
        module = re.compile(r"(?m)^\s*(?:ansible\.builtin\.)?script:")
        inline = re.compile(r"python3?\s+-c")
        for path in sorted((ROOT / "ansible").rglob("*")):
            if not path.is_file() or path.suffix in (".py", ".md"):
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for pattern in (module, inline):
                self.assertIsNone(
                    pattern.search(text),
                    f"{path} delivers python this gate cannot read")
        self.assertEqual(
            sorted(path.name for path in (ROOT / "ansible").rglob("templates/*")
                   if path.suffix == ".py"),
            [],
        )

    def raw_registry(self):
        import json
        return json.loads(
            (ROOT / "package-contract.json").read_text(encoding="utf-8"))

    @staticmethod
    def repository_modules(registry):
        layers = {None: registry.common, **registry.overlays}
        return {
            key: frozenset(
                module.name for module in layer.modules
                if module.origin == "repository")
            for key, layer in layers.items()
        }


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
