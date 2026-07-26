"""Tests for the Arch package-closure guard.

The guard exists because `make install-dependencies-arch` is supposed to run
without somebody watching it, and a virtual dependency with two providers stops
the transaction to ask a question. These tests use synthetic databases, so they
run on any host and do not depend on what the repositories happen to contain
today.
"""

import importlib.machinery
import importlib.util
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    loader = importlib.machinery.SourceFileLoader(
        "arch_packages", str(ROOT / "scripts" / "arch-packages"))
    spec = importlib.util.spec_from_loader("arch_packages", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


arch_packages = _load()


def database(entries):
    """Build the (packages, providers) pair from a compact description."""
    packages, providers = {}, {}
    for name, fields in entries.items():
        packages[name] = {"NAME": [name],
                          "DEPENDS": list(fields.get("depends", [])),
                          "PROVIDES": list(fields.get("provides", []))}
        for provided in fields.get("provides", []):
            entry = providers.setdefault(
                arch_packages.dependency_name(provided), {})
            entry.setdefault(name, set()).add(arch_packages.exact_version(provided))
    return packages, providers


class TestAmbiguities(unittest.TestCase):
    def test_two_providers_of_a_virtual_name_is_a_question(self):
        packages, providers = database({
            "qemu-audio-jack": {"depends": ["jack"]},
            "jack2": {"provides": ["jack"]},
            "pipewire-jack": {"provides": ["jack"]},
        })
        found = arch_packages.ambiguities(["qemu-audio-jack"], packages, providers)
        self.assertEqual([f["virtual"] for f in found], ["jack"])
        self.assertEqual(found[0]["providers"], ["jack2", "pipewire-jack"])

    def test_the_path_names_what_pulled_it_in(self):
        packages, providers = database({
            "qemu-full": {"depends": ["qemu-audio-jack"]},
            "qemu-audio-jack": {"depends": ["jack"]},
            "jack2": {"provides": ["jack"]},
            "pipewire-jack": {"provides": ["jack"]},
        })
        found = arch_packages.ambiguities(["qemu-full"], packages, providers)
        self.assertEqual(found[0]["path"], ["qemu-full", "qemu-audio-jack", "jack"])

    def test_a_single_provider_is_not_a_question(self):
        packages, providers = database({
            "thing": {"depends": ["libonly.so"]},
            "only": {"provides": ["libonly.so"]},
        })
        self.assertEqual(arch_packages.ambiguities(["thing"], packages, providers), [])

    def test_a_real_package_wins_over_the_same_virtual_name(self):
        # `bash` is a package; other packages also provide `bash`. pacman takes
        # the real one and asks nothing.
        packages, providers = database({
            "thing": {"depends": ["bash"]},
            "bash": {},
            "busybox": {"provides": ["bash"]},
            "dash": {"provides": ["bash"]},
        })
        self.assertEqual(arch_packages.ambiguities(["thing"], packages, providers), [])

    def test_a_provider_already_in_the_transaction_settles_it(self):
        # dnsmasq depends on both `nettle` and `libnettle.so`. nettle arrives by
        # name, so the soname needs no choice.
        packages, providers = database({
            "dnsmasq": {"depends": ["nettle", "libnettle.so"]},
            "nettle": {"provides": ["libnettle.so"]},
            "nettle3": {"provides": ["libnettle.so"]},
        })
        self.assertEqual(arch_packages.ambiguities(["dnsmasq"], packages, providers), [])

    def test_the_soname_version_narrows_the_providers(self):
        # libxcrypt provides libcrypt.so=2, libxcrypt-compat provides =1. A
        # dependency on =2 has exactly one candidate.
        packages, providers = database({
            "perl": {"depends": ["libcrypt.so=2-64"]},
            "libxcrypt": {"provides": ["libcrypt.so=2-64"]},
            "libxcrypt-compat": {"provides": ["libcrypt.so=1-64"]},
        })
        self.assertEqual(arch_packages.ambiguities(["perl"], packages, providers), [])

    def test_matching_soname_versions_are_still_a_question(self):
        packages, providers = database({
            "thing": {"depends": ["libz.so=1-64"]},
            "zlib": {"provides": ["libz.so=1-64"]},
            "zlib-ng-compat": {"provides": ["libz.so=1-64"]},
        })
        found = arch_packages.ambiguities(["thing"], packages, providers)
        self.assertEqual(found[0]["providers"], ["zlib", "zlib-ng-compat"])

    def test_a_package_in_no_repository_is_reported(self):
        packages, providers = database({"real": {}})
        found = arch_packages.ambiguities(["real", "imaginary"], packages, providers)
        self.assertEqual([f["missing"] for f in found], ["imaginary"])

    def test_a_cycle_terminates(self):
        packages, providers = database({
            "a": {"depends": ["b"]},
            "b": {"depends": ["a"]},
        })
        self.assertEqual(arch_packages.ambiguities(["a"], packages, providers), [])


class TestDeclaredPackages(unittest.TestCase):
    def test_variables_expand_across_continuation_lines(self):
        makefile = ROOT / "build" / "test-arch-packages.mk"
        makefile.parent.mkdir(parents=True, exist_ok=True)
        makefile.write_text(textwrap.dedent("""\
            ARCH_ONE := alpha beta
            ARCH_TWO := gamma \\
            \tdelta
            ARCH_PROVIDER_PACKAGES :=
            ARCH_DEPENDENCY_PACKAGES := $(ARCH_ONE) $(ARCH_TWO) \\
            \t$(ARCH_PROVIDER_PACKAGES)
            """))
        self.assertEqual(arch_packages.declared_packages(makefile),
                         ["alpha", "beta", "gamma", "delta"])

    def test_the_real_makefile_declares_the_homelab_packages(self):
        declared = arch_packages.declared_packages()
        for expected in ("qemu-base", "edk2-ovmf", "archiso", "ansible"):
            self.assertIn(expected, declared)
        # The packages that would ask about jack must never appear.
        for forbidden in ("qemu-full", "qemu-desktop"):
            self.assertNotIn(forbidden, declared)


if __name__ == "__main__":
    unittest.main()
