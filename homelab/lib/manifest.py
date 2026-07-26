"""The installation manifest: what this machine is, recorded on the machine.

ADR 0060 puts one JSON file at /etc/homelab/manifest.json and echoes it to the
console. It is the only durable record of an installation, and several accepted
decisions depend on it existing: ADR 0045's confirmed and derived network plan,
ADR 0043's `development-proof` label, ADR 0050's permanent MAC as the managed
interface's identity.

The manifest is non-secret **by construction**, and that is enforced here rather
than trusted to whoever adds a field next. `build()` refuses to produce a
manifest containing anything that looks like a credential, because the file is
readable by anyone who can unlock the root and because it is the obvious thing
for a future operator to paste into a bug report.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from typing import Any

SCHEMA_VERSION = 1
MANIFEST_PATH = "/etc/homelab/manifest.json"

# Key names that must never appear anywhere in a manifest, at any depth. This
# is a blunt instrument on purpose: the cost of a false positive is renaming a
# field, and the cost of a false negative is a secret in a world-readable file.
FORBIDDEN_KEY_PATTERN = re.compile(
    r"pass(word|phrase)|secret|private|credential|token|recovery[_-]?key"
    r"|luks[_-]?key|keyfile|\bpsk\b|\bpin\b",
    re.IGNORECASE,
)

# Values that look like key material regardless of what the field is called.
FORBIDDEN_VALUE_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"^\$[0-9a-z]+\$"),          # crypt(3) password hash
)


class ManifestError(ValueError):
    """A manifest that must not be written."""


def _walk(node: Any, path: str = "") -> list[tuple[str, Any]]:
    if isinstance(node, dict):
        found = []
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            found.append((here, value))
            found.extend(_walk(value, here))
        return found
    if isinstance(node, (list, tuple)):
        found = []
        for index, value in enumerate(node):
            here = f"{path}[{index}]"
            found.append((here, value))
            found.extend(_walk(value, here))
        return found
    return []


def assert_non_secret(document: dict) -> None:
    """Raise if anything in the manifest looks like a credential."""
    for path, value in _walk(document):
        leaf = path.split(".")[-1].split("[")[0]
        if FORBIDDEN_KEY_PATTERN.search(leaf):
            raise ManifestError(
                f"manifest field {path!r} looks like a credential. The manifest is "
                "non-secret by construction (ADR 0060); record an identity or a "
                "fingerprint, never the material itself."
            )
        if isinstance(value, str):
            for pattern in FORBIDDEN_VALUE_PATTERNS:
                if pattern.search(value):
                    raise ManifestError(
                        f"manifest field {path!r} contains what looks like key "
                        "material. Nothing of that kind belongs in this file."
                    )


def build(*, installer_version: str, installed_at: str, profile: str, hostname: str,
          development_proof: bool, firmware, target_disk, managed_interface=None,
          network_plan=None, partitions: list[dict] | None = None,
          verified_artifacts: dict[str, str] | None = None) -> dict:
    """Assemble the manifest and prove it carries no secrets.

    `firmware`, `target_disk`, `managed_interface` and `network_plan` are the
    dataclasses the rest of the installer already passes around, so the manifest
    records what was actually used rather than a re-derived copy of it.
    """
    document: dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "installer_version": installer_version,
        "installed_at": installed_at,
        "profile": profile,
        "hostname": hostname,
        "fqdn": f"{hostname}.home.arpa",
        # ADR 0043: this is a recorded project state, not a silent one. Later
        # tooling can refuse to treat such an installation as production.
        "development_proof": bool(development_proof),
        "firmware_observed": asdict(firmware),
        "target_disk": {
            "path": target_disk.path,
            "model": target_disk.model,
            "serial": target_disk.serial,
            "size_bytes": target_disk.size_bytes,
        },
        "partitions": partitions or [],
        "verified_artifacts": verified_artifacts or {},
    }

    if managed_interface is not None:
        document["managed_interface"] = {
            "installed_name": managed_interface.name,
            # ADR 0050: the MAC is the identity; the name is pinned to it.
            "permanent_mac": managed_interface.mac,
            "stable_name": "lan0",
        }

    if network_plan is not None:
        # ADR 0045 requires the confirmed inputs and every derived value.
        plan = asdict(network_plan)
        document["network"] = {
            "entered": {key: plan[key] for key in (
                "managed_ipv4_cidr", "controller_ipv4_address",
                "dhcp_pool_start", "dhcp_pool_end")},
            "derived": {key: plan[key] for key in (
                "network_address", "broadcast_address", "netmask", "prefix_length",
                "dns_server", "dns_suffix", "pool_size", "usable_addresses")},
            "default_router": None,
        }

    assert_non_secret(document)
    return document


def render(document: dict) -> str:
    """Stable, sorted JSON so two identical installs produce identical files."""
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def console_block(document: dict) -> list[str]:
    """The manifest as printed at the end of a run.

    ADR 0060 has the harness capture the manifest from the console, so the
    markers are part of the contract: they are how the acceptance matrix finds
    the JSON in a stream that also contains step output.
    """
    lines = ["--- BEGIN HOMELAB MANIFEST ---"]
    lines.extend(render(document).splitlines())
    lines.append("--- END HOMELAB MANIFEST ---")
    return lines


def extract_from_console(text: str) -> dict:
    """Recover the manifest from captured console output."""
    start = text.find("--- BEGIN HOMELAB MANIFEST ---")
    end = text.find("--- END HOMELAB MANIFEST ---")
    if start == -1 or end == -1 or end < start:
        raise ManifestError("no manifest found in the captured output")
    body = text[start + len("--- BEGIN HOMELAB MANIFEST ---"):end]
    return json.loads(body)
