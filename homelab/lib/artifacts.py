"""The HTTP artifact service and the iPXE script it serves.

ADR 0048 selects nginx and requires a manifest listing every artifact with its
SHA-256, verified by the installer before use. ADR 0044 keeps TFTP to the
first-stage loader only, so everything substantial arrives over HTTP.

Both the Controller and the temporary bootstrap host under ADR 0052 run this
same generated configuration, so the path exercised during the first build is
the path exercised for every build after it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

DOCUMENT_ROOT = "/srv/http/boot"
MANIFEST_NAME = "manifest.json"
SERVICE_USER = "homelab-http"


def render_nginx(*, listen_address: str, document_root: str = DOCUMENT_ROOT) -> str:
    """The artifact service. Read-only, one root, bound to one address."""
    return f"""# Homelab artifact service --- GENERATED, do not edit by hand.
# Source: homelab/lib/artifacts.py
#
# ADR 0048  nginx serves kernels, initramfs images and installer payloads.
# ADR 0044  TFTP carries only the first-stage loader; this carries the rest.
# ADR 0011  bound to the managed address only; this host does not route.

worker_processes 1;
error_log /var/log/nginx/homelab-error.log warn;
pid /run/nginx-homelab.pid;

events {{
    worker_connections 64;
}}

http {{
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    access_log    /var/log/nginx/homelab-access.log;

    sendfile      on;
    keepalive_timeout 15;

    server {{
        # Bind the managed address explicitly. A Controller with a second NIC
        # must not start serving boot artifacts on a network it does not own.
        listen {listen_address}:80;
        server_name _;

        root {document_root};

        # Read-only by construction: no upload, no method other than GET/HEAD,
        # and no directory listing of the published tree.
        autoindex off;
        limit_except GET HEAD {{ deny all; }}

        location / {{
            try_files $uri =404;
        }}
    }}
}}
"""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(root: Path) -> dict:
    """Checksum every published artifact.

    ADR 0043 permits checksum-verified artifacts during the functional proof and
    requires that provenance still be checked. This is that check's input.
    """
    root = Path(root)
    entries = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != MANIFEST_NAME:
            entries[path.relative_to(root).as_posix()] = sha256_of(path)
    return {"schema": 1, "artifacts": entries}


def verify_against(manifest: dict, root: Path) -> list[str]:
    """Return a problem for every artifact that is missing or altered."""
    root = Path(root)
    problems = []
    for name, expected in sorted(manifest.get("artifacts", {}).items()):
        path = root / name
        if not path.is_file():
            problems.append(f"{name}: listed in the manifest but not present")
            continue
        actual = sha256_of(path)
        if actual != expected:
            problems.append(
                f"{name}: checksum mismatch\n"
                f"    expected {expected}\n"
                f"    actual   {actual}")
    return problems


def render_ipxe(*, base_url: str, kernel: str = "vmlinuz-linux",
                initramfs: str = "initramfs-linux.img",
                archiso_label: str = "HOMELAB_INSTALL") -> str:
    """The iPXE script chainloaded after the first stage.

    Deliberately not a menu. There is exactly one thing to boot, and a menu with
    one entry is a timeout waiting to select the wrong thing.
    """
    return f"""#!ipxe
# Homelab network boot --- GENERATED, do not edit by hand.
# Source: homelab/lib/artifacts.py

echo
echo Homelab provisioning environment
echo Serving from {base_url}
echo

set base {base_url}

# The installer environment is interactive by design (ADR 0058). It asks
# every question at the console and writes nothing without authorization.
kernel ${{base}}/{kernel} \\
    archisobasedir=arch \\
    archisosearchuuid=${{uuid}} \\
    archiso_http_srv=${{base}}/ \\
    cms_verify=y \\
    console=ttyS0,115200 console=tty0 \\
    initrd={initramfs}

initrd ${{base}}/{initramfs}
boot || goto failed

:failed
echo
echo Boot failed. The artifact service may be unreachable, or an artifact
echo may not match its published checksum.
echo
shell
"""
