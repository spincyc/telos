"""Network boundary for the temporary bootstrap environment.

Only QEMU's socket transport is allowed during the offline build phase.  It
links guests to one another without creating a host interface, bridge, route,
DHCP service, or UniFi configuration.
"""

from __future__ import annotations

import re

ISOLATED_MODE = "isolated"
DEFAULT_PORT = 12961
_MAC = re.compile(r"^52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$")

_FORBIDDEN_TERMS = (
    "bridge",
    "br=",
    "helper=",
    "ifname=",
    "macvtap",
    "netdev tap",
    "netdev user",
    "passt",
    "proxy",
    "slirp",
    "trunk",
    "unifi",
    "vhost=",
)


class UnsafeNetworkPlan(ValueError):
    """The requested plan could change or reach the host network."""


def socket_network_args(
    *,
    role: str,
    mac: str,
    port: int = DEFAULT_PORT,
    mode: str = ISOLATED_MODE,
) -> list[str]:
    """Return a guest-only QEMU NIC, rejecting every physical attachment.

    One guest listens on a loopback TCP socket and the others connect to it.
    The socket carries virtual Ethernet frames only between those QEMU
    processes.  It supplies no NAT and no route to the host LAN.
    """
    if mode != ISOLATED_MODE:
        raise UnsafeNetworkPlan(
            f"network mode {mode!r} is deferred; only {ISOLATED_MODE!r} is allowed"
        )
    if role not in {"listen", "connect"}:
        raise UnsafeNetworkPlan("role must be 'listen' or 'connect'")
    if not _MAC.fullmatch(mac.lower()):
        raise UnsafeNetworkPlan("MAC must use the synthetic 52:54:00 prefix")
    if not 1024 <= port <= 65535:
        raise UnsafeNetworkPlan("socket port must be an unprivileged TCP port")

    endpoint = (
        f"socket,id=bootstrap,listen=127.0.0.1:{port}"
        if role == "listen"
        else f"socket,id=bootstrap,connect=127.0.0.1:{port}"
    )
    args = [
        "-nodefaults",
        "-netdev",
        endpoint,
        "-device",
        f"virtio-net-pci,netdev=bootstrap,mac={mac.lower()}",
    ]
    assert_isolated(args)
    return args


def assert_isolated(argv: list[str]) -> None:
    """Fail closed if a QEMU command can attach to a real network."""
    text = " ".join(argv).lower()
    if "-nodefaults" not in argv:
        raise UnsafeNetworkPlan("QEMU defaults must be disabled")
    if argv.count("-netdev") != 1:
        raise UnsafeNetworkPlan("exactly one network backend is allowed")
    backend = argv[argv.index("-netdev") + 1].lower()
    if not backend.startswith("socket,id=bootstrap,"):
        raise UnsafeNetworkPlan("the bootstrap socket transport is required")
    if "127.0.0.1" not in backend:
        raise UnsafeNetworkPlan("the bootstrap socket must bind to loopback")
    if "-nic" in argv:
        raise UnsafeNetworkPlan("QEMU shorthand NICs are not allowed")
    for term in _FORBIDDEN_TERMS:
        if term in text:
            raise UnsafeNetworkPlan(f"forbidden network attachment: {term}")


def describe() -> tuple[str, ...]:
    """Human-readable boundary for dry runs and manuals."""
    return (
        "Network mode: isolated QEMU socket segment",
        "Host interfaces changed: none",
        "Host bridges, routes, DHCP, and DNS changed: none",
        "UniFi settings changed: none",
        "Internet and household LAN access: none",
        "Physical attachment remains a later deployment gate",
    )
