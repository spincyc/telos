"""Generate the Controller's dnsmasq configuration from a validated plan.

ADR 0044 selects dnsmasq as the single daemon providing DHCPv4, local
`home.arpa` DNS, PXE selection and first-stage TFTP. ADR 0012 bundles DHCP and
DNS so they start and stop as one unit. ADR 0011 forbids routing, NAT and a
default-router option. ADR 0013 limits the initial scope to IPv4.

Those four decisions have exactly one correct dnsmasq configuration between
them, so it is generated rather than hand-written. A generated file cannot drift
from the decision record, and the generator can be tested against the rules the
ADRs state.

The output is deliberately explicit about what it refuses to do. `--test` will
not catch a missing `no-dhcp-interface`, and a reviewer reading the file six
months from now should be able to see the ADR 0011 boundary in the file itself.
"""

from __future__ import annotations

from netplan import NetworkPlan

# TFTP serves only the first-stage network loader. Everything substantial --
# kernels, initramfs images, root filesystems, WIMs -- goes over HTTP under
# ADR 0044, because TFTP is unauthenticated and slow.
TFTP_ROOT = "/srv/tftp"
FIRST_STAGE_BIOS = "undionly.kpxe"
FIRST_STAGE_UEFI = "ipxe.efi"

DEFAULT_LEASE_TIME = "12h"


def render(
    plan: NetworkPlan,
    *,
    interface: str,
    controller_hostname: str,
    lease_time: str = DEFAULT_LEASE_TIME,
    http_base_url: str | None = None,
    enable_pxe: bool = True,
) -> str:
    """Return the complete dnsmasq.conf body for an enabled Controller.

    `interface` is the single managed interface selected at install time. The
    daemon binds to it and nothing else, so a Controller with a second NIC on a
    network it does not own cannot start answering DHCP there.
    """
    if not interface or not interface.strip():
        raise ValueError("a managed interface must be selected before generating dnsmasq configuration")
    if not controller_hostname or "." in controller_hostname:
        raise ValueError(
            "controller_hostname must be the short hostname; the domain is appended from the plan"
        )

    fqdn = f"{controller_hostname}.{plan.dns_suffix}"
    lines: list[str] = []
    add = lines.append

    add("# Controller network services --- GENERATED, do not edit by hand.")
    add("# Source: homelab/lib/dnsmasq.py, from the validated ADR 0045 network plan.")
    add("#")
    add("# ADR 0012  DHCP and DNS are one bundled unit.")
    add("# ADR 0044  dnsmasq is the only DHCP authority on this layer-2 network.")
    add("# ADR 0011  no routing, no NAT, and therefore no default route advertised.")
    add("# ADR 0013  IPv4 only; the host IPv6 stack stays enabled but unmanaged.")
    add("")

    add("# --- binding ------------------------------------------------------------")
    add("# Bind to exactly one selected interface. bind-interfaces (not bind-dynamic)")
    add("# so the daemon fails to start rather than quietly serving the wrong link.")
    add(f"interface={interface}")
    add("bind-interfaces")
    add("except-interface=lo")
    add(f"listen-address={plan.controller_ipv4_address}")
    add("")

    add("# --- DNS ----------------------------------------------------------------")
    add(f"domain={plan.dns_suffix}")
    add("local=/%s/" % plan.dns_suffix)
    add("domain-needed")
    add("bogus-priv")
    add("expand-hosts")
    add("# Answer only from local data and the hosts file. On the isolated")
    add("# acceptance network there is no upstream resolver to forward to, and")
    add("# ADR 0011 gives this Controller no route to one.")
    add("no-resolv")
    add("no-poll")
    add(f"host-record={fqdn},{plan.controller_ipv4_address}")
    add("")

    add("# --- DHCPv4 -------------------------------------------------------------")
    add(f"dhcp-range={plan.dhcp_pool_start},{plan.dhcp_pool_end},{plan.netmask},{lease_time}")
    add(f"dhcp-option=option:netmask,{plan.netmask}")
    add(f"dhcp-option=option:dns-server,{plan.dns_server}")
    add(f"dhcp-option=option:domain-name,{plan.dns_suffix}")
    add("")
    add("# ADR 0011: this Controller is not a router. Sending option 3 with no")
    add("# gateway behind it would black-hole every client on the isolated")
    add("# network. The empty value explicitly suppresses the option.")
    add("dhcp-option=option:router")
    add("")
    add("dhcp-authoritative")
    add("dhcp-rapid-commit")
    add("")

    if enable_pxe:
        add("# --- PXE ----------------------------------------------------------------")
        add("# TFTP carries only the first-stage loader. ADR 0044 keeps kernels,")
        add("# initramfs images and WIMs on HTTP.")
        add("enable-tftp")
        add(f"tftp-root={TFTP_ROOT}")
        add("tftp-secure")
        add("tftp-no-blocksize")
        add("")
        add("# Architecture-appropriate first stage. Legacy BIOS clients are served")
        add("# for completeness; ADR 0019 makes the Controller profile itself")
        add("# UEFI-only, and the installer refuses a BIOS-mode target.")
        add(f"dhcp-match=set:bios,option:client-arch,0")
        add(f"dhcp-boot=tag:bios,{FIRST_STAGE_BIOS}")
        add(f"dhcp-match=set:efi64,option:client-arch,7")
        add(f"dhcp-boot=tag:efi64,{FIRST_STAGE_UEFI}")
        add(f"dhcp-match=set:efi64b,option:client-arch,9")
        add(f"dhcp-boot=tag:efi64b,{FIRST_STAGE_UEFI}")
        add("")
        add("# Break the iPXE chainload loop: once iPXE itself is running it")
        add("# re-requests, and must then be handed the script rather than iPXE.")
        add("dhcp-match=set:ipxe,175")
        if http_base_url:
            add(f"dhcp-boot=tag:ipxe,{http_base_url.rstrip('/')}/boot.ipxe")
        else:
            add("# No HTTP artifact base URL was configured, so no iPXE script is")
            add("# offered. Network installation is unavailable until one is set.")
        add("")

    add("# --- hygiene ------------------------------------------------------------")
    add("log-dhcp")
    add("log-queries=extra")
    add("# Never hand out a lease for the Controller's own service address.")
    add(f"dhcp-host={plan.controller_ipv4_address},ignore")
    add("")
    return "\n".join(lines) + "\n"


def refusals(plan: NetworkPlan, rendered: str) -> list[str]:
    """Assertions about what the generated file must never contain.

    Called by the tests and by the installer's own self-check. These are the
    failure modes that a syntax check like `dnsmasq --test` cannot see: a
    perfectly valid configuration that violates an accepted decision.
    """
    problems: list[str] = []
    # Inspect directives only. The generated file explains itself in comments,
    # and a comment saying "not bind-dynamic" must not read as a violation.
    directives = [
        line.strip() for line in rendered.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]

    def has_directive(prefix: str) -> bool:
        return any(line.startswith(prefix) for line in directives)

    if any(line.startswith("dhcp-option=option:router,") for line in directives):
        problems.append("ADR 0011: a default router is advertised")
    if not has_directive("dhcp-range="):
        problems.append("ADR 0012: DHCP is not configured, so the bundle is incomplete")
    if not has_directive(f"listen-address={plan.controller_ipv4_address}"):
        problems.append("the daemon does not bind the Controller service address")
    if has_directive("bind-dynamic"):
        problems.append("bind-dynamic would let the daemon follow interfaces it does not own")
    if has_directive("dhcp-range=::") or has_directive("enable-ra"):
        problems.append("ADR 0013: managed IPv6 is out of scope")
    expected_range = f"dhcp-range={plan.dhcp_pool_start},{plan.dhcp_pool_end},"
    if not has_directive(expected_range):
        problems.append("the rendered pool does not match the validated plan")
    return problems
