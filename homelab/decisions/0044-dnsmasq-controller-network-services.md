# ADR 0044: Use dnsmasq for initial Controller network services

- Status: Accepted
- Date: 2026-07-24

## Context

The initial Controller must optionally provide bundled DHCPv4 and DNS on an
isolated layer-2 network, supply PXE boot information, resolve `home.arpa`, and
operate without routing or NAT. On networks with external infrastructure such
as UniFi, Controller DHCP and DNS must remain disabled.

The main alternatives were:

- dnsmasq as one integrated DHCP, DNS, PXE, and small-file TFTP service;
- Kea DHCP plus a separate authoritative DNS server, DDNS integration, TFTP,
  and HTTP;
- systemd-networkd's DHCP server plus separate LAN-facing DNS and boot
  services; and
- external UniFi DHCP/DNS, which cannot satisfy the isolated-switch case by
  itself.

The functional proof values low operational burden over DHCP high availability,
database-backed lease management, API-driven IPAM, or advanced authoritative
DNS features.

## Decision

Use the Arch `dnsmasq` package as the initial host-native implementation of the
Controller's bundled network-services option.

When Controller network services are enabled:

- dnsmasq provides DHCPv4 and is the only address-assigning DHCP authority on
  the managed layer-2 network;
- dnsmasq serves the Controller's local `home.arpa` DNS data and eligible DHCP
  lease or reservation names;
- DHCP advertises the Controller as the DNS server and does not advertise a
  default router on the isolated network;
- dnsmasq supplies architecture-appropriate PXE information and a restricted,
  read-only TFTP service for the small first-stage boot program; and
- the service binds only to the explicitly selected managed interface and
  address.

When external infrastructure owns DHCP and DNS, keep the installed Controller's
dnsmasq network-service instance stopped. Whether the temporary bootstrap host
uses UniFi boot options or a separate dnsmasq ProxyDHCP configuration remains a
later decision.

Do not deploy Kea, BIND, Unbound, CoreDNS, or a separate TFTP daemon for the
initial Controller network-services bundle. Serve iPXE scripts, kernels,
initramfs images, WIMs, and other substantial artifacts over a separately
selected HTTP(S) service rather than TFTP.

Revisit the service split if the proven environment requires DHCP high
availability, several routed networks and relays, database- or API-driven IP
address management, independently operated DNS, or authoritative DNS features
beyond dnsmasq's practical scope.

## Consequences

- DHCP, local DNS, PXE selection, and first-stage TFTP share one daemon and one
  failure domain. This matches ADR 0012's deliberately bundled operating mode.
- DHCP lease names can become local DNS data without a separate DDNS daemon,
  protocol, or shared update credential.
- Configuration preflight can use `dnsmasq --test`, but that does not detect a
  competing DHCP server. The activation wrapper must perform the separately
  required interface, address, and DHCP-conflict checks and fail closed.
- TFTP remains unauthenticated and is limited to a dedicated root containing
  only the first-stage network loader.
- The exact subnet, Controller address, DHCP pool, lease and hostname policies,
  upstream resolver behavior, firewall rules, and HTTP(S) implementation remain
  open decisions.
- A later migration to a modular Kea and authoritative-DNS stack requires a new
  ADR and a tested lease, record, and boot-option migration.

## References

- dnsmasq manual:
  https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html
- Arch dnsmasq package:
  https://archlinux.org/packages/extra/x86_64/dnsmasq/
- Kea Administrator Reference Manual:
  https://kea.readthedocs.io/en/stable/
- Kea DHCP-DDNS architecture:
  https://kea.readthedocs.io/en/stable/arm/ddns.html
- systemd network configuration:
  https://man.archlinux.org/man/systemd.network.5.en
- UniFi DHCP server and network-boot options:
  https://help.ui.com/hc/en-us/articles/360012097513-UniFi-DHCP-Server
