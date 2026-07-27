# ADR 0066: Keep UniFi DHCP and use Samba AD DNS

- Status: Accepted
- Date: 2026-07-27

## Context

The external UniFi gateway already owns DHCP. Active Directory requires
authoritative DNS for its domain, so DHCP and DNS cannot remain bundled as
earlier Controller decisions assumed.

## Decision

For the workstation-factory deployment:

- UniFi is the only address-assigning DHCP authority;
- Samba is authoritative for the private `identity_dns_domain`;
- managed clients receive Samba AD DNS through DHCP;
- Samba forwards non-AD queries to the selected upstream resolver;
- UniFi network-boot options select the x86-64 UEFI first-stage loader; and
- dnsmasq must not provide DHCP or bind DNS port 53.

A retained dnsmasq instance may serve only a proven, explicitly bound TFTP
function. Prefer a separate minimal first-stage service if simpler.

This supersedes the bundled-service requirements in ADRs 0008, 0012 and 0044
for this deployment. Their prohibition on competing DHCP authorities remains.
ADR 0045's Controller DHCP-pool inputs do not apply.

## Consequences

- AD service discovery works without a second DHCP authority.
- DNS forwarding and VLAN firewall rules need explicit tests.
- UniFi options 66/67 are infrastructure state, not workstation state.
