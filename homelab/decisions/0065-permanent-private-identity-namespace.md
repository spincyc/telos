# ADR 0065: Use a permanent private identity namespace

- Status: Accepted
- Date: 2026-07-27

## Context

Windows domain join requires Active Directory. The deployment has no public
domain and clients must survive replacement of the first domain controller.

## Decision

Require the private instance overlay to freeze these values before provisioning
the first domain:

- `identity.dns_domain`, beneath the reserved `home.arpa` suffix;
- `identity.kerberos_realm`, the uppercase form of that DNS domain;
- `identity.netbios_name`;
- `services.bootstrap_dc_fqdn`; and
- `services.permanent_dc_fqdn`.

Use Samba AD with its internal DNS. Domain members discover LDAP, Kerberos,
global catalog and password services through AD DNS SRV records; they must not
encode a particular DC as the identity service.

The first implementation runs as host-level processes in the Arch operating
system of the bootstrap Controller: no container or nested service VM separates
Samba from that Controller. ADR 0067 places this first Controller OS in a QEMU
VM on the development workstation. A later physical Controller runs the same
roles directly in its Arch host OS.

## Consequences

- The identity domain is a child of ADR 0005's reserved `home.arpa` namespace.
- Samba DNS, accurate time and restricted AD firewall access are mandatory.
- The realm and NetBIOS name are effectively permanent.
- Moving identity into a VM later does not require workstation rebuilds.
- This amends only ADR 0055's VM-only placement rule. ADR 0055's identity,
  client, local-home and break-glass decisions remain accepted.

## References

- https://wiki.samba.org/index.php/Setting_up_Samba_as_an_Active_Directory_Domain_Controller
- https://wiki.samba.org/index.php/Samba_Internal_DNS_Back_End
