# ADR 0006: Keep baseline and bootstrap DNS on UniFi

- Status: Superseded by ADR 0008
- Date: 2026-07-24

## Supersession

ADR 0008 supersedes this decision. The Controller must optionally function as
the primary DHCP and DNS server, so UniFi cannot be a mandatory baseline
dependency. This ADR remains as the record of the earlier decision.

## Context

The Controller may eventually benefit from hosting authoritative DNS for
identity or service discovery. Making it the only DNS server would create a
circular dependency: DNS needed to locate or rebuild the Controller would
disappear whenever the Controller was unavailable.

Advertising DNS servers with different views as nominal primary and backup
servers would also be unreliable. Clients can continue using a responding
server even when it returns an authoritative but inconsistent answer.

## Decision

Keep UniFi as the normal client-facing DNS endpoint and the owner of the
Controller's bootstrap record. For a Controller whose instance hostname is
`polycarp`, that record is `polycarp.home.arpa`.

Defer Controller-hosted DNS. A later design may place an authoritative child
zone on the Controller and configure a UniFi Forward Domain rule for that child
zone, but it must preserve the UniFi-hosted Controller bootstrap record.

## Consequences

- Clients continue to receive the UniFi DNS endpoint through DHCP.
- The Controller's fully qualified hostname remains resolvable while that
  Controller is being rebuilt, although its services remain unavailable until
  the rebuild succeeds.
- Normal DNS resolution does not depend on Polycarp.
- UniFi's required local DNS records and recovery procedure must be documented
  and backed up outside Polycarp.
- Controller-hosted DNS is not part of the initial architecture.
- If a future Controller-hosted zone becomes critical, it needs a replica on a
  different physical host; another VM on Polycarp is not an independent failure
  domain.
- PXE boot files, artifacts, and reconstruction instructions still need an
  off-Controller recovery path; this DNS decision does not solve that bootstrap
  problem.

## References

- [UniFi DNS Records and Local Hostnames](https://help.ui.com/hc/en-us/articles/15179064940439-UniFi-DNS-Records-and-Local-Hostnames)
- [UniFi Content and Domain Filtering](https://help.ui.com/hc/en-us/articles/12568927589143-Content-and-Domain-Filtering-in-UniFi)
- [Microsoft DNS client guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/best-practices-for-dns-client-settings)
