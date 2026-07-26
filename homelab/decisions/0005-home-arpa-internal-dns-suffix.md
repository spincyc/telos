# ADR 0005: Use home.arpa for internal DNS

- Status: Accepted
- Date: 2026-07-24

## Context

Each Workstation needs an unambiguous fully qualified hostname for its
Controller. The name should work across internal VLANs without depending on a
DHCP search suffix, and internal naming should not require purchasing or
registering a public domain.

## Decision

Use `home.arpa` as the internal DNS suffix. Controller references use a fully
qualified hostname beneath it, such as `polycarp.home.arpa`.

## Consequences

- No public registration is required or available for these locally significant
  names.
- A local DNS service must publish and resolve the records.
- Clients that bypass the locally supplied resolver may not resolve the names.
- The same name is not globally unique and must not be treated as proof of the
  Controller's identity.
- Publicly trusted certificate authorities cannot provide the trust model for
  these internal names; internal certificate trust or explicit key pinning must
  be designed separately.
- Remote Workstations will require the home resolver through a VPN or another
  deliberately designed discovery path when Controller access away from home is
  desired.
- DHCP and DNS ownership is deployment-mode-dependent under ADR 0008.
- Certificate trust and remote-resolution details remain open.

## References

- [RFC 8375: Special-Use Domain `home.arpa`](https://www.rfc-editor.org/rfc/rfc8375.html)
- [IANA Special-Use Domain Names](https://www.iana.org/assignments/special-use-domain-names/special-use-domain-names.xhtml)
- [UniFi DNS Records and Local Hostnames](https://help.ui.com/hc/en-us/articles/15179064940439-UniFi-DNS-Records-and-Local-Hostnames)
- [UniFi DHCP Server](https://help.ui.com/hc/en-us/articles/360012097513-UniFi-DHCP-Server)
