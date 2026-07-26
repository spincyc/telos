# ADR 0045: Collect a minimal explicit Controller IPv4 network plan

- Status: Accepted
- Date: 2026-07-24

## Context

The Controller profile must configure a static service address and a dnsmasq
DHCPv4 pool without baking one lab-specific subnet into the generic profile.
Prompting for every value carried by DHCP would be repetitive and would invite
inconsistent netmasks, broadcast addresses, DNS addresses, or gateways.

The isolated network has no router, the Controller is its DNS endpoint, and
`home.arpa` is already fixed by earlier decisions. Those values should not be
presented as arbitrary inputs.

## Decision

When the bundled Controller network-services option is enabled, collect these
four machine-readable installation inputs:

- `managed_ipv4_cidr`: the canonical network address and prefix length for the
  managed subnet;
- `controller_ipv4_address`: the Controller's static service address;
- `dhcp_pool_start`: the first address in the inclusive dynamic pool; and
- `dhcp_pool_end`: the last address in the inclusive dynamic pool.

Derive rather than prompt for:

- the IPv4 netmask;
- the network and broadcast addresses;
- the client DNS-server address, which is
  `controller_ipv4_address`;
- the DNS suffix, which is `home.arpa`; and
- the absence of a default-router option.

Before destructive authorization, require all of the following:

- every input parses unambiguously as IPv4;
- `managed_ipv4_cidr` uses the actual network address rather than an address
  with host bits set;
- the subnet contains enough usable addresses for the Controller and pool;
- the Controller and both pool endpoints are usable unicast addresses inside
  the subnet;
- the pool start is not greater than the pool end;
- the Controller address is outside the inclusive DHCP pool; and
- the complete entered and derived network plan is displayed in the preflight
  summary.

Record the confirmed inputs and derived plan in the non-secret installation
manifest. If Controller-owned DHCP and DNS are disabled, these managed-network
inputs are not required; the external-network host-addressing policy remains a
separate decision.

Do not prompt for a netmask, broadcast address, DNS server, DNS suffix, or
gateway separately.

## Consequences

- The generic profile can install different autonomous networks without a
  hard-coded lab subnet.
- The operator makes the material address-allocation choices while deterministic
  values are calculated once.
- Contradictory netmask, DNS, and gateway inputs cannot reach dnsmasq
  configuration generation.
- The final destructive summary includes the future isolated-network identity,
  not merely disk and hostname information.
- The exact serialization format, prefix-size policy, lease duration,
  reservation range, client-hostname policy, and managed-interface selection
  remain open decisions.

## References

- dnsmasq manual:
  https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html
- IPv4 Address Conflict Detection:
  https://www.rfc-editor.org/rfc/rfc5227
