# ADR 0076: Attach the controller without transferring network authority

- Status: Accepted
- Date: 2026-07-27

## Context

The isolated `bootstrap-dc` VM now boots successfully, but it has not been
tested on the physical UniFi network. UniFi already provides reliable DHCP,
routing and Internet access. Connecting a partially configured controller must
not introduce a second DHCP server, become the clients' DNS resolver, or make
workstation service depend on the experiment.

Later phases will add Samba AD DNS, PXE and identity services. Those changes
need separate, observable gates. A successful network attachment alone is not
authorization to enable them.

## Decision

Attach `bootstrap-dc` first as an ordinary UniFi DHCP client on a restricted
validation network. UniFi remains the sole network authority.

Before attachment:

- record the VM NIC MAC address and bind the VM bridge to one explicitly
  selected physical interface;
- create a UniFi DHCP reservation for `bootstrap-dc`;
- confirm that `dnsmasq`, Samba, nginx and every PXE service are disabled and
  inactive;
- confirm that nothing listens on UDP ports 53, 67, 69 or 4011;
- retain serial-console and `local-rescue` access independent of networking;
  and
- export or record the affected UniFi settings before changing them.

During this gate:

- UniFi supplies the address, default route, DNS resolver and NTP reachability;
- the controller must not advertise routes or provide DHCP, DNS, TFTP, HTTP
  boot, AD or PXE service;
- no UniFi DHCP option 66 or 67 is set;
- no client uses the controller as DNS;
- inbound access is limited to SSH from the administrative network; and
- the validation network may reach only the services required for Arch updates,
  time synchronization and explicit operator administration.

The operator verifies, in order:

1. UniFi shows exactly the reserved address and recorded MAC.
2. The controller's address, route, resolver and clock agree with UniFi.
3. A second device still receives its lease and DNS solely from UniFi.
4. A DHCP-discovery capture shows no offer from `bootstrap-dc`.
5. Port and socket checks show no listener on the prohibited service ports.
6. Rebooting or powering off `bootstrap-dc` has no effect on ordinary clients.

Only after those checks are recorded may later gates enable one controller
role at a time. Samba AD DNS, PXE options and workstation enrollment each
require their own rollout and rollback procedure. DHCP remains on UniFi
throughout, as required by ADR 0066.

## Rollback

If any check fails:

1. disconnect or disable the VM's bridged NIC;
2. power off `bootstrap-dc`;
3. remove the UniFi reservation and any firewall rule added only for this
   test;
4. confirm an ordinary client can renew DHCP, resolve DNS and reach its normal
   gateway without the controller; and
5. restore the recorded UniFi settings if they differ.

Rollback must not require logging in to `bootstrap-dc`. Serial-console access
is for diagnosis after network isolation, not a prerequisite for restoring the
network.

## Consequences

- Initial attachment cannot make the household network depend on the
  controller.
- The VM can receive updates and be observed in its eventual network context.
- A reserved address provides a stable test target without assigning the
  controller DHCP authority.
- AD DNS and PXE remain unavailable until later explicit gates.
- The operator must maintain a small UniFi reservation and restricted-network
  rule set during validation.
