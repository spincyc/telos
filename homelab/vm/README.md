# Bootstrap VM network boundary

The initial `bootstrap-dc` environment uses only QEMU socket networking bound
to host loopback. It can exchange Ethernet frames with test guests, but it
cannot reach the household LAN or internet.

This phase does not create a bridge, tap, route, VLAN, DHCP listener, firewall
rule, or UniFi setting. Physical attachment is deliberately deferred.

Code must obtain NIC arguments from `vm.network.socket_network_args()`. A later
network design may add an existing-LAN, dedicated-interface, or VLAN-trunk
profile, but none is accepted by the bootstrap implementation.

## Lifecycle boundary

`make homelab-bootstrap-vm-create APPLY=1` creates private state
transactionally. The state directory is mode 0700, its files are mode 0600,
and `manifest.json` records the VM shape, firmware provenance, creation time,
and blocked physical-network gate. Existing state, symlinked state paths, and
partial state are refused.

Boot installation media with
`make homelab-bootstrap-vm-run ISO=/path/to/arch.iso APPLY=1`. Omitting
`APPLY=1` prints the complete QEMU command without starting the guest.

The VM is temporary infrastructure, but its directory data becomes durable
once it provisions the real domain. Destruction therefore requires
`APPLY=1 CONFIRM=bootstrap-dc` and refuses unexpected or symlinked files.
Ansible convergence from the host cannot begin while the socket-only boundary
is in force; it waits for the separately approved physical-network gate.
