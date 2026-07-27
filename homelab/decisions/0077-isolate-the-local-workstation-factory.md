# 0077: Isolate the local workstation factory

Date: 2026-07-27

Status: accepted

## Decision

The complete controller and dual-boot workstation lifecycle must pass inside a
local, disposable QEMU network before any UniFi change or physical attachment.
The local runner fails closed unless all of these conditions hold:

- every guest NIC connects only to an explicitly audited host-loopback Ethernet
  hub; QEMU user networking, TAP, bridge, VDE, passt, forwarding, host port
  forwarding, shared filesystems, guest agents, and extra NICs are forbidden;
- the simulated gateway is the only DHCP authority and supplies the PXE
  next-server and boot-file options;
- the controller serves boot artifacts, HTTP, DNS, time, and synthetic
  directory identity as required, but sends no DHCP offer, acknowledgement, or
  negative acknowledgement, including proxy-DHCP replies;
- controller and workstation disks and writable firmware variables are
  disposable; accepted images and installation media are read-only and their
  hashes are unchanged after every run;
- an installer may erase only one disposable disk with the exact expected
  synthetic serial, after an explicit `APPLY=1` gate;
- Windows, Arch, and `wimboot` inputs pass their pinned provenance, digest, and
  content checks before they enter a PXE release;
- only public-safe synthetic domain, host, user, and credential values appear
  in the public lifecycle;
- secrets never appear in process arguments, generated answer files retained
  after the run, console evidence, or committed files;
- host links, addresses, routes, namespaces, bridges, VLANs, firewall state,
  and listeners match their pre-run state after success, failure, interruption,
  and timeout; and
- retained evidence is structured, bounded, mode `0600` inside mode `0700`
  ignored directories, rejects symbolic-link targets, and passes a private-data
  scan.

The runner must audit both planned and live process arguments. It must also
record packet-level proof that the gateway was the sole DHCP authority, that
the controller and workstation communicated only through the isolated hub, and
that no external socket was established.

## Consequences

A dnsmasq proxy-DHCP configuration on the controller is not acceptable in this
test architecture. The simulated gateway provides DHCP options 66 and 67; the
controller provides TFTP/HTTP payloads without participating in DHCP.

All child processes have bounded timeouts and are terminated and reaped in
reverse order on `SIGINT`, `SIGTERM`, `SIGHUP`, error, or normal completion.
Disposable disks, firmware variables, transient credentials, and answer files
are removed only after their users have exited. Leftover processes or writable
artifacts make the run fail.

The lifecycle is not accepted after one favorable run. It must be destroyed
and recreated twice from the same verified local inputs. Release manifests and
salient acceptance results must match; nondeterministic bytes must be
identified and explained.

This decision does not authorize a UniFi query or change, creation of a host
bridge/TAP/VLAN, attachment to a physical NIC, or erasure of physical media.
Those remain separately authorized gates.
