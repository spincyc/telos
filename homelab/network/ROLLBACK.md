# Pre-AD controller attachment rollback

This procedure removes the `bootstrap-dc` VM from the physical network before
the controller has DHCP, DNS, AD or PXE authority. It does not require guest
login. Use the host console, not an SSH session carried by the interface being
changed.

## Record the attachment

Before creating anything, choose a dedicated physical interface. Do not move
the host's only management interface into a bridge.

Set only the evidence paths as shell variables. The host helper fixes the
reviewed interface names as `eno2`, `br-dc`, and `tap-dc`; do not copy names
from a stale shell variable into a deletion command.

```sh
network_config=/absolute/private/path/bootstrap-network.json
evidence="$PWD/build/homelab/network/attachment-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$evidence"
```

Record the state before attachment:

```sh
ip -details link show >"$evidence/ip-link.before.txt"
ip route show table all >"$evidence/routes.before.txt"
nmcli -f NAME,UUID,TYPE,DEVICE connection show >"$evidence/nm.before.txt"
nmcli -f GENERAL,IP4,IP6 device show eno2 >"$evidence/uplink.before.txt"
sudo nft list ruleset >"$evidence/nft.before.txt"
cp -- "$network_config" "$evidence/network-config.json"
chmod 600 "$evidence/network-config.json"
```

In UniFi, export the configuration if available and capture screenshots of the
validation network, DHCP reservation, firewall rules, and DHCP options. Record
the reservation MAC and address in the change log. Confirm options 66 and 67
are unset.

Before booting the attached VM, its disk-only boot command must be able to run
without installer media. The private network JSON selects the pre-created tap:

```json
{
  "schema": 2,
  "mode": "precreated-tap",
  "tap": "tap-dc",
  "bridge": "br-dc",
  "uplink": "eno2",
  "mac": "52:54:00:11:11:12"
}
```

The file must be owned by the invoking user and mode `0600`.

## Emergency isolation

Use this first if a duplicate DHCP response, unexpected DNS response, route
advertisement, or unexplained client outage appears.

Disable the tap immediately:

```sh
sudo ip link set dev tap-dc down
```

If QEMU does not stop promptly, terminate only this named VM:

```sh
pkill -TERM -f 'qemu-system-x86_64 -name bootstrap-dc'
pgrep -af 'qemu-system-x86_64 -name bootstrap-dc' || true
```

If it remains after a reasonable graceful-shutdown interval:

```sh
pkill -KILL -f 'qemu-system-x86_64 -name bootstrap-dc'
```

Evidence of isolation is all of the following:

```sh
ip -brief link show dev tap-dc
bridge link show dev tap-dc
pgrep -af 'qemu-system-x86_64 -name bootstrap-dc' || true
```

The tap must be `DOWN` and no matching QEMU process may remain. Do not log in
to the guest to perform this step.

## Remove the host attachment

Power off the VM first, then use the same host helper that created the
attachment. Its root-owned state records the exact interfaces, original link
state, tap owner, and whether NetworkManager managed `eno2`.

```sh
pgrep -af 'qemu-system-x86_64 -name bootstrap-dc' || true
sudo APPLY=1 homelab/bin/homelab-host-network teardown
```

At its prompt, type exactly:

```text
DETACH eno2 br-dc tap-dc
```

The helper refuses teardown unless its trusted state exists and both `eno2`
and `tap-dc` are still members of `br-dc`. It deletes `tap-dc` and `br-dc`,
detaches `eno2`, restores its recorded link and NetworkManager-managed state,
and only then removes its state file. If it refuses, preserve
`/run/telos-controller-network/state` and investigate; do not substitute
manual `ip link delete` commands.

The helper does not create or delete NetworkManager connection profiles. If a
profile was changed separately, recover its exact UUID from
`nm.before.txt`. Before changing it, assert that the UUID still identifies the
recorded name, type, and `eno2`; never delete a profile by a remembered name:

```sh
profile_uuid='<exact UUID from nm.before.txt>'
test "$(nmcli -g connection.uuid connection show uuid "$profile_uuid")" = "$profile_uuid"
test "$(nmcli -g connection.id connection show uuid "$profile_uuid")" = '<recorded name>'
test "$(nmcli -g connection.type connection show uuid "$profile_uuid")" = '<recorded type>'
test "$(nmcli -g connection.interface-name connection show uuid "$profile_uuid")" = eno2
```

Every assertion must succeed. Stop on any mismatch. Restore that profile by
UUID only:

```sh
sudo nmcli connection up uuid "$profile_uuid"
```

Do not delete any NetworkManager profile during the normal helper rollback.

Remove the controller's DHCP reservation and test-only firewall rules in
UniFi. Restore only values captured before this change. Do not invent DHCP,
DNS, gateway, VLAN or PXE values during rollback.

## Prove recovery

From the host, prove the experimental devices are absent and the original
uplink is healthy:

```sh
ip link show dev tap-dc 2>&1 | tee "$evidence/tap.after.txt"
ip link show dev br-dc 2>&1 | tee "$evidence/bridge.after.txt"
ip -brief address show dev eno2 | tee "$evidence/uplink.after.txt"
ip route show default | tee "$evidence/default-route.after.txt"
nmcli -f GENERAL,IP4,IP6 device show eno2 >"$evidence/uplink.after-full.txt"
sudo nft list ruleset >"$evidence/nft.after.txt"
```

The first two commands should report that the named devices do not exist. The
uplink must have its expected state and the default route must point to the
recorded UniFi gateway.

Use a separate ordinary client on the validation network to renew its lease,
resolve a name, and reach the gateway. Substitute the recorded gateway and a
known external name:

```sh
sudo nmcli device reapply "<client-interface>"
resolvectl query example.com
ping -c 3 "<recorded-unifi-gateway>"
```

In UniFi, verify that the client lease comes from UniFi, no lease remains for
the disconnected controller, options 66 and 67 are still unset, and ordinary
client traffic is healthy. Save the client lease, resolver result, gateway
test, and UniFi screenshots with the change evidence.

Rollback is complete only when the controller is absent, the experimental
host interfaces are gone, UniFi is again in its recorded state, and an
ordinary client works without `bootstrap-dc`.

## Preserve the installed VM

Rollback removes only network attachment. Keep
`build/homelab/vm/bootstrap-dc/bootstrap-dc.qcow2` and its companion VM state
for the next controlled attempt. Do not run the destructive VM target unless
the installed controller itself is intentionally being discarded.
