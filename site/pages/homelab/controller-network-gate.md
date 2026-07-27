# Controller network gate

Version `20260727.003`

This runbook gives the installed `bootstrap-dc` VM ordinary client access to a
restricted UniFi network. It does **not** enable AD, DNS, DHCP, PXE, TFTP or
HTTP service. UniFi remains the only DHCP and client-DNS authority.

Use one sacrificial wired port. Do not change a trunk, AP uplink, switch uplink
or the port used to administer UniFi.

> **Private values**
>
> Choose the VLAN ID, subnet, reservation, switch, port, administrative
> network and VM MAC in the private overlay. The examples below are labels,
> not deployable values. Keep the subnet small—normally `/28`, which has 14
> usable addresses—and choose a clean base-10 boundary such as
> `10.A.B.0/28`. The gateway will then normally be `10.A.B.1`.
>
> Put the actual attachment JSON and completed gate record in `telos-private`,
> never in this public repository. In the commands below,
> `/absolute/private/path/bootstrap-network.json` means the mode-`0600` file
> documented in the private overlay; do not replace this page's placeholders
> with household values.

## Gate record

Fill this before changing anything.

| Item | Recorded value |
|---|---|
| Date and operator | |
| UniFi OS and Network versions | |
| UDM configuration backup/export | |
| Validation network name | `controller-validation` |
| Custom zone name | `controller-validation` |
| VLAN ID | |
| IPv4 subnet/prefix | |
| Gateway | |
| DHCP range | |
| Reserved controller address | |
| VM NIC MAC | |
| Administrative network | |
| Internal zones (enumerate LAN, VPN, Hotspot, DMZ and custom) | |
| Switch and sacrificial port | |
| Port's original native network | |
| Port's original tagged-VLAN setting | |

**Verify:** every blank is filled and the chosen subnet does not overlap an
existing LAN, VPN route or remote site.

**Stop if:** there is no current backup, the VM MAC is unknown, or the port's
original configuration is not recorded.

## 1. Record the baseline

1. In **UniFi OS → Control Plane → Backups**, create or confirm a current
   console backup. Download an offline copy if the interface offers it.
2. In **Network → Settings**, record the Network application version.
3. In **Network → Devices → selected switch → Ports → Port Manager**, open the
   sacrificial port and capture its name, native VLAN/network, tagged VLAN
   management, PoE state and link state.
4. In **Network → Settings → Networks**, capture the existing network list,
   VLAN IDs and subnets.
5. Search Network settings for **Zones** or **Policy Engine**, then capture the
   current zone matrix and custom policy order. UniFi moves settings between
   releases; use the labels in this runbook against the exact Network version
   recorded above, rather than assuming an old menu path is current.

> **What this does**
>
> The record makes rollback mechanical. It also catches subnet reuse before a
> gateway starts answering ARP for an existing address range.

**Verify:** open the backup list again and confirm its timestamp; compare every
planned subnet and VLAN ID with the captured network list.

## 2. Create the validation network

In the current Network application, open **Settings**, find **Networks**, and
choose **New Virtual Network**:

1. Set **Name** to `controller-validation`.
2. Select the UDM Pro Max as router.
3. Set the private **VLAN ID**.
4. Enter the private IPv4 gateway and `/28` prefix.
5. Enable the UniFi DHCP server with a narrow range wholly inside that subnet.
6. Leave the DNS server at **Auto/UDM**.
7. Leave DHCP options 66 and 67 absent.
8. Disable multicast DNS forwarding, UPnP and content filtering for this test.
9. Disable IPv6 router advertisements and prefix delegation for this IPv4-only
   gate.
10. Apply the change.

> **What this does**
>
> The UDM becomes the validation segment's gateway, DHCP server and DNS
> forwarder. The VM receives client configuration; it receives no network
> authority.

**Verify:** reopen the network and read back its VLAN, gateway/prefix, DHCP
range and DNS setting. Confirm the gateway is outside the lease pool and
options 66/67 are absent.

**Stop if:** UniFi reports an overlap, silently changes the prefix, or another
DHCP server is selected.

## 3. Put the network in its own zone

In **Settings**, find **Zones** (called **Policy Engine → Zones** in some
releases):

1. Create the custom zone `controller-validation`.
2. Assign only the `controller-validation` network.
3. Apply and reopen the zone.

> **What this does**
>
> A separate zone makes the test boundary visible and prevents an accidental
> broad rule for ordinary trusted clients from becoming the controller's
> policy.

**Verify:** the zone shows exactly one network. No production network moved
zones.

## 4. Add the policies

Create narrow allows before the final denies. From **Settings**, find **Zones**
or **Policy Table**, then choose **Create Policy**. Labels can move between
Network releases; the recorded policy names, endpoints, services and order
below are the authoritative specification.

Use named network/IP and port objects where the interface supports them.
Enable logging on every deny policy.

| Order and exact name | Source | Destination | Service/action | What it permits |
|---:|---|---|---|---|
| 1 — `CV-01-admin-ssh-in` | administrative network | reserved controller IP | TCP 22, allow | SSH administration only |
| 2 — `CV-02-unifi-client-services` | validation zone | Gateway zone | DHCP client UDP source 68 to destination 67; DNS TCP/UDP destination 53, allow | Address and resolver from UniFi |
| 3 — `CV-03-updates-time-out` | validation zone | External zone | TCP 80/443 and UDP 123, allow | Arch updates and external NTP |
| 4 — `CV-04-block-other-external` | validation zone | External zone | any other IPv4 and IPv6, block/log | No other Internet egress |
| 5 — `CV-05-block-other-gateway` | validation zone | Gateway zone | any other IPv4 and IPv6, block/log | No other UDM access |
| 6 — one `CV-06-block-out-<zone>` per internal zone | validation zone | that one LAN, VPN, Hotspot, DMZ or custom zone | any IPv4 and IPv6, block/log | No lateral access |
| 7 — one `CV-07-block-in-<zone>` per non-administrative internal zone | that one LAN, VPN, Hotspot, DMZ or custom zone | validation zone | any IPv4 and IPv6, block/log | No unsolicited inbound access |

Keep established/related return traffic enabled. If UniFi's built-in Gateway
policy already supplies DHCP and gateway DNS, do not create a duplicate broad
allow: verify the built-in behavior and narrow rule 2 accordingly. Never place
a blanket Gateway deny above DHCP/DNS; UniFi warns that doing so can break
those services. Do not describe UniFi as an NTP server unless you separately
proved it is one. For this gate, DHCP option 42 remains unset and the
controller synchronizes to an external NTP source through
`CV-03-updates-time-out`. External DNS is not allowed: the controller sends
DNS only to the UDM gateway through `CV-02-unifi-client-services`.

Create `CV-06` and `CV-07` as explicit zone pairs. Do not use an `all
internal` shortcut unless its inspector proves it includes every recorded
LAN, VPN, Hotspot, DMZ and custom zone. Within each zone pair, place the narrow
allow before its matching deny.

> **What this does**
>
> The controller can update and an administrator can reach SSH. It cannot
> initiate connections into household networks or serve clients.

**Verify:** search for exact `CV-01` through `CV-05` names and every recorded
`CV-06-*` and `CV-07-*` name, then read each zone pair top to bottom. Confirm
source and destination are not reversed, the SSH destination is one reserved
IP, and each deny follows its required allow. Record every policy's enabled
state, position and initial hit counter.

**Stop if:** a rule says `Any → Any`, a production zone is included in the
source object, or IPv6 is left as an unexamined bypass.

## 5. Configure one access port

In **Network → Devices → selected switch → Ports → Port Manager**:

1. Select only the recorded sacrificial port.
2. Give it a clear name such as `TEST-controller-validation`.
3. Set **Native VLAN / Network** to `controller-validation`.
4. Set **Tagged VLAN Management** to **Block All**.
5. Leave link speed on auto and preserve the recorded PoE setting.
6. Apply.

> **What this does**
>
> Untagged traffic from the attached host enters only the validation VLAN.
> Blocking tagged VLANs makes this an access port, not a trunk.

The gateway firewall cannot filter two devices talking directly on the same
VLAN. Keep the controller as this VLAN's only persistent client; never place a
household or administrative client there. A disposable test client may join
only long enough for section 7's DHCP capture and must contain no sensitive
data.

**Verify:** reopen Port Manager. Read back the native network and **Block
All**. Confirm only the intended port changed and switch/AP uplinks still show
online.

Do not connect the host yet.

## 6. Reserve the VM address

Run these from the public repository root, substituting only private absolute
paths. First inspect the VM command and host-network plan:

```sh
make homelab-bootstrap-network-preflight NETWORK_CONFIG=/absolute/private/path/bootstrap-network.json
make homelab-bootstrap-network-plan NETWORK_CONFIG=/absolute/private/path/bootstrap-network.json
make homelab-bootstrap-network-host-plan NETWORK_CONFIG=/absolute/private/path/bootstrap-network.json
```

These commands are non-mutating. If their interface names and topology match
the gate record, create the dedicated bridge and TAP:

```sh
make homelab-bootstrap-network-host-prepare NETWORK_CONFIG=/absolute/private/path/bootstrap-network.json APPLY=1
```

Type the helper's displayed `ATTACH eno2 br-dc tap-dc` confirmation only after
checking each name against the private attachment JSON. The VM is still off.

Now boot the VM **isolated**, without `NETWORK_CONFIG`:

```sh
make homelab-bootstrap-vm-boot APPLY=1
```

At its serial console run all three commands and record their exact output in
the private gate evidence:

```sh
sudo /usr/local/sbin/homelab-network-attach-preflight
cat /proc/sys/kernel/random/boot_id
sed -n 's/.*"commit": "\([0-9a-f]*\)".*/\1/p' /opt/telos-source/seed-receipt.json
```

The preflight's final line must begin `RESULT PASS`; the boot ID must be one
lowercase UUID and the source commit must be one full 40-character lowercase
commit. Power off the isolated VM:

```sh
sudo poweroff
```

After QEMU exits, create a receipt at a new path in the private overlay:

```sh
make homelab-bootstrap-network-receipt NETWORK_RECEIPT=/absolute/private/path/bootstrap-network-receipt.json GUEST_BOOT_ID=<recorded-UUID> GUEST_SOURCE_COMMIT=<recorded-full-commit>
```

The command prints a 16-character evidence token and the exact second-gate
confirmation. Read the receipt and compare its disk, serial, guest values and
host commit with what you just observed:

```sh
python -m json.tool /absolute/private/path/bootstrap-network-receipt.json
```

Then authorize it using the token it printed:

```sh
make homelab-bootstrap-network-authorize NETWORK_RECEIPT=/absolute/private/path/bootstrap-network-receipt.json CONFIRM='ATTACH <printed-token>'
```

Within 15 minutes of **creating** the receipt, start the approved disk-only VM
on the physical TAP:

```sh
make homelab-bootstrap-network-run NETWORK_CONFIG=/absolute/private/path/bootstrap-network.json NETWORK_RECEIPT=/absolute/private/path/bootstrap-network-receipt.json APPLY=1 CONFIRM=attach-bootstrap-dc
```

The receipt is short-lived operator-recorded evidence. It binds the observed
isolated boot, current disk identity and public source commit to this launch;
it is not cryptographic guest attestation and cannot prove that the subsequent
boot is running the same guest state. Expiry, a changed disk or a changed
public `HEAD` causes the launch to fail closed. If that happens, delete the
expired private receipt and repeat the isolated observation from the
beginning—never edit receipt JSON or its timestamps.

When `bootstrap-dc` appears under **Client Devices**:

1. Match its displayed MAC to the gate record.
2. Open **Settings** for that client.
3. Enable **Fixed IP Address**.
4. Select `controller-validation` and enter the private reserved address.
5. Do not enable a local DNS record yet.
6. Apply, then renew the VM lease or reboot it.

> **What this does**
>
> UniFi still assigns the address by DHCP, but always gives this MAC the same
> address. Later services can use a stable target without a static guest
> configuration.

**Verify in UniFi:** client name, MAC, network, switch port and address all
match the record.

**Verify at the VM console:**

```sh
ip -br link
ip -4 -br address
ip route
resolvectl status
timedatectl
sudo ss -lntup
sudo /usr/local/sbin/homelab-network-attach-preflight
```

The address, default route and resolver must agree with UniFi. Nothing may
listen on UDP 53, 67, 69 or 4011. `dnsmasq`, Samba, nginx and PXE units must
remain disabled and inactive. `timedatectl` must report
`System clock synchronized: yes`; its NTP server is external, not presumed to
be the UniFi gateway. Finish the repository-supplied check:

```sh
make homelab-bootstrap-network-check NETWORK_CONFIG=/absolute/private/path/bootstrap-network.json
```

## 7. Prove the boundary

Run each check and record pass/fail.

| Check | Expected result |
|---|---|
| Renew a second ordinary client's lease | One UniFi offer; normal address, gateway and DNS |
| From admin network, SSH to reserved address | Connects |
| From a non-admin client, SSH to reserved address | Fails; inbound deny counter rises |
| From controller, reach UDM gateway and resolve a public name | Succeeds |
| From controller, fetch an Arch HTTPS endpoint | Succeeds |
| From controller, connect to one private client | Fails; lateral deny counter rises |
| Capture a complete DHCP renewal on the validation segment | Exactly one OFFER and ACK, both from UniFi; none from the controller MAC |
| Power controller off, then renew ordinary client | Normal service is unchanged |

> **What this proves**
>
> Positive tests show the small allowed path works. Negative tests and policy
> counters show isolation is enforced. Power-off proves the household has not
> acquired a dependency on the experiment.

**Stop if:** any client receives two DHCP offers, a forbidden probe succeeds,
the expected deny counter does not rise, or ordinary service changes when the
VM stops.

### Capture the DHCP proof

On a separate Linux test client attached to the validation segment, record its
interface name and the controller and UniFi MAC addresses from the gate record.
Start the capture before renewing the lease:

```sh
capture="dhcp-validation-$(date -u +%Y%m%dT%H%M%SZ).pcap"
sudo timeout 30 tcpdump -ni <test-client-interface> -e -s0 -w "$capture" 'udp port 67 or udp port 68'
```

While that command is running, renew the test client's lease using its normal
network manager. Then inspect the saved capture without resolving names:

```sh
sudo tcpdump -nn -e -r "$capture" -vvv 'udp port 67 or udp port 68'
```

Record the DISCOVER/REQUEST/OFFER/ACK transaction IDs, Ethernet source MACs,
DHCP server identifier, offered address, router and DNS options. Pass only if
there is one server identifier, every OFFER and ACK source is the recorded
UniFi MAC, and the controller MAC sends no OFFER or ACK. Preserve the pcap in
the private evidence directory because it contains instance addresses and
MACs; never commit it to this public repository.

## Roll back

Rollback never requires logging in to the VM.

1. In Port Manager, disable the recorded sacrificial port.
2. Power off `bootstrap-dc`.
3. Restore the port's recorded name, native network, tagged-VLAN management
   and PoE state.
4. Remove the controller's fixed-IP reservation.
5. Delete, by exact name, `CV-01-admin-ssh-in`,
   `CV-02-unifi-client-services`, `CV-03-updates-time-out`,
   `CV-04-block-other-external`, `CV-05-block-other-gateway`, and every
   recorded `CV-06-block-out-<zone>` and `CV-07-block-in-<zone>`. Stop if a
   name, endpoint or service differs from the recorded rule; investigate
   instead of deleting a look-alike.
6. Remove `controller-validation`.
7. From the host console, run the repository teardown acknowledgement:

   ```sh
   make homelab-bootstrap-network-teardown APPLY=1
   ```

   Type the helper's exact `DETACH eno2 br-dc tap-dc` confirmation. The target
   performs the stateful host teardown; use `homelab/network/ROLLBACK.md` to
   verify the result.
8. Renew an ordinary client's DHCP lease and verify gateway DNS and Internet
   access.
9. Compare Networks, Zones and Port Manager with the baseline captures.
10. Restore the UniFi backup only if manual rollback cannot reproduce the
   recorded state.

**Rollback passes when:** the test VLAN and rules are absent, the port matches
its baseline, an ordinary client receives exactly one UniFi lease, and the
controller is powered off.

## Do not advance yet

Successful attachment authorizes only ordinary client networking. Separate
gates must enable Samba AD DNS, directory service, PXE HTTP/TFTP, DHCP options
66/67, workstation enrollment and migration to physical controller hardware.
UniFi remains the DHCP authority in every phase.

## UniFi references

- [Creating Virtual Networks](https://help.ui.com/hc/en-us/articles/9761080275607-Creating-Virtual-Networks-VLANs)
- [Zone-Based Firewalls](https://help.ui.com/hc/en-us/articles/115003173168-Zone-Based-Firewalls-in-UniFi)
- [Switch Port VLAN Assignment](https://help.ui.com/hc/en-us/articles/26136855808919-Switch-Port-VLAN-Assignment-Trunk-Access-Ports)
- [UniFi DHCP Server](https://help.ui.com/hc/en-us/articles/360012097513-UniFi-DHCP-Server)
- [Fixed IP and local DNS records](https://help.ui.com/hc/en-us/articles/15179064940439-UniFi-DNS-Records-and-Local-Hostnames)
