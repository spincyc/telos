# Private directory identity

Two hand-edited JSON documents live here. They answer different questions about
the same directory and neither has a fallback the durable path may take:

| File | Declares | Absent |
| --- | --- | --- |
| [`directory.json`](#the-permanent-directory-identity-directoryjson) | **What the directory is** — realm, NetBIOS name, DNS domain, controller FQDNs, address | The durable path refuses. Acceptance is unaffected. |
| [`principals.json`](#private-principal-roster) | **Who is in it** — the real account names | Every account keeps the synthetic contract name. |

## The permanent directory identity (`directory.json`)

    homelab/instance/identity/directory.json

ADR 0065 requires the private overlay to **freeze** the directory's identity
*before the first domain is provisioned*, and records the realm and the NetBIOS
name as **effectively permanent**. That is not a style rule. The domain SID is
minted once, at provisioning, and every user, group and machine SID derives
from it; the realm is written into every Kerberos principal and the NetBIOS
name into the pre-Windows-2000 domain name that every joined machine records.
Changing any of them afterwards is a directory migration, not a convergence.

So the durable path — `bootstrap_dc.py persistent-converge`, and anything else
that provisions or names the durable directory — reads this file and **refuses
if it is absent or incomplete**, naming the file and every key that is still
missing. It never falls back to the synthetic acceptance identity
(`ad.factory.test`, NetBIOS `FACTORY`) that gates 3–12 build the disposable
Controller from. A fallback there would not be a wrong run you repeat; it would
be a permanent domain under a name nobody chose.

**Copying this template changes nothing and provisions nothing.** The shipped
`directory.json` carries its worked example under `_example`, so a fresh
overlay is an explicit refusal that tells you the whole shape at once, rather
than a plausible-looking default.

### Shape

```json
{
  "schema_version": 1,
  "identity": {
    "dns_domain": "<domain>.home.arpa",
    "kerberos_realm": "<DOMAIN>.HOME.ARPA",
    "netbios_name": "<NETBIOS>"
  },
  "services": {
    "bootstrap_dc_fqdn": "bootstrap-dc.<domain>.home.arpa",
    "permanent_dc_fqdn": "<permanent-controller>.<domain>.home.arpa"
  },
  "network": {
    "address": "<controller-ipv4>",
    "prefix": <prefix-length>,
    "gateway": "<gateway-ipv4>"
  }
}
```

`prefix` is a JSON **number**; a string is refused.

The `identity` and `services` blocks are deliberately the same shape, with the
same key names, as
[`src/homelab/private-contract/instance.schema.json`](../../../src/homelab/private-contract/instance.schema.json),
which models the same ADR 0065 decision for the sibling private repository. If
you already keep a `telos-private/homelab/instance.json`, lift the two blocks
straight across.

Note the spelling **`netbios_name`**. ADR 0065 and the private contract both
use it. `homelab/workstations/acceptance.json` and the Ansible variable
`homelab_ad_netbios_domain` say *domain* for the same value; those are separate
documents with separate readers. `netbios_domain` here is refused by name, with
the correct spelling in the message, rather than ignored back to a default.

### Rules the loader enforces, each fail-closed

| Rule | Why |
| --- | --- |
| `schema_version` must be `1` | An unversioned file cannot be migrated later |
| Only `schema_version`, `identity`, `services`, `network` at the top level, and only the listed keys inside each | A typo must be refused, not silently ignored back to the acceptance identity |
| Keys beginning `_` are documentation and ignored | JSON has no comments and this file is hand-edited |
| Every listed key must be present and non-empty | ADR 0065 says *freeze*, and a partly frozen identity is not frozen |
| `dns_domain` must be a lower-case DNS name beneath `home.arpa`, and not `home.arpa` itself | ADR 0005 reserves the suffix; ADR 0065 makes the identity domain a child of it |
| `kerberos_realm` must be exactly `dns_domain.upper()` | A mismatched pair provisions cleanly and only surfaces at the first Kerberos login |
| `netbios_name` must match `^[A-Z0-9-]{1,15}$` | Longer names are truncated silently and the pre-Windows-2000 domain name is permanent |
| Both DC FQDNs must be beneath `dns_domain`, must differ from each other, and each host label must match `^[a-z0-9][a-z0-9-]{0,14}$` | Domain members find a DC through AD DNS SRV records under the identity domain; the 15-character label cap is the NetBIOS machine-name limit samba truncates past. Two names exist so clients survive replacing the first controller |
| `bootstrap_dc_fqdn`'s host label must be `bootstrap-dc` | The serial console is the only channel into a simulated persistent instance, and every step of the protocol matches on `<hostname> login:` |
| `address`/`prefix` must parse as an unambiguous dotted-quad and prefix, and `address` and `gateway` must both be usable hosts inside that subnet and differ | The same ADR 0045 rules `homelab/lib/netplan.py` applies to the managed network; the address is written into the guest's durable systemd-networkd unit, its `/etc/hosts` and every A record it serves |
| A file that exists but cannot be understood is an error | Falling back to the acceptance realm would mint a permanent domain SID under it |

### What is deliberately *not* here

- **NTP upstreams.** Fabric, not identity; ADR 0065 does not freeze them, and a
  *simulated* persistent instance can reach no NTP server but the one the
  userspace gateway answers for. A real Controller's upstreams are
  `homelab_ad_ntp_upstreams` in `inventory/group_vars/controllers.yml`.
- **The subnet and netmask.** Arithmetic on `address` and `prefix`, so they
  cannot disagree with them.
- **Any credential.** The domain Administrator password and every account
  password are typed at your own terminal, once, and reach no file here. See
  the parent [`README.md`](../README.md).

### Keep it in step with the Ansible variables

`inventory/group_vars/controllers.yml` declares the same three identity values
as `homelab_ad_dns_domain`, `homelab_ad_realm` and `homelab_ad_netbios_domain`
for the **host-side** Ansible path (`make homelab-bootstrap-controller`), which
reaches a Controller over SSH. This JSON document serves the **simulated**
persistent path, which has no route to the host and is driven over the serial
console. Nothing checks that the two agree today — this side reads JSON and
that side reads YAML — so set them to the same values by hand, once.

## Private principal roster

`principals.json` is **the one place real account names are declared.** Real
account names are instance data (ADR 0046), so they live here — under the
gitignored `homelab/instance/` overlay — and never in a tracked file.

    homelab/instance/identity/principals.json

Everything that needs those names reads them from here:

| Reader | What it does with them |
| --- | --- |
| `homelab/workstations/arch_second.py` | bakes them onto the installed workstation disk (probe helper, sudoers rules, the break-glass `useradd`) |
| `homelab/vm/controller_principals.py` | stages the disposable acceptance principals and owns the **one** directory POSIX allocation rule |
| `homelab/vm/arch_identity_run.py` | drives gate 8 — logs in as the daily administrator, sets the rescue password |
| `ansible/roles/domain_controller` | converges the **durable** directory accounts on a persistent Controller |

The Ansible role cannot import Python from this repository at the moment it
converges a guest, so it does not try: its own
`files/resolve-directory-accounts.py` renders its account plan from this file on
the **control host**, and the guest receives nothing but the finished plan. The
role's variable `homelab_ad_directory_accounts` therefore names contract *roles*
and never an account. See
[`../inventory/group_vars/controllers.yml`](../inventory/group_vars/controllers.yml).

The file is optional. **With no file, every account keeps the synthetic name
recorded in the tracked contract `homelab/workstations/identity_lifecycle.json`**
(`student`, `operator`, `directory-admin`, `local-rescue`), which is exactly what
the acceptance gates expect. The template beside this README is deliberately
inert for the same reason: `principals` is empty, so `make homelab-instance`
copies it without changing a single name.

### Shape

A sparse patch of the contract's own `principals` block, so a reader who knows
the contract already knows this file. Name only the roles you want renamed:

```json
{
  "schema_version": 1,
  "principals": {
    "standard_user":        {"name": "<standard-user>"},
    "domain_administrator": {"name": "<domain-administrator>"}
  }
}
```

Rules the loader enforces, each fail-closed:

| Rule | Why |
| --- | --- |
| `schema_version` must be `1` | An unversioned file cannot be migrated later |
| Only `schema_version` and `principals` at the top level | A typo must be refused, not silently ignored back to the synthetic default |
| Keys beginning `_` are documentation and ignored | JSON has no comments and this file is hand-edited |
| A role may only set `name` | `domain_role` and `workstation_role` are policy the lifecycle judge grades, not instance data |
| Role must be one of the four below | A misspelled role would leave the real account unnamed |
| A name must match `^[a-z][a-z0-9-]{0,31}$` | Names flow into shell words, sudoers rules, SMB share names and Kerberos principals; anything needing quoting is refused rather than escaped |
| All four names must be distinct | Two roles sharing a name collapses the very separation the lifecycle proves, and collides in the directory POSIX allocation |
| A file that exists but cannot be understood is an error | Falling back to the synthetic names would install accounts you did not ask for |

### The four roles

| Role | What it is | UID | Notes |
| --- | --- | --- | --- |
| `standard_user` | Unprivileged directory account | 10000 | No `wheel`, no sudo rule |
| `daily_administrator` | Directory account with **passworded** sudo on the workstation | 10001 | Deliberately **not** a Domain Admins member (ADR 0055): the everyday elevated account is not a directory administrator |
| `domain_administrator` | Directory account in **Domain Admins** | 10002 | Deliberately never resolved on the workstation, so an offline lookup of it is denied |
| `local_rescue` | Local break-glass administrator, `wheel`, passworded sudo | 1000 (local) | **Never a directory account and never `root`** (ADR 0055, ADR 0063). It is the only way in while the directory is down |

UIDs belong to the **role**, not to the name: renaming an account never moves a
UID, and adding a role appends one without moving any existing one. The rule is
written once, in
`homelab/vm/controller_principals.directory_account_plan`, and both the
disposable acceptance Controller and the durable directory of a persistent
instance derive their numbers from it.

`local_rescue` has no directory UID at all — it is a local account on the disk,
which is the whole point of it, and the durable-account resolver refuses it by
name so no instance variable can smuggle it into the directory.

A durable account that the directory has **already** allocated keeps its number:
convergence refuses to move a `uidNumber`, because files on every workstation,
the per-user share directory and every ACL keyed on that number cannot follow it.

Keep the `local_rescue` name here and `homelab_breakglass_user` in
`inventory/group_vars/all.yml` **the same**. Nothing checks that today: this
Python path reads JSON contracts and the Ansible path reads YAML vars, and they
are separate readers of the same decision.

### The one thing this file cannot do

`daily_administrator` and `domain_administrator` are two different accounts on
purpose. If you want one everyday account that is *also* a Domain Admins member,
that is a change to the identity contract, not a rename — and it is not what the
acceptance gates currently prove.

Note also that today the `domain_administrator` role receives Domain Admins
membership and a directory POSIX identity but **no sudoers rule on the
workstation**; only `daily_administrator` and `local_rescue` get one. Granting
the domain administrator passworded sudo as well is an acceptance-semantics
change (a new `/etc/sudoers.d/30-domain-admin`, re-proving `arch-uncached-denied`)
and has not been made.

### After changing this file

The names are baked onto the disk at install time — into the identity probe
helper, the sudoers rules and the break-glass `useradd`. A disk installed under
one roster is refused by the gate-8 drive against another, by name, comparing a
fingerprint the probe reports. **Changing this file requires a fresh gate-7
install.**
