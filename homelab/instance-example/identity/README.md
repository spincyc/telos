# Private principal roster

`principals.json` names the real directory and break-glass accounts the factory
creates on a workstation. Real account names are instance data (ADR 0046), so
they live here — under the gitignored `homelab/instance/` overlay — and never in
a tracked file.

    homelab/instance/identity/principals.json

The file is optional. **With no file, every account keeps the synthetic name
recorded in the tracked contract `homelab/workstations/identity_lifecycle.json`**
(`student`, `operator`, `directory-admin`, `local-rescue`), which is exactly what
the acceptance gates expect. The template beside this README is deliberately
inert for the same reason: `principals` is empty, so `make homelab-instance`
copies it without changing a single name.

## Shape

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

## The four roles

| Role | What it is | UID | Notes |
| --- | --- | --- | --- |
| `standard_user` | Unprivileged directory account | 10000 | No `wheel`, no sudo rule |
| `daily_administrator` | Directory account with **passworded** sudo on the workstation | 10001 | Deliberately **not** a Domain Admins member (ADR 0055): the everyday elevated account is not a directory administrator |
| `domain_administrator` | Directory account in **Domain Admins** | 10002 | Deliberately never resolved on the workstation, so an offline lookup of it is denied |
| `local_rescue` | Local break-glass administrator, `wheel`, passworded sudo | 1000 (local) | **Never a directory account and never `root`** (ADR 0055, ADR 0063). It is the only way in while the directory is down |

UIDs belong to the **role**, not to the name: renaming an account never moves a
UID. `local_rescue` has no directory UID at all — it is a local account on the
disk, which is the whole point of it.

Keep the `local_rescue` name here and `homelab_breakglass_user` in
`group_vars/all.yml` **the same**. Nothing checks that today: this Python path
reads JSON contracts and the Ansible path reads YAML vars, and they are separate
readers of the same decision.

## The one thing this file cannot do

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

## After changing this file

The names are baked onto the disk at install time — into the identity probe
helper, the sudoers rules and the break-glass `useradd`. A disk installed under
one roster is refused by the gate-8 drive against another, by name, comparing a
fingerprint the probe reports. **Changing this file requires a fresh gate-7
install.**
