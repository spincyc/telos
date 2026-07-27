# Workstation identity procedures

Version `20260727.001`

Use this command-by-command companion at workstation-factory Stage 9. Keep
site-specific names in the private inventory and substitute them only while
performing the procedure.

### Prove Windows 11 identity

Use the tested local-rescue administrator on a wired provisioning connection.
Set the permanent computer name and confirm every active domain interface uses
only AD DNS.

```powershell
Rename-Computer -NewName "<workstation-name>" -Restart
Get-DnsClientServerAddress -AddressFamily IPv4
Resolve-DnsName -Type SRV "_ldap._tcp.dc._msdcs.<identity-domain>"
w32tm /query /source
Test-NetConnection <dc-fqdn> -Port 445
```

**What this proves:** the client has its permanent identity, discovers AD
through DNS, has a time source, and can reach the domain service. Stop if clock
offset is five minutes or more, any public DNS server is active, or the SRV
lookup fails. A hosts-file entry is not a repair.

Join through **Settings → System → About → Domain or workgroup → Change**.
Select **Domain**, enter `<identity-domain>`, and use a temporary delegated
join credential. Restart.

```powershell
Get-CimInstance Win32_ComputerSystem |
  Select-Object Name,PartOfDomain,Domain
nltest /dsgetdc:<identity-domain>
Test-ComputerSecureChannel -Verbose
```

**Pass:** `PartOfDomain` is true, the domain is exact, a DC is discovered, and
the secure channel is `True`. Revoke the join credential.

Sign in as the standard test identity, then measure:

```powershell
whoami
whoami /groups
echo $env:USERPROFILE
net localgroup Administrators
```

The profile must be local and the test identity must not be an administrator.
Separately prove the approved daily administrator can elevate and local rescue
works with the DC off. Restart offline and prove the previously used identity
can enter its cached local desktop. Reconnect, disable the test identity, and
prove a fresh connected sign-in is denied. Record that phase 1 cannot revoke
an already cached login while the laptop remains offline.

### Prove Arch identity

Use a full Arch transaction; never perform a partial upgrade:

```sh
sudo pacman -Syu --needed sssd samba krb5 bind
resolvectl status
timedatectl show -p NTPSynchronized --value
host -t SRV _ldap._tcp.dc._msdcs.<identity-domain>
```

**Pass:** AD DNS is active, time reports `yes`, the SRV answer names a DC, and
all packages came from enabled official Arch repositories. Stop if any check
fails.

Generate `/etc/samba/smb.conf` from private values with `security = ads`, exact
`workgroup = <netbios-name>`, `realm = <kerberos-realm>`, and
`kerberos method = secrets and keytab`. Generate root-owned mode-0600
`/etc/sssd/sssd.conf`:

```ini
[sssd]
services = nss, pam
config_file_version = 2
domains = <identity-domain>

[domain/<identity-domain>]
id_provider = ad
auth_provider = ad
access_provider = ad
ad_domain = <identity-domain>
krb5_realm = <kerberos-realm>
cache_credentials = true
use_fully_qualified_names = true
fallback_homedir = /home/%u
default_shell = /bin/bash
ldap_id_mapping = true
```

Review both rendered files, then join interactively with a one-use delegated
credential:

```sh
sudo net ads join -U '<delegated-join-user>'
sudo net ads testjoin
sudo klist -k /etc/krb5.keytab
sudo test "$(stat -c %a /etc/sssd/sssd.conf)" = 600
sudo systemctl enable --now sssd
```

Never put the password in a command, answer file, or repository. Revoke it
after the join. Confirm `sss` appears on the `passwd`, `group`, and `shadow`
lines in `/etc/nsswitch.conf`. Keep fully-qualified logins unless the private
policy explicitly adopts one collision-safe short-name rule.

```sh
getent passwd '<standard-user>@<identity-domain>'
id '<standard-user>@<identity-domain>'
getent group '<approved-admin-group>@<identity-domain>'
sssctl user-checks '<standard-user>@<identity-domain>' -s login
```

Record UID, primary GID, and supplementary groups. The test user must resolve
exactly once and must not belong to the administrator group.

For a local home, review the PAM stack and add this session action to the
workstation login path, normally `/etc/pam.d/system-login`:

```text
session optional pam_mkhomedir.so skel=/etc/skel umask=0077
```

Do not add it to authentication or account sections. Keep a local-rescue
session open and test the domain login from a second TTY.

```sh
getent passwd '<standard-user>@<identity-domain>'
findmnt --target '/home/<resolved-home>'
stat -c '%U %G %a %n' '/home/<resolved-home>'
sudo -l -U '<standard-user>@<identity-domain>'
```

**Pass:** the first login creates exactly the local path reported by `getent`;
ownership matches the resolved UID/GID; the standard user has no `sudo`;
the approved group alone can elevate. Restart offline and prove the cached
identity retains the same UID/GID and opens the same home. Also prove local
rescue still logs in and elevates while the DC is unavailable.

Record these measurements in the acceptance evidence:

| Measurement | Required observation |
|---|---|
| DNS | LDAP and Kerberos SRV answers name an approved DC |
| Time | synchronized; offset remains below Kerberos's rejection limit |
| Windows | domain exact; secure channel true; profile local |
| Arch | realm configured; SSSD active; UID/GID stable over two cold boots |
| Authorization | standard user cannot elevate; approved group can |
| Failure mode | local rescue and local homes work with AD and storage off |

NFS remains disabled until numeric-ID mapping is explicitly designed and
tested. Phase 1 uses local homes plus fail-soft SMB.
