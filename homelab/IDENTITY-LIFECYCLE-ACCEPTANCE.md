# Identity lifecycle acceptance

This is the durable acceptance contract for the local workstation factory. It
uses synthetic identities in public evidence. Private account names and
credentials are supplied only by the private instance.

## Phase-one release gate

Run the same sequence against Windows 11 and Arch:

1. With the controller online, prove AD DNS, Kerberos time, the machine
   account, and the secure channel.
2. Log in once as the synthetic standard user. Record the resolved identity
   and prove that administrator elevation is denied.
3. Log in as the synthetic daily administrator. Prove local workstation
   administration and prove that this identity is not a domain administrator.
4. Power off the controller. Do not merely block one service: record that AD
   DNS, Kerberos, LDAP, and SMB authority are unreachable.
5. Log in as each previously primed domain identity. Both Windows cached
   logon and Arch SSSD cached logon must work without a time limit.
6. Attempt login with a valid domain identity that has never logged in on that
   workstation. It must fail while the controller is unavailable.
7. Log in with the distinct local rescue account and prove local
   administration. Do not record its password.
8. Restore the controller. Prove the Windows secure channel and Arch identity
   lookup recover without rejoining either workstation.

Arch must render `offline_credentials_expiration = 0`. This is SSSD's
no-expiration value. A large finite value is not equivalent.

## What disabling an account can and cannot do

Account disablement is a connected control. Once a workstation can reach the
controller, a disabled account must be denied new authentication and network
resources. It does not erase credentials already cached on a disconnected
workstation and cannot guarantee immediate denial of local offline login.

This limitation is intentional for laptops that may remain away at college
indefinitely. Phase one must never describe disablement as remote device
lockout.

## Phase-two revocation rehearsal

Phase two must execute the machine-readable `disable-reenable` sequence in
`workstations/identity_lifecycle.json` on both operating systems:

1. Prime the cache online, then disable the directory account.
2. While connected, prove new login and network-resource access are denied.
3. Disconnect the controller and prove the previously cached offline login
   remains usable. Record the applicable local-data policy separately.
4. Reconnect, re-enable the account, and prove connected login recovers.
5. Rotate the password. Prove the new credential works online and the old
   credential does not.
6. Refresh the offline cache with a successful online login, disconnect, and
   prove the new credential works offline.

Do not infer password-cache behavior from account disablement. Record every
transition independently for Windows and Arch.

## Evidence rules

- Every event states `external_access: false`.
- Controller shutdown and restoration are explicit events.
- Evidence names roles, not private people.
- Passwords, password hashes, tickets, keytabs, and private domain values are
  never captured.
- A missing, duplicated, reordered, or failed event fails the lifecycle.
- Phase-two revocation remains deferred until its entire sequence passes on
  both operating systems.
