# ADR 0068: Use stable service discovery and migrate the DC

- Status: Accepted
- Date: 2026-07-27

## Context

The bootstrap VM will eventually yield to a physical Controller. Installed
workstations must not be rebuilt for that move.

## Decision

Publish PXE through the private `services.boot_fqdn` and immutable,
digest-manifested release directories. Discover identity only through AD DNS
SRV records.

Every published manifest binds the release version (`YYYYMMDD.NNN`) to the
exact public Telos Git commit that built it and the SHA-256 digest of every
payload. Promotion verifies those values before changing the `current` pointer.
Rebuilding changed bytes therefore requires a new release version.

Migrate in this order:

1. build `services.permanent_dc_fqdn` independently and join it as an additional DC;
2. prove directory, DNS and SYSVOL replication in both directions;
3. prove Windows, Arch and NAS authentication with either DC unavailable;
4. copy and verify PXE releases on the permanent DC;
5. move the boot alias and UniFi boot options;
6. transfer directory roles and make the permanent DC preferred DNS;
7. perform a reversible bootstrap outage test; then
8. demote `services.bootstrap_dc_fqdn` and remove stale records.

Never leave and rejoin workstations merely to move a DC. Never power on a stale
DC snapshot as rollback.

## Consequences

- Domain membership, machine accounts, user profiles and SIDs survive.
- Before demotion, rollback repoints discovery to the healthy bootstrap DC.
- After demotion, recovery uses a tested Samba domain backup.
- Samba SYSVOL consistency needs an explicit mechanism and test.

## References

- https://wiki.samba.org/index.php/Back_up_and_Restoring_a_Samba_AD_DC
- https://wiki.samba.org/index.php/Upgrading_a_Samba_AD_DC
