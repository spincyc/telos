import base64
import io
import json
import socket
import shlex
import subprocess
import sys
import tempfile
import threading
import tokenize
import unittest

from pathlib import Path

from homelab.vm import controller_principals
from homelab.vm.controller_principals import (
    ControllerPrincipalError,
    ControllerPrincipalResult,
    ControllerPrincipalSerial,
)
from homelab.workstations.arch_second import (
    CONTRACT_ROLES,
    DIRECTORY_ROLES,
    identity_declaration,
    identity_roster,
)
from homelab.vm.serial_automation import (
    SerialAutomation,
    SerialAutomationError,
)
from homelab.vm.controller_factory import FactoryBundle


# The three directory principals this module stages, taken from the resolved
# roster rather than written out, so the suite proves the same thing whether or
# not the owner has a private overlay under homelab/instance/identity/.  The
# pinned synthetic names are asserted separately, against the contract read with
# the overlay explicitly out of the way (CONTRACT_ROSTER below).
ROLES = controller_principals._ROLES
VALUES = {
    name: f"Secret-{index}-47!" for index, name in enumerate(ROLES)
}
# The contract's own roster, resolved with no overlay: what the acceptance path
# must always be, byte for byte.
CONTRACT_ROSTER = identity_roster(
    overlay_path=Path(__file__).with_name("no-such-identity-overlay.json"))


class ControllerPrincipalSerialTests(unittest.TestCase):
    def run_operation(self, invoke, returncode=0, sudo_password=None):
        left, right = socket.socketpair()
        observed = []

        def responder():
            stream = right.makefile("rb", buffering=0)
            self.assertEqual(b"\n", stream.readline())
            right.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            command = stream.readline()
            observed.append(command)
            token = command.split(
                b"__TELOS_PRINCIPAL_READY_", 1)[1].split(b"__", 1)[0]
            result = command.split(
                b"__TELOS_PRINCIPAL_RC_", 1)[1].split(b"=", 1)[0]
            # The public command may be echoed.  It must contain no secret.
            right.sendall(command)
            self.assertFalse(any(
                secret.encode() in command for secret in VALUES.values()))
            right.sendall(
                b"__TELOS_PRINCIPAL_READY_" + token + b"__\r\n")
            payload = stream.readline()
            observed.append(payload)
            if sudo_password is not None:
                prompt = command.split(
                    b"__TELOS_PRINCIPAL_SUDO_", 1)[1].split(b"__", 1)[0]
                right.sendall(
                    b"\r\n__TELOS_PRINCIPAL_SUDO_" + prompt + b"__\r\n")
                observed.append(stream.readline())
            right.sendall(
                b"\r\n__TELOS_PRINCIPAL_RC_" + result + b"="
                + str(returncode).encode() + b"\r\n")

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            serial = ControllerPrincipalSerial(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0),
                timeout=1,
            )
            serial.console.password = sudo_password
            result = invoke(serial)
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        return result, observed

    def test_stage_suppresses_echo_and_transmits_only_encoded_stdin(self):
        result, observed = self.run_operation(
            lambda serial: serial.stage(VALUES))
        self.assertEqual("stage", result.operation)
        self.assertEqual(tuple(VALUES), result.principals)
        self.assertIn(b"stty -echo || exit 91", observed[0])
        self.assertIn(b"sudo -n python3", observed[0])
        self.assertIn(b"os.close(2)", observed[0])
        self.assertNotIn(b"2>/dev/null", observed[0])
        self.assertNotIn(b"samba-tool", observed[0])
        self.assertEqual(
            VALUES,
            json.loads(base64.b64decode(observed[1]).decode("utf-8")),
        )
        for secret in VALUES.values():
            self.assertNotIn(secret, repr(result))
            self.assertNotIn(secret.encode(), observed[0])

    def test_destroy_uses_same_non_echo_boundary_and_no_credentials(self):
        names = tuple(VALUES)
        result, observed = self.run_operation(
            lambda serial: serial.destroy(names))
        self.assertEqual("destroy", result.operation)
        self.assertEqual(names, result.principals)
        self.assertEqual(
            list(names),
            json.loads(base64.b64decode(observed[1]).decode("utf-8")),
        )
        self.assertFalse(any(
            secret.encode() in b"".join(observed)
            for secret in VALUES.values()))

    def test_stage_program_verifies_public_identity_and_account_state(self):
        program = controller_principals._STAGE_PROGRAM
        for attribute in (
                "sAMAccountName", "userPrincipalName", "userAccountControl",
                "msDS-User-Account-Control-Computed", "accountExpires",
                "lockoutTime", "badPwdCount", "pwdLastSet", "objectSid",
                "uidNumber", "gidNumber", "loginShell", "unixHomeDirectory"):
            self.assertIn(f'"{attribute}"', program)
        self.assertIn("expected_upn = name + \"@\" + realm", program)
        self.assertIn("FLAG_MOD_REPLACE", program)
        self.assertIn("controls[0] & 0x0200 == 0", program)
        self.assertIn("controls[0] & (0x0002 | 0x0020 | 0x800000)", program)
        self.assertIn("expires not in ([], [0], [9223372036854775807])",
                      program)
        self.assertIn("lockout not in ([], [0])", program)
        self.assertIn("bad_passwords not in ([], [0])", program)
        self.assertIn("password_set[0] <= 0", program)
        self.assertIn("sid_values[0] in sids", program)
        self.assertIn("rollback_failures = []", program)
        self.assertIn('"staged principal rollback failed: "', program)

    def test_posix_allocation_is_pinned_for_sssd_id_mapping_off(self):
        # ADR 0055: UID and GID come from the directory.  These numbers are
        # the stable cross-machine identities; changing them orphans every
        # file an Arch Workstation ever wrote.  Users are base 10000 plus
        # ROLE position; groups are base 10000 plus well-known AD RID.
        #
        # Pinned against the contract roster with the private overlay
        # explicitly out of the way, so this is the acceptance path's
        # allocation whether or not this machine has an overlay.
        self.assertEqual(
            {
                "users": {
                    "student": {
                        "uidNumber": 10000,
                        "gidNumber": 10513,
                        "loginShell": "/bin/bash",
                        "unixHomeDirectory": "/home/student",
                    },
                    "operator": {
                        "uidNumber": 10001,
                        "gidNumber": 10513,
                        "loginShell": "/bin/bash",
                        "unixHomeDirectory": "/home/operator",
                    },
                    "directory-admin": {
                        "uidNumber": 10002,
                        "gidNumber": 10513,
                        "loginShell": "/bin/bash",
                        "unixHomeDirectory": "/home/directory-admin",
                    },
                },
                "groups": {
                    "Domain Users": 10513,
                    "Domain Admins": 10512,
                },
            },
            controller_principals._posix_allocation(CONTRACT_ROSTER),
        )
        # Re-deriving the live allocation must reproduce the live roster.
        self.assertEqual(
            controller_principals.POSIX_ALLOCATION,
            controller_principals._posix_allocation(),
        )

    def test_stage_program_bakes_and_verifies_posix_attributes(self):
        program = controller_principals._STAGE_PROGRAM
        self.assertNotIn("@POSIX_JSON@", program)
        self.assertIn(
            json.dumps(
                controller_principals.POSIX_ALLOCATION,
                sort_keys=True, separators=(",", ":"),
            ),
            program,
        )
        # The users are created with the directory-stored POSIX attributes.
        for keyword in (
                'uidnumber=unix["uidNumber"]',
                'gidnumber=unix["gidNumber"]',
                'loginshell=unix["loginShell"]',
                'unixhome=unix["unixHomeDirectory"]'):
            self.assertIn(keyword, program)
        # The privilege and primary groups receive their gidNumber before
        # any user exists, and both writes are verified read-back.
        self.assertIn(
            '"(&(objectClass=group)(sAMAccountName=" + group + "))"',
            program)
        self.assertIn("posix group is not stored exactly once", program)
        self.assertIn("posix group gidNumber is invalid", program)
        # Every staged user is verified to carry the exact allocation.
        for message in (
                "staged principal uidNumber is invalid",
                "staged principal gidNumber is invalid",
                "staged principal login shell is invalid",
                "staged principal unix home is invalid"):
            self.assertIn(message, program)

    def test_stage_program_creates_owned_per_user_unas_share_roots(self):
        # Gate 9: each staged user owns /srv/unas/<name>, owned by the
        # directory-stored POSIX uid/gid so smbd's rfc2307 mapping grants the
        # share owner (arch-storage-attached) and denies a foreign user
        # (arch-storage-denied).  Both the reachable-storage checks depend on
        # these owned directories existing on the serving Controller.
        program = controller_principals._STAGE_PROGRAM
        # The root now arrives as a substituted JSON literal, so this asserts
        # the rendered form rather than a second spelling of the path.
        self.assertIn(
            'path = "' + controller_principals.SHARE_ROOT + '" + "/" + name',
            program)
        self.assertIn("os.makedirs(path, mode=0o700, exist_ok=True)", program)
        self.assertIn(
            'os.chown(path, unix["uidNumber"], unix["gidNumber"])', program)
        self.assertIn("os.chmod(path, 0o700)", program)

    def test_destroy_program_removes_per_user_unas_share_roots(self):
        # The disposable Controller's share roots are torn down with the
        # principals so a reused canonical state never retains stale shares.
        program = controller_principals._DESTROY_PROGRAM
        self.assertIn(
            'shutil.rmtree("' + controller_principals.SHARE_ROOT
            + '" + "/" + name', program)

    def test_posix_allocation_rejects_collisions(self):
        validate = controller_principals._validated_posix_allocation
        base = controller_principals.POSIX_ALLOCATION

        def variant(**changes):
            users = {
                name: dict(attrs) for name, attrs in base["users"].items()
            }
            groups = dict(base["groups"])
            for name, attrs in changes.pop("users", {}).items():
                users[name].update(attrs)
            groups.update(changes.pop("groups", {}))
            return {"users": users, "groups": groups}

        self.assertEqual(base, validate(variant()))
        with self.assertRaisesRegex(ValueError, "uidNumber .*collides"):
            validate(variant(users={ROLES[1]: {"uidNumber": 10000}}))
        with self.assertRaisesRegex(ValueError, "gidNumber .*collides"):
            validate(variant(groups={"Domain Admins": 10513}))
        with self.assertRaisesRegex(ValueError, "ranges collide"):
            validate(variant(users={ROLES[0]: {"uidNumber": 10512}}))
        with self.assertRaisesRegex(ValueError, "not a staged group"):
            validate(variant(users={ROLES[0]: {"gidNumber": 10999}}))
        with self.assertRaisesRegex(ValueError, "uidNumber is out of range"):
            validate(variant(users={ROLES[0]: {"uidNumber": 999}}))
        with self.assertRaisesRegex(ValueError, "gidNumber is out of range"):
            validate(variant(groups={"Domain Users": 100}))

    def test_destroy_program_proves_every_principal_absent(self):
        program = controller_principals._DESTROY_PROGRAM
        self.assertIn('expression="(sAMAccountName=" + name + ")"', program)
        self.assertIn('attrs=["sAMAccountName"]', program)
        self.assertIn('failures.append("PrincipalRemains")', program)

    def test_password_authenticated_sudo_is_secret_safe(self):
        password = b"Controller-private-47!"
        result, observed = self.run_operation(
            lambda serial: serial.stage(VALUES), sudo_password=password)
        self.assertEqual("stage", result.operation)
        self.assertIn(b"sudo -k -p", observed[0])
        self.assertNotIn(b"sudo -S", observed[0])
        self.assertNotIn(password, observed[0])
        self.assertEqual(password + b"\n", observed[2])

    def test_result_shape_cannot_retain_payload_or_transcript(self):
        self.assertEqual(
            ("operation", "principals", "events"),
            tuple(ControllerPrincipalResult.__dataclass_fields__),
        )

    def test_rejects_missing_duplicate_or_multiline_credentials(self):
        serial = ControllerPrincipalSerial(
            io.BytesIO(), io.BytesIO(),
        )
        with self.assertRaisesRegex(ValueError, "roster"):
            serial.stage({ROLES[0]: "value"})
        duplicate = dict(VALUES)
        duplicate[ROLES[1]] = duplicate[ROLES[0]]
        with self.assertRaisesRegex(ValueError, "distinct"):
            serial.stage(duplicate)
        multiline = dict(VALUES)
        multiline[ROLES[1]] = "unsafe\nvalue"
        with self.assertRaisesRegex(ValueError, "credential"):
            serial.stage(multiline)

    def test_nonzero_guest_result_is_fail_closed(self):
        with self.assertRaisesRegex(
                ControllerPrincipalError, "stage returned 7"):
            self.run_operation(
                lambda serial: serial.stage(VALUES), returncode=7)

    def test_destroy_refuses_partial_roster(self):
        left, right = socket.socketpair()
        try:
            serial = ControllerPrincipalSerial(
                left.makefile("rb"), left.makefile("wb"))
            with self.assertRaisesRegex(ValueError, "roster"):
                serial.destroy(ROLES[:2])
        finally:
            left.close()
            right.close()

    def test_disposable_controller_session_starts_systemd_and_logs_in(self):
        left, right = socket.socketpair()
        password = b"Controller-private-47!"
        observed = []

        def responder():
            stream = right.makefile("rb", buffering=0)
            right.sendall(b"bash-5.2# ")
            remount = stream.readline()
            observed.append(remount)
            marker = remount.split(
                b"__TELOS_CONTROLLER_INIT_", 1)[1].split(b"__", 1)[0]
            right.sendall(
                b"\r\n__TELOS_CONTROLLER_INIT_" + marker + b"__\r\n"
                b"bash-5.2# ")
            observed.append(stream.readline())
            right.sendall(b"New password: ")
            observed.append(stream.readline())
            right.sendall(b"Retype new password: ")
            observed.append(stream.readline())
            right.sendall(
                b"passwd: password updated successfully\r\nbash-5.2# ")
            observed.append(stream.readline())
            right.sendall(b"bootstrap-dc login: ")
            observed.append(stream.readline())
            right.sendall(b"Password: ")
            observed.append(stream.readline())
            right.sendall(b"[local-rescue@bootstrap-dc ~]$ ")

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            console = SerialAutomation(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0),
                password,
                timeout=1,
            )
            console.establish_disposable_controller_session()
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertIn(b"mount -o remount,rw /", observed[0])
        self.assertEqual(b"/usr/bin/passwd local-rescue\n", observed[1])
        self.assertEqual(password + b"\n", observed[2])
        self.assertEqual(password + b"\n", observed[3])
        self.assertEqual(
            b"exec /usr/lib/systemd/systemd\n", observed[4])
        self.assertEqual(b"local-rescue\n", observed[5])
        self.assertEqual(password + b"\n", observed[6])
        self.assertNotIn(password, observed[0])

    def test_convergence_requires_pass_release_and_ad_readiness(self):
        left, right = socket.socketpair()
        password = b"Controller-private-47!"
        observed = []

        def responder():
            stream = right.makefile("rb", buffering=0)
            self.assertEqual(b"\n", stream.readline())
            right.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            command = stream.readline()
            observed.append(command)
            sudo = command.split(
                b"__TELOS_CONVERGE_SUDO_", 1)[1].split(b"__", 1)[0]
            begin = command.split(
                b"__TELOS_CONVERGENCE_BEGIN_", 1)[1].split(b"__", 1)[0]
            result = command.split(
                b"__TELOS_CONVERGENCE_RC_", 1)[1].split(b"=", 1)[0]
            right.sendall(
                b"\r\n__TELOS_CONVERGENCE_BEGIN_" + begin + b"__\r\n"
                b"__TELOS_CONVERGE_SUDO_" + sudo + b"__\r\n")
            observed.append(stream.readline())
            right.sendall(
                b"TELOS FACTORY CONTROLLER PASS\r\n"
                b"__TELOS_CONVERGENCE_RC_" + result + b"=0\r\n")
            self.assertEqual(b"\n", stream.readline())
            right.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            release = stream.readline()
            observed.append(release)
            release_sudo = release.split(
                b"__TELOS_RELEASE_SUDO_", 1)[1].split(b"__", 1)[0]
            released = release.split(
                b"__TELOS_CONVERGENCE_RELEASED_", 1)[1].split(b"=", 1)[0]
            right.sendall(
                b"\r__TELOS_RELEASE_SUDO_" + release_sudo + b"__")
            observed.append(stream.readline())
            right.sendall(
                b"\r\n__TELOS_CONVERGENCE_RELEASED_" + released + b"=0\r\n")
            services = stream.readline()
            observed.append(services)
            service_token = services.split(
                b"__TELOS_CONTROLLER_SERVICES_", 1)[1].split(b"=", 1)[0]
            right.sendall(
                b"\r\n__TELOS_CONTROLLER_SERVICES_"
                + service_token + b"=0\r\n")

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            console = SerialAutomation(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0),
                password,
                timeout=1,
            )
            guest_command = FactoryBundle.guest_command("a" * 64)
            console.converge_disposable_controller(guest_command)
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())
        self.assertNotIn(password, observed[0] + observed[2] + observed[4])
        self.assertEqual(password + b"\n", observed[1])
        self.assertEqual(password + b"\n", observed[3])
        self.assertIn(b"umount /run/telos-factory", observed[2])
        self.assertIn(b"systemctl is-active --quiet samba.service", observed[4])
        words = shlex.split(observed[0].decode("ascii").strip())
        self.assertEqual(guest_command, words[words.index("-c") + 1])

    def test_convergence_waits_for_complete_stage_line(self):
        left, right = socket.socketpair()
        password = b"Controller-private-47!"

        def responder():
            stream = right.makefile("rb", buffering=0)
            self.assertEqual(b"\n", stream.readline())
            right.sendall(b"[local-rescue@bootstrap-dc ~]$ ")
            command = stream.readline()
            sudo = command.split(
                b"__TELOS_CONVERGE_SUDO_", 1)[1].split(b"__", 1)[0]
            begin = command.split(
                b"__TELOS_CONVERGENCE_BEGIN_", 1)[1].split(b"__", 1)[0]
            result = command.split(
                b"__TELOS_CONVERGENCE_RC_", 1)[1].split(b"=", 1)[0]
            right.sendall(
                b"\r\n__TELOS_CONVERGENCE_BEGIN_" + begin + b"__\r\n"
                b"__TELOS_CONVERGE_SUDO_" + sudo + b"__\r\n")
            self.assertEqual(password + b"\n", stream.readline())
            for byte in (
                b"TELOS FACTORY STEP package-missing-krb5\r\n"
                b"__TELOS_CONVERGENCE_RC_" + result + b"=1\r\n"
            ):
                right.sendall(bytes((byte,)))

        thread = threading.Thread(target=responder, daemon=True)
        thread.start()
        try:
            console = SerialAutomation(
                left.makefile("rb", buffering=0),
                left.makefile("wb", buffering=0),
                password,
                timeout=1,
            )
            with self.assertRaisesRegex(
                SerialAutomationError,
                r"returned 1 after package-missing-krb5$",
            ):
                console.converge_disposable_controller(
                    FactoryBundle.guest_command("a" * 64))
        finally:
            left.close()
            right.close()
        thread.join(timeout=1)
        self.assertFalse(thread.is_alive())


class RosterOverlayTests(unittest.TestCase):
    """The staged roster follows the ONE loader, and its UIDs follow the ROLE.

    These exercise the derivation functions directly rather than reloading the
    module, so nothing global is mutated and the proofs stay honest about what
    they cover: the allocation, the guest programs and the wire roster.
    """

    def test_no_overlay_reproduces_todays_roster_and_uids_exactly(self):
        # The acceptance path, byte for byte.  If this ever needs editing, gate
        # 6 and gate 8 both have to be re-proven and every file an Arch
        # Workstation wrote under the old UIDs is orphaned.
        self.assertEqual(
            {
                "standard_user": "student",
                "daily_administrator": "operator",
                "domain_administrator": "directory-admin",
                "local_rescue": "local-rescue",
            },
            CONTRACT_ROSTER,
        )
        self.assertEqual(
            ("student", "operator", "directory-admin"),
            tuple(CONTRACT_ROSTER[role] for role in DIRECTORY_ROLES),
        )
        allocation = controller_principals._posix_allocation(CONTRACT_ROSTER)
        self.assertEqual(
            {"student": 10000, "operator": 10001, "directory-admin": 10002},
            {name: user["uidNumber"]
             for name, user in allocation["users"].items()},
        )
        self.assertEqual(
            {10513}, {user["gidNumber"]
                      for user in allocation["users"].values()})
        # The break-glass account owns no directory UID at all: it is the local
        # 1000 that ADR 0055 requires to stay local.
        self.assertNotIn(
            CONTRACT_ROSTER["local_rescue"], allocation["users"])

    def _renamed(self) -> dict[str, str]:
        # Placeholder names in the same shape the owner's real overlay uses.
        return {
            "standard_user": "roster-a",
            "daily_administrator": "roster-b",
            "domain_administrator": "roster-c",
            "local_rescue": "roster-d",
        }

    def test_an_overlay_renames_the_roster_without_moving_a_uid(self):
        renamed = self._renamed()
        allocation = controller_principals._posix_allocation(renamed)
        self.assertEqual(
            {"roster-a": 10000, "roster-b": 10001, "roster-c": 10002},
            {name: user["uidNumber"]
             for name, user in allocation["users"].items()},
        )
        # The UID belongs to the ROLE, so a rename moves no number.
        for role, index in zip(DIRECTORY_ROLES, range(3)):
            self.assertEqual(
                controller_principals._posix_allocation(
                    CONTRACT_ROSTER)["users"][
                        CONTRACT_ROSTER[role]]["uidNumber"],
                allocation["users"][renamed[role]]["uidNumber"],
                role,
            )
        self.assertEqual(
            {"roster-a": "/home/roster-a", "roster-b": "/home/roster-b",
             "roster-c": "/home/roster-c"},
            {name: user["unixHomeDirectory"]
             for name, user in allocation["users"].items()},
        )
        self.assertEqual(
            controller_principals._validated_posix_allocation(allocation),
            allocation)

    def test_a_renamed_roster_reaches_both_guest_programs(self):
        # A stale hardcoded name left in a guest program would fail as
        # "unexpected principal roster" inside a disposable VM, so the roster is
        # substituted into BOTH programs and neither retains a literal name.
        renamed = self._renamed()
        roles = tuple(renamed[role] for role in DIRECTORY_ROLES)
        roster_json = controller_principals._roster_json(
            roles, renamed["domain_administrator"])
        allocation = controller_principals._posix_allocation(renamed)
        for template in (
            controller_principals._STAGE_PROGRAM_TEMPLATE,
            controller_principals._DESTROY_PROGRAM_TEMPLATE,
        ):
            program = controller_principals._substituted(
                template, roster_json, allocation)
            self.assertNotIn("@ROSTER_JSON@", program)
            self.assertIn('"order":["roster-a","roster-b","roster-c"]', program)
            for name in CONTRACT_ROSTER.values():
                self.assertNotIn(name, program, name)
        staged = controller_principals._substituted(
            controller_principals._STAGE_PROGRAM_TEMPLATE,
            roster_json, allocation)
        self.assertIn('"domain_administrator":"roster-c"', staged)
        self.assertIn(
            'samdb.add_remove_group_members(\n'
            '        "Domain Admins", [roster["domain_administrator"]]',
            staged)

    def test_the_live_programs_carry_the_live_roster_and_no_placeholder(self):
        for program in (controller_principals._STAGE_PROGRAM,
                        controller_principals._DESTROY_PROGRAM):
            self.assertNotIn("@ROSTER_JSON@", program)
            self.assertNotIn("@POSIX_JSON@", program)
            self.assertIn(controller_principals._ROSTER_JSON, program)

    def test_an_unsafe_or_colliding_roster_is_refused(self):
        # Gate one: the shared loader refuses anything that would need quoting
        # in a shell word, a sudoers rule, an SMB share name or a Kerberos
        # principal, and refuses two roles sharing a name.
        from homelab.workstations.arch_second import IdentityRosterError
        for unsafe in ("who; reboot", "WHO", "0who", "who root", "", "a" * 33):
            with self.subTest(name=unsafe):
                with self.assertRaisesRegex(
                        IdentityRosterError, "safely representable"):
                    self._roster_with(standard_user=unsafe)
        with self.assertRaisesRegex(IdentityRosterError, "not distinct"):
            self._roster_with(standard_user=CONTRACT_ROSTER["local_rescue"])
        # Gate two, deliberately kept: this module re-checks the same names
        # before baking them into a guest program.
        self.assertIsNone(
            controller_principals._SAFE_NAME.fullmatch("who; reboot"))
        for name in controller_principals._ROLES:
            self.assertIsNotNone(
                controller_principals._SAFE_NAME.fullmatch(name), name)

    def test_a_hand_built_roster_cannot_collapse_two_roles(self):
        # ``directory_account_plan(roles, roster=...)`` is PUBLIC and the
        # durable path (the domain_controller role's control-host resolver)
        # reaches it with a mapping identity_roster never saw.  The allocation
        # keys ``users`` by NAME, so two roles sharing one name used to
        # overwrite each other silently: the plan came back one account short
        # and every collision check still passed, because there was nothing
        # left to collide.
        collapsed = dict(
            CONTRACT_ROSTER,
            daily_administrator=CONTRACT_ROSTER["domain_administrator"])
        with self.assertRaisesRegex(
                controller_principals.DirectoryPlanError, "not distinct"):
            controller_principals.directory_account_plan(
                list(DIRECTORY_ROLES), roster=collapsed)
        with self.assertRaisesRegex(
                controller_principals.DirectoryPlanError, "not distinct"):
            controller_principals._posix_allocation(collapsed)
        # The same public entry point also applies the name gate the loader
        # applies, and refuses a roster missing a directory role outright.
        with self.assertRaisesRegex(
                controller_principals.DirectoryPlanError,
                "safely representable"):
            controller_principals.directory_account_plan(
                list(DIRECTORY_ROLES),
                roster=dict(CONTRACT_ROSTER, standard_user="who; reboot"))
        with self.assertRaisesRegex(
                controller_principals.DirectoryPlanError, "no name"):
            controller_principals.directory_account_plan(
                list(DIRECTORY_ROLES),
                roster={"standard_user": "roster-a"})
        # A valid roster still plans exactly one account per requested role.
        self.assertEqual(
            len(DIRECTORY_ROLES),
            len(controller_principals.directory_account_plan(
                list(DIRECTORY_ROLES), roster=CONTRACT_ROSTER)))

    def test_a_roster_refusal_names_where_the_roster_came_from(self):
        # The refusal a live gate-6 run met was the bare "Controller principal
        # roster is invalid", from inside stage_controller_principals, with a
        # serial transcript as the only evidence.  It named neither the roster
        # it expected nor the file that produced it.
        serial = ControllerPrincipalSerial(io.BytesIO(), io.BytesIO())
        with self.assertRaises(ValueError) as raised:
            serial.stage({"nobody-here": "Secret-47!"})
        message = str(raised.exception)
        for name in ROLES:
            self.assertIn(name, message)
        self.assertIn("nobody-here", message)
        self.assertIn(controller_principals.ROSTER_SOURCE, message)
        # And the source phrase names the tracked contract, always.
        self.assertIn(
            "identity_lifecycle.json", controller_principals.ROSTER_SOURCE)

    def _roster_with(self, **overrides):
        import json as json_module
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            overlay = Path(root) / "principals.json"
            overlay.write_text(json_module.dumps({
                "schema_version": 1,
                "principals": {
                    role: {"name": name} for role, name in overrides.items()
                },
            }), encoding="utf-8")
            return identity_roster(overlay_path=overlay)

    def test_one_declaration_reaches_the_disk_and_the_persistent_directory(self):
        # The defect this replaced: two independent declarations of the same real
        # accounts, in two files, in two shapes, with two different UID keyings.
        # Now the workstation disk's names and the durable directory's accounts
        # are the same resolution of the same declaration, and the durable
        # allocation is the same function the disposable path already uses.
        from homelab.workstations import arch_second

        for roster in (CONTRACT_ROSTER, self._renamed()):
            with self.subTest(roster=sorted(roster)[0]):
                # The names the gate-7 installer bakes onto the disk.
                baked = arch_second._identity_principals(roster)
                plan = controller_principals.directory_account_plan(
                    list(DIRECTORY_ROLES), roster=roster)
                self.assertEqual(
                    [entry["name"] for entry in plan],
                    [baked["standard"], baked["daily_admin"],
                     baked["domain_admin"]],
                )
                # ...and the break-glass account is on the disk and nowhere in
                # the directory allocation (ADR 0055/0063).
                self.assertEqual(baked["local_rescue"], roster["local_rescue"])
                self.assertNotIn(baked["local_rescue"],
                                 [entry["name"] for entry in plan])
                # One rule: the durable plan's numbers ARE the disposable
                # allocation's numbers for the same roster.
                allocation = controller_principals._posix_allocation(roster)
                for entry in plan:
                    unix = allocation["users"][entry["name"]]
                    for attribute in ("uidNumber", "gidNumber", "loginShell",
                                      "unixHomeDirectory"):
                        self.assertEqual(entry[attribute], unix[attribute])

    def test_the_wire_roster_and_the_credentials_follow_the_live_roster(self):
        # ``stage``/``destroy`` accept EXACTLY the resolved roster, so a caller
        # holding a stale name is refused on this side of the console.
        serial = ControllerPrincipalSerial(io.BytesIO(), io.BytesIO())
        with self.assertRaisesRegex(ValueError, "roster"):
            serial.destroy(tuple(self._renamed()[role]
                                 for role in DIRECTORY_ROLES))
        with self.assertRaisesRegex(ValueError, "roster"):
            serial.stage({self._renamed()[role]: "Secret-47!"
                          for role in DIRECTORY_ROLES})
        self.assertEqual(set(ROLES), set(VALUES))
        self.assertEqual(len(CONTRACT_ROLES), 4)


class DurableDirectoryRosterTests(unittest.TestCase):
    """The roster a PERMANENT directory may be provisioned from.

    The disposable acceptance lane falls back to the tracked contract's
    synthetic names, and that is correct there: the accounts are destroyed with
    the guest.  A persistent instance is the opposite case -- the SIDs it mints
    are permanent -- so the durable entry point requires the owner's private
    overlay and refuses rather than falling back.
    """

    OVERLAY = {
        "schema_version": 1,
        "principals": {
            "standard_user": {"name": "ava"},
            "daily_administrator": {"name": "ksh"},
            "domain_administrator": {"name": "roster-c"},
        },
    }

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.overlay = self.root / "principals.json"
        self.overlay.write_text(json.dumps(self.OVERLAY), encoding="utf-8")
        self.roster = controller_principals.durable_directory_roster(
            self.overlay)

    def test_a_missing_overlay_is_a_refusal_and_never_a_fallback(self):
        absent = self.root / "not-here.json"
        with self.assertRaises(Exception) as raised:
            controller_principals.durable_directory_roster(absent)
        message = str(raised.exception)
        self.assertIn(str(absent), message)
        self.assertIn("synthetic acceptance roster", message)
        # The same path with no ``require_overlay`` is exactly the synthetic
        # roster, which is what makes the refusal load-bearing.
        self.assertEqual(
            ("student", "operator", "directory-admin"),
            tuple(identity_roster(overlay_path=absent)[role]
                  for role in DIRECTORY_ROLES))

    def test_an_unreadable_overlay_is_a_refusal_too(self):
        broken = self.root / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        with self.assertRaisesRegex(Exception, "unreadable JSON"):
            controller_principals.durable_directory_roster(broken)

    def test_a_durable_roster_bakes_its_own_programs_and_its_own_names(self):
        stage, destroy, roles = controller_principals._programs(self.roster)
        self.assertEqual(("ava", "ksh", "roster-c"), roles)
        for program in (stage, destroy):
            self.assertIn('"order":["ava","ksh","roster-c"]', program)
            # The synthetic acceptance names are nowhere in a durable program.
            for synthetic in ("student", "operator", "directory-admin"):
                self.assertNotIn(f'"{synthetic}"', program)
        # One rule, two rosters: the durable POSIX numbers are the acceptance
        # allocation's numbers for the same ROLE positions.
        self.assertIn('"ava":{"gidNumber":10513,"loginShell":"/bin/bash",'
                      '"uidNumber":10000', stage)
        self.assertIn('"ksh":{"gidNumber":10513,"loginShell":"/bin/bash",'
                      '"uidNumber":10001', stage)

    def test_only_the_domain_administrator_joins_domain_admins(self):
        stage, _destroy, _roles = controller_principals._programs(self.roster)
        self.assertEqual(
            ("domain_administrator",),
            controller_principals.DIRECTORY_ADMIN_ROLES)
        self.assertIn('"domain_administrator":"roster-c"', stage)
        membership = stage.split(
            "add_remove_group_members(", 1)[1].split(")", 1)[0]
        self.assertIn('"Domain Admins"', membership)
        self.assertIn('roster["domain_administrator"]', membership)
        self.assertNotIn("ksh", membership)
        plan = controller_principals.directory_account_plan(
            list(DIRECTORY_ROLES), roster=self.roster)
        by_role = {entry["contract_role"]: entry for entry in plan}
        self.assertEqual("standard", by_role["daily_administrator"]["role"])
        self.assertEqual(
            "administrator", by_role["domain_administrator"]["role"])

    def test_a_durable_console_validates_against_its_own_roster(self):
        serial = ControllerPrincipalSerial(
            io.BytesIO(), io.BytesIO(), roster=self.roster,
            roster_source="a private overlay")
        self.assertEqual(("ava", "ksh", "roster-c"), serial.roles)
        # The module's own (possibly synthetic) roster is not what this console
        # accepts, and the refusal names the source it was told about.
        with self.assertRaises(ValueError) as raised:
            serial.stage({CONTRACT_ROSTER[role]: f"Secret-{index}-47!"
                          for index, role in enumerate(DIRECTORY_ROLES)})
        message = str(raised.exception)
        self.assertIn("a private overlay", message)
        self.assertIn("student", message)
        self.assertIn("ava", message)
        # A default console is byte-for-byte unchanged.
        default = ControllerPrincipalSerial(io.BytesIO(), io.BytesIO())
        self.assertEqual(ROLES, default.roles)
        self.assertEqual(controller_principals.ROSTER_SOURCE,
                         default.roster_source)
        self.assertIsNone(default.console.password)

    def test_an_overlay_that_names_nobody_is_a_refusal(self):
        # The template `make homelab-instance` copies is exactly this: it
        # exists, so require_overlay alone accepted it, and every durable
        # account took its synthetic name -- permanently.
        inert = self.root / "inert.json"
        inert.write_text(json.dumps({"schema_version": 1, "principals": {}}),
                         encoding="utf-8")
        with self.assertRaises(
                controller_principals.IdentityRosterError) as raised:
            controller_principals.durable_directory_roster(inert)
        message = str(raised.exception)
        self.assertIn(str(inert), message)
        self.assertIn("synthetic acceptance roster", message)
        for role in DIRECTORY_ROLES:
            self.assertIn(role, message)

    def test_an_overlay_that_leaves_a_directory_role_unnamed_is_a_refusal(self):
        partial = self.root / "partial.json"
        partial.write_text(json.dumps({
            "schema_version": 1,
            "principals": {
                "standard_user": {"name": "ava"},
                "daily_administrator": {"name": "ksh"},
            },
        }), encoding="utf-8")
        with self.assertRaises(
                controller_principals.IdentityRosterError) as raised:
            controller_principals.durable_directory_roster(partial)
        message = str(raised.exception)
        # It names the unnamed role and the synthetic name it would have got.
        self.assertIn("domain_administrator -> directory-admin", message)
        self.assertNotIn("standard_user ->", message)
        # A caller that plans only the named roles is not refused.
        self.assertEqual("ksh", controller_principals.durable_directory_roster(
            partial, roles=("standard_user", "daily_administrator"),
        ).roster["daily_administrator"])

    def test_the_break_glass_role_need_not_be_named(self):
        # local_rescue is a LOCAL account, never a directory SID, so leaving it
        # to its contract name mints nothing permanent in the directory.
        self.assertNotIn("local_rescue", self.OVERLAY["principals"])
        self.assertEqual("local-rescue", self.roster.roster["local_rescue"])

    def test_change_at_first_logon_is_opt_in_and_durable_only(self):
        plain = ControllerPrincipalSerial(
            io.BytesIO(), io.BytesIO(), roster=self.roster)
        first = ControllerPrincipalSerial(
            io.BytesIO(), io.BytesIO(), roster=self.roster, first_logon=True)
        self.assertNotIn('"first_logon":true', plain._stage_program)
        self.assertIn('"first_logon":true', first._stage_program)
        self.assertEqual(plain.roles, first.roles)
        # The disposable acceptance lanes log in as these accounts.
        with self.assertRaisesRegex(ValueError, "durable roster only"):
            ControllerPrincipalSerial(
                io.BytesIO(), io.BytesIO(), first_logon=True)

    def test_the_policy_is_lifted_only_around_account_creation(self):
        stage = ControllerPrincipalSerial(
            io.BytesIO(), io.BytesIO(), roster=self.roster,
            first_logon=True)._stage_program
        lifted = stage.index("set_password_policy(policy_saved[0] & ~1, 0)")
        created = stage.index("samdb.newuser(")
        restored = stage.index("set_password_policy(*policy_saved)")
        self.assertLess(lifted, created)
        self.assertLess(created, restored)
        # Restored in a finally clause, so a failed stage restores it too,
        # and a restore that fails is its own named failure.
        self.assertIn("finally:", stage[created:restored])
        self.assertIn("password-policy-not-restored", stage[restored:])
        self.assertIn("force_password_change_at_next_login_req=first_logon",
                      stage)
        # The verification demands an expired password here and nowhere else.
        self.assertIn("expired = 0x800000 if first_logon else 0", stage)

    def test_a_durable_console_answers_sudos_own_prompt(self):
        # A persistent instance's console account has a password the operator
        # typed into the offline installer, so the durable path must take the
        # `sudo -k -p` branch and never the disposable `sudo -n` one.
        password = b"typed-console-secret"
        serial = ControllerPrincipalSerial(
            io.BytesIO(), io.BytesIO(), roster=self.roster,
            password=password)
        self.assertEqual(password, serial.console.password)


# The Windows lane modules that used to restate the roster.  Each one is
# imported by, or imports, this module's principal names.
WINDOWS_LANE = (
    "windows_identity_run",
    "windows_identity_orchestrator",
    "windows_identity_adapter",
    "windows_join_iso",
    "controller_join_material",
)


def _code_without_comments(path: Path) -> str:
    """The module's source with ``#`` comments removed, strings intact."""
    pieces = []
    with path.open("rb") as stream:
        for token in tokenize.tokenize(stream.readline):
            if token.type == tokenize.COMMENT:
                continue
            pieces.append(token.string)
    return "\n".join(pieces)


class WindowsLaneDerivesItsRosterTests(unittest.TestCase):
    """Blocker 6: the Windows lane must DERIVE the roster, never restate it.

    ``windows_identity_run.stage_controller_principals`` hardcoded
    ``("student", "operator", "directory-admin")`` and never consulted the
    roster loader, while this module refuses any roster but its own -- so the
    first run against the owner's private overlay died at
    ``stage_controller_principals`` with "Controller principal roster is
    invalid", naming neither the roster source nor the overlay file.  The Arch
    lane was already correct (``arch_identity_run`` reads
    ``POSIX_ALLOCATION["users"]``); these tests hold the Windows lane to the
    same seam.
    """

    def test_no_windows_lane_module_restates_a_principal_name(self):
        # Comments are stripped: the modules explain the old literals in prose,
        # and prose is not what runs.  ``"operator"`` on its own stays legal --
        # it is the join document's FIELD name and the guest control script's
        # contract, not a principal name -- so the scan looks for the two
        # unambiguous names and for the operator UPN literal.
        forbidden = ('"student"', "'student'", '"directory-admin"',
                     "'directory-admin'", "operator@")
        root = Path(controller_principals.__file__).resolve().parent
        for module in WINDOWS_LANE:
            code = _code_without_comments(root / f"{module}.py")
            for needle in forbidden:
                with self.subTest(module=module, literal=needle):
                    self.assertNotIn(needle, code)

    def test_the_lane_stages_exactly_what_this_module_accepts(self):
        # The seam itself, with no overlay in play: what
        # stage_controller_principals will ask for is exactly the roster
        # ControllerPrincipalSerial._values admits.
        from homelab.vm.windows_identity_run import DIRECTORY_PRINCIPALS
        self.assertEqual(ROLES, DIRECTORY_PRINCIPALS)
        serial = ControllerPrincipalSerial(io.BytesIO(), io.BytesIO())
        self.assertEqual(
            set(DIRECTORY_PRINCIPALS),
            set(serial._values({
                name: f"Secret-{index}-47!"
                for index, name in enumerate(DIRECTORY_PRINCIPALS)})))
        # And with no overlay that is still the synthetic acceptance roster,
        # byte for byte, which is what keeps gates 6 and 8 passing untouched.
        self.assertEqual(
            ("student", "operator", "directory-admin"),
            tuple(CONTRACT_ROSTER[role] for role in DIRECTORY_ROLES))

    def test_a_renamed_roster_reaches_every_windows_lane_module(self):
        # The reviewer's reproduction, run against the REAL modules in a child
        # interpreter: a private overlay naming ava/ksh used to produce
        # "STAGE REFUSED: ValueError Controller principal roster is invalid".
        # A child process because the roster resolves at import and this suite
        # must not disturb the parent's already-imported modules -- nor read or
        # write the owner's real overlay, which is why the overlay is written
        # to a temporary directory and injected by name.
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            overlay = Path(temporary) / "principals.json"
            overlay.write_text(json.dumps({
                "schema_version": 1,
                "principals": {
                    "standard_user": {"name": "ava"},
                    "daily_administrator": {"name": "ksh"},
                },
            }), encoding="utf-8")
            program = f"""
import io, json, sys
sys.path.insert(0, {str(root / "homelab" / "workstations")!r})
import pathlib
import arch_second
arch_second.identity_overlay_path = (
    lambda: pathlib.Path({str(overlay)!r}))
sys.path.insert(0, {str(root)!r})
from homelab.vm import controller_principals as cp
from homelab.vm import windows_identity_run as run
from homelab.vm import windows_identity_orchestrator as orchestrator
from homelab.vm import windows_join_iso as join_iso
from homelab.vm import controller_join_material as material
staged = {{
    name: "Secret-%d-47!" % index
    for index, name in enumerate(run.DIRECTORY_PRINCIPALS)
}}
print(json.dumps({{
    "roles": list(cp.DIRECTORY_PRINCIPALS),
    "staged": sorted(
        cp.ControllerPrincipalSerial(
            io.BytesIO(), io.BytesIO())._values(staged)),
    "uids": {{
        name: entry["uidNumber"]
        for name, entry in cp.POSIX_ALLOCATION["users"].items()
    }},
    "daily_admin_check": orchestrator._CREDENTIAL_ROLES[
        "windows-daily-admin"][0],
    "standard_check": orchestrator._CREDENTIAL_ROLES[
        "windows-standard-online"][0],
    "join_operator": join_iso._validate_material({{
        "nonce": "a" * 32,
        "domain": "ad.factory.test",
        "realm": "AD.FACTORY.TEST",
        "username": "tj-" + "b" * 16 + "@AD.FACTORY.TEST",
        "password": "private value",
        "operator": cp.DAILY_ADMINISTRATOR + "@AD.FACTORY.TEST",
    }})["operator"],
    "material_daily_admin": material.DAILY_ADMINISTRATOR,
    "source": cp.ROSTER_SOURCE,
}}))
"""
            completed = subprocess.run(
                [sys.executable, "-c", program],
                capture_output=True, text=True, cwd=str(root), check=False)
        self.assertEqual(
            0, completed.returncode,
            f"child refused the overlay: {completed.stderr}")
        observed = json.loads(completed.stdout)
        # Staging succeeds under the renamed roster; this is the exact call
        # that used to raise.
        self.assertEqual(["ava", "directory-admin", "ksh"], observed["staged"])
        self.assertEqual(
            ["ava", "ksh", "directory-admin"], observed["roles"])
        # Renaming moves no UID: the allocation is keyed on the ROLE.
        self.assertEqual(
            {"ava": 10000, "ksh": 10001, "directory-admin": 10002},
            observed["uids"])
        # Every Windows-lane consumer followed.
        self.assertEqual("ksh", observed["daily_admin_check"])
        self.assertEqual("ava", observed["standard_check"])
        self.assertEqual("ksh@AD.FACTORY.TEST", observed["join_operator"])
        self.assertEqual("ksh", observed["material_daily_admin"])
        # And the resolved source names the overlay that produced it.
        self.assertIn("patched by overlay", observed["source"])


# The owner's requested layout, 2026-09-25, with PLACEHOLDER names (ADR 0046):
# domain administrator 10000, daily administrator 10001, one additional standard
# user 10002, standard user 10003; local_rescue keeps its contract name.
OWNER_LAYOUT = {
    "schema_version": 1,
    "principals": {
        "standard_user": {"name": "roster-a", "uid_number": 10003},
        "daily_administrator": {"name": "roster-b", "uid_number": 10001},
        "domain_administrator": {"name": "roster-c", "uid_number": 10000},
    },
    "additional_standard_users": [
        {"name": "roster-e", "uid_number": 10002},
    ],
}
# (contract_role, name, directory role, uidNumber) of every durable account the
# owner's layout must produce, in plan order.
OWNER_PLAN = [
    ("standard_user", "roster-a", "standard", 10003),
    ("daily_administrator", "roster-b", "standard", 10001),
    ("domain_administrator", "roster-c", "administrator", 10000),
    ("additional_standard_user_10002", "roster-e", "standard", 10002),
]


class UidPinAndAdditionalUserTests(unittest.TestCase):
    """uid_number pins and additional standard users, through every derivation.

    The loader judges the overlay; these prove what the allocation, the durable
    plan, the guest programs and the console do with a judged declaration --
    and that the disposable acceptance default never carries an additional
    user.  Every overlay is a temporary file.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.overlay = self.write(OWNER_LAYOUT)
        self.durable = controller_principals.durable_directory_roster(
            self.overlay)

    def write(self, document, name="principals.json"):
        path = self.root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    @staticmethod
    def summary(plan):
        return [(entry["contract_role"], entry["name"], entry["role"],
                 entry["uidNumber"]) for entry in plan]

    def test_the_owners_layout_is_the_durable_plan(self):
        plan = controller_principals.directory_account_plan(
            list(DIRECTORY_ROLES), roster=self.durable)
        self.assertEqual(OWNER_PLAN, self.summary(plan))
        for entry in plan:
            with self.subTest(account=entry["contract_role"]):
                self.assertEqual(10513, entry["gidNumber"])
                self.assertEqual("/bin/bash", entry["loginShell"])
                self.assertEqual("/home/" + entry["name"],
                                 entry["unixHomeDirectory"])
        # Additional users are planned whatever subset of roles is declared:
        # they belong to no role.
        subset = controller_principals.directory_account_plan(
            ["daily_administrator"], roster=self.durable)
        self.assertEqual([OWNER_PLAN[1], OWNER_PLAN[3]], self.summary(subset))

    def test_the_owners_layout_is_the_allocation(self):
        allocation = controller_principals._validated_posix_allocation(
            controller_principals._posix_allocation(self.durable), accounts=4)
        self.assertEqual(
            {"roster-a": 10003, "roster-b": 10001, "roster-c": 10000,
             "roster-e": 10002},
            {name: user["uidNumber"]
             for name, user in allocation["users"].items()})
        self.assertEqual({"Domain Users": 10513, "Domain Admins": 10512},
                         allocation["groups"])

    def test_the_owners_layout_is_baked_into_both_guest_programs(self):
        stage, destroy, roles = controller_principals._programs(self.durable)
        self.assertEqual(("roster-a", "roster-b", "roster-c", "roster-e"),
                         roles)
        for program in (stage, destroy):
            self.assertIn(
                '"order":["roster-a","roster-b","roster-c","roster-e"]',
                program)
        for name, uid in (("roster-a", 10003), ("roster-b", 10001),
                          ("roster-c", 10000), ("roster-e", 10002)):
            with self.subTest(name=name):
                self.assertIn(
                    f'"{name}":{{"gidNumber":10513,"loginShell":"/bin/bash",'
                    f'"uidNumber":{uid}', stage)
        # Domain Admins still takes the domain administrator alone, by role.
        self.assertIn('"domain_administrator":"roster-c"', stage)
        membership = stage.split(
            "add_remove_group_members(", 1)[1].split(")", 1)[0]
        self.assertIn('roster["domain_administrator"]', membership)
        self.assertNotIn("roster-e", membership)

    def test_a_durable_console_wants_a_credential_for_every_account(self):
        serial = ControllerPrincipalSerial(
            io.BytesIO(), io.BytesIO(), roster=self.durable,
            roster_source="a private overlay")
        self.assertEqual(("roster-a", "roster-b", "roster-c", "roster-e"),
                         serial.roles)
        three = {name: f"Secret-{index}-47!"
                 for index, name in enumerate(serial.roles[:3])}
        with self.assertRaisesRegex(ValueError, "roster-e"):
            serial.stage(three)
        self.assertEqual(
            set(serial.roles),
            set(serial._values(dict(three, **{"roster-e": "Secret-9-47!"}))))

    def test_a_declaration_from_either_import_path_keeps_its_pins(self):
        # arch_second is importable as ``arch_second`` (what this module uses)
        # and as ``homelab.workstations.arch_second``; they are distinct module
        # objects with distinct classes.  A declaration built through the other
        # one must still be recognised as a declaration, never silently read as
        # a bare name mapping with positional numbers.
        from homelab.workstations import arch_second as other
        declared = other.identity_declaration(overlay_path=self.overlay)
        self.assertEqual(
            OWNER_PLAN, self.summary(controller_principals.directory_account_plan(
                list(DIRECTORY_ROLES), roster=declared)))

    def test_a_bare_name_mapping_gets_positional_numbers_only(self):
        names = dict(self.durable.roster)
        self.assertEqual(
            [("standard_user", "roster-a", "standard", 10000),
             ("daily_administrator", "roster-b", "standard", 10001),
             ("domain_administrator", "roster-c", "administrator", 10002)],
            self.summary(controller_principals.directory_account_plan(
                list(DIRECTORY_ROLES), roster=names)))

    def test_no_pin_means_todays_allocation_and_programs_exactly(self):
        # With no overlay, and with an overlay that renames but pins nothing,
        # the declaration path and the historical bare-roster path produce the
        # same allocation, the same plan and byte-identical guest programs.
        absent = identity_declaration(
            overlay_path=self.root / "no-such-overlay.json")
        renamed_only = controller_principals.durable_directory_roster(
            self.write({
                "schema_version": 1,
                "principals": {
                    role: {"name": entry["name"]}
                    for role, entry in OWNER_LAYOUT["principals"].items()},
            }, name="names-only.json"))
        for declared in (absent, renamed_only):
            with self.subTest(source=declared.source.split()[-1]):
                bare = dict(declared.roster)
                self.assertEqual(
                    controller_principals._programs(bare),
                    controller_principals._programs(declared))
                self.assertEqual(
                    controller_principals._posix_allocation(bare),
                    controller_principals._posix_allocation(declared))
                self.assertEqual(
                    controller_principals.directory_account_plan(
                        list(DIRECTORY_ROLES), roster=bare),
                    controller_principals.directory_account_plan(
                        list(DIRECTORY_ROLES), roster=declared))
                self.assertEqual(
                    [10000, 10001, 10002],
                    [entry["uidNumber"]
                     for entry in controller_principals.directory_account_plan(
                         list(DIRECTORY_ROLES), roster=declared)])
        self.assertEqual(
            {"student": 10000, "operator": 10001, "directory-admin": 10002},
            {name: user["uidNumber"] for name, user in
             controller_principals._posix_allocation(absent)["users"].items()})

    def test_a_caller_built_declaration_is_judged_again(self):
        from dataclasses import replace
        cases = {
            "claimed by both": replace(
                self.durable,
                uid_numbers=dict(self.durable.uid_numbers,
                                 standard_user=10000)),
            "outside the directory range": replace(
                self.durable,
                uid_numbers=dict(self.durable.uid_numbers,
                                 standard_user=60001)),
            "reserved directory object": replace(
                self.durable,
                additional_standard_users=(
                    type(self.durable.additional_standard_users[0])(
                        "krbtgt", 10002),)),
        }
        for reason, declared in cases.items():
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(
                        controller_principals.DirectoryPlanError, reason):
                    controller_principals.directory_account_plan(
                        list(DIRECTORY_ROLES), roster=declared)
                with self.assertRaisesRegex(
                        controller_principals.DirectoryPlanError, reason):
                    controller_principals._programs(declared)
        with self.assertRaisesRegex(ValueError, "out of range"):
            controller_principals._validated_posix_allocation({
                "users": {"a": {"uidNumber": 60001, "gidNumber": 10513}},
                "groups": {"Domain Users": 10513}}, accounts=1)

    def test_the_acceptance_lanes_apply_pins_and_never_stage_extra_users(self):
        # The disposable lanes resolve the overlay at IMPORT, so this runs in a
        # child interpreter with the loader pointed at a temporary overlay --
        # never the owner's real one, and never disturbing this process's
        # already-imported modules.
        root = Path(__file__).resolve().parents[2]
        program = f"""
import io, json, sys
sys.path.insert(0, {str(root / "homelab" / "workstations")!r})
import pathlib
import arch_second
arch_second.identity_overlay_path = (
    lambda: pathlib.Path({str(self.overlay)!r}))
sys.path.insert(0, {str(root)!r})
from homelab.vm import controller_principals as cp
from homelab.vm import windows_identity_run as run
from homelab.vm import arch_identity_run as arch
print(json.dumps({{
    "principals": list(cp.DIRECTORY_PRINCIPALS),
    "windows": list(run.DIRECTORY_PRINCIPALS),
    "uids": {{name: user["uidNumber"]
              for name, user in cp.POSIX_ALLOCATION["users"].items()}},
    "console": list(cp.ControllerPrincipalSerial(
        io.BytesIO(), io.BytesIO()).roles),
    "plan": [entry["contract_role"]
             for entry in cp.directory_account_plan(
                 list(cp.DIRECTORY_ROLES))],
    "program_mentions_extra": "roster-e" in cp._STAGE_PROGRAM
        or "roster-e" in cp._DESTROY_PROGRAM,
    "operator": arch.OPERATOR_PRINCIPAL,
}}))
"""
        completed = subprocess.run(
            [sys.executable, "-c", program],
            capture_output=True, text=True, cwd=str(root), check=False)
        self.assertEqual(0, completed.returncode, completed.stderr)
        observed = json.loads(completed.stdout)
        staged = ["roster-a", "roster-b", "roster-c"]
        self.assertEqual(staged, observed["principals"])
        self.assertEqual(staged, observed["windows"])
        self.assertEqual(staged, observed["console"])
        self.assertEqual(list(DIRECTORY_ROLES), observed["plan"])
        self.assertFalse(observed["program_mentions_extra"])
        # A rehearsal exercises the production numbers: the pins apply, and
        # gate 8's storage check compares against this very allocation.
        self.assertEqual(
            {"roster-a": 10003, "roster-b": 10001, "roster-c": 10000},
            observed["uids"])
        self.assertEqual("roster-b", observed["operator"])


class ShareRootParityTests(unittest.TestCase):
    """One share root, declared twice, held honest here.

    Gate 9 proves a per-user share under this root. The Ansible role declares
    it as ``homelab_ad_share_root`` for the host-side path; this module holds
    its own copy because a program staged over the serial console cannot read
    an Ansible variable. Two copies are the design -- an unchecked pair is not.
    A mismatch would put the persistent Controller's per-user directories
    somewhere ``[homes]`` does not serve, and the first symptom would be a
    failed login on a physical machine.
    """

    def role_default(self) -> str:
        homelab = Path(__file__).resolve().parents[1]
        defaults = (homelab / "ansible" / "roles" / "domain_controller"
                    / "defaults" / "main.yml").read_text(encoding="utf-8")
        for line in defaults.splitlines():
            if line.startswith("homelab_ad_share_root:"):
                return line.split(":", 1)[1].strip()
        self.fail("homelab_ad_share_root is not declared by the role")

    def test_the_module_and_the_role_declare_the_same_share_root(self):
        self.assertEqual(self.role_default(), controller_principals.SHARE_ROOT)

    def test_the_staged_program_carries_no_second_literal(self):
        # The programs must reach the root through the substituted constant,
        # so changing SHARE_ROOT changes what the guest actually creates.
        rendered = json.dumps(controller_principals.SHARE_ROOT)
        for program in (controller_principals._STAGE_PROGRAM,
                        controller_principals._DESTROY_PROGRAM):
            self.assertIn(rendered, program)
            self.assertNotIn(
                controller_principals.SHARE_ROOT + "/", program,
                "the root is spelled out a second time instead of substituted")



class DirectoryPasswordPolicyTests(unittest.TestCase):
    """The host judges a typed durable password the way the directory will."""

    def test_the_default_policy_is_applied(self):
        problem = controller_principals.directory_password_problem
        self.assertIsNone(problem("Short1!", "roster-a"))
        self.assertIsNone(problem("longlowercase7!", "roster-a"))
        self.assertIn("shorter than 7", problem("Ab1!xy", "roster-a"))
        self.assertIn("fewer than 3", problem("lowercaseonly", "roster-a"))
        self.assertIn("fewer than 3", problem("lower-and-symbols", "roster-a"))
        self.assertIn("account name",
                      problem("My-Roster-A-Pass1", "roster-a"))
        # A two-character name is too short to be a meaningful match.
        self.assertIsNone(problem("Xy-Password-1", "xy"))

    def test_a_reason_never_repeats_the_password(self):
        for password in ("abc", "lowercaseonly", "Has-roster-a-1"):
            reason = controller_principals.directory_password_problem(
                password, "roster-a")
            self.assertIsNotNone(reason)
            self.assertNotIn(password, reason)


class PrincipalResultPatternTests(unittest.TestCase):
    """The stage's return code, with the category a failure prints first."""

    def pattern(self):
        import re as _re

        return _re.compile(
            controller_principals._principal_result_pattern(
                b"__TELOS_PRINCIPAL_RC_tok="), _re.MULTILINE)

    def test_a_failure_carries_its_category(self):
        buffer = (b"\r\n__TELOS_PRINCIPAL_FAILURE=password-policy\r\n"
                  b"Traceback noise that never names a value\r\n"
                  b"\r\n__TELOS_PRINCIPAL_RC_tok=1\r\n")
        match = self.pattern().search(buffer)
        self.assertEqual(b"1", match.group("rc"))
        self.assertEqual(b"password-policy", match.group("reason"))

    def test_a_success_has_no_category(self):
        match = self.pattern().search(b"\r\n__TELOS_PRINCIPAL_RC_tok=0\r\n")
        self.assertEqual(b"0", match.group("rc"))
        self.assertIsNone(match.group("reason"))

    def test_a_partial_read_matches_nothing(self):
        line = b"\n__TELOS_PRINCIPAL_RC_tok=127\r\n"
        for cut in range(len(line) - 2):
            self.assertIsNone(self.pattern().search(line[:cut]))

    def test_the_stage_program_prints_a_category_and_never_a_value(self):
        stage, _destroy, _roles = controller_principals._programs(
            controller_principals._ACCEPTANCE)
        self.assertIn("__TELOS_PRINCIPAL_FAILURE=", stage)
        self.assertIn('return "password-policy"', stage)
        self.assertIn('return "account-exists"', stage)
        # The only thing printed on failure is the category.
        self.assertNotIn("print(values", stage)
        self.assertNotIn("print(error", stage)


if __name__ == "__main__":
    unittest.main()
