import base64
import io
import json
import socket
import shlex
import threading
import unittest

from homelab.vm import controller_principals
from homelab.vm.controller_principals import (
    ControllerPrincipalError,
    ControllerPrincipalResult,
    ControllerPrincipalSerial,
)
from homelab.vm.serial_automation import (
    SerialAutomation,
    SerialAutomationError,
)
from homelab.vm.controller_factory import FactoryBundle


VALUES = {
    "student": "Student-secret-47!",
    "operator": "Operator-secret-47!",
    "directory-admin": "Directory-secret-47!",
}


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
        # roster position; groups are base 10000 plus well-known AD RID.
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
            controller_principals.POSIX_ALLOCATION,
        )
        # Re-deriving the allocation must reproduce the pinned numbers.
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
            validate(variant(users={"operator": {"uidNumber": 10000}}))
        with self.assertRaisesRegex(ValueError, "gidNumber .*collides"):
            validate(variant(groups={"Domain Admins": 10513}))
        with self.assertRaisesRegex(ValueError, "ranges collide"):
            validate(variant(users={"student": {"uidNumber": 10512}}))
        with self.assertRaisesRegex(ValueError, "not a staged group"):
            validate(variant(users={"student": {"gidNumber": 10999}}))
        with self.assertRaisesRegex(ValueError, "uidNumber is out of range"):
            validate(variant(users={"student": {"uidNumber": 999}}))
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
            serial.stage({"student": "value"})
        duplicate = dict(VALUES)
        duplicate["operator"] = duplicate["student"]
        with self.assertRaisesRegex(ValueError, "distinct"):
            serial.stage(duplicate)
        multiline = dict(VALUES)
        multiline["operator"] = "unsafe\nvalue"
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
                serial.destroy(("student", "operator"))
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


if __name__ == "__main__":
    unittest.main()
