"""Runtime safety tests for the privileged host-network helper."""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).parents[1]
HELPER = ROOT / "bin" / "homelab-host-network"


class HostNetworkRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sys = self.root / "sys"
        self.bin = self.root / "bin"
        self.state = self.root / "state"
        self.bin.mkdir()
        physical = self.sys / "eno2"
        physical.mkdir(parents=True)
        (physical / "flags").write_text("0x1003\n")
        text = HELPER.read_text()
        text = text.replace("/sys/class/net", str(self.sys))
        text = text.replace(
            "state_dir=/run/telos-controller-network",
            f"state_dir={self.state}",
        )
        self.helper = self.root / "helper"
        self.helper.write_text(text)
        self.helper.chmod(0o755)
        self.log = self.root / "calls"
        self._write_commands()

    def tearDown(self):
        self.tmp.cleanup()

    def _command(self, name, body):
        path = self.bin / name
        path.write_text("#!/usr/bin/env bash\nset -eu\n" + body)
        path.chmod(0o755)

    def _write_commands(self):
        self._command(
            "id",
            'if [ "${1:-}" = -u ]; then echo 0; else /usr/bin/id "$@"; fi\n',
        )
        self._command(
            "getent",
            '[ "$1" = passwd ] && [ "$2" = tester ] && '
            "echo 'tester:x:1234:1234::/tmp:/bin/sh'\n",
        )
        self._command(
            "install",
            '[ "$1" = -d ] && exec /usr/bin/install -d -m "$3" "${@: -1}"\n',
        )
        self._command(
            "stat",
            textwrap.dedent(
                """
                if [ "$1" = -c ] && [ "$2" = %u:%a ]; then
                    case "$3" in
                        "$TEST_STATE") echo 0:700 ;;
                        "$TEST_STATE/state") echo 0:600 ;;
                        *) exec /usr/bin/stat "$@" ;;
                    esac
                else
                    exec /usr/bin/stat "$@"
                fi
                """
            ),
        )
        self._command(
            "nmcli",
            textwrap.dedent(
                """
                echo "nmcli $*" >>"$TEST_LOG"
                if [ "$1" = -g ]; then
                    echo "${NM_MANAGED:-yes}"
                fi
                """
            ),
        )
        self._command(
            "ip",
            textwrap.dedent(
                """
                echo "ip $*" >>"$TEST_LOG"
                [ "${FAIL_IP_MATCH:-}" != "$*" ] || exit 91
                if [ "$1" = -o ]; then exit 0; fi
                if [ "$1 $2 $3" = "link add name" ]; then
                    mkdir -p "$TEST_SYS/$4/bridge"
                    echo 0x0 >"$TEST_SYS/$4/flags"
                elif [ "$1 $2" = "tuntap add" ]; then
                    mkdir -p "$TEST_SYS/$4"
                    : >"$TEST_SYS/$4/tun_flags"
                    echo 0x0 >"$TEST_SYS/$4/flags"
                elif [ "$1 $2" = "link delete" ]; then
                    rm -rf "$TEST_SYS/$3"
                elif [ "$1 $2" = "link set" ] && [ "$4" = master ]; then
                    ln -sfn "$TEST_SYS/$5" "$TEST_SYS/$3/master"
                elif [ "$1 $2" = "link set" ] && [ "$4" = nomaster ]; then
                    rm -f "$TEST_SYS/$3/master"
                elif [ "$1 $2" = "link set" ] && [ "$4" = up ]; then
                    echo 0x1 >"$TEST_SYS/$3/flags"
                elif [ "$1 $2" = "link set" ] && [ "$4" = down ]; then
                    echo 0x0 >"$TEST_SYS/$3/flags"
                fi
                """
            ),
        )

    def _run(self, action, *, answer="", extra_env=None):
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin}:{env['PATH']}",
                "TEST_SYS": str(self.sys),
                "TEST_LOG": str(self.log),
                "TEST_STATE": str(self.state),
                "TAP_OWNER": "tester",
                "APPLY": "1",
            }
        )
        env.update(extra_env or {})
        return subprocess.run(
            [str(self.helper), action],
            input=answer,
            text=True,
            capture_output=True,
            env=env,
        )

    def test_prepare_uses_only_fixed_interfaces_and_records_nm_identity(self):
        result = self._run("prepare", answer="ATTACH eno2 br-dc tap-dc\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.log.read_text()
        self.assertIn("nmcli device set eno2 managed no", calls)
        self.assertIn("ip link set eno2 master br-dc", calls)
        self.assertIn("ip tuntap add dev tap-dc mode tap user tester", calls)
        self.assertNotIn(" address add ", calls)
        self.assertNotIn(" route add ", calls)
        state = (self.state / "state").read_text()
        self.assertIn("physical=eno2\nbridge=br-dc\ntap=tap-dc\n", state)
        self.assertIn("owner=tester\nowner_uid=1234\n", state)
        self.assertIn("nm_managed=yes\n", state)

    def test_failed_prepare_rolls_back_links_nm_and_private_state(self):
        result = self._run(
            "prepare",
            answer="ATTACH eno2 br-dc tap-dc\n",
            extra_env={"FAIL_IP_MATCH": "tuntap add dev tap-dc mode tap user tester"},
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.sys / "br-dc").exists())
        self.assertFalse((self.sys / "tap-dc").exists())
        self.assertFalse((self.sys / "eno2" / "master").exists())
        self.assertFalse(self.state.exists())
        calls = self.log.read_text()
        self.assertIn("nmcli device set eno2 managed no", calls)
        self.assertIn("nmcli device set eno2 managed yes", calls)

    def test_wrong_confirmation_makes_no_network_changes(self):
        result = self._run("prepare", answer="ATTACH eno2 br-dc tap-other\n")
        self.assertEqual(result.returncode, 2)
        calls = self.log.read_text()
        self.assertNotIn("ip link ", calls)
        self.assertNotIn("nmcli device set ", calls)
        self.assertFalse(self.state.exists())

    def test_teardown_restores_original_link_and_nm_state(self):
        prepared = self._run("prepare", answer="ATTACH eno2 br-dc tap-dc\n")
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        result = self._run("teardown", answer="DETACH eno2 br-dc tap-dc\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.sys / "br-dc").exists())
        self.assertFalse((self.sys / "tap-dc").exists())
        self.assertFalse((self.sys / "eno2" / "master").exists())
        self.assertFalse(self.state.exists())
        calls = self.log.read_text()
        self.assertIn("ip link set eno2 up", calls)
        self.assertEqual(
            calls.count("nmcli device set eno2 managed yes"),
            1,
        )

    def test_unmanaged_device_is_never_claimed_by_networkmanager(self):
        prepared = self._run(
            "prepare",
            answer="ATTACH eno2 br-dc tap-dc\n",
            extra_env={"NM_MANAGED": "no"},
        )
        self.assertEqual(prepared.returncode, 0, prepared.stderr)
        result = self._run(
            "teardown",
            answer="DETACH eno2 br-dc tap-dc\n",
            extra_env={"NM_MANAGED": "no"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("nmcli device set", self.log.read_text())


if __name__ == "__main__":
    unittest.main()
