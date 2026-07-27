import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).parents[1] / "bin" / "homelab-pxe-deploy"
loader = importlib.machinery.SourceFileLoader("pxe_deploy", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
pxe_deploy = importlib.util.module_from_spec(spec)
loader.exec_module(pxe_deploy)


class DestinationTests(unittest.TestCase):
    def test_accepts_safe_absolute_remote(self):
        host, path = pxe_deploy.destination("deployer@controller:/srv/http/boot")
        self.assertEqual(host, "deployer@controller")
        self.assertEqual(str(path), "/srv/http/boot")

    def test_rejects_relative_or_shell_destination(self):
        for value in (
            "controller:relative",
            "bad;host:/srv/boot",
            "-oProxyCommand=x:/srv/boot",
            "controller:/srv/../etc",
            "controller:/srv/boot path",
            "controller:/srv/\nboot",
        ):
            with self.subTest(value=value), self.assertRaises(Exception):
                pxe_deploy.destination(value)


class ReleaseIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def release(self, target="controller", version="20260727.001"):
        release = self.root / target / version
        release.mkdir(parents=True)
        (release / "payload").write_text("payload\n")
        manifest = {
            "schema": 1,
            "target": target,
            "version": version,
            "artifacts": {
                "payload": {
                    "size": 8,
                    "sha256": (
                        "d4e4877bac978b7952f0d544fc52ebff5411d351d129f1f0"
                        "56fa43f11da9af2b"),
                },
            },
        }
        (release / "release.json").write_text(json.dumps(manifest))
        return release

    def test_accepts_verified_canonical_identity(self):
        release = self.release()
        self.assertEqual(
            pxe_deploy.release_identity(release),
            ("controller", "20260727.001"),
        )

    def test_rejects_noncanonical_target_even_when_path_matches(self):
        release = self.release(target="other")
        with self.assertRaisesRegex(ValueError, "deployable"):
            pxe_deploy.release_identity(release)

    def test_rejects_identity_path_mismatch(self):
        release = self.release()
        manifest_path = release / "release.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["target"] = "windows"
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "verification"):
            pxe_deploy.release_identity(release)


class DeploymentTests(unittest.TestCase):
    def arguments(self, release):
        return mock.Mock(
            release=release,
            destination=("deployer@controller", pxe_deploy.PurePosixPath("/srv/pxe")),
            apply=True,
        )

    @mock.patch.object(pxe_deploy.secrets, "token_hex", return_value="a1b2c3")
    @mock.patch.object(pxe_deploy, "release_identity",
                       return_value=("controller", "20260727.001"))
    @mock.patch.object(pxe_deploy, "run")
    def test_publish_locks_verifies_freezes_and_switches(
            self, run, _identity, _token):
        run.side_effect = ("", "", "", "")
        pxe_deploy.publish(self.arguments(Path("/local/controller/20260727.001")))
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn("mkdir /srv/pxe/controller/.deploy.lock", commands[0][2])
        self.assertIn(".incoming-20260727.001-a1b2c3", commands[1][-1])
        self.assertIn("python3 -c", commands[3][2])
        self.assertIn("chmod -R a-w /srv/pxe/controller/20260727.001",
                      commands[3][2])
        self.assertIn("readlink /srv/pxe/controller/current", commands[3][2])

    @mock.patch.object(pxe_deploy.secrets, "token_hex", return_value="a1b2c3")
    @mock.patch.object(pxe_deploy, "release_identity",
                       return_value=("controller", "20260727.001"))
    @mock.patch.object(pxe_deploy, "cleanup")
    @mock.patch.object(pxe_deploy, "run")
    def test_publish_cleans_owned_temporary_state_after_failure(
            self, run, cleanup, _identity, _token):
        run.side_effect = subprocess.CalledProcessError(1, ["ssh"])
        with self.assertRaises(subprocess.CalledProcessError):
            pxe_deploy.publish(self.arguments(Path("/local/controller/20260727.001")))
        cleanup.assert_called_once()

    @mock.patch.object(pxe_deploy.secrets, "token_hex", return_value="a1b2c3")
    @mock.patch.object(pxe_deploy, "run")
    def test_rollback_verifies_release_under_lock_before_switch(self, run, _token):
        args = mock.Mock(
            target="windows",
            version="20260727.001",
            destination=("controller", pxe_deploy.PurePosixPath("/srv/pxe")),
            apply=True,
        )
        pxe_deploy.rollback(args)
        command = run.call_args.args[0][2]
        self.assertLess(command.index("python3 -c"), command.index("ln -sfn"))
        self.assertIn("artifact inventory differs", command)
        self.assertIn("readlink /srv/pxe/windows/current", command)


class CleanupTests(unittest.TestCase):
    @mock.patch.object(pxe_deploy.subprocess, "run")
    def test_cleanup_retries_and_only_removes_owned_lock(self, run):
        run.side_effect = [
            mock.Mock(returncode=1),
            mock.Mock(returncode=1),
            mock.Mock(returncode=0),
        ]
        root = pxe_deploy.PurePosixPath("/srv/pxe/controller")
        pxe_deploy.cleanup(
            "controller", root / ".incoming-20260727.001-a1b2c3",
            root / ".deploy.lock", root / ".deploy.lock/a1b2c3")
        self.assertEqual(run.call_count, 3)
        command = run.call_args.args[0][2]
        self.assertIn("test -f /srv/pxe/controller/.deploy.lock/a1b2c3", command)


if __name__ == "__main__":
    unittest.main()
