"""Contracts for the honest, locally supportable factory Make targets."""

from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = (ROOT / "Makefile").read_text(encoding="utf-8")

sys.path.insert(0, str(ROOT / "homelab" / "vm"))


def emitted(target: str, **variables: str) -> list[list[str]]:
    """Every ``bootstrap_dc.py`` argv a target's recipe would really run.

    Asserting on Makefile *text* cannot catch an argument in the wrong place,
    and that is exactly the class of defect that made every persistent target
    die for any operator who set ``FACTORY_CONTROLLER_STATE``: ``--state-dir``
    is declared on the top-level parser only, and the recipes emitted it after
    the subcommand. ``make -n`` expands the recipe for real; the caller then
    feeds each argv to the parser that would receive it.
    """
    assignments = [f"{name}={value}" for name, value in variables.items()]
    result = subprocess.run(
        ["make", "-n", target, *assignments],
        cwd=ROOT, check=True, capture_output=True, text=True)
    joined = result.stdout.replace("\\\n", " ")
    commands = []
    for statement in joined.replace("\n", ";").split(";"):
        if "bootstrap_dc.py" not in statement:
            continue
        parts = shlex.split(statement)
        index = next(
            position for position, part in enumerate(parts)
            if part.endswith("bootstrap_dc.py"))
        commands.append(parts[index + 1:])
    return commands


def emitted_by(target: str, script: str, **variables: str) -> list[list[str]]:
    """``emitted`` for any script: each argv the recipe passes to *script*."""
    assignments = [f"{name}={value}" for name, value in variables.items()]
    result = subprocess.run(
        ["make", "-n", target, *assignments],
        cwd=ROOT, check=True, capture_output=True, text=True)
    joined = result.stdout.replace("\\\n", " ")
    argvs = []
    for statement in joined.replace("\n", ";").split(";"):
        if script not in statement:
            continue
        parts = shlex.split(statement)
        index = next(
            position for position, part in enumerate(parts)
            if part.endswith(script))
        argvs.append(parts[index + 1:])
    return argvs


def recipe(target: str) -> str:
    match = re.search(
        rf"^{re.escape(target)}(?:\s*:[^\n]*)?\n"
        rf"(?P<body>(?:\t[^\n]*\n|#[^\n]*\n|\n)*)",
        MAKEFILE,
        re.MULTILINE,
    )
    if not match:
        raise AssertionError(f"missing Make target: {target}")
    return match.group("body")


def commands(target: str) -> str:
    """Only a target's recipe lines.

    ``recipe`` also swallows the comment block that introduces the *next*
    target, which is fine for presence checks and wrong for absence checks.
    """
    return "".join(
        line for line in recipe(target).splitlines(keepends=True)
        if line.startswith("\t"))


class FactoryMakeTargetTests(unittest.TestCase):
    def test_supportable_targets_are_phony(self):
        phony = re.search(
            r"^\.PHONY:(?P<body>.*?)(?=^\S|\Z)",
            MAKEFILE,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(phony)
        for target in (
            "homelab-factory-deps",
            "homelab-factory-media",
            "homelab-media-workstation-repo",
            "homelab-factory-cache-seal",
            "homelab-factory-offline-check",
            "homelab-factory-controller-bundle",
            "homelab-factory-pxe",
            "homelab-factory-verify",
            "homelab-windows-identity-prepare",
            "homelab-windows-identity-run",
            "homelab-windows-identity-judge",
        ):
            self.assertIn(target, phony.group("body"))

    def test_windows_identity_judge_requires_explicit_evidence(self):
        text = recipe("homelab-windows-identity-judge")
        self.assertIn("WINDOWS_IDENTITY_EVIDENCE", text)
        self.assertIn("homelab-windows-identity-judge", text)
        self.assertNotIn("--apply", text)

    def test_windows_identity_prepare_is_apply_gated(self):
        text = recipe("homelab-windows-identity-prepare")
        self.assertIn("WINDOWS_RUN", text)
        self.assertIn("APPLY", text)
        self.assertIn("--apply", text)
        self.assertEqual(4, text.count("FACTORY_CONTROLLER_STATE"))
        self.assertEqual(2, text.count("--controller-state"))

    def test_windows_identity_run_requires_attempt_and_is_apply_gated(self):
        text = recipe("homelab-windows-identity-run")
        self.assertIn("WINDOWS_IDENTITY_ATTEMPT", text)
        self.assertIn("homelab-windows-identity-run", text)
        self.assertIn("APPLY", text)
        self.assertEqual(1, text.count("--apply"))
        self.assertIn("WINDOWS_SUBMIT_FOCUS_TABS", text)
        self.assertIn("WINDOWS_REVIEWED_SUBMIT_FOCUS", text)
        self.assertIn("--authorize-reviewed-submit-focus", text)

    def test_offline_check_cannot_invoke_acquisition(self):
        declaration = re.search(
            r"^homelab-factory-offline-check:(.*)$", MAKEFILE, re.MULTILINE)
        self.assertIsNotNone(declaration)
        self.assertNotIn("homelab-factory-cache-seal", declaration.group(1))
        text = recipe("homelab-factory-offline-check")
        self.assertIn("homelab-media-seal verify", text)
        self.assertNotIn("homelab-media-seal create", text)
        for forbidden in (
            "homelab-media-arch",
            "homelab-media-windows",
            "homelab-media-wimboot",
            "fetch-",
            "curl",
            "wget",
            "git ",
        ):
            self.assertNotIn(forbidden, text)

    def test_workstation_repo_acquire_is_online_only_and_receipt_bound(self):
        text = recipe("homelab-media-workstation-repo")
        self.assertIn("homelab-media-workstation-repo build", text)
        self.assertIn("WORKSTATION_REPO", text)
        self.assertIn("package-contract.json", text)
        # Acquisition is part of the aggregate acquire phase.
        aggregate = re.search(
            r"^homelab-media:(.*(?:\\\n.*)*)$", MAKEFILE, re.MULTILINE)
        self.assertIsNotNone(aggregate)
        self.assertIn(
            "homelab-media-workstation-repo", aggregate.group(1))

    def test_offline_check_refuses_an_unsealed_workstation_repo(self):
        text = recipe("homelab-factory-offline-check")
        self.assertIn("homelab-media-workstation-repo verify", text)
        self.assertNotIn("homelab-media-workstation-repo build", text)
        self.assertIn("WORKSTATION_REPO", text)

    def test_cache_seal_verifies_and_binds_all_media_inputs(self):
        text = recipe("homelab-factory-cache-seal")
        self.assertIn("homelab-media-seal create", text)
        self.assertIn("ARCH_ISO", text)
        self.assertIn("ARCH_ISO).receipt.json", text)
        self.assertIn("WINDOWS_ISO_CACHE", text)
        self.assertIn("WINDOWS_ISO_CACHE).provenance.json", text)
        self.assertIn("WINDOWS_ISO_CACHE).verification.json", text)
        self.assertIn("WINDOWS_INSTALL_SOURCE", text)
        self.assertIn("WIMBOOT", text)
        self.assertIn("wimboot.json", text)
        for forbidden in ("fetch-", "curl", "wget"):
            self.assertNotIn(forbidden, text)

    def test_controller_bundle_is_dry_run_by_default(self):
        text = recipe("homelab-factory-controller-bundle")
        self.assertIn("APPLY", text)
        self.assertIn("--print-guest-command", text)
        self.assertIn("--output", text)

    def test_pxe_aggregate_derives_arch_and_defaults_controller_source(self):
        declaration = re.search(
            r"^homelab-factory-pxe:(.*)$", MAKEFILE, re.MULTILINE)
        self.assertIsNotNone(declaration)
        self.assertIn(
            "homelab-factory-offline-check", declaration.group(1))
        text = recipe("homelab-factory-pxe")
        self.assertIn("FACTORY_CONTROLLER_SOURCE", text)
        self.assertIn("ARCH_SOURCE", text)
        self.assertIn("homelab-pxe-release-set", text)
        self.assertIn("BASE_URL", text)
        self.assertNotIn("homelab-pxe-all", text)
        self.assertNotIn("fetch-", text)
        release = recipe("homelab-pxe-release-set")
        self.assertIn("FACTORY_ARCH_SOURCE_CACHE", release)
        self.assertIn("--arch-cache", release)
        self.assertIn("--arch-source", release)

    def test_factory_verify_is_read_only_and_apply_gated(self):
        text = recipe("homelab-factory-verify")
        # Requires the retained-run evidence to validate.
        self.assertIn("FACTORY_EVIDENCE", text)
        # Dry run by default; APPLY=1 emits the receipt.
        self.assertIn("APPLY", text)
        self.assertIn("dry run", text)
        self.assertIn("--plan", text)
        # Invokes the real verifier CLI and can validate the release set.
        self.assertIn("factory_verify.py", text)
        self.assertIn("--release-set", text)
        # Read-only acceptance gate: it must never install or run a guest.
        self.assertNotIn("--apply", text)
        for forbidden in ("qemu", "fetch-", "curl", "wget"):
            self.assertNotIn(forbidden, text)

    def test_factory_recover_is_apply_gated_and_requires_its_run(self):
        text = recipe("homelab-factory-recover")
        # A recovery run is aimed deliberately: no default run bundle exists.
        self.assertIn("require RECOVERY_RUN=", text)
        self.assertIn("--run '$(RECOVERY_RUN)'", text)
        # Dry run by default; APPLY=1 is what writes evidence and result.json.
        self.assertIn("APPLY", text)
        self.assertIn("dry run", text)
        self.assertEqual(1, text.count("--apply"))
        self.assertIn("homelab-lifecycle-recovery", text)
        # A guest boot is opt-in, and --boot is forwarded only when asked for.
        self.assertEqual(2, text.count("$(if $(RECOVERY_BOOT),--boot)"))
        self.assertNotIn("--boot ", text.replace(
            "$(if $(RECOVERY_BOOT),--boot)", ""))

    def test_factory_recover_judge_is_read_only_and_needs_produced_evidence(self):
        text = recipe("homelab-factory-recover-judge")
        self.assertIn("require RECOVERY_EVIDENCE=", text)
        self.assertIn("'$(RECOVERY_EVIDENCE)'", text)
        self.assertIn("lifecycle_recovery.py", text)
        # Grading never runs, boots, or applies anything.
        self.assertNotIn("--apply", text)
        self.assertNotIn("APPLY", text)
        for forbidden in ("qemu", "--boot", "curl", "wget"):
            self.assertNotIn(forbidden, text)

    def test_the_recovery_variables_are_declared_not_only_used(self):
        # They were used by the recipes long before they were declared, which
        # left a reader to guess at their shape and their defaults.
        for name in ("RECOVERY_RUN", "RECOVERY_BOOT", "RECOVERY_EVIDENCE"):
            with self.subTest(variable=name):
                self.assertRegex(
                    MAKEFILE, rf"(?m)^{name} \?=\s*$",
                    f"{name} is used but never declared with an empty default")

    def test_persistent_recipes_emit_argv_the_cli_actually_accepts(self):
        """The whole class of defect, not just the one instance of it.

        ``make homelab-factory-persistent-plan PERSISTENT_DC=x
        FACTORY_CONTROLLER_STATE=y`` died with "unrecognized arguments:
        --state-dir", because the option is declared on the top-level parser
        and the recipe emitted it after the subcommand. No test anywhere fed a
        generated recipe's argv to the parser that receives it; this one does,
        for every persistent target and both sides of its APPLY gate.
        """
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        import bootstrap_dc

        variables = {
            "PERSISTENT_DC": "lab-dc1",
            # The variable whose mere presence broke every one of them.
            "FACTORY_CONTROLLER_STATE": "build/homelab/vm/bootstrap-dc",
            "SEED_ISO": "seed.iso",
            "RECONVERGE": "1",
            "PERSISTENT_CONVERGE_TIMEOUT": "100",
            "CONFIRM": "DESTROY lab-dc1",
        }
        targets = (
            "homelab-factory-persistent-plan",
            "homelab-factory-persistent-status",
            "homelab-factory-persistent-up",
            "homelab-factory-persistent-converge-plan",
            "homelab-factory-persistent-converge",
            "homelab-factory-persistent-accounts-plan",
            "homelab-factory-persistent-accounts",
            "homelab-factory-persistent-destroy",
        )
        for target in targets:
            for apply in ("", "1"):
                with self.subTest(target=target, APPLY=apply):
                    commands = emitted(target, APPLY=apply, **variables)
                    self.assertTrue(
                        commands, f"{target} emits no bootstrap_dc.py argv")
                    for argv in commands:
                        parsed = bootstrap_dc.parser().parse_args(argv)
                        # And the state directory really is the one the
                        # operator asked for, not the default.
                        if "--state-dir" in argv:
                            self.assertEqual(
                                str(parsed.state_dir),
                                variables["FACTORY_CONTROLLER_STATE"])

    def test_bootstrap_vm_install_is_apply_and_confirm_gated(self):
        text = recipe("homelab-bootstrap-vm-install")
        self.assertIn("bootstrap_install.py", text)
        self.assertIn("require SEED_ISO=", text)
        self.assertIn("--seed-iso '$(SEED_ISO)'", text)
        # Dry run by default; the erase needs both APPLY=1 and a CONFIRM the
        # operator typed. The confirmation is only ever passed on the applied
        # side, so a dry run cannot answer the guest's prompt.
        self.assertIn("dry run", text)
        self.assertEqual(1, text.count("--apply"))
        self.assertEqual(1, text.count("--confirm '$(CONFIRM)'"))
        self.assertIn("refusing to erase the canonical image", text)
        self.assertIn("[ -z '$(CONFIRM)' ]", text)
        # The recipe never spells the phrase out as a value it could pass:
        # what reaches --confirm is only ever $(CONFIRM).
        recipe_lines = commands("homelab-bootstrap-vm-install")
        self.assertNotIn("ERASE TELOS-BOOTSTRAP-DC1", recipe_lines)

    def test_bootstrap_vm_install_dry_run_emits_no_confirmation_and_no_apply(self):
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        import bootstrap_install

        for apply, expect_confirm in (("", False), ("1", True)):
            with self.subTest(APPLY=apply):
                result = subprocess.run(
                    ["make", "-n", "homelab-bootstrap-vm-install",
                     f"APPLY={apply}", "SEED_ISO=seed.iso", "ISO=arch.iso",
                     "CONFIRM=ERASE TELOS-BOOTSTRAP-DC1"],
                    cwd=ROOT, check=True, capture_output=True, text=True)
                joined = result.stdout.replace("\\\n", " ")
                argv = None
                for statement in joined.replace("\n", ";").split(";"):
                    if "bootstrap_install.py" not in statement:
                        continue
                    parts = shlex.split(statement)
                    index = next(
                        position for position, part in enumerate(parts)
                        if part.endswith("bootstrap_install.py"))
                    candidate = parts[index + 1:]
                    if ("--apply" in candidate) == bool(apply):
                        argv = candidate
                self.assertIsNotNone(argv)
                parsed = bootstrap_install.parser().parse_args(argv)
                self.assertEqual(bool(apply), parsed.apply)
                self.assertEqual(
                    expect_confirm, parsed.confirm is not None)

    def test_homelab_instance_seeds_missing_paths_without_overwriting(self):
        """All-or-nothing on the top directory seeded nothing, silently.

        A checkout with ``homelab/instance/`` but no ``identity/`` -- this
        one -- was told "leaving it alone" and got no principals file at all.
        """
        text = recipe("homelab-instance")
        self.assertNotIn("leaving it alone", text)
        self.assertNotIn(
            "cp -r homelab/instance-example homelab/instance", text)
        self.assertIn("homelab/instance-example", text)
        # Per-path, and only when the destination is absent: an operator's own
        # answers and inventory are never overwritten.
        self.assertIn('[ ! -e "homelab/instance/$$item" ]', text)
        for destructive in ("rm ", "rm -", "--force", "mv "):
            self.assertNotIn(destructive, text)

    def test_persistent_targets_are_phony_and_opt_in_by_name(self):
        phony = re.search(
            r"^\.PHONY:(?P<body>.*?)(?=^\S|\Z)",
            MAKEFILE,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(phony)
        for target in (
            "homelab-factory-persistent-plan",
            "homelab-factory-persistent-status",
            "homelab-factory-persistent-up",
            "homelab-factory-persistent-converge-plan",
            "homelab-factory-persistent-converge",
            "homelab-factory-persistent-accounts-plan",
            "homelab-factory-persistent-accounts",
            "homelab-factory-persistent-destroy",
        ):
            with self.subTest(target=target):
                self.assertIn(target, phony.group("body"))
                text = recipe(target)
                # Persistence is never inferred: without a named instance every
                # persistent target refuses instead of guessing one.
                self.assertIn("require PERSISTENT_DC=<instance name>", text)
                self.assertIn("PERSISTENT_DC_ROOT", text)
        # PERSISTENT_DC has no default value, so a bare `make` cannot bring a
        # persistent instance up by accident.
        self.assertRegex(MAKEFILE, r"(?m)^PERSISTENT_DC \?=\s*$")

    def test_persistent_plan_and_status_are_read_only(self):
        for target in ("homelab-factory-persistent-plan",
                       "homelab-factory-persistent-converge-plan",
                       "homelab-factory-persistent-status"):
            with self.subTest(target=target):
                text = commands(target)
                self.assertNotIn("--apply", text)
                self.assertNotIn("--confirm", text)

    def test_persistent_up_is_apply_gated(self):
        text = recipe("homelab-factory-persistent-up")
        self.assertIn("APPLY", text)
        self.assertIn("dry run", text)
        self.assertEqual(1, text.count("--apply"))
        self.assertIn("bootstrap_dc.py", text)
        # ``--state-dir`` is a top-level option, so it precedes the
        # subcommand; ``test_persistent_recipes_emit_argv_the_cli_actually_accepts``
        # proves the emitted argv really parses.
        self.assertIn("persistent-up \\", text)
        self.assertIn("--instance '$(PERSISTENT_DC)'", text)
        # A first bring-up may carry the read-only convergence medium; never
        # installer media, which would reinstall over the retained directory.
        self.assertIn("--seed-iso '$(SEED_ISO)'", text)
        self.assertNotIn("--iso", text)

    def test_persistent_converge_is_apply_gated_and_takes_no_credential(self):
        text = recipe("homelab-factory-persistent-converge")
        self.assertIn("APPLY", text)
        self.assertIn("dry run", text)
        self.assertEqual(1, text.count("--apply"))
        self.assertIn("bootstrap_dc.py", text)
        # ``--state-dir`` is a top-level option, so it precedes the
        # subcommand; ``test_persistent_recipes_emit_argv_the_cli_actually_accepts``
        # proves the emitted argv really parses.
        self.assertIn("persistent-converge \\", text)
        self.assertIn("--instance '$(PERSISTENT_DC)'", text)
        # Credentials are typed at the terminal, so no Make variable may carry
        # one and no answer file may be named.
        commands_only = commands("homelab-factory-persistent-converge")
        for forbidden in (
            "PASSWORD", "CREDENTIAL", "SECRET", "--password", "ADMIN_PASSWORD",
        ):
            self.assertNotIn(forbidden, commands_only)
        # Installer media would reinstall over the directory this mode keeps.
        self.assertNotIn("--iso", commands_only)
        # FACTORY_DURATION's 120-second default would abort a provisioning run,
        # so the convergence bound is its own variable with no default.
        self.assertNotIn("FACTORY_DURATION", commands_only)
        self.assertIn("PERSISTENT_CONVERGE_TIMEOUT", commands_only)
        self.assertRegex(MAKEFILE, r"(?m)^PERSISTENT_CONVERGE_TIMEOUT \?=\s*$")
        self.assertRegex(MAKEFILE, r"(?m)^RECONVERGE \?=\s*$")

    def test_persistent_destroy_requires_apply_instance_and_confirmation(self):
        text = commands("homelab-factory-persistent-destroy")
        self.assertIn("APPLY", text)
        self.assertIn("refusing destruction", text)
        self.assertIn("CONFIRM='DESTROY <instance>'", text)
        self.assertIn("--confirm '$(CONFIRM)'", text)
        self.assertNotIn("--apply", text)

    def test_no_acceptance_target_reaches_the_persistent_mode(self):
        # The disposable acceptance path must not change behaviour at all, so no
        # gate target may mention the persistent instance variables or verbs.
        for target in (
            "homelab-factory-sim-run",
            "homelab-factory-sim-plan",
            "homelab-factory-verify",
            "homelab-factory-recover",
            "homelab-bootstrap-vm-run",
            "homelab-bootstrap-vm-boot",
            "homelab-bootstrap-vm-destroy",
            "homelab-sim-run",
            "homelab-sim-auto-run",
        ):
            with self.subTest(target=target):
                text = commands(target)
                for forbidden in ("PERSISTENT_DC", "persistent-up",
                                  "persistent-converge",
                                  "persistent-destroy"):
                    self.assertNotIn(forbidden, text)

    def test_persistent_probe_is_opt_in_dry_run_first_and_parses(self):
        """The TASK-28 probe: named instance, dry run by default, real argv."""
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        from homelab.vm import persistent_controller_session

        phony = re.search(
            r"^\.PHONY:(?P<body>.*?)(?=^\S|\Z)",
            MAKEFILE,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIn("homelab-factory-persistent-probe", phony.group("body"))
        text = recipe("homelab-factory-persistent-probe")
        self.assertIn("require PERSISTENT_DC=<instance name>", text)
        self.assertIn("dry run", text)
        only = commands("homelab-factory-persistent-probe")
        self.assertEqual(1, only.count("--apply"))
        # The console password is typed at the terminal; no variable may
        # carry it, and no medium may be attached to a durable directory.
        for forbidden in ("PASSWORD", "CREDENTIAL", "SECRET", "--iso",
                          "--seed-iso"):
            self.assertNotIn(forbidden, only)
        self.assertRegex(MAKEFILE, r"(?m)^REPAIR_SID \?=\s*$")
        variables = {
            "PERSISTENT_DC": "lab-dc1",
            "FACTORY_CONTROLLER_STATE": "build/homelab/vm/bootstrap-dc",
            "DIRECTORY_IDENTITY": "identity.json",
            "IDENTITY_OVERLAY": "roster.json",
        }
        for repair in ("", "1"):
            with self.subTest(REPAIR_SID=repair):
                # ``make -n`` prints both sides of the shell's APPLY gate:
                # the dry run first, then the applied run.
                argvs = emitted_by(
                    "homelab-factory-persistent-probe",
                    "persistent_controller_session.py",
                    REPAIR_SID=repair, **variables)
                self.assertEqual(len(argvs), 2)
                for argv, applied in zip(argvs, (False, True)):
                    parsed = persistent_controller_session.parser(
                    ).parse_args(argv)
                    self.assertEqual(parsed.command, "probe")
                    self.assertEqual(parsed.instance, "lab-dc1")
                    self.assertEqual(
                        str(parsed.state_dir),
                        variables["FACTORY_CONTROLLER_STATE"])
                    self.assertEqual(
                        str(parsed.persistent_root),
                        "build/homelab/vm/persistent-dc")
                    self.assertEqual(
                        str(parsed.directory_identity), "identity.json")
                    self.assertEqual(
                        str(parsed.identity_overlay), "roster.json")
                    self.assertEqual(parsed.apply, applied)
                    self.assertEqual(parsed.repair_sid, repair == "1")

    def test_persistent_probe_refuses_without_a_named_instance(self):
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        result = subprocess.run(
            ["make", "homelab-factory-persistent-probe", "PERSISTENT_DC="],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("require PERSISTENT_DC=<instance name>", result.stderr)

    def test_clean_keeps_durable_vm_state(self):
        # build/homelab/vm holds the canonical Controller image, persistent
        # directory instances and kept workstations; a domain cannot be
        # rebuilt, so the reflexive `make clean` must never reach it.
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        with tempfile.TemporaryDirectory() as temporary:
            build = Path(temporary) / "build"
            kept = build / "homelab" / "vm" / "persistent-dc" / "marker.json"
            removed = (
                build / "site" / "index.html",
                build / "homelab" / "decisions.pdf",
                build / "homelab" / "manual" / "guide.pdf",
            )
            for path in (kept, *removed):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic\n", encoding="utf-8")
            result = subprocess.run(
                ["make", "-s", "clean", f"BUILD_ROOT={build}"],
                cwd=ROOT, check=True, capture_output=True, text=True)
            self.assertTrue(kept.is_file())
            for path in removed:
                self.assertFalse(path.exists(), path)
            self.assertEqual([p.name for p in build.iterdir()], ["homelab"])
            self.assertEqual(
                [p.name for p in (build / "homelab").iterdir()], ["vm"])
            self.assertIn("kept", result.stdout)

    def test_durable_workstation_recipes_parse(self):
        sys.path.insert(0, str(ROOT))
        from homelab.vm import workstation_instance
        cases = (
            ("homelab-durable-workstation-plan", {
                "WORKSTATION": "w1", "WINDOWS_RUN": "/runs/gate5",
                "PERSISTENT_DC": "synthetic-dc"}),
            ("homelab-durable-workstation-status", {"WORKSTATION": "w1"}),
            ("homelab-durable-workstation-reconcile", {"WORKSTATION": "w1"}),
            ("homelab-durable-workstation-reconcile", {
                "WORKSTATION": "w1", "APPLY": "1"}),
            ("homelab-durable-workstation-adopt", {
                "WORKSTATION": "w1", "WINDOWS_RUN": "/runs/gate5",
                "PERSISTENT_DC": "synthetic-dc", "APPLY": "1"}),
            ("homelab-durable-workstation-destroy", {
                "WORKSTATION": "w1", "APPLY": "1", "CONFIRM": "DESTROY w1"}),
        )
        for target, variables in cases:
            with self.subTest(target=target):
                argvs = emitted_by(
                    target, "homelab-durable-workstation", **variables)
                self.assertEqual(len(argvs), 1)
                workstation_instance.parser().parse_args(argvs[0])
        adopt = emitted_by(
            "homelab-durable-workstation-adopt", "homelab-durable-workstation",
            WORKSTATION="w1", WINDOWS_RUN="/runs/gate5",
            PERSISTENT_DC="synthetic-dc")[0]
        self.assertNotIn("--apply", adopt)
        reconcile = emitted_by(
            "homelab-durable-workstation-reconcile",
            "homelab-durable-workstation", WORKSTATION="w1")[0]
        self.assertNotIn("--apply", reconcile)

    def test_durable_workstation_targets_require_a_name(self):
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        for target in ("homelab-durable-workstation-status",
                       "homelab-durable-workstation-reconcile",
                       "homelab-durable-workstation-adopt"):
            with self.subTest(target=target):
                result = subprocess.run(
                    ["make", target, "WORKSTATION="],
                    cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("require WORKSTATION=<name>", result.stderr)

    def test_release_set_build_consumes_the_verified_seal(self):
        text = recipe("homelab-pxe-release-set")
        self.assertIn("homelab-pxe-release-set build", text)
        self.assertIn("FACTORY_MEDIA_SEAL", text)
        self.assertIn("WINDOWS_INSTALL_SOURCE", text)
        self.assertNotIn("homelab-pxe-all", text)
        release_set_tool = (
            ROOT / "homelab/bin/homelab-pxe-release-set"
        ).read_text(encoding="utf-8")
        self.assertIn("stage_from_install_source", release_set_tool)
        self.assertNotIn("windows_stage.stage(argparse.Namespace", release_set_tool)

    def test_durable_arch_install_recipes_parse(self):
        # TASK-28 step 6. Each argv the recipes really emit is fed to the
        # runner's own parser; the plan target never forwards --apply.
        sys.path.insert(0, str(ROOT))
        from homelab.vm import arch_durable_install_run
        script = "arch_durable_install_run.py"
        names = {"WORKSTATION": "w1", "PERSISTENT_DC": "synthetic-dc",
                 "ARCH_HOSTNAME": "kept-ws1"}
        optional = {
            "FACTORY_CONTROLLER_STATE": "/state/canonical",
            "FACTORY_RELEASES": "/releases",
            "SEED_ISO": "/media/seed.iso",
            "DIRECTORY_IDENTITY": "/identity/directory.json",
            "DURABLE_WORKSTATION_ROOT": "/kept",
            "PERSISTENT_DC_ROOT": "/persistent",
        }
        cases = (
            ("homelab-durable-arch-install-plan",
             {**names, "APPLY": "1"}, False),
            ("homelab-durable-arch-install", names, False),
            ("homelab-durable-arch-install",
             {**names, **optional, "APPLY": "1", "FACTORY_DURATION": "1800"},
             True),
        )
        for target, variables, applies in cases:
            with self.subTest(target=target, applies=applies):
                argvs = emitted_by(target, script, **variables)
                self.assertEqual(len(argvs), 1)
                args = arch_durable_install_run.parser().parse_args(argvs[0])
                self.assertIs(args.apply, applies)
                self.assertEqual(
                    (args.workstation, args.persistent_dc, args.hostname),
                    ("w1", "synthetic-dc", "kept-ws1"))
        args = arch_durable_install_run.parser().parse_args(emitted_by(
            "homelab-durable-arch-install", script,
            **names, **optional, APPLY="1", FACTORY_DURATION="1800")[0])
        self.assertEqual(args.duration, 1800)
        self.assertEqual(args.controller_state, Path("/state/canonical"))
        self.assertEqual(args.releases, Path("/releases"))
        self.assertEqual(args.seed_iso, Path("/media/seed.iso"))
        self.assertEqual(args.directory_identity,
                         Path("/identity/directory.json"))
        self.assertEqual(args.root, Path("/kept"))
        self.assertEqual(args.persistent_root, Path("/persistent"))

    def test_durable_arch_install_targets_are_phony_and_require_names(self):
        phony = re.search(
            r"^\.PHONY:(?P<body>.*?)(?=^\S|\Z)", MAKEFILE,
            re.MULTILINE | re.DOTALL)
        for target in ("homelab-durable-arch-install-plan",
                       "homelab-durable-arch-install"):
            self.assertIn(target, phony.group("body").split())
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        for target in ("homelab-durable-arch-install-plan",
                       "homelab-durable-arch-install"):
            with self.subTest(target=target):
                result = subprocess.run(
                    ["make", target, "WORKSTATION=", "PERSISTENT_DC=",
                     "ARCH_HOSTNAME="],
                    cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn(
                    "require WORKSTATION=<name> PERSISTENT_DC=<instance> "
                    "ARCH_HOSTNAME=<name>", result.stderr)


class DurableArchJoinTargetTests(unittest.TestCase):
    """TASK-28 step 7: the arch-join recipes, fed to the runner's parser."""

    SCRIPT = "arch_durable_join.py"
    TARGETS = ("homelab-durable-arch-join-plan", "homelab-durable-arch-join")
    NAMES = {"WORKSTATION": "w1", "PERSISTENT_DC": "synthetic-dc",
             "ARCH_HOSTNAME": "kept-ws1"}

    def parse(self, target, **variables):
        sys.path.insert(0, str(ROOT))
        from homelab.vm import arch_durable_join
        argvs = emitted_by(target, self.SCRIPT, **variables)
        self.assertEqual(len(argvs), 1)
        return arch_durable_join.parser().parse_args(argvs[0])

    def test_durable_arch_join_recipes_parse(self):
        # The plan target never forwards --apply; neither target forwards a
        # credential or a duration, and FIRST_LOGON_DONE=1 is the only way to
        # ask for the current password.
        cases = (
            ("homelab-durable-arch-join-plan",
             {**self.NAMES, "APPLY": "1", "FIRST_LOGON_DONE": "1"},
             False, True),
            ("homelab-durable-arch-join", self.NAMES, False, False),
            ("homelab-durable-arch-join", {**self.NAMES, "APPLY": "1"},
             True, False),
            ("homelab-durable-arch-join",
             {**self.NAMES, "APPLY": "1", "FIRST_LOGON_DONE": "yes"},
             True, False),
        )
        for target, variables, applies, done in cases:
            with self.subTest(target=target, variables=variables):
                args = self.parse(target, **variables)
                self.assertIs(args.apply, applies)
                self.assertIs(args.first_logon_done, done)
                self.assertEqual(
                    (args.workstation, args.persistent_dc, args.hostname),
                    ("w1", "synthetic-dc", "kept-ws1"))
        args = self.parse(
            "homelab-durable-arch-join", **self.NAMES, APPLY="1",
            FACTORY_CONTROLLER_STATE="/state/canonical",
            DIRECTORY_IDENTITY="/identity/directory.json",
            DURABLE_WORKSTATION_ROOT="/kept",
            PERSISTENT_DC_ROOT="/persistent")
        self.assertEqual(args.controller_state, Path("/state/canonical"))
        self.assertEqual(args.directory_identity,
                         Path("/identity/directory.json"))
        self.assertEqual(args.root, Path("/kept"))
        self.assertEqual(args.persistent_root, Path("/persistent"))

    def test_durable_arch_join_targets_are_phony_and_require_names(self):
        phony = re.search(
            r"^\.PHONY:(?P<body>.*?)(?=^\S|\Z)", MAKEFILE,
            re.MULTILINE | re.DOTALL)
        for target in self.TARGETS:
            self.assertIn(target, phony.group("body").split())
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        for target in self.TARGETS:
            with self.subTest(target=target):
                result = subprocess.run(
                    ["make", target, "WORKSTATION=", "PERSISTENT_DC=",
                     "ARCH_HOSTNAME="],
                    cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn(
                    "require WORKSTATION=<name> PERSISTENT_DC=<instance> "
                    "ARCH_HOSTNAME=<name>", result.stderr)


class DurableWindowsJoinTargetTests(unittest.TestCase):
    """TASK-28 step 8: the windows-join recipes, fed to the runner's parser."""

    SCRIPT = "windows_durable_join.py"
    TARGETS = ("homelab-durable-windows-join-plan",
               "homelab-durable-windows-join")
    NAMES = {"WORKSTATION": "w1", "PERSISTENT_DC": "synthetic-dc"}

    def parse(self, target, **variables):
        sys.path.insert(0, str(ROOT))
        from homelab.vm import windows_durable_join
        argvs = emitted_by(target, self.SCRIPT, **variables)
        self.assertEqual(len(argvs), 1)
        return windows_durable_join.parser().parse_args(argvs[0])

    def test_durable_windows_join_recipes_parse(self):
        # The plan target never forwards --apply, and no recipe forwards a
        # credential: every password is typed at the terminal.
        for target, variables, applies in (
                ("homelab-durable-windows-join-plan",
                 {**self.NAMES, "APPLY": "1"}, False),
                ("homelab-durable-windows-join", self.NAMES, False),
                ("homelab-durable-windows-join",
                 {**self.NAMES, "APPLY": "1"}, True)):
            with self.subTest(target=target, variables=variables):
                args = self.parse(target, **variables)
                self.assertIs(args.apply, applies)
                self.assertEqual((args.workstation, args.persistent_dc),
                                 ("w1", "synthetic-dc"))
        args = self.parse(
            "homelab-durable-windows-join", **self.NAMES, APPLY="1",
            FACTORY_CONTROLLER_STATE="/state/canonical",
            DIRECTORY_IDENTITY="/identity/directory.json",
            DURABLE_WORKSTATION_ROOT="/kept",
            PERSISTENT_DC_ROOT="/persistent")
        self.assertEqual(args.controller_state, Path("/state/canonical"))
        self.assertEqual(args.directory_identity,
                         Path("/identity/directory.json"))
        self.assertEqual(args.root, Path("/kept"))
        self.assertEqual(args.persistent_root, Path("/persistent"))
        self.assertNotIn("PASSWORD", commands("homelab-durable-windows-join"))

    def test_durable_windows_join_targets_are_phony_and_require_names(self):
        phony = re.search(
            r"^\.PHONY:(?P<body>.*?)(?=^\S|\Z)", MAKEFILE,
            re.MULTILINE | re.DOTALL)
        for target in self.TARGETS:
            self.assertIn(target, phony.group("body").split())
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        for target in self.TARGETS:
            with self.subTest(target=target):
                result = subprocess.run(
                    ["make", target, "WORKSTATION=", "PERSISTENT_DC="],
                    cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn(
                    "require WORKSTATION=<name> PERSISTENT_DC=<instance>",
                    result.stderr)


class DurableWorkstationVerifyTargetTests(unittest.TestCase):
    """TASK-28 step 9: the keep-verify recipe, fed to the runner's parser."""

    SCRIPT = "durable_workstation_verify.py"
    TARGET = "homelab-durable-workstation-verify"
    NAMES = {"WORKSTATION": "w1", "PERSISTENT_DC": "synthetic-dc",
             "ARCH_HOSTNAME": "kept-ws1"}

    def parse(self, **variables):
        sys.path.insert(0, str(ROOT))
        from homelab.vm import durable_workstation_verify
        argvs = emitted_by(self.TARGET, self.SCRIPT, **variables)
        self.assertEqual(len(argvs), 1)
        return durable_workstation_verify.parser().parse_args(argvs[0])

    def test_durable_workstation_verify_recipe_parses(self):
        # APPLY=1 is the only way to act; no recipe forwards a credential.
        for variables, applies in ((self.NAMES, False),
                                   ({**self.NAMES, "APPLY": "yes"}, False),
                                   ({**self.NAMES, "APPLY": "1"}, True)):
            with self.subTest(variables=variables):
                args = self.parse(**variables)
                self.assertIs(args.apply, applies)
                self.assertEqual(
                    (args.workstation, args.persistent_dc, args.hostname),
                    ("w1", "synthetic-dc", "kept-ws1"))
        args = self.parse(
            **self.NAMES, APPLY="1",
            FACTORY_CONTROLLER_STATE="/state/canonical",
            DIRECTORY_IDENTITY="/identity/directory.json",
            DURABLE_WORKSTATION_ROOT="/kept",
            PERSISTENT_DC_ROOT="/persistent")
        self.assertEqual(args.controller_state, Path("/state/canonical"))
        self.assertEqual(args.directory_identity,
                         Path("/identity/directory.json"))
        self.assertEqual(args.root, Path("/kept"))
        self.assertEqual(args.persistent_root, Path("/persistent"))
        self.assertNotIn("PASSWORD", commands(self.TARGET))

    def test_durable_workstation_verify_is_phony_and_requires_names(self):
        phony = re.search(
            r"^\.PHONY:(?P<body>.*?)(?=^\S|\Z)", MAKEFILE,
            re.MULTILINE | re.DOTALL)
        self.assertIn(self.TARGET, phony.group("body").split())
        self.assertIn(f"make {self.TARGET} ", MAKEFILE)
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        result = subprocess.run(
            ["make", self.TARGET, "WORKSTATION=", "PERSISTENT_DC=",
             "ARCH_HOSTNAME="],
            cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "require WORKSTATION=<name> PERSISTENT_DC=<instance> "
            "ARCH_HOSTNAME=<name>", result.stderr)


class PersistentPasswordPolicyTargetTests(unittest.TestCase):
    """The directory password policy target, fed to its runner's parser."""

    SCRIPT = "persistent_password_policy.py"
    TARGET = "homelab-factory-persistent-password-policy"
    NAMES = {"PERSISTENT_DC": "lab-dc1", "MIN_PASSWORD_LENGTH": "4",
             "PASSWORD_COMPLEXITY": "off"}

    def parse(self, **variables):
        sys.path.insert(0, str(ROOT))
        from homelab.vm import persistent_password_policy
        return [persistent_password_policy.parser().parse_args(argv)
                for argv in emitted_by(self.TARGET, self.SCRIPT, **variables)]

    def test_the_recipe_is_dry_run_first_and_parses(self):
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        variables = {
            **self.NAMES,
            "FACTORY_CONTROLLER_STATE": "/state/canonical",
            "DIRECTORY_IDENTITY": "identity.json",
            "IDENTITY_OVERLAY": "roster.json",
            "PERSISTENT_DC_ROOT": "/persistent",
        }
        # ``make -n`` prints both sides of the shell's APPLY gate: the dry
        # run first, then the applied run.
        parsed = self.parse(**variables)
        self.assertEqual(len(parsed), 2)
        for args, applied in zip(parsed, (False, True)):
            self.assertEqual(args.apply, applied)
            self.assertEqual(
                (args.instance, args.min_length, args.complexity),
                ("lab-dc1", "4", "off"))
            self.assertEqual(args.state_dir, Path("/state/canonical"))
            self.assertEqual(args.persistent_root, Path("/persistent"))
            self.assertEqual(args.directory_identity, Path("identity.json"))
            self.assertEqual(args.identity_overlay, Path("roster.json"))
        only = commands(self.TARGET)
        self.assertEqual(1, only.count("--apply"))
        self.assertIn("dry run", only)
        # The console password is typed at the terminal: no variable, file
        # or medium carries a credential into a durable directory.
        for forbidden in ("CREDENTIAL", "SECRET", "--password", "--iso",
                          "--seed-iso"):
            self.assertNotIn(forbidden, only)
        for name in ("MIN_PASSWORD_LENGTH", "PASSWORD_COMPLEXITY"):
            self.assertRegex(MAKEFILE, rf"(?m)^{name} \?=\s*$")

    def test_the_target_is_phony_listed_and_requires_every_value(self):
        phony = re.search(
            r"^\.PHONY:(?P<body>.*?)(?=^\S|\Z)", MAKEFILE,
            re.MULTILINE | re.DOTALL)
        self.assertIn(self.TARGET, phony.group("body").split())
        self.assertIn(f"make {self.TARGET} ", MAKEFILE)
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        for variables, message in (
                ({**self.NAMES, "PERSISTENT_DC": ""},
                 "require PERSISTENT_DC=<instance name>"),
                ({**self.NAMES, "MIN_PASSWORD_LENGTH": ""},
                 "require MIN_PASSWORD_LENGTH=<1-14> "
                 "PASSWORD_COMPLEXITY=off|on"),
                ({**self.NAMES, "PASSWORD_COMPLEXITY": ""},
                 "require MIN_PASSWORD_LENGTH=<1-14> "
                 "PASSWORD_COMPLEXITY=off|on")):
            with self.subTest(variables=variables):
                result = subprocess.run(
                    ["make", self.TARGET, *(
                        f"{name}={value}"
                        for name, value in variables.items())],
                    cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)


class PersistentAccountPasswordTargetTests(unittest.TestCase):
    """The one-account password reset target, fed to its runner's parser."""

    SCRIPT = "persistent_account_password.py"
    TARGET = "homelab-factory-persistent-account-password"
    NAMES = {"PERSISTENT_DC": "lab-dc1", "ROLE": "daily_administrator"}

    def parse(self, **variables):
        sys.path.insert(0, str(ROOT))
        from homelab.vm import persistent_account_password
        return [persistent_account_password.parser().parse_args(argv)
                for argv in emitted_by(self.TARGET, self.SCRIPT, **variables)]

    def test_the_recipe_is_dry_run_first_and_parses(self):
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        variables = {
            **self.NAMES,
            "FACTORY_CONTROLLER_STATE": "/state/canonical",
            "DIRECTORY_IDENTITY": "identity.json",
            "IDENTITY_OVERLAY": "roster.json",
            "PERSISTENT_DC_ROOT": "/persistent",
        }
        for change, temporary in (("", False), ("1", True)):
            with self.subTest(CHANGE_AT_FIRST_LOGON=change):
                # ``make -n`` prints both sides of the shell's APPLY gate:
                # the dry run first, then the applied run.
                parsed = self.parse(
                    **variables, CHANGE_AT_FIRST_LOGON=change)
                self.assertEqual(len(parsed), 2)
                for args, applied in zip(parsed, (False, True)):
                    self.assertEqual(args.apply, applied)
                    self.assertEqual(
                        (args.instance, args.role),
                        ("lab-dc1", "daily_administrator"))
                    self.assertIs(args.change_at_first_logon, temporary)
                    self.assertEqual(args.state_dir, Path("/state/canonical"))
                    self.assertEqual(args.persistent_root, Path("/persistent"))
                    self.assertEqual(args.directory_identity,
                                     Path("identity.json"))
                    self.assertEqual(args.identity_overlay,
                                     Path("roster.json"))
        only = commands(self.TARGET)
        self.assertEqual(1, only.count("--apply"))
        self.assertIn("dry run", only)
        # Both passwords are typed at the terminal: no variable, file or
        # medium carries a credential, and RESTAGE never reaches a reset.
        for forbidden in ("CREDENTIAL", "SECRET", "PASSWORD)", "--password",
                          "--iso", "--seed-iso", "RESTAGE", "--restage"):
            self.assertNotIn(forbidden, only)
        for name in ("ROLE", "CHANGE_AT_FIRST_LOGON"):
            self.assertRegex(MAKEFILE, rf"(?m)^{name} \?=\s*$")

    def test_the_target_is_phony_listed_and_refuses_what_it_cannot_run(self):
        phony = re.search(
            r"^\.PHONY:(?P<body>.*?)(?=^\S|\Z)", MAKEFILE,
            re.MULTILINE | re.DOTALL)
        self.assertIn(self.TARGET, phony.group("body").split())
        self.assertIn(f"make {self.TARGET} ", MAKEFILE)
        if not shutil.which("make"):
            self.skipTest("make is not installed")
        for variables, message in (
                ({**self.NAMES, "PERSISTENT_DC": ""},
                 "require PERSISTENT_DC=<instance name> ROLE=<contract role>"),
                ({**self.NAMES, "ROLE": ""},
                 "require PERSISTENT_DC=<instance name> ROLE=<contract role>"),
                ({**self.NAMES, "CHANGE_AT_FIRST_LOGON": "yes"},
                 "CHANGE_AT_FIRST_LOGON must be 1 or unset")):
            with self.subTest(variables=variables):
                result = subprocess.run(
                    ["make", self.TARGET, *(
                        f"{name}={value}"
                        for name, value in variables.items())],
                    cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
