#!/usr/bin/env python3
"""Live Arch identity login harness and identity-lifecycle evidence producer.

Gate 8. This drives a *real*, already installed Arch workstation over its
serial console through the ordered identity lifecycle that
``homelab/workstations/identity_lifecycle.py`` judges, and emits the exact
JSONL evidence events that judge grades. It replaces the hand-authored
``valid_events`` fixture with evidence produced from an actual guest.

The gate-7 disk ships a join-*capable* identity client; it does not arrive
joined into *this* run's directory, and it cannot.  Every gate-8 run boots the
canonical ``bootstrap-dc`` image, which carries no provisioned AD, so
``ansible/roles/domain_controller`` re-runs ``samba-tool domain provision``
and the run gets a fresh domain SID, a fresh krbtgt and an empty SAM: the
machine account gate 7's install-time join created simply does not exist here.
So this gate joins in-run -- exactly as the Windows lane does
(``windows_identity_orchestrator._execute_join``) -- with the same one-use
``tj-<hex>`` join principal and ``TELOS_JOIN`` media machinery gates 5-7 use,
after the systemd-boot menu drive and strictly before the operator login.

The Arch side of the lifecycle is console/SSSD, not GUI: the joined guest
presents a login on ``/dev/ttyS0`` and every proof is a bounded serial
exchange whose result the guest prints as an allowlisted marker. No secret is
ever recorded; only the pass/fail of each marker is retained.

Structure:

* ``ArchIdentityBundle`` validates a prepared, isolated bundle fail-closed.
* ``drive_boot_menu``/``login_operator``/``elevate_operator`` take the live
  workstation from power-on to a root shell: the systemd-boot menu is driven
  over serial to the Arch entry (the gate-7 disk keeps the Windows default;
  a missed window is power-cycled over QMP), the in-run domain join is carried
  through one-use media (``ArchIdentityBoundary._join_workstation``), the
  staged operator logs in on the ttyS0 getty, and one echo-suppressed
  ``sudo -S`` elevation follows.
  The per-run operator credential is staged on the disposable Controller by
  ``controller_principals`` exactly as the Windows lane does; it lives only
  in memory.  A bounded, redacted workstation transcript and the secret-free
  menu/login facts are retained in the bundle evidence on success and
  failure alike.
* ``ArchIdentityDrive`` drives one serial console through the ordered Arch
  lifecycle proofs, returning only booleans (plus the one measured login
  duration the storage-absent proof reports).
* ``run_lifecycle`` orchestrates an ``ArchIdentitySession`` (boundary +
  controller outage control + peer Windows evidence) and assembles the full
  ordered required-check evidence stream.
* ``run`` validates the bundle, gates on ``--apply``, produces the evidence
  file, and self-judges it with the real ``identity_lifecycle`` judge.

The disposable-controller boot, the loopback fabric and the live Arch guest
are produced by the neighbouring gates; the live session is behind an
injectable factory so this module is fully unit-tested without QEMU.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Protocol

from .signal_cleanup import RunInterrupted, SignalGuard

# The judge lives under workstations/ and is imported by path so the producer
# and the judge stay in lockstep on the contract (order, checks, fields).
_WORKSTATIONS = Path(__file__).resolve().parents[1] / "workstations"
if str(_WORKSTATIONS) not in sys.path:
    sys.path.insert(0, str(_WORKSTATIONS))
import identity_lifecycle as lifecycle  # noqa: E402

CONTRACT = lifecycle.load_json(lifecycle.CONTRACT)
REQUIRED_CHECKS: tuple[str, ...] = tuple(CONTRACT["required_checks"])
WINDOWS_CHECKS: tuple[str, ...] = tuple(
    check for check in REQUIRED_CHECKS if check.startswith("windows-"))
ARCH_CHECKS: tuple[str, ...] = tuple(
    check for check in REQUIRED_CHECKS if check.startswith("arch-"))
CONTROLLER_CHECKS: tuple[str, ...] = (
    "controller-ready", "controller-offline", "controller-restored")

# The exact per-check evidence fields the judge requires, mirroring
# homelab/tests/test_identity_lifecycle.valid_events. Every emitted event also
# carries result and external_access. These are the single source of truth for
# the fields this producer writes and for validating peer Windows evidence.
CHECK_DETAILS: dict[str, dict[str, object]] = {
    "controller-ready": {
        "samba_ad": True, "dns": True, "kerberos": True, "time": True,
        "synthetic_directory": True},
    "windows-joined": {
        "domain_joined": True, "secure_channel": True, "machine_account": True},
    "arch-joined": {
        "domain_joined": True, "secure_channel": True, "machine_account": True},
    "windows-standard-online": {
        "principal_role": "standard", "elevated": False},
    "arch-standard-online": {
        "principal_role": "standard", "elevated": False},
    "windows-daily-admin": {
        "principal_role": "daily-administrator", "local_admin": True,
        "domain_admin": False},
    "arch-daily-admin": {
        "principal_role": "daily-administrator", "local_admin": True,
        "domain_admin": False},
    "domain-admin-separate": {"same_principal": False},
    "controller-offline": {"authority_reachable": False},
    "windows-cached-login": {"controller_online": False, "cached": True},
    "arch-cached-login": {"controller_online": False, "cached": True},
    "windows-uncached-denied": {"controller_online": False, "login": "denied"},
    "arch-uncached-denied": {"controller_online": False, "login": "denied"},
    "windows-local-rescue": {"scope": "local", "local_admin": True},
    "arch-local-rescue": {"scope": "local", "local_admin": True},
    "controller-restored": {"authority_reachable": True},
    "windows-secure-channel-restored": {"secure_channel": True},
    "arch-identity-restored": {"identity_lookup": True},
    "arch-storage-attached": {
        "storage_reachable": True, "mount_state": "mounted",
        "storage_access": "authorized"},
    "arch-storage-denied": {
        "storage_reachable": True, "mount_state": "refused",
        "storage_access": "denied", "foreign_share": True},
    "arch-storage-absent-login": {
        "storage_reachable": False, "mount_state": "absent",
        "login": "allowed", "login_path_independent": True,
        "login_bound_seconds": CONTRACT["login_bound_seconds"]},
}

# Fields the judge requires that are *measured live* rather than templated:
# the guest probe prints the observed login duration as a token-scoped data
# line and the producer merges it into the event.  A passing event without
# its measurement is refused rather than fabricated.
MEASURED_CHECK_FIELDS: dict[str, tuple[str, ...]] = {
    "arch-storage-absent-login": ("login_seconds",),
}

# The joined guest exposes a fixed, secret-free probe helper. Each invocation
# runs exactly one lifecycle check and prints a token-scoped marker. The probe
# owns the SSSD/Kerberos/sudo commands; this host only reads its verdict.
PROBE_HELPER = "/usr/local/sbin/homelab-arch-identity-probe"

# The daily administrator is the principal the live drive logs in as on the
# ttyS0 getty.  The name comes from the shared lifecycle contract; the
# credential is the per-run synthetic one staged on the disposable Controller
# (controller_principals), held in memory only and never recorded.
OPERATOR_PRINCIPAL = str(CONTRACT["principals"]["daily_administrator"]["name"])

# The break-glass administrator.  ``identity_lifecycle.json`` gives it
# ``domain_role: none``, so -- unlike the three principals above -- NO
# Controller-staged account supplies its credential: ``controller_principals``
# ``POSIX_ALLOCATION`` stages only ``student``, ``operator`` and
# ``directory-admin``.  Gate 7 installs it with a *disabled* password, and the
# ``arch-local-rescue`` probe requires ``passwd -S`` to report ``P``, so this
# run generates the credential in memory and sets it once from the root shell
# ``elevate_operator`` already obtained.  Nothing ever needs the value again,
# so it is never stored on the boundary.
RESCUE_PRINCIPAL = str(CONTRACT["principals"]["local_rescue"]["name"])

# Gate 7 grants the operator a *passworded* sudoers rule
# ("operator ALL=(ALL:ALL) ALL" in workstations/arch_second.py — no NOPASSWD),
# so the probe helper's `sudo -n` self-elevation cannot succeed from a fresh
# operator session.  The drive therefore elevates exactly once with `sudo -S`
# fed the staged credential echo-suppressed (stty -echo around the send), and
# hands the probes an already-root shell: the probe skips self-elevation when
# `id -u` is 0.  This decision is pinned by tests against the rendered gate-7
# sudoers rule.
#
# The 2026-08-14 live run taught the rest of the exchange the hard way.  The
# domain login worked (a home directory was created, an operator prompt
# rendered) and the elevation still failed with sudo's "Sorry, try again.",
# because the harness wrote the credential when its OWN pre-sudo `printf`
# marker appeared -- i.e. before `sudo` had even been exec'd, let alone
# configured the tty and started reading.  The write was lost, and the next
# thing the harness typed (the `id -u` proof) became sudo's password.  Two
# separate defects produced that:
#
# 1. The credential must be written only after the READER has asked for it.
#    ``login``(1) and ``passwd``(1) are driven exactly that way in this module
#    (``login_operator`` waits for ``Password:``, ``set_rescue_password`` waits
#    for whichever PAM module asks -- see ``rescue_prompt_pattern``, and note
#    that gating on the reader's prompt is only half the discipline: the
#    *wording* has to be the wording that reader actually uses, which is what
#    the run below then stopped on); only the elevation gated on a marker
#    printed by the shell *before* the reader existed.  So the elevation now
#    gives sudo a token-scoped prompt with `-p` -- the same discipline
#    ``serial_automation.SerialAutomation.run`` has always used for the
#    Controller preflight -- and writes the credential only once that prompt is
#    on the console.  sudo prints the prompt after it has disabled echo on
#    stdin, so nothing can be discarded by the reader's own terminal setup.
# 2. Nothing about the outcome may be inferred from an unscoped shell-prompt
#    heuristic.  The old outcome pattern accepted any line ending in `#`, and
#    sudo's default lecture ("#1) Respect the privacy of others.") satisfied it
#    whenever a serial read landed on the `#`; the run then typed a shell
#    command into sudo's password prompt 18ms after sending the credential,
#    while the real SSSD authentication at the getty had taken 1.4s.  Every
#    verdict is now a token-scoped marker or sudo's own re-prompt, and each
#    outcome names its own layer.
#
# The lecture is deliberately NOT suppressed with a `Defaults lecture=never`
# drop-in.  That would be an installer change, and an installer change costs a
# fresh gate-7 install; the lecture is harmless once nothing pattern-matches on
# its shape, and a test pins the outcome pattern against the verbatim lecture
# at every read boundary.  Neither is any of this a PAM problem: stock Arch
# ships /etc/pam.d/sudo as `auth include system-auth`, and gate 7 writes
# pam_sss into that file's auth stack, so sudo's stack does reach SSSD.
#
# Failed sudo attempts feed pam_faillock exactly like failed logins (see
# LOGIN_ATTEMPTS), so the exchange also refuses to burn attempts: a refusal is
# detected from sudo's second prompt and aborts immediately, leaving one
# recorded failure and two of the stock `deny=3` still in hand.

#: Gate 7 must ship these on the join-capable disk for the live drive to work.
GATE7_CONTRACT = (
    f"a secret-free probe helper at {PROBE_HELPER} that runs one lifecycle "
    "check and prints __TELOS_ARCH_<CHECK>_<token>=PASS|FAIL, a systemd-boot "
    "menu rendered on ttyS0 listing the Arch and Windows entries behind the "
    "Windows-default five-second window (gate-7 acceptance requires the "
    "Windows default), an enabled one-shot boot unit that re-joins this run's "
    "freshly provisioned domain from one-use TELOS_JOIN media before sssd and "
    "before user sessions, a second one-shot unit ordered after sssd and "
    "before user sessions that holds the login prompt until SSSD's AD "
    "backend is actually online, a passworded serial getty on ttyS0 that "
    "takes the "
    "staged operator's SSSD domain login, and a passworded operator sudoers "
    "rule for the drive's single sudo -S elevation"
)

# Distinct, named boot-phase refusals.  Every one of these is fail-closed: a
# menu that never renders, a selection that keeps missing its window, a getty
# that never appears, a refused login, and a failed elevation each abort the
# run with its own message so the next run knows exactly where it stopped.
MENU_NEVER_RENDERED_FAILURE = (
    "systemd-boot menu never rendered on the workstation serial console; "
    "gate 7 must ship " + GATE7_CONTRACT)
MENU_WINDOW_MISSED_FAILURE = (
    "systemd-boot Arch selection missed the five-second menu window even "
    "after a QMP power-cycle retry")
MENU_NOT_COMMITTED_FAILURE = (
    "the systemd-boot Arch entry was selected but never committed with "
    "Enter, even after a QMP power-cycle retry; the highlight never settled "
    "on the Arch row")
GETTY_NEVER_APPEARED_FAILURE = (
    "ttyS0 getty never appeared after the Arch kernel handoff; gate 7 must "
    "ship " + GATE7_CONTRACT)
JOIN_FAILURE = (
    "the in-run domain join from the one-use TELOS_JOIN media never completed "
    "on the workstation console; this run provisions a brand-new domain, so "
    "the gate-7 machine account does not exist here and no login can succeed "
    "until the boot-time join unit prints both of its markers")
DOMAIN_ONLINE_FAILURE = (
    "SSSD never reported its domain online on the workstation console after "
    "the in-run join; sssd.service reaching active only means its responders "
    "answered READY=1, so gate 7 ships a one-shot gate that holds user "
    "sessions until the AD backend is usable and fails closed otherwise. A "
    "stop here is a readiness failure, never a refused login: the credential "
    "was never sent")
JOIN_PRINCIPAL_NOT_DESTROYED_FAILURE = (
    "the one-use domain-join principal was not provably destroyed on the "
    "disposable Controller; the run refuses to continue with a live join "
    "account in the directory")
LOGIN_REFUSED_FAILURE = (
    "operator login on the ttyS0 getty was refused with the staged "
    "credential")
SUDO_ELEVATION_FAILURE = (
    "operator sudo -S elevation did not yield a root shell for the probes")
# The four ways the elevation can stop, each naming its OWN layer so the next
# run never has to re-derive which of sudoers, PAM, sudo's exit or the root
# shell was at fault.  All of them are bound to arch-joined, and every one of
# them is secret-free: the boot facts carry booleans, sudo's exit code and the
# observed uid, never the credential.
SUDO_ECHO_NOT_SUPPRESSED_FAILURE = (
    "the operator shell never confirmed terminal echo was off before the "
    "elevation, so the credential was deliberately never written; nothing "
    "was exposed and the fault is in the operator shell, not in sudo")
SUDO_PROMPT_MISSING_FAILURE = (
    "sudo never asked the operator for a password, so the credential was "
    "never written; that is the sudoers/policy layer (the gate-7 rule, sudo "
    "itself or its path), never an authentication failure")
SUDO_CREDENTIAL_REFUSED_FAILURE = (
    "sudo read the operator credential and asked again: its PAM stack "
    "refused it. login_completed in the same boot facts records whether the "
    "ttyS0 getty accepted those same bytes seconds earlier -- if it did, the "
    "value is right and the fault is sudo's PAM stack, which must reach the "
    "pam_sss line gate 7 writes into /etc/pam.d/system-auth")
SUDO_EXITED_FAILURE = (
    "sudo exited without yielding a root shell; its own exit code is "
    "retained as sudo_returncode in the workstation boot facts")
SUDO_ROOT_UNPROVEN_FAILURE = (
    "the shell sudo yielded did not prove uid 0; the observed uid is "
    "retained as sudo_uid in the workstation boot facts")
RESCUE_PASSWORD_FAILURE = (
    "the local-rescue break-glass password was not set from the elevated "
    "console; gate 7 installs that account with a disabled password and the "
    "arch-local-rescue probe requires passwd -S to report P")
# The five ways the break-glass exchange can stop, each naming its OWN layer,
# for the same reason the sudo family above does.  The 2026-08-14 run
# ``run-20260814T155301Z-4b21f9334459`` reached a proven root shell
# (``sudo_uid: 0``) and then recorded nothing but ``rescue_password_set:
# false``, so the next run had to reconstruct the exchange from an
# ANSI-stripped transcript to find that ``passwd`` HAD asked -- in words the
# harness was not watching for (``rescue_prompt_pattern``).  Every one of these
# is secret-free: the facts carry booleans, a write count and passwd's own exit
# code, never the credential.
RESCUE_ECHO_NOT_SUPPRESSED_FAILURE = (
    "the elevated root shell never confirmed terminal echo was off before the "
    "break-glass password was set, so the credential was deliberately never "
    "written; nothing was exposed and the fault is in the root shell, not in "
    "passwd")
RESCUE_PROMPT_MISSING_FAILURE = (
    "passwd never asked for the local-rescue account's new password, so the "
    "credential was never written; that is the passwd/PAM layer (the account "
    "missing locally, passwd itself, or a password stack that asks in words "
    "rescue_prompt_pattern does not know), never a rejected credential")
RESCUE_CONFIRM_PROMPT_MISSING_FAILURE = (
    "passwd asked for the local-rescue password once, took it, and then "
    "neither asked for the confirmation nor returned; the exchange stopped "
    "half-written rather than typing the next command into a live reader")
RESCUE_CREDENTIAL_REJECTED_FAILURE = (
    "passwd read the generated break-glass credential and refused it -- it "
    "printed its own diagnostic, or kept re-asking past the bounded write "
    "budget.  The value is a fresh 35-character random string and root "
    "bypasses every strength check this disk installs (the gate-7 password "
    "stack carries no pam_pwquality), so a stop here indicts the password "
    "stack rather than the credential")
RESCUE_PASSWD_EXITED_FAILURE = (
    "passwd exited without setting the local-rescue password; its own exit "
    "code is retained as rescue_returncode in the workstation boot facts")

#: Retained workstation console evidence (bounded + redacted, no secrets).
WORKSTATION_LOG_FILENAME = "workstation-serial.log"
BOOT_FACTS_FILENAME = "workstation-boot.json"
TRANSCRIPT_RETENTION_BYTES = 4 * 1024 * 1024

# --------------------------------------------------------------------------
# Boot-stall evidence.  Two of eight gate-8 runs on 2026-08-14 produced
# console-init output and then nothing: no ``BdsDxe: loading Boot0007`` line,
# no menu, no fall-through to the Windows entry, no disk write, and a QEMU
# that stayed alive until the harness's wait expired.  Parsing the post-run
# variable stores settled a great deal -- ``Boot0007 "Linux Boot Manager"``
# was present, ACTIVE and first in the live ``BootOrder``; ``BootNext`` was
# never set; and BOTH failures wrote ``HDDP``, which EDK2 only writes inside
# ``EfiBootManagerBoot()`` once ``BmExpandPartitionDevicePath()`` has matched
# the ESP -- so the guest wedged after the entry was selected and the
# partition resolved, and before ``LoadImage`` read
# ``\EFI\systemd\systemd-bootx64.efi``.  What it could NOT settle is the
# mechanism (spinning vCPU, stalled device emulation, or a host I/O stall
# through the three-deep cache=none qcow2 chain), because the firmware's
# print level emits two lines an entire boot and four serial transcripts were
# the only artifacts this lane kept.  These names cover the artifacts that
# make the next occurrence self-diagnosing.
#: The firmware's own debug console.  If this OVMF build uses the I/O-port
#: DebugLib the whole firmware log lands here and the stall point is a
#: one-line read; if it uses the serial DebugLib the file stays empty, which
#: costs nothing and is itself the answer.
WORKSTATION_FIRMWARE_LOG_FILENAME = "workstation-firmware.log"
#: The fabric switch log, copied out of the runtime tempdir that deletes it.
#: It is the only record of fabric timing and of whether the switch itself
#: failed, and the single artifact that can confirm or kill the
#: "QEMU stalled" reading: a switch still logging while the guest says
#: nothing means the QEMU process was alive and scheduled.
SWITCH_LOG_FILENAME = "workstation-switch.jsonl"
#: One framebuffer frame per stall.  ``-device VGA`` was added specifically so
#: QMP ``screendump`` would work and nothing in this module ever called it; a
#: frame separates "firmware still on a blank screen" from "systemd-boot
#: rendered to VGA but not to ttyS0" at a glance.
STALL_FRAME_TEMPLATE = "workstation-stall-{index}.ppm"
FIRMWARE_LOG_RETENTION_BYTES = 4 * 1024 * 1024
SWITCH_LOG_RETENTION_BYTES = 1024 * 1024
#: A 1024x768 PPM is ~2.3MB; anything past this is not a framebuffer dump.
STALL_FRAME_MAX_BYTES = 16 * 1024 * 1024
#: Bounds on the retained diagnosis: stall records, drained QMP events per
#: record, and timestamped serial labels.
BOOT_STALL_RETENTION_LIMIT = 8
STALL_QMP_EVENT_LIMIT = 24
STALL_QMP_TIMEOUT = 10.0
SERIAL_TIMELINE_LIMIT = 512
#: ``SerialAutomation._wait`` raises one exception type for two very
#: different faults, and ``drive_boot_menu`` used to rewrite both into the
#: same message.  That ambiguity -- did QEMU die, or did a live guest go
#: quiet? -- cost most of the 2026-08-14 investigation, so the distinction is
#: named and retained.
STALL_SERIAL_CLOSED = "serial-closed"
STALL_TIMED_OUT = "timed-out"

#: Dead in-subnet address the ``unas`` storage label is repointed to for the
#: storage-absent proof: DNS resolution stays healthy (identity services keep
#: running) while every SMB connection attempt fails fast.
STORAGE_ABSENT_ADDRESS = "10.1.31.14"

#: Bound for the Linux EFI-stub handoff after the Arch entry is committed; a
#: miss means the five-second Windows-default window won and the guest must be
#: power-cycled over QMP rather than waited out inside Windows.
HANDOFF_TIMEOUT = 45.0
#: Bound for the systemd-boot menu itself.  Firmware that starts no
#: bootloader says nothing at all on ttyS0, so waiting out the much longer
#: console-ready bound buys no evidence -- fail in minutes, not in five.
MENU_RENDER_TIMEOUT = 120.0
#: Bounded highlight steps between selecting the Arch entry and committing it.
#: A keypress stops the countdown, so the menu then waits indefinitely and each
#: step only needs the next re-render, not another five-second window.
MENU_COMMIT_STEPS = 8
#: Per-step bound on that re-render.
MENU_COMMIT_TIMEOUT = 10.0
#: Bounded getty credential attempts.  Deliberately BELOW pam_faillock's
#: default ``deny=3`` rather than equal to it: the gate-7 system-auth stack is
#: the stock Arch one, so the third consecutive failure locks the account for
#: the default 600s ``unlock_time``.  A harness that spent all three would
#: leave the guest locked, and every later proof that touches this principal
#: (the probes' ``su -l``, the sec=krb5 storage mounts) would then be denied by
#: a lockout the evidence would misreport as an identity failure.  Two attempts
#: absorb one spurious refusal (SSSD may still be connecting when the first
#: prompt renders) while keeping a full failure of headroom below the
#: threshold, so a refusal reported here is always an honest refusal.
LOGIN_ATTEMPTS = 2
#: Bound for the guest-side one-shot join: the boot unit waits up to
#: 60 x 2s for the media before it fails closed, and the join plus
#: ``net ads testjoin`` follow, so the marker waits need real headroom.
JOIN_TIMEOUT = 420.0
#: Bound for the guest-side domain-online gate.  That unit waits up to
#: 60 x 2s for the SSSD domain to report online and then up to another
#: 60 x 2s for the login principal to resolve, so the marker wait needs
#: headroom past both; a stop here is bounded, named, and never a login
#: refusal.
DOMAIN_ONLINE_TIMEOUT = 300.0
#: Bound for the single ``sudo -S`` elevation.  Every step of it is local: the
#: prompt arrives in milliseconds and the one PAM round trip to the disposable
#: Controller measured 1.4s at the getty on 2026-08-14.  It is bounded on its
#: own because that run inherited the 300s console-ready timeout and spent five
#: minutes of a live run waiting on an exchange it had already desynchronised.
SUDO_ELEVATION_TIMEOUT = 60.0
#: Bound for one root-proof ask inside that budget.  Two bounded asks cover a
#: proof line typed into a root login shell that had not started reading yet,
#: without letting a genuinely dead exchange consume the whole elevation
#: budget in a single wait.  Three waits of this length fit the budget above.
SUDO_PROOF_TIMEOUT = 20.0
#: How many times the root proof may be typed before the elevation fails
#: closed.  Bounded for the same reason every other retry here is: a live run
#: must fail fast enough to be worth re-running.
SUDO_PROOF_ASKS = 2
#: Bound for the single ``passwd local-rescue`` exchange on the root shell.
RESCUE_PASSWORD_TIMEOUT = 60.0
#: Per-wait bound inside that exchange, for the same reason
#: ``SUDO_PROOF_TIMEOUT`` exists: every step of it is local (``passwd`` prints
#: its prompt in milliseconds and no PAM round trip leaves the box, because
#: ``local-rescue`` is a files-only account), and the 2026-08-14 run spent the
#: whole 60s budget in ONE wait for a prompt that was already on the console.
#: At most ``RESCUE_PASSWORD_WRITES + 1`` waits of this length can run.
RESCUE_PROMPT_TIMEOUT = 15.0
#: How many times the credential may be written into that exchange before it
#: fails closed.  Two is the expected count, but this disk's password stack can
#: legitimately ask twice over: gate 7 puts ``pam_sss`` ahead of ``pam_unix``
#: in ``/etc/pam.d/system-auth``, ``pam_sss`` asks its own pair first and only
#: then discovers the account is not a domain one, and whether ``pam_unix``
#: reuses that authtok (``try_first_pass``) or asks its own pair is a property
#: of the installed module, not of this harness.  Four writes converge either
#: way; a fifth ask is a refusal, not a stack, and stops the run.  Unlike the
#: getty and sudo credentials this costs no ``pam_faillock`` headroom --
#: faillock lives in the auth stack, and this is chauthtok.
RESCUE_PASSWORD_WRITES = 4
#: The one diagnostic ``passwd``(1) prints when the change actually landed.
#: Observed, recorded, and deliberately NOT required: the exit code is the
#: verdict, and requiring a localised sentence would trade a working live run
#: for a stricter proof of the same fact.
RESCUE_UPDATED_DIAGNOSTIC = b"password updated successfully"


def new_boot_facts() -> dict[str, object]:
    """Secret-free workstation boot/login lifecycle facts for the evidence."""
    return {
        "menu_seen": False,
        "entry_selected": None,
        "entry_committed": False,
        "menu_retries": 0,
        # Deliberately NOT folded into menu_retries.  A retry counted there
        # means a rendered menu whose five-second Windows default won the
        # window; a boot stall counted here means no menu was ever rendered at
        # all, with the firmware provably inside EfiBootManagerBoot for a
        # correct, active, first-in-BootOrder entry whose ESP it had already
        # matched.  They are different faults, and conflating them would
        # destroy the only signal either one has.  ``boot_stalls`` counts the
        # stalls a power-cycle recovered from, so the flake rate stays visible
        # in the evidence instead of being hidden by the retry.
        "boot_stalls": 0,
        # One bounded, secret-free record per observed stall (the recovered
        # ones and the terminal one alike): reason, frame, QMP status and the
        # asynchronous QMP events this lane never used to drain.
        "boot_stall_evidence": [],
        "handoff_seen": False,
        # In-run join lifecycle: secret-free booleans only, mirroring the
        # gate-7 ``join_media`` facts plus the DC-side destruction proof.
        "join_media_built": False,
        "join_media_attached": False,
        "join_media_consumed": False,
        "join_media_destroyed": False,
        "join_verified": False,
        "join_principal_destroyed": False,
        # Login readiness: the guest's domain-online gate printed its marker,
        # so the ttyS0 prompt that follows is backed by a usable AD backend.
        # The 2026-08-14 run proved a joined guest still refuses the operator
        # when this is false, so it is recorded next to the join facts.
        "domain_online_observed": False,
        "getty_seen": False,
        "login_completed": False,
        # The elevation, layer by layer.  The 2026-08-14 run recorded only
        # ``sudo_elevated: false`` and the next run had to reconstruct the
        # whole exchange from an ANSI-stripped transcript, so each stage of it
        # is now its own secret-free fact:
        #   sudo_echo_suppressed  the operator shell proved echo off, so the
        #                         credential was safe to write at all;
        #   sudo_prompt_seen      sudo asked -- past the sudoers/policy layer;
        #   sudo_credential_sent  the credential was written, and only after
        #                         the reader asked for it;
        #   sudo_root_shell_seen  a root shell prompt rendered;
        #   sudo_credential_refused  sudo read a line and asked again.  Read
        #                         together with login_completed this is the
        #                         whole diagnosis: the getty accepting the
        #                         same bytes proves the value and indicts
        #                         sudo's PAM stack instead;
        #   sudo_returncode       sudo's own exit code, when it exited;
        #   sudo_uid              the uid the elevated shell reported;
        #   sudo_proof_asks       how many times the root proof was typed.
        "sudo_echo_suppressed": False,
        "sudo_prompt_seen": False,
        "sudo_credential_sent": False,
        "sudo_root_shell_seen": False,
        "sudo_credential_refused": False,
        "sudo_returncode": None,
        "sudo_uid": None,
        "sudo_proof_asks": 0,
        "sudo_elevated": False,
        # The break-glass password, layer by layer, exactly as the elevation
        # above.  The 2026-08-14 run that first reached a root shell recorded
        # only ``rescue_password_set: false`` and the diagnosis had to come out
        # of the transcript, so each stage of this exchange is its own
        # secret-free fact:
        #   rescue_echo_suppressed    the root shell proved echo off, so the
        #                             credential was safe to write at all;
        #   rescue_prompt_seen        passwd asked for the new password;
        #   rescue_confirm_prompt_seen  and asked again for the confirmation;
        #   rescue_credential_sent    the credential was written, and only
        #                             after a reader had asked for it;
        #   rescue_credential_writes  how many times -- two means one PAM
        #                             module asked, four means pam_sss and
        #                             pam_unix each asked their own pair;
        #   rescue_credential_rejected  passwd printed its own diagnostic or
        #                             kept re-asking past the write budget;
        #   rescue_password_updated   passwd said the change landed;
        #   rescue_returncode         passwd's own exit code.
        "rescue_echo_suppressed": False,
        "rescue_prompt_seen": False,
        "rescue_confirm_prompt_seen": False,
        "rescue_credential_sent": False,
        "rescue_credential_writes": 0,
        "rescue_credential_rejected": False,
        "rescue_password_updated": False,
        "rescue_returncode": None,
        "rescue_password_set": False,
        # Timing.  Every instant in the 2026-08-14 stall investigation had to
        # be reconstructed from file mtimes, so the workstation's power-on
        # wall clock and a bounded, timestamped serial-label timeline (offsets
        # in seconds from that instant) are retained with the facts.
        "workstation_spawned_at": None,
        "serial_timeline": [],
        # The OVMF variable store either side of the boot.  Comparing a failed
        # run's post-boot hash with a passing one's is then a grep rather than
        # a varstore-parsing script, and before-versus-after answers "did the
        # firmware write the varstore at all this boot" on its own.
        "firmware_vars_sha256_before": None,
        "firmware_vars_sha256_after": None,
        # Size of the retained firmware debug console: nonzero proves this
        # OVMF build uses the I/O-port DebugLib and the whole firmware log is
        # in the bundle; zero proves it uses the serial one.
        "firmware_debug_log_bytes": None,
    }


class ArchIdentityError(RuntimeError):
    """The Arch identity lifecycle could not be produced safely.

    ``check`` names the lifecycle stage a failure is bound to, when one
    applies, so a failure teaches the next run where it stopped.
    """

    def __init__(self, message: str, *, check: str | None = None) -> None:
        super().__init__(message)
        self.check = check


def event(check: str, result: str, **fields: object) -> dict[str, object]:
    """Build one evidence event in the exact judged shape."""
    return {"check": check, "result": result, "external_access": False,
            **fields}


# --------------------------------------------------------------------------
# Bundle: a prepared, isolated Arch identity attempt.
# --------------------------------------------------------------------------

# gate 7 produces the installed+joined disk into the bundle; these are the
# artifacts that must be present, private, and isolation-preserving.
BUNDLE_DISK = "arch-workstation.qcow2"
BUNDLE_FIRMWARE = "OVMF_VARS.fd"
BUNDLE_AUTHORIZATION = "authorization.json"
BUNDLE_WINDOWS_EVIDENCE = "windows-evidence.jsonl"
#: Written by the run, not the producer: the exact argv the workstation booted.
BUNDLE_QEMU_COMMAND = "qemu-command.json"
EVIDENCE_DIRNAME = "evidence"
EVIDENCE_FILENAME = "identity-lifecycle.jsonl"

# ``domain_joined`` is retained deliberately, and it means what gate 7 can
# honestly promise: the disk is a join-CAPABLE identity client (Kerberos,
# Samba, SSSD, the enabled one-shot join unit).  It does NOT mean the disk
# arrives joined into this run's directory -- it cannot, because this run
# provisions a brand-new domain -- so the boundary joins in-run before login.
_AUTHORIZATION_EXPECTED = {
    "status": "prepared",
    "external_access": False,
    "installation_media_attached": False,
    "pxe_boot_enabled": False,
    "domain_joined": True,
}


@dataclass
class ArchIdentityBundle:
    """Fail-closed view of a prepared Arch identity acceptance bundle."""

    bundle: Path
    controller_state: Path
    realm: str = ""

    def __post_init__(self) -> None:
        self.bundle = Path(self.bundle).absolute()
        self.controller_state = Path(self.controller_state).absolute()

    @property
    def disk(self) -> Path:
        return self.bundle / BUNDLE_DISK

    @property
    def firmware(self) -> Path:
        return self.bundle / BUNDLE_FIRMWARE

    @property
    def windows_evidence_path(self) -> Path:
        return self.bundle / BUNDLE_WINDOWS_EVIDENCE

    @property
    def evidence_path(self) -> Path:
        return self.bundle / EVIDENCE_DIRNAME / EVIDENCE_FILENAME

    def _require_private_dir(self, path: Path, what: str) -> None:
        if path.is_symlink() or not path.is_dir():
            raise ArchIdentityError(f"{what} must be a real directory")
        if path.stat().st_mode & 0o077:
            raise ArchIdentityError(f"{what} must be private (mode 0700)")

    def _require_private_file(self, path: Path, what: str) -> None:
        if path.is_symlink() or not path.is_file():
            raise ArchIdentityError(f"{what} must be a regular file")
        if path.stat().st_mode & 0o077:
            raise ArchIdentityError(f"{what} must be mode 0600")

    def validate(self) -> None:
        """Prove the bundle is a private, isolated, joined attempt or refuse."""
        self._require_private_dir(self.bundle, "identity bundle")
        # The live disk is produced by gate 7; a bundle without it cannot run.
        self._require_private_file(self.disk, BUNDLE_DISK)
        self._require_private_file(self.firmware, BUNDLE_FIRMWARE)

        authorization_path = self.bundle / BUNDLE_AUTHORIZATION
        if authorization_path.is_symlink() or not authorization_path.is_file():
            raise ArchIdentityError(
                f"{BUNDLE_AUTHORIZATION} must be a regular file")
        try:
            authorization = json.loads(
                authorization_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ArchIdentityError(
                "identity authorization is unreadable") from error
        if not isinstance(authorization, dict):
            raise ArchIdentityError("identity authorization is not an object")
        for key, expected in _AUTHORIZATION_EXPECTED.items():
            if authorization.get(key) != expected:
                raise ArchIdentityError(
                    "identity authorization does not preserve joined isolation "
                    f"({key} must be {expected!r})")
        realm = authorization.get("realm")
        if not isinstance(realm, str) or not realm:
            raise ArchIdentityError(
                "identity authorization must name the Kerberos realm")
        self.realm = realm

        # Peer Windows evidence is a bundle input; the joined Arch harness does
        # not drive Windows, it merges the Windows lane's produced evidence.
        peer = self.windows_evidence_path
        if peer.is_symlink() or not peer.is_file():
            raise ArchIdentityError(
                f"{BUNDLE_WINDOWS_EVIDENCE} must be a regular file "
                "(the Windows lane's produced evidence)")

        # The Controller state is disposable but must be a real private dir.
        self._require_private_dir(self.controller_state, "controller state")

    def read_windows_evidence(self) -> list[dict[str, object]]:
        """Load and fail-closed validate the peer Windows evidence events."""
        try:
            with self.windows_evidence_path.open(encoding="utf-8") as source:
                events = lifecycle.load_events(source)
        except (OSError, lifecycle.EvidenceError) as error:
            raise ArchIdentityError(
                f"peer Windows evidence is unreadable: {error}") from error
        return validate_windows_evidence(events)


def validate_windows_evidence(
    events: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Fail-closed check that peer evidence proves every Windows check.

    The joined Arch harness never fabricates Windows facts. It merges the
    Windows lane's evidence verbatim, but refuses to emit a combined stream
    unless that evidence actually proves each Windows check with the fields the
    judge requires.
    """
    by_check: dict[str, dict[str, object]] = {}
    for candidate in events:
        check = candidate.get("check")
        if check in WINDOWS_CHECKS:
            if check in by_check:
                raise ArchIdentityError(
                    f"peer Windows evidence duplicates {check}")
            by_check[str(check)] = candidate
    ordered: list[dict[str, object]] = []
    for check in WINDOWS_CHECKS:
        candidate = by_check.get(check)
        if candidate is None:
            raise ArchIdentityError(
                f"peer Windows evidence is missing {check}")
        if candidate.get("result") != "pass":
            raise ArchIdentityError(
                f"peer Windows evidence for {check} did not pass")
        if candidate.get("external_access") is not False:
            raise ArchIdentityError(
                f"peer Windows evidence for {check} allows external access")
        for name, value in CHECK_DETAILS[check].items():
            if candidate.get(name) != value:
                raise ArchIdentityError(
                    f"peer Windows evidence for {check} lacks {name}={value!r}")
        ordered.append(candidate)
    return ordered


# --------------------------------------------------------------------------
# Serial drive: bounded Arch proofs.
# --------------------------------------------------------------------------

class SerialChannel(Protocol):
    """The bounded serial console surface this drive needs.

    ``homelab.vm.serial_automation.SerialAutomation`` satisfies it; tests
    provide a scripted double.
    """

    token: str

    def _send(self, value: bytes, event: str) -> None: ...

    def _wait(self, pattern: bytes, label: str): ...


class ArchIdentityDrive:
    """Drive one joined Arch guest through the seven lifecycle proofs.

    Each proof runs the guest probe helper for a single check and reads its
    token-scoped marker. Only the pass/fail verdict is retained. A missing
    marker (a timed-out or closed console) propagates as a serial error, which
    the caller binds to the pursued check; a ``FAIL`` marker is a genuine
    lifecycle failure and returns ``False`` so the judge rejects the evidence.
    """

    def __init__(self, channel: SerialChannel) -> None:
        self.channel = channel

    def _marker_key(self, check: str) -> str:
        return check.upper().replace("-", "_")

    def _probe(self, check: str) -> bool:
        token = self.channel.token
        command = f"{PROBE_HELPER} {check} {token}".encode("ascii")
        self.channel._send(command, f"arch-probe-{check}-sent")
        prefix = f"__TELOS_ARCH_{self._marker_key(check)}_{token}=".encode(
            "ascii")
        match = self.channel._wait(
            re.escape(prefix) + rb"(PASS|FAIL)\b",
            f"arch-probe-{check}-observed",
        )
        return match.group(1) == b"PASS"

    def prove_joined(self) -> bool:
        """`net ads testjoin`: a live secure channel and machine account."""
        return self._probe("arch-joined")

    def prove_standard_online(self) -> bool:
        """SSSD resolves and logs in the synthetic standard user, unelevated."""
        return self._probe("arch-standard-online")

    def prove_daily_admin(self) -> bool:
        """The daily administrator gets sudo via the domain admin group."""
        return self._probe("arch-daily-admin")

    def prove_domain_admin_separate(self) -> bool:
        """The daily and directory administrators are distinct principals."""
        return self._probe("domain-admin-separate")

    def prove_cached_login(self) -> bool:
        """With the Controller offline, the primed user logs in from cache."""
        return self._probe("arch-cached-login")

    def prove_uncached_denied(self) -> bool:
        """With the Controller offline, an unprimed user is denied."""
        return self._probe("arch-uncached-denied")

    def prove_local_rescue(self) -> bool:
        """The local break-glass administrator logs in independently."""
        return self._probe("arch-local-rescue")

    def prove_identity_restored(self) -> bool:
        """After reconnect, SSSD resolves the directory identity again."""
        return self._probe("arch-identity-restored")

    def prove_storage_attached(self) -> bool:
        """The reachable per-user SMB share mounts with the user's identity."""
        return self._probe("arch-storage-attached")

    def prove_storage_denied(self) -> bool:
        """A foreign user's share is refused while storage is reachable."""
        return self._probe("arch-storage-denied")

    def prove_storage_absent_login(self) -> tuple[bool, int | None]:
        """With the storage target absent, login stays bounded and allowed.

        The guest probe prints one token-scoped data line with the measured
        login duration before its verdict; both are read here.  A ``PASS``
        without the measurement is refused — the judge requires the observed
        seconds and this producer never fabricates them.
        """
        from homelab.workstations.arch_second import (
            STORAGE_LOGIN_SECONDS_MARKER)

        check = "arch-storage-absent-login"
        token = self.channel.token
        command = f"{PROBE_HELPER} {check} {token}".encode("ascii")
        self.channel._send(command, f"arch-probe-{check}-sent")
        data_prefix = f"{STORAGE_LOGIN_SECONDS_MARKER}{token}=".encode(
            "ascii")
        verdict_prefix = (
            f"__TELOS_ARCH_{self._marker_key(check)}_{token}=".encode(
                "ascii"))
        pattern = (
            rb"(?:" + re.escape(data_prefix) + rb"([0-9]+)|"
            + re.escape(verdict_prefix) + rb"(PASS|FAIL)\b)")
        seconds: int | None = None
        while True:
            match = self.channel._wait(pattern, f"arch-probe-{check}-observed")
            if match.group(1) is not None:
                seconds = int(match.group(1))
                continue
            passed = match.group(2) == b"PASS"
            break
        if passed and seconds is None:
            raise ArchIdentityError(
                f"{check} passed without its measured login duration",
                check=check)
        return passed, seconds


# --------------------------------------------------------------------------
# Session orchestration.
# --------------------------------------------------------------------------

class ArchIdentitySession(Protocol):
    """A live boundary the lifecycle is driven over.

    The real implementation boots the loopback fabric, the disposable Samba AD
    Controller and the joined Arch workstation, and controls the Controller
    outage. Tests provide a deterministic double.
    """

    def start(self) -> None: ...

    def open_channel(self) -> SerialChannel: ...

    def observe_controller_ready(self) -> bool: ...

    def take_controller_offline(self) -> None: ...

    def observe_controller_offline(self) -> bool: ...

    def restore_controller(self) -> None: ...

    def observe_controller_restored(self) -> bool: ...

    def make_storage_unreachable(self) -> None: ...

    def windows_evidence(self) -> list[dict[str, object]]: ...

    def stop(self) -> list[str]: ...


def assemble_evidence(
    outcomes: Mapping[str, bool],
    windows_events: list[dict[str, object]],
    *,
    measurements: Mapping[str, Mapping[str, object]] | None = None,
) -> list[dict[str, object]]:
    """Compose the full ordered required-check evidence stream.

    Arch and Controller checks come from ``outcomes`` (live observations);
    Windows checks are merged verbatim from validated peer evidence. The order
    is the contract's required order, so a well-formed pass stream is exactly
    the shape the judge accepts.  ``measurements`` carries the live-observed
    fields of ``MEASURED_CHECK_FIELDS``; a passing check missing one is
    refused rather than fabricated.
    """
    windows_by_check = {str(item["check"]): item for item in windows_events}
    measured = {key: dict(value) for key, value in
                (measurements or {}).items()}
    events: list[dict[str, object]] = []
    for check in REQUIRED_CHECKS:
        if check in WINDOWS_CHECKS:
            events.append(windows_by_check[check])
            continue
        if check not in outcomes:
            raise ArchIdentityError(
                f"lifecycle observation is missing for {check}", check=check)
        result = "pass" if outcomes[check] else "fail"
        extra = measured.get(check, {})
        for name in MEASURED_CHECK_FIELDS.get(check, ()):
            if result == "pass" and name not in extra:
                raise ArchIdentityError(
                    f"{check} passed without measured {name}", check=check)
        events.append(event(check, result, **CHECK_DETAILS[check], **extra))
    return events


def _probe_check(
    outcomes: dict[str, bool], check: str, prove: Callable[[], bool],
) -> None:
    """Run one bounded proof, binding a serial failure to its check."""
    try:
        outcomes[check] = prove()
    except lifecycle.EvidenceError:
        raise
    except ArchIdentityError:
        raise
    except Exception as error:  # bounded serial failure: name the stage
        raise ArchIdentityError(
            f"{check} proof failed on the console: {type(error).__name__}",
            check=check,
        ) from error


def run_lifecycle(
    session: ArchIdentitySession,
) -> list[dict[str, object]]:
    """Drive the ordered Arch lifecycle and return the evidence stream.

    Teardown is always attempted and bounded. Any lifecycle failure is raised
    after teardown so a live guest is never left running.
    """
    primary: BaseException | None = None
    cleanup_errors: list[str] = []
    events: list[dict[str, object]] = []
    started = False
    try:
        session.start()
        started = True
        outcomes: dict[str, bool] = {}
        outcomes["controller-ready"] = session.observe_controller_ready()
        drive = ArchIdentityDrive(session.open_channel())

        _probe_check(outcomes, "arch-joined", drive.prove_joined)
        _probe_check(
            outcomes, "arch-standard-online", drive.prove_standard_online)
        _probe_check(outcomes, "arch-daily-admin", drive.prove_daily_admin)
        _probe_check(
            outcomes, "domain-admin-separate",
            drive.prove_domain_admin_separate)

        session.take_controller_offline()
        outcomes["controller-offline"] = session.observe_controller_offline()
        _probe_check(outcomes, "arch-cached-login", drive.prove_cached_login)
        _probe_check(
            outcomes, "arch-uncached-denied", drive.prove_uncached_denied)
        _probe_check(outcomes, "arch-local-rescue", drive.prove_local_rescue)

        session.restore_controller()
        outcomes["controller-restored"] = session.observe_controller_restored()
        _probe_check(
            outcomes, "arch-identity-restored", drive.prove_identity_restored)

        # Gate 9: the reachable-storage proofs run against the live target
        # (after the operator login primed the Kerberos ticket the sec=krb5
        # mounts need), then the target is made unreachable so the bounded,
        # storage-independent login can be proven honestly.
        _probe_check(
            outcomes, "arch-storage-attached", drive.prove_storage_attached)
        _probe_check(
            outcomes, "arch-storage-denied", drive.prove_storage_denied)
        session.make_storage_unreachable()
        measurements: dict[str, dict[str, object]] = {}
        try:
            passed, seconds = drive.prove_storage_absent_login()
        except (lifecycle.EvidenceError, ArchIdentityError):
            raise
        except Exception as error:  # bounded serial failure: name the stage
            raise ArchIdentityError(
                "arch-storage-absent-login proof failed on the console: "
                + type(error).__name__,
                check="arch-storage-absent-login") from error
        outcomes["arch-storage-absent-login"] = passed
        if seconds is not None:
            measurements["arch-storage-absent-login"] = {
                "login_seconds": seconds}

        events = assemble_evidence(
            outcomes, session.windows_evidence(),
            measurements=measurements)
    except BaseException as error:  # noqa: BLE001 - re-raised after teardown
        primary = error
    finally:
        if started:
            try:
                cleanup_errors = session.stop()
            except BaseException as error:  # noqa: BLE001
                cleanup_errors = [f"teardown: {type(error).__name__}"]

    if primary is not None:
        if isinstance(primary, RunInterrupted) and not cleanup_errors:
            raise primary
        if isinstance(primary, ArchIdentityError) and not cleanup_errors:
            raise primary
        detail = f"lifecycle: {type(primary).__name__}"
        raise ArchIdentityError(
            "Arch identity lifecycle failed; "
            + "; ".join([detail, *cleanup_errors]),
            check=getattr(primary, "check", None),
        ) from primary
    if cleanup_errors:
        raise ArchIdentityError(
            "Arch identity teardown was incomplete; " + "; ".join(
                cleanup_errors))
    return events


def write_evidence(path: Path, events: list[dict[str, object]]) -> None:
    """Write the evidence stream as one private JSONL file."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    body = "".join(
        json.dumps(item, sort_keys=True) + "\n" for item in events)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o600)


def self_judge(path: Path) -> tuple[bool, str]:
    """Grade the produced evidence with the real lifecycle judge."""
    try:
        with path.open(encoding="utf-8") as source:
            result = lifecycle.judge(CONTRACT, lifecycle.load_events(source))
    except (OSError, lifecycle.EvidenceError) as error:
        return False, str(error)
    return True, (
        f"{result['checks']} checks, external_access="
        f"{result['external_access']}")


SessionFactory = Callable[[ArchIdentityBundle], ArchIdentitySession]

#: Overall wall-clock bound for one live identity session.  The per-exchange
#: SerialAutomation timeout only bounds a single console wait; this bound
#: covers the whole boundary (fabric, Controller convergence, guest drive).
DEFAULT_DURATION = 1800.0
MAX_DURATION = 10800.0
#: Boot-to-console bound for the joined workstation before probes start.
CONSOLE_READY_TIMEOUT = 300.0
#: Per-probe console bound once the guest shell is live.
PROBE_TIMEOUT = 90.0


def audit_arch_identity_boot(command: list[str], *, disk: Path) -> None:
    """Refuse any identity boot that could install, PXE, or write elsewhere.

    Gate 8 proves login on the *already installed* joined system, so the only
    writable medium is the bundle overlay, no installation media may be
    attached, and firmware must boot the disk, never the network.
    """
    expected = str(Path(disk).resolve())
    writable = []
    for index, argument in enumerate(command):
        if argument == "-cdrom":
            raise ArchIdentityError(
                "identity boot must not attach installation media")
        if argument != "-drive" or index + 1 >= len(command):
            continue
        fields = dict(
            item.split("=", 1)
            for item in command[index + 1].split(",") if "=" in item)
        if fields.get("media") == "cdrom":
            raise ArchIdentityError(
                "identity boot must not attach installation media")
        if fields.get("readonly") == "on" or fields.get("if") == "pflash":
            continue
        writable.append(fields)
    if len(writable) != 1:
        raise ArchIdentityError(
            "identity boot must expose exactly one writable disk")
    exposed = writable[0].get("file")
    if exposed is None or str(Path(exposed).resolve()) != expected:
        raise ArchIdentityError(
            "writable disk differs from the authorized bundle overlay")
    if any("order=n" in item for item in command):
        raise ArchIdentityError(
            "identity boot must never PXE; the joined disk is the boot path")
    if "order=c,menu=off" not in command:
        raise ArchIdentityError(
            "identity boot must deterministically boot from disk")


def workstation_boot_command(
    disk: Path, variables: Path, switch_port: int, *,
    qmp_socket: Path | None = None,
    firmware_log: Path | None = None,
) -> list[str]:
    """Build the disk-only boot command for the joined Arch workstation.

    No PXE and no installation media: the joined disk is cold-plugged as the
    same NVMe device (same synthetic serial) the gate-7 installer targeted,
    so the installed system enumerates the disk it was installed onto.  The
    boot itself rides the gate-7 bundle's authored NVRAM entries rather than
    ESP auto-discovery, which the live 2026-08-13 run showed starts no
    bootloader at all here; the argv otherwise matches the gate-10 dual-boot
    boundary, the only one that renders this menu reliably.

    ``qmp_socket`` (mirroring the dual-boot lane) pins a private QMP socket
    so a missed systemd-boot window can be power-cycled with ``system_reset``
    instead of being waited out inside Windows.

    ``firmware_log`` wires OVMF's own debug console to a file.  The 2026-08-14
    stalls left this lane with four serial transcripts of a firmware whose
    print level emits two lines an entire boot, so where inside
    ``EfiBootManagerBoot`` the guest wedged could not be read off any
    artifact.  ``-debugcon`` plus the ``0x402`` I/O port OVMF's
    ``BaseDebugLibIoPort`` uses turns that into a one-line read when the build
    carries that DebugLib, and produces an empty file (costing nothing, and
    itself informative) when it carries the serial one.  Both audits are run
    below with the extra tokens present, because a rejected token would break
    every run rather than one.

    One empty ``pcie-root-port`` is cold-plugged for the one-use ``TELOS_JOIN``
    media the in-run join hot-attaches: q35's root complex (``pcie.0``) does
    not support PCIe hotplug, so ``device_add`` needs a root port that was
    present at boot.  It carries no device at boot, only the slot -- the
    credential cannot exist before the domain is provisioned -- which is
    exactly the arrangement ``arch_install_prepare`` uses for gate 7.
    """
    # Imported lazily: topology helpers are never needed by the pure
    # producer/judge path.
    from .arch_install_prepare import (
        DISK_SERIAL, JOIN_PORT_CHASSIS, JOIN_PORT_ID)
    from .simulated_topology import MACS, _base, audit_qemu_argv

    if not 1 <= switch_port <= 65535:
        raise ArchIdentityError("switch port is invalid")
    command = _base("arch-identity", Path(variables), 8192)
    command += [
        "-boot", "order=c,menu=off",
        "-monitor", "none",
        # The frame evidence needs a display device: with -nodefaults there is
        # none and every screendump fails, which is exactly why the 2026-08-13
        # no-menu boot could not be diagnosed from this lane's own artifacts.
        "-device", "VGA",
    ]
    if firmware_log is not None:
        target = Path(firmware_log)
        # A chardev spec is comma-separated, so a comma in the path would be
        # parsed as another option and QEMU would refuse to start at all.
        if not target.is_absolute() or "," in str(target):
            raise ArchIdentityError(
                "the firmware debug log path must be absolute and comma-free")
        command += [
            "-debugcon", f"file:{target}",
            "-global", "isa-debugcon.iobase=0x402",
        ]
    if qmp_socket is not None:
        if len(str(Path(qmp_socket)).encode()) > 100:
            raise ArchIdentityError(
                "QMP socket path exceeds the AF_UNIX length bound")
        command += [
            "-qmp", f"unix:{Path(qmp_socket)},server=on,wait=off"]
    command += [
        "-drive",
        (
            "if=none,id=osdisk,format=qcow2,cache=none,"
            f"file={Path(disk).resolve()}"
        ),
        # No bootindex: it injects an fw_cfg boot order that competes with the
        # authored NVRAM entries, and the gate-10 lane -- the one boundary that
        # renders this menu reliably -- pins no bootindex either.
        "-device", f"nvme,drive=osdisk,serial={DISK_SERIAL}",
        # The empty hotplug slot the in-run join media is realised into.  It
        # holds no device and no backend at boot, so audit_arch_identity_boot
        # still sees exactly one writable disk and no installation media.
        "-device",
        (
            f"pcie-root-port,id={JOIN_PORT_ID},bus=pcie.0,"
            f"chassis={JOIN_PORT_CHASSIS}"
        ),
        "-netdev", f"socket,id=factory,connect=127.0.0.1:{switch_port}",
        "-device", f"e1000e,netdev=factory,mac={MACS['client']}",
    ]
    audit_qemu_argv("client", command, allowed_nic_models=("e1000e",))
    audit_arch_identity_boot(command, disk=disk)
    return command


# --------------------------------------------------------------------------
# Boot drive: systemd-boot menu, getty login, single sudo -S elevation.
# --------------------------------------------------------------------------

def _utc_now() -> str:
    """One wall-clock stamp in the shape the other evidence lanes write."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _file_sha256(path: Path) -> str | None:
    """The repository's file digest, or ``None`` when it cannot be taken."""
    from .windows_install_contract import sha256

    try:
        return sha256(Path(path))
    except OSError:
        return None


def stall_reason(error: BaseException) -> str:
    """Tell a dead QEMU apart from a live guest that went quiet.

    ``SerialAutomation._wait`` raises the same ``SerialAutomationError`` for
    EOF on the console (``serial closed while waiting for ...``, i.e. the QEMU
    process exited) and for a guest that simply stopped speaking (``timed out
    waiting for ...``), and ``drive_boot_menu`` rewrote both into one message,
    so the retained facts could not tell them apart.  Reconstructing that
    distinction from QEMU's lifetime consumed most of the 2026-08-14 stall
    investigation; here it is read once and retained.
    """
    return (STALL_SERIAL_CLOSED if str(error).startswith("serial closed")
            else STALL_TIMED_OUT)


def _bounded_qmp_events(queued) -> list[dict[str, object]]:
    """The asynchronous QMP events on the socket, bounded and secret-free.

    ``QmpClient`` queues every event it reads past while awaiting a command
    response and nothing in this lane has ever looked at that queue, so a
    ``BLOCK_IO_ERROR``, ``RESET`` or ``STOP`` raised during a stalled boot was
    discarded -- exactly the traffic that would have distinguished a host I/O
    stall from a spinning vCPU.  Only QEMU-generated names, timestamps and
    small primitive payloads are kept, and only the most recent few.
    """
    result: list[dict[str, object]] = []
    try:
        recent = list(queued)[-STALL_QMP_EVENT_LIMIT:]
    except TypeError:  # not iterable: a double, or nothing at all
        return result
    for item in recent:
        if not isinstance(item, dict):
            continue
        entry: dict[str, object] = {"event": str(item.get("event"))[:64]}
        stamp = item.get("timestamp")
        if isinstance(stamp, dict):
            entry["timestamp"] = {
                str(key)[:16]: value for key, value in stamp.items()
                if isinstance(value, (int, float))}
        data = item.get("data")
        if isinstance(data, dict):
            entry["data"] = {
                str(key)[:32]: (
                    value if isinstance(value, (bool, int, float))
                    else str(value)[:96])
                for key, value in list(data.items())[:8]}
        result.append(entry)
    return result


class TimestampedEvents(list):
    """A ``SerialAutomation.events`` list that also records *when*.

    ``serial_automation`` appends bare labels, so a retained bundle said which
    console exchanges happened and in what order but never at what time, and
    the whole 2026-08-14 stall investigation had to reconstruct its timings
    from file mtimes.  Subclassing ``list`` keeps the label sequence
    byte-identical for every existing reader (and every existing assertion)
    while ``timeline`` records ``[offset_seconds, label]`` against the
    workstation's power-on instant.
    """

    def __init__(self, existing=(), *, clock=None, origin=None) -> None:
        super().__init__(existing)
        self.clock = clock or time.monotonic
        self.origin = self.clock() if origin is None else origin
        self.timeline: list[list[object]] = []

    def append(self, item) -> None:
        self.timeline.append([round(self.clock() - self.origin, 3), item])
        super().append(item)


def _send_raw(console, value: bytes, event: str) -> None:
    """Write raw bytes without the line terminator ``_send`` appends.

    The systemd-boot keys are bare bytes (digit, arrow, ``\r``); a trailing
    newline would be typed ahead into the booted system's console.
    """
    console.writer.write(value)
    console.writer.flush()
    console.events.append(event)


def _commit_menu_entry(
    console, entries: list[str], menu_pattern: bytes, *,
    steps: int = MENU_COMMIT_STEPS,
    step_timeout: float = MENU_COMMIT_TIMEOUT,
) -> bool:
    """Drive the systemd-boot highlight onto Arch and press Enter.

    A digit key selects a menu row but does NOT boot it -- the live gate-8
    run of 2026-08-14 rendered the menu, moved the highlight onto Arch and
    then sat there until the harness gave up, and the dual-boot lane recorded
    the same lesson.  ``\\r`` is what boots the highlighted entry.  The
    highlight is read back from the raw inverse-video render rather than
    assumed, so a firmware whose digit key selects nothing still converges by
    cursor navigation.  Returns whether Enter was sent.
    """
    from .dualboot_acceptance import (
        MENU_ARCH_ENTRY, MENU_DOWN_KEY, MENU_ENTER_KEY, MENU_UP_KEY,
        _menu_highlighted)
    from .serial_automation import SerialAutomationError

    target = entries.index(MENU_ARCH_ENTRY)
    original = console.timeout
    try:
        console.timeout = step_timeout
        for step in range(max(1, steps)):
            # Read the highlight from a render that reflects the last key.
            # On the first pass the digit's own re-render may already have
            # arrived, so a miss there is not yet a failure.
            try:
                console._wait(menu_pattern, "arch-menu-rerendered")
            except SerialAutomationError:
                if step:
                    return False
            highlighted = _menu_highlighted(
                console.transcript.decode("utf-8", "replace"))
            if highlighted == MENU_ARCH_ENTRY:
                _send_raw(console, MENU_ENTER_KEY, "arch-menu-entry-committed")
                return True
            if highlighted not in entries:
                return False
            _send_raw(
                console,
                MENU_UP_KEY if entries.index(highlighted) > target
                else MENU_DOWN_KEY,
                "arch-menu-highlight-moved")
    finally:
        console.timeout = original
    return False


def drive_boot_menu(
    console, facts: dict[str, object], *,
    reset: Callable[[], object],
    attempts: int = 2,
    menu_timeout: float | None = None,
    handoff_timeout: float = HANDOFF_TIMEOUT,
    on_stall: Callable[..., object] | None = None,
) -> None:
    """Select the Arch entry on the serial systemd-boot menu, fail-closed.

    Mirrors the dual-boot acceptance lane (``dualboot_acceptance``): the menu
    entries are parsed from the raw escape-bearing serial render (positioned,
    space-padded cells — plain log text mentioning an entry title never
    counts), the digit key for the Arch entry is sent raw within the
    five-second Windows-default window, the highlight is then driven onto
    Arch and committed with Enter, and the Linux EFI-stub handoff markers
    prove the selection took.  A missed window means Windows is
    booting silently; the guest is power-cycled via *reset* (QMP
    ``system_reset``) and the menu is driven once more.  A menu that never
    renders at all is power-cycled the same way and counted separately as a
    boot stall (see the branch below).  Every terminal outcome is a distinct,
    named failure.

    ``on_stall(reason, attempt=..., terminal=..., label=...)`` is invoked on
    each never-rendered miss so the caller can retain the frame/QMP evidence
    the mechanism of a stall needs; it is best-effort and never affects the
    outcome.
    """
    from .dualboot_acceptance import (
        ARCH_HANDOFF_MARKERS, MENU_ARCH_ENTRY, MENU_WINDOWS_ENTRY,
        _menu_entries)
    from .serial_automation import SerialAutomationError

    arch = re.escape(MENU_ARCH_ENTRY.encode("ascii"))
    windows = re.escape(MENU_WINDOWS_ENTRY.encode("ascii"))
    menu_pattern = (
        rb"(?s)(?:" + arch + rb".*" + windows + rb"|"
        + windows + rb".*" + arch + rb")")
    handoff_pattern = rb"(?:" + rb"|".join(
        re.escape(marker.encode("ascii"))
        for marker in ARCH_HANDOFF_MARKERS) + rb")"
    original = console.timeout
    try:
        for attempt in range(max(1, attempts)):
            if menu_timeout is not None:
                console.timeout = menu_timeout
            try:
                console._wait(menu_pattern, "arch-menu-rendered")
            except SerialAutomationError as error:
                # Power-cycle once and drive the menu again rather than
                # failing here on the first miss.  A retry can look like
                # papering over a fault, so the justification is recorded:
                # the 2026-08-14 stall bundles prove Boot0007 was present,
                # LOAD_OPTION_ACTIVE and first in the live BootOrder, that
                # nobody set BootNext, and that the firmware had already
                # written HDDP -- which EDK2 only writes once
                # EfiBootManagerBoot has expanded and matched the ESP device
                # path.  The entry, the boot order, the partition and the
                # loader path were therefore all correct and resolved, so this
                # is not a configuration or artifact error that a retry would
                # mask; it is a stall inside the first read of the loader, and
                # a power-cycle is exactly what a real workstation would get.
                # This lane already sanctions QMP ``system_reset`` for the
                # analogous post-menu miss just below, ``attempts`` bounds it
                # to one extra try, the final attempt still raises the named
                # never-rendered failure (fail-closed), and ``boot_stalls``
                # plus the retained stall evidence keep the flake rate visible
                # instead of hiding it.  Both failures recorded
                # ``menu_retries: 0`` precisely because this branch used to
                # raise before the power-cycle below could ever be reached.
                reason = stall_reason(error)
                terminal = attempt + 1 >= max(1, attempts)
                if on_stall is not None:
                    try:
                        on_stall(
                            reason, attempt=attempt + 1, terminal=terminal,
                            label="arch-menu-rendered")
                    except Exception:  # noqa: BLE001 - diagnosis never raises
                        pass
                if terminal:
                    raise ArchIdentityError(
                        MENU_NEVER_RENDERED_FAILURE, check="arch-joined",
                    ) from error
                facts["boot_stalls"] = int(facts.get("boot_stalls", 0)) + 1
                console.buffer = b""
                reset()
                console.events.append("arch-workstation-power-cycled")
                continue
            facts["menu_seen"] = True
            # ``_wait`` matches (and trims) the ANSI-stripped buffer, so the
            # raw render ``_menu_entries`` needs lives only in the console's
            # consumption-independent transcript tail.
            entries = _menu_entries(
                console.transcript.decode("utf-8", "replace"))
            if MENU_ARCH_ENTRY not in entries:
                raise ArchIdentityError(
                    MENU_NEVER_RENDERED_FAILURE, check="arch-joined")
            digit = str(entries.index(MENU_ARCH_ENTRY) + 1)
            _send_raw(
                console, digit.encode("ascii"), "arch-menu-entry-selected")
            facts["entry_selected"] = digit
            # The digit key only moves the highlight (and stops the
            # countdown); Enter is what boots the entry.
            committed = _commit_menu_entry(
                console, entries, menu_pattern,
                step_timeout=min(MENU_COMMIT_TIMEOUT, handoff_timeout))
            facts["entry_committed"] = committed
            console.timeout = handoff_timeout
            try:
                if not committed:
                    raise SerialAutomationError(
                        "Arch entry was never committed with Enter")
                console._wait(handoff_pattern, "arch-handoff-observed")
            except SerialAutomationError as error:
                if attempt + 1 >= max(1, attempts):
                    raise ArchIdentityError(
                        MENU_WINDOW_MISSED_FAILURE if committed
                        else MENU_NOT_COMMITTED_FAILURE,
                        check="arch-joined",
                    ) from error
                # The Windows default won the window; never wait it out.
                facts["menu_retries"] = int(facts.get("menu_retries", 0)) + 1
                console.buffer = b""
                reset()
                console.events.append("arch-workstation-power-cycled")
                continue
            facts["handoff_seen"] = True
            return
    finally:
        console.timeout = original


def await_domain_online(
    console, facts: dict[str, object], *,
    timeout: float | None = DOMAIN_ONLINE_TIMEOUT,
) -> None:
    """Observe the guest's domain-online gate, bounded and fail-closed.

    Strictly between the in-run join and the login.  Gate 7 installs a one-shot
    unit ordered ``After=sssd.service`` and ``Before=systemd-user-sessions.
    service`` that waits for SSSD's AD backend to be usable and prints
    ``DOMAIN_ONLINE_MARKER``; because ``serial-getty@ttyS0`` is ordered after
    user sessions, the login prompt cannot render until that unit finished.  So
    this wait is not a sleep and not a readiness poll -- it reads the guest's
    own secret-free proof, and a miss is its OWN named failure rather than a
    login refusal, because the credential has not been sent yet.
    """
    from .serial_automation import SerialAutomationError
    from homelab.workstations.arch_second import DOMAIN_ONLINE_MARKER

    marker = re.escape(DOMAIN_ONLINE_MARKER.encode("ascii"))
    original = console.timeout
    if timeout is not None:
        console.timeout = timeout
    try:
        try:
            console._wait(marker, "arch-domain-online-observed")
        except SerialAutomationError as error:
            raise ArchIdentityError(
                DOMAIN_ONLINE_FAILURE, check="arch-joined") from error
        facts["domain_online_observed"] = True
    finally:
        console.timeout = original


def login_operator(
    console, facts: dict[str, object], *,
    attempts: int = LOGIN_ATTEMPTS,
    getty_timeout: float | None = None,
) -> None:
    """Log the staged operator in on the ttyS0 getty, fail-closed.

    The username is sent at the getty prompt; ``login``(1) reads the
    credential with terminal echo disabled, so the staged secret never
    enters the serial transcript.  A getty that never appears and a login
    that stays refused are distinct, named failures.
    """
    from .serial_automation import SerialAutomationError

    if console.password is None:
        raise ArchIdentityError(
            "operator credential is unavailable for the getty login",
            check="arch-joined")
    login_prompt = rb"(?:^|\n)[\w.-]+ login:"
    original = console.timeout
    if getty_timeout is not None:
        console.timeout = getty_timeout
    try:
        try:
            console._wait(login_prompt, "arch-getty-observed")
        except SerialAutomationError as error:
            raise ArchIdentityError(
                GETTY_NEVER_APPEARED_FAILURE, check="arch-joined") from error
        facts["getty_seen"] = True
        for attempt in range(max(1, attempts)):
            console._send(
                OPERATOR_PRINCIPAL.encode("ascii"),
                "arch-login-username-sent")
            try:
                console._wait(
                    rb"(?:^|\n)Password:", "arch-login-password-prompt")
                console._send(console.password, "arch-login-password-sent")
                outcome = console._wait(
                    rb"(?:^|\n)(?:(Login incorrect)|[^\n]*\$[ \t]*$)",
                    "arch-login-outcome")
            except SerialAutomationError as error:
                raise ArchIdentityError(
                    LOGIN_REFUSED_FAILURE, check="arch-joined") from error
            if outcome.group(1) is None:
                facts["login_completed"] = True
                return
            if attempt + 1 >= max(1, attempts):
                break
            try:
                console._wait(login_prompt, "arch-getty-observed")
            except SerialAutomationError as error:
                raise ArchIdentityError(
                    LOGIN_REFUSED_FAILURE, check="arch-joined") from error
        raise ArchIdentityError(LOGIN_REFUSED_FAILURE, check="arch-joined")
    finally:
        console.timeout = original


def elevation_command(token: str) -> tuple[bytes, bytes, bytes, bytes]:
    """The single echo-suppressed ``sudo -S`` elevation, token-scoped.

    Returns ``(command, ready_marker, password_prompt, failure_prefix)``.

    Two independent protections, both learned from the 2026-08-14 live run:

    * Echo is provably off before the credential is written -- the ready
      marker only prints once ``stty -echo`` succeeded.  That is necessary but
      NOT sufficient, because the shell prints it before ``sudo`` has even
      been exec'd.
    * ``sudo`` is given its own token-scoped prompt with ``-p``, so the
      credential can be written when *the reader* asks for it rather than when
      the shell says it is about to start one.  ``sudo``(8) writes that prompt
      after it has disabled echo on stdin, so a credential written in response
      to it cannot be discarded by the reader's terminal setup.  This is the
      discipline ``login``(1) and ``passwd``(1) are already driven with here,
      and the one ``serial_automation.SerialAutomation.run`` has always used
      for the Controller preflight.

    ``sudo -S`` reads the credential from stdin and writes the prompt to
    stderr; both are this one serial console.  The failure prefix only ever
    carries an exit code -- never a secret.  The command deliberately never
    uses ``sudo -n``: the gate-7 operator rule is passworded, and proving a
    passworded elevation is the whole point of the check.
    """
    tok = token.encode("ascii")
    ready = b"__TELOS_ARCH_SUDO_READY_" + tok + b"__"
    prompt = b"__TELOS_ARCH_SUDO_PROMPT_" + tok + b"__"
    failed = b"__TELOS_ARCH_SUDO_RC_" + tok + b"="
    command = (
        b"stty -echo && printf '\\n" + ready + b"\\n' && "
        b"sudo -k -S -p '" + prompt + b"' -i; __telos_rc=$?; stty echo; "
        b"printf '\\n" + failed + b"%s\\n' \"$__telos_rc\""
    )
    return command, ready, prompt, failed


def sudo_prompt_pattern(prompt: bytes) -> bytes:
    """Match sudo asking for the operator's password, once per ask.

    The token-scoped ``-p`` prompt is the expected form.  ``pam_unix`` supplies
    its own ``Password:`` prompt and sudo only substitutes ``-p`` for prompts
    it recognises as that default, so the bare prompt is accepted as well: a
    localised or otherwise unrecognised PAM prompt must still gate the write
    rather than time out and waste a live run.  Neither alternative can
    collide inside this window -- the echoed command line, which does contain
    the marker literal, is consumed by the ready-marker wait before this one
    runs, and the only other output here is sudo's lecture.
    """
    return (rb"(?:" + re.escape(prompt) + rb"|(?:^|\n)Password:[ \t]*)")


def root_proof_marker(token: str) -> bytes:
    """The token-scoped prefix the elevated shell prints ``id -u`` behind."""
    return b"__TELOS_ARCH_ROOT_" + token.encode("ascii") + b"="


def elevation_outcome_pattern(token: str) -> bytes:
    """Every elevation verdict, each in its own named group.

    ``uid``/``rc`` are token-scoped markers and ``refused`` is sudo's own
    re-prompt, so all three are verdicts nothing else on the console can
    forge.  ``root_shell`` is the one shape-based alternative and it is NOT a
    verdict: it only says "a root prompt is on the console, ask for the
    proof", so a guest whose root ``PS1`` differs still converges through the
    bounded second ask.

    Its predecessor accepted any line ending in ``#``, which sudo's default
    lecture ("    #1) Respect the privacy of others.") satisfies whenever a
    serial read lands on the ``#`` -- exactly what desynchronised the
    2026-08-14 live run 18ms after the credential was written.  Tests pin this
    pattern against that lecture at every read boundary.
    """
    _command, _ready, prompt, failed = elevation_command(token)
    proof = root_proof_marker(token)
    return (
        rb"(?:^|\n)" + re.escape(proof) + rb"(?P<uid>[0-9]+)\s*(?:\n|$)"
        rb"|(?:^|\n)" + re.escape(failed) + rb"(?P<rc>[0-9]+)\s*(?:\n|$)"
        rb"|(?P<refused>" + sudo_prompt_pattern(prompt) + rb")"
        rb"|(?P<root_shell>(?:^|\n)\[root@[^\n]*\]#[ \t]*)"
    )


def elevate_operator(
    console, facts: dict[str, object], *,
    timeout: float | None = None,
    proof_timeout: float | None = SUDO_PROOF_TIMEOUT,
) -> None:
    """Elevate the logged-in operator to a root shell for the probes.

    The gate-7 sudoers rule is passworded, so the staged credential is fed
    once through ``sudo -S`` -- written only after sudo's own prompt is on the
    console, with terminal echo already provably off -- and the root shell is
    proven with a token-scoped ``id -u`` echo before any probe runs.

    Every stop names its own layer instead of collapsing into one message,
    because the 2026-08-14 run left nothing behind that could separate them:

    * no ready marker -> the operator shell, and the credential was never
      written (``SUDO_ECHO_NOT_SUPPRESSED_FAILURE``);
    * no prompt -> sudoers/policy, and the credential was never written
      (``SUDO_PROMPT_MISSING_FAILURE``);
    * a second prompt -> sudo read the credential and its PAM stack refused it
      (``SUDO_CREDENTIAL_REFUSED_FAILURE``); the run aborts on that second
      prompt rather than feeding it, so pam_faillock records one failure and
      the stock ``deny=3`` keeps two in hand for the later proofs;
    * an exit code -> sudo gave up, and its own code is retained
      (``SUDO_EXITED_FAILURE``);
    * a non-zero uid -> the shell is not root (``SUDO_ROOT_UNPROVEN_FAILURE``).

    The root proof is asked for at most twice, each ask bounded by
    ``proof_timeout``: an ask typed into a login shell that has not started
    reading yet is the one race the prompt gate cannot cover, and a second
    bounded ask costs seconds where a lost one costs a whole live run.
    """
    from .serial_automation import SerialAutomationError

    if console.password is None:
        raise ArchIdentityError(
            "operator credential is unavailable for sudo elevation",
            check="arch-joined")
    command, ready, prompt, _failed = elevation_command(console.token)
    asked = sudo_prompt_pattern(prompt)
    proof_command = (
        b"printf '\\n" + root_proof_marker(console.token) + b"%s\\n' "
        b"\"$(id -u)\"")
    outcome_pattern = elevation_outcome_pattern(console.token)
    original = console.timeout
    if timeout is not None:
        console.timeout = timeout
    try:
        console._send(command, "arch-sudo-command-sent")
        try:
            console._wait(
                rb"(?:^|\n)" + re.escape(ready) + rb"\s*(?:\n|$)",
                "arch-sudo-echo-off")
        except SerialAutomationError as error:
            raise ArchIdentityError(
                SUDO_ECHO_NOT_SUPPRESSED_FAILURE,
                check="arch-joined") from error
        facts["sudo_echo_suppressed"] = True
        # The credential is written only in response to this.
        try:
            console._wait(asked, "arch-sudo-password-prompt")
        except SerialAutomationError as error:
            raise ArchIdentityError(
                SUDO_PROMPT_MISSING_FAILURE, check="arch-joined") from error
        facts["sudo_prompt_seen"] = True
        console._send(console.password, "arch-sudo-password-sent")
        facts["sudo_credential_sent"] = True
        # One wait loop, three exits.  A verdict marker or a re-prompt settles
        # the elevation; a root-shell prompt (or a silence the recognised
        # shapes cannot explain) means "ask for the proof"; a third such pass
        # is the bounded umbrella failure.
        console.timeout = console.timeout if proof_timeout is None else min(
            console.timeout, proof_timeout)
        while True:
            silence: SerialAutomationError | None = None
            try:
                settled = console._wait(outcome_pattern, "arch-sudo-outcome")
            except SerialAutomationError as error:
                settled, silence = None, error
            if settled is not None and settled.group("root_shell") is None:
                outcome = settled
                break
            if settled is not None:
                facts["sudo_root_shell_seen"] = True
            asks = int(facts["sudo_proof_asks"] or 0)
            if asks >= SUDO_PROOF_ASKS:
                raise ArchIdentityError(
                    SUDO_ELEVATION_FAILURE, check="arch-joined") from silence
            console._send(proof_command, "arch-root-proof-requested")
            facts["sudo_proof_asks"] = asks + 1
        if outcome.group("refused") is not None:
            facts["sudo_credential_refused"] = True
            raise ArchIdentityError(
                SUDO_CREDENTIAL_REFUSED_FAILURE, check="arch-joined")
        if outcome.group("rc") is not None:
            facts["sudo_returncode"] = int(outcome.group("rc"))
            raise ArchIdentityError(
                SUDO_EXITED_FAILURE, check="arch-joined")
        facts["sudo_uid"] = int(outcome.group("uid"))
        if facts["sudo_uid"] != 0:
            raise ArchIdentityError(
                SUDO_ROOT_UNPROVEN_FAILURE, check="arch-joined")
        facts["sudo_elevated"] = True
    finally:
        console.timeout = original


def rescue_password_command(token: str) -> tuple[bytes, bytes, bytes]:
    """The single echo-suppressed ``passwd local-rescue``, token-scoped.

    Returns ``(command, ready_marker, result_prefix)``.  Mirrors
    ``elevation_command`` here and ``AutomatedSerial.run`` in
    ``automated_controller`` (which sets the Controller's own break-glass
    password the same way): ``passwd``(1) reads both prompts with terminal
    echo already disabled, and the explicit ``stty -echo`` in front makes that
    provable *before* the credential is written -- the ready marker only prints
    once echo is off.  The result prefix only ever carries an exit code.
    """
    tok = token.encode("ascii")
    ready = b"__TELOS_ARCH_RESCUE_READY_" + tok + b"__"
    result = b"__TELOS_ARCH_RESCUE_RC_" + tok + b"="
    command = (
        b"stty -echo && printf '\\n" + ready + b"\\n' && "
        b"LC_ALL=C passwd " + RESCUE_PRINCIPAL.encode("ascii")
        + b"; __telos_rc=$?; stty echo; "
        b"printf '\\n" + result + b"%s\\n' \"$__telos_rc\""
    )
    return command, ready, result


def rescue_prompt_pattern() -> bytes:
    """Match whichever PAM module asks for the new break-glass password.

    THE 2026-08-14 defect, and it is a different one from the elevation's: this
    exchange did gate its write on the reader's own prompt, and still stopped,
    because it gated on the wrong WORDING.  Two modules can ask on this disk
    and they do not use the same words:

    * ``pam_unix`` asks ``New password:`` / ``Retype new password:``;
    * ``pam_sss`` asks ``New Password:`` / ``Reenter new Password:``.

    Gate 7 writes ``password [success=1 default=ignore] pam_sss.so`` ahead of
    ``pam_unix`` in ``/etc/pam.d/system-auth``, and Arch's shadow ships
    ``/etc/pam.d/passwd`` as ``password include system-auth``, so ``pam_sss``
    asks FIRST -- for a files-only account it cannot serve, because it only
    discovers that after it has collected the value.  Run
    ``run-20260814T155301Z-4b21f9334459`` therefore sat out its whole 60s
    budget with ``New Password: `` on the console while waiting for the
    lowercase ``pam_unix`` wording, and stopped without writing anything.  The
    Controller path (``serial_automation``) matches the lowercase form and has
    always worked because bootstrap-dc has no ``pam_sss`` in its password
    stack.

    Both wordings are accepted, case-insensitively, and each alternative is
    anchored to a line start: without that anchor the confirmation prompt
    (which literally contains ``new Password:``) would satisfy the
    first-prompt alternative and the two would be indistinguishable.  Neither
    alternative may consume a newline, so a prompt is only ever matched on the
    line it was printed on, and the trailing space is optional so a read that
    lands on the colon still gates the write -- ``passwd`` is already reading
    by then.
    """
    return (
        rb"(?:^|\n)(?P<new>(?i:new[ \t]+password:)[ \t]*)"
        rb"|(?:^|\n)(?P<retype>"
        rb"(?i:(?:retype|reenter)[ \t]+new[ \t]+password:)[ \t]*)"
    )


def rescue_outcome_pattern(token: str) -> bytes:
    """Every outcome of the ``passwd local-rescue`` exchange, in named groups.

    ``rc`` is the token-scoped exit-code marker and is the only verdict; both
    it and ``diag`` require a real newline, so a serial read that lands
    mid-line can never be mistaken for a complete one -- the mistake that cost
    the elevation a live run.  ``new``/``retype`` are not verdicts: they say
    "a reader is asking, write the credential once".
    """
    _command, _ready, result = rescue_password_command(token)
    return (
        rb"(?:^|\n)" + re.escape(result) + rb"(?P<rc>[0-9]+)[ \t\r]*\n"
        rb"|(?:^|\n)passwd:[ \t]*(?P<diag>[^\n]*?)[ \t\r]*\n"
        rb"|" + rescue_prompt_pattern()
    )


def set_rescue_password(
    console, facts: dict[str, object], credential: bytes, *,
    timeout: float | None = None,
    prompt_timeout: float | None = RESCUE_PROMPT_TIMEOUT,
    writes: int = RESCUE_PASSWORD_WRITES,
) -> None:
    """Set the break-glass password once from the elevated root shell.

    Gate 7 installs ``local-rescue`` with a *disabled* password (``useradd``
    with no ``-p`` leaves ``!`` in ``/etc/shadow``, so ``passwd -S`` reports
    ``L``) and nothing else sets it, so the ``arch-local-rescue`` probe --
    which requires ``passwd -S`` to report ``P`` -- could only ever fail, even
    after the login works.  ``passwd``(1) is the right tool for exactly that
    disabled state: root's change replaces the whole field rather than adding
    to it, so the set password clears the disable and reports ``P``.
    ``identity_lifecycle.json`` gives the principal ``domain_role: none``, so
    no Controller-staged account supplies the credential; the caller generates
    it per run in memory, and it is never retained on the boundary, in the
    evidence, or in the transcript.

    The exchange is prompt-driven, not step-scripted: one bounded wait loop
    answers each prompt the password stack prints -- see
    ``rescue_prompt_pattern`` for why the count is not knowable in advance --
    and settles only on ``passwd``'s own token-scoped exit code.  Nothing is
    written before echo is provably off, nothing is written that a reader did
    not just ask for, every wait is bounded by ``prompt_timeout``, and each
    distinguishable stop names its own layer.
    """
    from .serial_automation import SerialAutomationError

    if not credential or b"\n" in credential or b"\r" in credential:
        raise ArchIdentityError(
            "the local-rescue credential must be one non-empty line",
            check="arch-local-rescue")
    command, ready, _result = rescue_password_command(console.token)
    outcome_pattern = rescue_outcome_pattern(console.token)
    original = console.timeout
    if timeout is not None:
        console.timeout = timeout
    try:
        console._send(command, "arch-rescue-command-sent")
        # The ready marker prints only behind a successful ``stty -echo``, so
        # this wait is what makes echo-off provable before any write.
        try:
            console._wait(
                rb"(?:^|\n)" + re.escape(ready) + rb"\s*(?:\n|$)",
                "arch-rescue-echo-off")
        except SerialAutomationError as error:
            raise ArchIdentityError(
                RESCUE_ECHO_NOT_SUPPRESSED_FAILURE,
                check="arch-local-rescue") from error
        facts["rescue_echo_suppressed"] = True
        console.timeout = console.timeout if prompt_timeout is None else min(
            console.timeout, prompt_timeout)
        written = 0
        while True:
            try:
                settled = console._wait(outcome_pattern, "arch-rescue-outcome")
            except SerialAutomationError as error:
                # Name the layer by how far the exchange got.  A silence
                # before the first ask means nothing was written at all.
                if not written:
                    stop = RESCUE_PROMPT_MISSING_FAILURE
                elif written == 1:
                    stop = RESCUE_CONFIRM_PROMPT_MISSING_FAILURE
                else:
                    stop = RESCUE_PASSWORD_FAILURE
                raise ArchIdentityError(
                    stop, check="arch-local-rescue") from error
            if settled.group("rc") is not None:
                break
            if settled.group("diag") is not None:
                diagnostic = settled.group("diag").strip()
                if diagnostic == RESCUE_UPDATED_DIAGNOSTIC:
                    facts["rescue_password_updated"] = True
                    console.events.append("arch-rescue-password-updated")
                    continue
                facts["rescue_credential_rejected"] = True
                console.events.append("arch-rescue-credential-rejected")
                raise ArchIdentityError(
                    RESCUE_CREDENTIAL_REJECTED_FAILURE,
                    check="arch-local-rescue")
            if settled.group("new") is not None:
                facts["rescue_prompt_seen"] = True
                console.events.append("arch-rescue-new-password-prompt")
            else:
                facts["rescue_confirm_prompt_seen"] = True
                console.events.append("arch-rescue-password-confirm-prompt")
            # A stack that is still asking past the budget is refusing the
            # value, not asking again in a new module's words.
            if written >= writes:
                facts["rescue_credential_rejected"] = True
                console.events.append("arch-rescue-credential-rejected")
                raise ArchIdentityError(
                    RESCUE_CREDENTIAL_REJECTED_FAILURE,
                    check="arch-local-rescue")
            console._send(credential, "arch-rescue-password-sent")
            written += 1
            facts["rescue_credential_sent"] = True
            facts["rescue_credential_writes"] = written
        console.events.append("arch-rescue-result")
        facts["rescue_returncode"] = int(settled.group("rc"))
        if facts["rescue_returncode"] != 0:
            raise ArchIdentityError(
                RESCUE_PASSWD_EXITED_FAILURE, check="arch-local-rescue")
        if not written:
            # ``passwd`` cannot have set anything it never asked for, whatever
            # it exited with; refuse to record a password that does not exist.
            raise ArchIdentityError(
                RESCUE_PROMPT_MISSING_FAILURE, check="arch-local-rescue")
        facts["rescue_password_set"] = True
    finally:
        console.timeout = original


class ArchIdentityBoundary:
    """Live loopback session: fabric, disposable Samba AD, joined Arch guest.

    This is the real, unattended path. It boots a loopback userspace switch
    and gateway in identity mode (the gateway's DHCP answers point DNS at the
    Controller), converges the disposable Samba AD Controller with the same
    gate-6 machinery the Windows identity lane uses (disposable raw copy of
    the canonical bootstrap-dc state under its ``.simulation.lock`` flock,
    in-guest verified seed install, offline factory convergence over the
    private serial console), boots the joined Arch workstation from the
    bundle disk, and hands its serial console to ``ArchIdentityDrive``.

    Every heavy dependency is imported inside the start path so importing
    this module (for the producer/judge unit tests) never needs QEMU. The
    small ``_spawn``/``_audit``/``_wait_switch_port``/``_connect_qmp`` seams
    exist so tests can prove the wiring without booting anything.
    """

    #: Gate 7 must ship these on the joined disk for the live drive to work.
    GATE7_CONTRACT = GATE7_CONTRACT

    def __init__(
        self, bundle: ArchIdentityBundle, *,
        duration: float = DEFAULT_DURATION,
    ) -> None:
        self.bundle = bundle
        self.duration = duration
        #: Overridable seed media path; defaults to the repository seed ISO.
        self.seed_iso: Path | None = None
        self._runtime: Path | None = None
        self._qmp_root: Path | None = None
        self._port: int | None = None
        self._processes: dict[str, object] = {}
        self._controller_console = None
        self._controller_disk = None
        self._controller_qmp = None
        self._factory_media: Path | None = None
        self._channel: SerialChannel | None = None
        self._controller_online = False
        self._watchdog = None
        self._expired = False
        #: Per-run synthetic principal credentials, memory-only.  They are
        #: staged on the disposable Controller (whose copy is destroyed at
        #: stop) and dropped from memory during teardown; they never reach
        #: evidence or logs.
        self._principals: dict[str, str] = {}
        self._workstation_console = None
        self._workstation_qmp = None
        #: The run-built one-use join ISO.  ``ArchJoinMedia`` destroys it by
        #: exact inode in the happy path; teardown sweeps a leftover.
        self._join_iso: Path | None = None
        self._boot_facts: dict[str, object] = new_boot_facts()

    # -- test seams (real implementations are trivially thin) ---------------

    def _spawn(self, role: str, command: list[str], *, pass_fds=(),
               stdio: bool = False):  # pragma: no cover - live path
        import subprocess

        streams = subprocess.PIPE if stdio else subprocess.DEVNULL
        process = subprocess.Popen(
            command, stdin=streams,
            stdout=subprocess.PIPE if stdio else subprocess.DEVNULL,
            stderr=subprocess.STDOUT, pass_fds=pass_fds)
        self._processes[role] = process
        return process

    def _audit(self, role: str, pid: int, **kw) -> None:  # pragma: no cover
        from .simulated_topology import audit_live_process

        audit_live_process(pid, role, **kw)

    def _wait_switch_port(self, name: str, mac: str) -> None:  # pragma: no cover
        from .factory_runner import wait_for_switch_port

        assert self._runtime is not None
        wait_for_switch_port(self._runtime / "switch.jsonl", name, mac)

    def _connect_qmp(self, path: Path, pid: int):  # pragma: no cover
        import time

        from .windows_gui import QmpClient

        deadline = time.monotonic() + 30.0
        while True:
            try:
                return QmpClient.connect(
                    path, timeout=5.0, expected_peer_pid=pid)
            except (OSError, RuntimeError):
                if time.monotonic() >= deadline:
                    raise ArchIdentityError(
                        "Controller QMP authentication failed",
                        check="controller-ready")
                time.sleep(0.1)

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        # run_lifecycle only calls stop() once start() has returned, so a
        # partial start must tear down what it already brought up.
        try:
            self._start_all()
        except BaseException:
            try:
                self.stop()
            except BaseException:
                pass
            raise

    def _start_all(self) -> None:
        import tempfile
        import threading

        runtime = Path(tempfile.mkdtemp(prefix="telos-arch-identity-"))
        runtime.chmod(0o700)
        self._runtime = runtime
        self._watchdog = threading.Timer(self.duration, self._expire)
        self._watchdog.daemon = True
        self._watchdog.start()
        self._start_fabric()
        self._start_controller()
        self._start_workstation()

    def _expire(self) -> None:
        """Wall-clock bound: kill the boundary so every console wait fails."""
        self._expired = True
        for process in list(self._processes.values()):
            try:
                process.terminate()  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001 - best-effort expiry teardown
                pass

    def _start_fabric(self) -> None:
        import socket

        from .factory_runner import (
            GATEWAY_MAC, gateway_command, switch_command)
        from .simulated_topology import MACS

        assert self._runtime is not None
        listener = socket.socket()
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 0))
            listener.listen(3)
            self._port = int(listener.getsockname()[1])
            self._spawn(
                "switch",
                switch_command(
                    listener.fileno(), self._runtime / "switch.jsonl",
                    accept_timeout=1200, idle_timeout=self.duration + 60,
                    identity_mode=True),
                pass_fds=(listener.fileno(),))
        finally:
            listener.close()
        self._spawn(
            "gateway",
            gateway_command(
                self._port, controller_mac=MACS["controller"],
                identity_mode=True))
        self._wait_switch_port("gateway", GATEWAY_MAC)

    def _start_controller(self) -> None:
        """Boot and converge the disposable Samba AD Controller.

        Same canonical gate-6 state and machinery as the Windows identity
        lane: ``DisposableBootDisk`` copies the canonical bootstrap-dc disk
        (taking the ``.simulation.lock`` flock through its overlay guard),
        the signed seed is verified and installed in-guest, and the offline
        factory convergence runs over the private serial console.  Both media
        are attached and provably released over QMP so the disposable guest
        never retains the secret-bearing convergence ISO.
        """
        import secrets as secrets_module
        import tempfile

        from .automated_controller import DisposableBootDisk
        from .bootstrap_dc import paths
        from .serial_automation import SerialAutomation, SerialAutomationError
        from .simulated_topology import MACS, controller_command

        assert self._runtime is not None and self._port is not None
        try:
            canonical = paths(self.bundle.controller_state)
            self._controller_disk = DisposableBootDisk(
                canonical["disk"], canonical["vars"],
                run_root=self._runtime / "controller").prepare()
            self._qmp_root = Path(
                tempfile.mkdtemp(prefix="telos-arch-id-qmp-"))
            self._qmp_root.chmod(0o700)
            qmp_path = self._qmp_root / "controller.qmp"
            command = controller_command(
                self.bundle.controller_state,
                self._controller_disk.disk, self._controller_disk.vars,
                self._port, disk_format="raw")
            command = command + [
                "-qmp", f"unix:{qmp_path},server=on,wait=off",
                "-device", "virtio-scsi-pci,id=identityfactorybus",
            ]
            process = self._spawn("controller", command, stdio=True)
            self._audit(
                "controller", process.pid,
                disposable_disk=self._controller_disk.disk,
                disposable_vars=self._controller_disk.vars,
                forbidden_paths=(canonical["disk"], canonical["vars"]),
                qmp_socket=qmp_path)
            password = (
                "Synthetic-Controller-"
                + secrets_module.token_urlsafe(24) + "-47!"
            ).encode("ascii")
            console = SerialAutomation(
                process.stdout, process.stdin, password, timeout=120.0)
            try:
                console.establish_disposable_controller_session()
            except SerialAutomationError as error:
                console.release_password()
                raise ArchIdentityError(
                    "Controller session initialization failed",
                    check="controller-ready") from error
            self._controller_console = console
            self._wait_switch_port("controller", MACS["controller"])
            self._controller_qmp = self._connect_qmp(qmp_path, process.pid)
            self._install_controller_seed(console)
            self._converge_controller(console)
            # Controller up and converged -> principals staged -> only then
            # may the workstation boot (its SSSD login needs them).
            self._stage_principals()
            self._controller_online = True
        except ArchIdentityError:
            raise
        except Exception as error:
            raise ArchIdentityError(
                "Controller bring-up failed: " + type(error).__name__,
                check="controller-ready") from error

    def _stage_principals(self) -> None:
        """Stage the per-run synthetic principals on the disposable Controller.

        Mirrors the Windows lane's ``windows_identity_adapter``
        ``stage_principals``: the principal protocol runs over the already
        authenticated Controller console (``ControllerPrincipalSerial`` with
        its ``console`` swapped for the shared session), the POSIX contract
        is ``controller_principals.POSIX_ALLOCATION``, and each credential is
        generated in memory with the Windows lane's shape (locale-independent
        prefix plus 128 bits of entropy).  Credentials are echo-suppressed on
        the wire by the principal protocol and never recorded; the Controller
        copy is disposable, so teardown drops the in-memory values rather
        than driving a serial destroy against a possibly-stopped guest.
        """
        import secrets as secrets_module

        from .controller_principals import (
            ControllerPrincipalError,
            ControllerPrincipalSerial,
            POSIX_ALLOCATION,
        )

        process = self._processes.get("controller")
        console = self._controller_console
        if process is None or console is None:
            raise ArchIdentityError(
                "Controller console is unavailable for principal staging",
                check="controller-ready")
        values = {
            name: "T7a" + secrets_module.token_hex(16)
            for name in POSIX_ALLOCATION["users"]
        }
        serial = ControllerPrincipalSerial(
            process.stdout, process.stdin, timeout=120.0)  # type: ignore[attr-defined]
        serial.console = console
        try:
            serial.stage(values)
        except ControllerPrincipalError as error:
            values.clear()
            raise ArchIdentityError(
                "Controller principal staging failed",
                check="controller-ready") from error
        self._principals = values

    def _install_controller_seed(self, console) -> None:
        """Attach, verify, install, and provably release the signed seed."""
        from .factory_runner import DEFAULT_SEED_ISO

        seed = self.seed_iso
        if seed is None:
            seed = Path(__file__).resolve().parents[2] / DEFAULT_SEED_ISO
        if (
            seed.is_symlink()
            or not seed.is_file()
            or seed.stat().st_mode & 0o022
        ):
            raise ArchIdentityError(
                "Controller seed media has an unsafe identity",
                check="controller-ready")
        qmp = self._controller_qmp
        assert qmp is not None
        qmp.execute("blockdev-add", {
            "node-name": "identityseedfile",
            "driver": "file",
            "filename": str(seed.resolve()),
        })
        qmp.execute("blockdev-add", {
            "node-name": "identityseednode",
            "driver": "raw",
            "read-only": True,
            "file": "identityseedfile",
        })
        qmp.execute("device_add", {
            "driver": "scsi-cd",
            "id": "identityseedcd",
            "drive": "identityseednode",
            "bus": "identityfactorybus.0",
        })
        console.install_offline_controller_dependencies()
        qmp.execute("device_del", {"id": "identityseedcd"})
        qmp.await_device_deleted("identityseedcd", timeout=30.0)
        qmp.execute("blockdev-del", {"node-name": "identityseednode"})
        qmp.execute("blockdev-del", {"node-name": "identityseedfile"})

    def _converge_controller(self, console) -> None:
        """Run the offline factory convergence and release its media."""
        import secrets as secrets_module

        from .controller_factory import FactoryBundle

        assert self._runtime is not None
        nonce = secrets_module.token_hex(32)
        media_root = self._runtime / "controller-media"
        media_root.mkdir(mode=0o700)
        bundle = FactoryBundle(
            Path(__file__).resolve().parents[2],
            media_root / "controller-convergence.iso",
            authorization_nonce=nonce)
        qmp = self._controller_qmp
        assert qmp is not None
        try:
            bundle.build()
            self._factory_media = bundle.output
            qmp.execute("blockdev-add", {
                "node-name": "identityfactoryfile",
                "driver": "file",
                "filename": str(bundle.output.resolve()),
            })
            qmp.execute("blockdev-add", {
                "node-name": "identityfactorynode",
                "driver": "raw",
                "read-only": True,
                "file": "identityfactoryfile",
            })
            qmp.execute("device_add", {
                "driver": "scsi-cd",
                "id": "identityfactorycd",
                "drive": "identityfactorynode",
                "bus": "identityfactorybus.0",
            })
            console.converge_disposable_controller(
                FactoryBundle.guest_command(nonce))
            qmp.execute("device_del", {"id": "identityfactorycd"})
            qmp.await_device_deleted("identityfactorycd", timeout=30.0)
            qmp.execute("blockdev-del", {"node-name": "identityfactorynode"})
            qmp.execute("blockdev-del", {"node-name": "identityfactoryfile"})
        finally:
            bundle.password = ""
        bundle.output.unlink(missing_ok=True)
        self._factory_media = None
        media_root.rmdir()

    def _join_workstation(self) -> None:
        """Join this run's freshly provisioned domain from one-use media.

        The premise gate 8 used to run on -- "the gate-7 disk arrives joined"
        -- is false and cannot be made true: this run provisions a brand-new
        domain (fresh SID, fresh krbtgt, empty SAM), so the machine account the
        gate-7 install created is not in it, and ``controller_principals``
        stages only the three *user* roles.  The 2026-08-14 live run showed the
        exact consequence: the whole boot chain worked and ``operator`` was
        refused three times, because SSSD could not bind with a host keytab no
        directory knows and offline auth needs a cached credential that cannot
        exist on a fresh overlay.  No retry count or delay fixes that.

        So the join happens here, in-run, with the machinery gates 5-7 already
        prove: a one-use ``tj-<hex>`` principal staged on the freshly converged
        Controller over the *same authenticated console* ``_stage_principals``
        uses, sealed into a run-built mode-0600 ``TELOS_JOIN`` ISO, attached
        read-only into the cold-plugged empty join root port, destroyed by
        inode as soon as the guest prints the consumed marker, and the DC-side
        account destroyed with proof whether this succeeds or fails.  The guest
        side is the one-shot boot unit gate 7 installs and enables; the host
        only waits for its two secret-free markers.
        """
        from .arch_install_run import JOIN_ISO_NAME, run_join_install
        from .controller_join_material import (
            ControllerJoinSerial, OneUseDomainJoinMaterial)
        from homelab.workstations.arch_second import (
            JOIN_MEDIA_CONSUMED_MARKER, JOIN_VERIFIED_MARKER)

        console = self._workstation_console
        controller = self._controller_console
        controller_process = self._processes.get("controller")
        workstation_process = self._processes.get("workstation")
        qmp = self._workstation_qmp
        if (console is None or controller is None or qmp is None
                or controller_process is None or workstation_process is None):
            raise ArchIdentityError(
                "the in-run join needs both live consoles and the workstation "
                "QMP channel", check="arch-joined")
        realm = self.bundle.realm
        if not realm:
            raise ArchIdentityError(
                "the authorized Kerberos realm is unavailable for the in-run "
                "join", check="arch-joined")
        assert self._runtime is not None
        iso = self._runtime / JOIN_ISO_NAME
        self._join_iso = iso
        facts = self._boot_facts
        media_facts: dict = {}

        # Exactly the seam _stage_principals and arch_install_run use: the
        # one-use principal protocol reuses the ALREADY AUTHENTICATED
        # Controller console rather than opening a second reader on it.
        join_serial = ControllerJoinSerial(
            controller_process.stdout, controller_process.stdin,  # type: ignore[attr-defined]
            timeout=CONSOLE_READY_TIMEOUT)
        join_serial.console = controller
        material = OneUseDomainJoinMaterial(
            realm, stage=join_serial.stage, destroy=join_serial.destroy)
        consumed = re.escape(JOIN_MEDIA_CONSUMED_MARKER.encode("ascii"))
        verified = re.escape(JOIN_VERIFIED_MARKER.encode("ascii"))

        def consume(values: Mapping[str, str]) -> tuple[str, dict]:
            def drive(
                attach_media: Callable[[], None],
                consume_media: Callable[[], None],
            ) -> str:
                attach_media()
                # The guest prints this once it holds the credential in its
                # mode-0600 tmpfs file and has unmounted the media, so the
                # media is destroyed before the join itself runs.
                console._wait(consumed, "arch-join-media-consumed")
                consume_media()
                console._wait(verified, "arch-join-verified")
                return bytes(
                    getattr(console, "transcript", b"")).decode(
                        "utf-8", "replace")

            return run_join_install(
                material=values, iso=iso, qmp=qmp,
                qemu_pid=workstation_process.pid,  # type: ignore[attr-defined]
                drive=drive, facts=media_facts)

        original = console.timeout
        console.timeout = JOIN_TIMEOUT
        try:
            _consumed, destruction = material.use(consume)
        except ArchIdentityError:
            raise
        except Exception as error:
            raise ArchIdentityError(
                JOIN_FAILURE + "; " + type(error).__name__,
                check="arch-joined") from error
        finally:
            console.timeout = original
            # Secret-free lifecycle booleans, retained on failure too so a
            # future run reads off exactly how far the join got.
            facts["join_media_built"] = bool(media_facts.get("built"))
            facts["join_media_attached"] = bool(media_facts.get("attached"))
            facts["join_media_consumed"] = bool(media_facts.get("consumed"))
            facts["join_media_destroyed"] = bool(media_facts.get("destroyed"))
        facts["join_verified"] = True
        facts["join_principal_destroyed"] = destruction.destruction_proved
        if not destruction.destruction_proved:
            raise ArchIdentityError(
                JOIN_PRINCIPAL_NOT_DESTROYED_FAILURE, check="arch-joined")

    def _set_rescue_password(self) -> None:
        """Give the break-glass account the set password its check requires."""
        import secrets as secrets_module

        console = self._workstation_console
        if console is None:
            raise ArchIdentityError(
                RESCUE_PASSWORD_FAILURE, check="arch-local-rescue")
        # Same shape as the staged principal credentials.  It is local-only, so
        # it is generated here, used once, and never retained on the boundary,
        # in the evidence, or in the transcript.
        set_rescue_password(
            console, self._boot_facts,
            ("T7a" + secrets_module.token_hex(16)).encode("ascii"),
            timeout=RESCUE_PASSWORD_TIMEOUT)

    def _start_workstation(self) -> None:
        """Boot the workstation, select Arch, join in-run, log the operator in.

        The gate-7 disk keeps the gate-7 acceptance default (``loader.conf``
        boots Windows after five seconds) and renders its systemd-boot menu
        on ttyS0, so the drive selects the Arch entry over serial within the
        window — power-cycling over QMP on a miss instead of waiting inside
        Windows.  The in-run domain join then runs (``_join_workstation``),
        followed by the guest's domain-online gate (``await_domain_online``).
        Both of those guest units are ordered before
        ``systemd-user-sessions.service`` and ``serial-getty@ttyS0`` is ordered
        after it, so the login prompt cannot appear until the guest has both
        joined and proven SSSD's AD backend usable; ``login_operator``
        consequently needs no readiness logic and no sleeps.  The staged
        operator then logs in, one echo-suppressed ``sudo -S`` elevation
        follows, and the break-glass password is set from that root shell so
        the secret-free probes can all pass.
        """
        from .serial_automation import SerialAutomation
        from .simulation_evidence import private_file

        assert self._port is not None and self._qmp_root is not None
        if OPERATOR_PRINCIPAL not in self._principals:
            raise ArchIdentityError(
                "workstation boot requires the staged operator principal",
                check="arch-joined")
        qmp_path = self._qmp_root / "workstation.qmp"
        # QEMU writes the firmware debug console itself, so the destination is
        # created private and empty first: the chardev opens it O_TRUNC and so
        # keeps this mode-0600 inode, and a missing evidence directory would
        # make QEMU refuse to start at all rather than merely lose the log.
        firmware_log = (
            self.bundle.evidence_path.parent
            / WORKSTATION_FIRMWARE_LOG_FILENAME)
        private_file(firmware_log, b"")
        command = workstation_boot_command(
            self.bundle.disk, self.bundle.firmware, self._port,
            qmp_socket=qmp_path, firmware_log=firmware_log)
        # Hashed BEFORE the boot as well as after: the pair answers "did the
        # firmware write the variable store at all this boot" without a
        # varstore parser, which is the question both 2026-08-14 stalls turned
        # on (they had written HDDP, so they had).
        self._boot_facts["firmware_vars_sha256_before"] = _file_sha256(
            self.bundle.firmware)
        # Retained beside the bundle's authorization, as the install and
        # dual-boot lanes do: a boot that renders no menu is diagnosed from
        # the firmware knobs it actually ran with, and reconstructing them
        # after the fact is exactly what stalled the 2026-08-13 failure.
        recorded = self.bundle.bundle / BUNDLE_QEMU_COMMAND
        recorded.write_text(
            json.dumps({"schema": 1, "argv": command}, indent=2) + "\n",
            encoding="utf-8")
        recorded.chmod(0o600)
        spawned_at = time.monotonic()
        process = self._spawn("workstation", command, stdio=True)
        self._boot_facts["workstation_spawned_at"] = _utc_now()
        self._audit("client", process.pid, allowed_nic_models=("e1000e",))
        try:
            self._workstation_qmp = self._connect_qmp(qmp_path, process.pid)
        except ArchIdentityError as error:
            raise ArchIdentityError(
                "workstation QMP authentication failed",
                check="arch-joined") from error
        console = SerialAutomation(
            process.stdout, process.stdin,
            self._principals[OPERATOR_PRINCIPAL].encode("ascii"),
            timeout=CONSOLE_READY_TIMEOUT)
        # Every console label from here on is timestamped against power-on.
        console.events = TimestampedEvents(console.events, origin=spawned_at)
        self._workstation_console = console
        drive_boot_menu(
            console, self._boot_facts,
            reset=lambda: self._workstation_qmp.execute("system_reset"),
            menu_timeout=MENU_RENDER_TIMEOUT,
            on_stall=self._retain_boot_stall_evidence)
        # Strictly between the menu drive and the login: the guest cannot log
        # anybody in until its join unit has finished, and nobody can log in at
        # all until this run's directory knows this machine.
        self._join_workstation()
        # And strictly between the join and the login: a joined guest whose
        # SSSD backend is still connecting refuses the operator (proven
        # 2026-08-14), so the guest's own readiness gate is observed here.
        await_domain_online(console, self._boot_facts)
        login_operator(console, self._boot_facts)
        # Bounded on its own: the 2026-08-14 run inherited the 300s
        # console-ready timeout here and spent five minutes waiting on an
        # exchange it had already desynchronised.
        elevate_operator(
            console, self._boot_facts, timeout=SUDO_ELEVATION_TIMEOUT)
        self._set_rescue_password()
        console.timeout = PROBE_TIMEOUT
        self._channel = console

    def open_channel(self) -> SerialChannel:
        if self._channel is None:
            raise ArchIdentityError("Arch serial console is not open")
        return self._channel

    def observe_controller_ready(self) -> bool:
        return self._controller_online

    def take_controller_offline(self) -> None:
        import signal as signal_module

        process = self._processes.get("controller")
        if process is not None:
            process.send_signal(signal_module.SIGSTOP)  # type: ignore[attr-defined]
        self._controller_online = False

    def observe_controller_offline(self) -> bool:
        return not self._controller_online

    def restore_controller(self) -> None:
        import signal as signal_module

        process = self._processes.get("controller")
        if process is not None:
            process.send_signal(signal_module.SIGCONT)  # type: ignore[attr-defined]
        self._controller_online = True

    def observe_controller_restored(self) -> bool:
        return self._controller_online

    def make_storage_unreachable(self) -> None:
        """Repoint the ``unas`` storage label at a dead in-subnet address.

        The gate-7 probe resolves the optional storage target by its stable
        DNS label, so absence is toggled in DNS alone: over the retained
        Controller console, ``samba-tool dns update`` moves the ``unas`` A
        record from the Controller address to ``STORAGE_ABSENT_ADDRESS``.
        Kerberos, LDAP, and DNS identity services stay online throughout;
        only the storage target dies.  Every failure is fail-closed and
        bound to the storage-absent check.
        """
        import secrets as secrets_module

        from .controller_factory import FactorySpec
        from .serial_automation import SerialAutomationError
        from homelab.workstations.arch_second import STORAGE_HOST_LABEL

        console = self._controller_console
        if console is None or console.password is None:
            raise ArchIdentityError(
                "Controller console is unavailable to remove the storage "
                "target", check="arch-storage-absent-login")
        spec = FactorySpec()
        token = secrets_module.token_hex(16).encode("ascii")
        sudo_prompt = b"__TELOS_STORAGE_DNS_SUDO_" + token + b"__"
        result = b"__TELOS_STORAGE_DNS_RC_" + token + b"="
        command = (
            b"sudo -k -S -p '" + sudo_prompt + b"' samba-tool dns update "
            b"127.0.0.1 " + spec.domain.encode("ascii") + b" "
            + STORAGE_HOST_LABEL.encode("ascii") + b" A "
            + spec.address.encode("ascii") + b" "
            + STORAGE_ABSENT_ADDRESS.encode("ascii") + b" -P; "
            b"__telos_rc=$?; printf '\\n" + result
            + b"%s\\n' \"$__telos_rc\""
        )
        try:
            console._send(b"", "storage-dns-shell-requested")
            console._wait(
                rb"(?:^|\n)[^\n]*\$\s*$", "storage-dns-shell-ready")
            console._send(command, "storage-dns-command-sent")
            console._wait(
                rb"(?:^|[\r\n])" + re.escape(sudo_prompt) + rb"\s*$",
                "storage-dns-sudo-prompt")
            console._send(console.password, "storage-dns-password-sent")
            match = console._wait(
                rb"(?:^|\n)" + re.escape(result) + rb"([0-9]+)\s*(?:\n|$)",
                "storage-dns-rc-observed")
        except SerialAutomationError as error:
            raise ArchIdentityError(
                "storage DNS removal failed on the Controller console",
                check="arch-storage-absent-login") from error
        if int(match.group(1)) != 0:
            raise ArchIdentityError(
                "storage DNS removal returned " + match.group(1).decode(
                    "ascii"),
                check="arch-storage-absent-login")

    def windows_evidence(self) -> list[dict[str, object]]:
        return self.bundle.read_windows_evidence()

    def _retain_boot_stall_evidence(
        self, reason: str, *, attempt: int, terminal: bool, label: str,
    ) -> None:
        """Make the next boot stall self-diagnosing, bounded and secret-free.

        Called from ``drive_boot_menu`` on every never-rendered miss: the one
        it power-cycles and retries, and the terminal one it raises on.  The
        two 2026-08-14 stalls left this lane with four serial transcripts of a
        firmware that prints two lines an entire boot, and nothing else, so
        the mechanism could not be settled: the guest was demonstrably inside
        ``EfiBootManagerBoot(Boot0007)`` past the ESP match (it had written
        ``HDDP``) and before ``LoadImage``, but no artifact could say whether
        the vCPU was spinning, a device had stalled, or host I/O had stalled
        through the three-deep ``cache=none`` qcow2 chain.  Three cheap
        artifacts separate those, and none of them was being kept:

        * a framebuffer frame -- ``-device VGA`` exists for exactly this and
          ``screendump`` had never once been called from this module -- which
          separates "firmware still on a blank screen" from "systemd-boot
          rendered to VGA but not to ttyS0";
        * ``query-status`` plus the asynchronous events queued on the QMP
          socket this lane holds open and never drains, so ``paused`` versus
          ``running`` (and any ``BLOCK_IO_ERROR`` or ``RESET``) separates a
          stalled device or host I/O stall from a spinning vCPU;
        * the stall reason, EOF versus a quiet guest, which ``_wait`` and this
          function both used to collapse into one message.

        Everything retained is bounded (record count, frame size, event count)
        and secret-free: this runs strictly before the in-run join and the
        operator login, so no credential has reached the console or the
        framebuffer yet.  Capture failures are recorded in the record itself
        and never raised -- diagnosis must not change the run's outcome.
        """
        from .simulation_evidence import private_directory

        records = self._boot_facts.setdefault("boot_stall_evidence", [])
        if (not isinstance(records, list)
                or len(records) >= BOOT_STALL_RETENTION_LIMIT):
            return
        record: dict[str, object] = {
            "reason": reason,
            "label": label,
            "attempt": attempt,
            "terminal": terminal,
            "at": _utc_now(),
            "frame": None,
            "status": None,
            "qmp_events": [],
        }
        records.append(record)
        console = self._workstation_console
        if console is not None:
            record["transcript_bytes"] = len(
                bytes(getattr(console, "transcript", b"")))
        evidence = self.bundle.evidence_path.parent
        try:
            private_directory(evidence)
        except Exception as error:  # noqa: BLE001 - diagnosis never raises
            record["retention_error"] = type(error).__name__
            return
        qmp = self._workstation_qmp
        if qmp is None:
            record["qmp"] = "unavailable"
            return
        frame = evidence / STALL_FRAME_TEMPLATE.format(index=len(records))
        try:
            qmp.screenshot(frame)
            if frame.is_file():
                size = frame.stat().st_size
                if size > STALL_FRAME_MAX_BYTES:
                    frame.unlink()
                    record["frame_error"] = "frame exceeded its size bound"
                else:
                    frame.chmod(0o600)
                    record["frame"] = frame.name
                    record["frame_bytes"] = size
        except Exception as error:  # noqa: BLE001 - diagnosis never raises
            record["frame_error"] = type(error).__name__
        try:
            status = qmp.execute("query-status", timeout=STALL_QMP_TIMEOUT)
        except Exception as error:  # noqa: BLE001 - diagnosis never raises
            record["status_error"] = type(error).__name__
        else:
            if isinstance(status, dict):
                record["status"] = status.get("status")
                record["running"] = status.get("running")
        # Reading the queue after a command drains the socket: ``execute``
        # queues every event it passes over on the way to its response.
        record["qmp_events"] = _bounded_qmp_events(
            getattr(qmp, "_events", ()))

    def _retain_switch_log(self) -> None:
        """Copy the fabric switch log out of the tempdir that deletes it.

        ``switch.jsonl`` is written for the whole run and then removed with
        ``self._runtime``, so the only record of fabric timing -- and of
        whether the switch process itself failed -- has never survived a run.
        It is the one artifact that can confirm or kill the "QEMU stalled"
        reading of a boot stall: a switch still logging while the guest says
        nothing places the stall inside a live, scheduled QEMU.  Bounded to a
        line-aligned tail so the retained file stays parseable.
        """
        from .simulation_evidence import private_file, redact

        if self._runtime is None:
            return
        source = self._runtime / "switch.jsonl"
        if source.is_symlink() or not source.is_file():
            return
        data = source.read_bytes()[-SWITCH_LOG_RETENTION_BYTES:]
        if len(data) == SWITCH_LOG_RETENTION_BYTES and b"\n" in data:
            data = data.split(b"\n", 1)[1]
        private_file(
            self.bundle.evidence_path.parent / SWITCH_LOG_FILENAME,
            redact(data))

    def _retain_firmware_log(self) -> None:
        """Bound the firmware debug console QEMU wrote for itself.

        A debug-DebugLib OVMF can emit megabytes over a long boot, so the
        retained size is capped the same way the transcript is and the
        observed size is recorded: nonzero means this build carries the
        I/O-port DebugLib and the whole firmware log is in the bundle, zero
        means it carries the serial one and the empty file is the answer.
        """
        from .simulation_evidence import private_file

        path = (
            self.bundle.evidence_path.parent
            / WORKSTATION_FIRMWARE_LOG_FILENAME)
        if path.is_symlink() or not path.is_file():
            return
        size = path.stat().st_size
        self._boot_facts["firmware_debug_log_bytes"] = size
        if size > FIRMWARE_LOG_RETENTION_BYTES:
            private_file(
                path, path.read_bytes()[-FIRMWARE_LOG_RETENTION_BYTES:])
        else:
            path.chmod(0o600)

    def _retain_workstation_evidence(self, transcript: bytes) -> None:
        """Keep a bounded, redacted transcript and secret-free boot facts.

        Mirrors ``arch_install_run._sanitize_log``: only a bounded tail is
        kept, secret-shaped values are redacted, and the files are private.
        The facts record the menu/login lifecycle (menu-seen, entry-selected,
        getty-seen, login-completed, retries, elevation), the boot-stall
        diagnosis, the console timeline and the firmware-variable digests, and
        nothing else.
        """
        from .simulation_evidence import private_file, redact

        evidence = self.bundle.evidence_path.parent
        private_file(
            evidence / WORKSTATION_LOG_FILENAME,
            redact(transcript[-TRANSCRIPT_RETENTION_BYTES:]))
        # Timing and firmware state, both of which had to be reconstructed by
        # hand after the 2026-08-14 stalls: the bounded timestamped console
        # timeline, and the post-boot variable-store digest to compare against
        # this run's pre-boot one and against another run's.
        timeline = getattr(
            getattr(self._workstation_console, "events", None),
            "timeline", None)
        if isinstance(timeline, list):
            self._boot_facts["serial_timeline"] = [
                list(item) for item in timeline[-SERIAL_TIMELINE_LIMIT:]]
        self._boot_facts["firmware_vars_sha256_after"] = _file_sha256(
            self.bundle.firmware)
        try:
            self._retain_firmware_log()
        except OSError:
            # Bounding QEMU's own log must never cost the facts file, which is
            # the artifact that says how far the boot actually got.
            self._boot_facts["firmware_debug_log_bytes"] = None
        payload = {"schema": 1, **self._boot_facts}
        private_file(
            evidence / BOOT_FACTS_FILENAME,
            (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"))

    def stop(self) -> list[str]:
        import shutil

        from .signal_cleanup import terminate_children

        failures: list[str] = []
        if self._watchdog is not None:
            self._watchdog.cancel()
            self._watchdog = None
        if self._controller_console is not None:
            try:
                self._controller_console.release_password()
            except Exception:  # noqa: BLE001 - teardown is reported, not raised
                failures.append("controller credential release failed")
            self._controller_console = None
        if self._workstation_console is not None:
            try:
                self._workstation_console.release_password()
            except Exception:  # noqa: BLE001
                failures.append("workstation credential release failed")
        self._channel = None
        if self._controller_qmp is not None:
            try:
                self._controller_qmp.close()
            except Exception:  # noqa: BLE001
                failures.append("controller QMP close failed")
            self._controller_qmp = None
        if self._workstation_qmp is not None:
            try:
                self._workstation_qmp.close()
            except Exception:  # noqa: BLE001
                failures.append("workstation QMP close failed")
            self._workstation_qmp = None
        processes = [
            proc for proc in self._processes.values() if proc is not None]
        if processes:
            failures += terminate_children(
                processes, terminate_timeout=8, kill_timeout=3)  # type: ignore[arg-type]
        self._processes.clear()
        # Success and failure alike retain the bounded, redacted workstation
        # transcript plus the secret-free menu/login lifecycle facts.
        if self._workstation_console is not None:
            try:
                self._retain_workstation_evidence(bytes(
                    getattr(self._workstation_console, "transcript", b"")))
            except Exception as error:  # noqa: BLE001
                failures.append(
                    "workstation evidence retention failed: "
                    + type(error).__name__)
            self._workstation_console = None
        # Strictly before the runtime tempdir is removed below: the switch log
        # is written there all run and has never survived one.
        try:
            self._retain_switch_log()
        except Exception as error:  # noqa: BLE001
            failures.append(
                "switch log retention failed: " + type(error).__name__)
        self._principals = {}
        if self._controller_disk is not None:
            try:
                self._controller_disk.close()
            except Exception as error:  # noqa: BLE001
                failures.append(
                    "controller disk teardown failed: "
                    + type(error).__name__)
            self._controller_disk = None
        if self._factory_media is not None:
            try:
                self._factory_media.unlink(missing_ok=True)
            except OSError:
                failures.append("convergence media was not removed")
            self._factory_media = None
        if self._join_iso is not None:
            # ArchJoinMedia destroys the ISO by exact inode in the happy path;
            # reuse the install lane's sweep for a run that died before that.
            from .arch_install_run import _destroy_leftover_join_iso

            leftover = _destroy_leftover_join_iso(self._join_iso)
            if leftover:
                failures.append(leftover)
            self._join_iso = None
        for attribute in ("_qmp_root", "_runtime"):
            root = getattr(self, attribute)
            if root is not None:
                shutil.rmtree(root, ignore_errors=True)
                setattr(self, attribute, None)
        if self._expired:
            failures.append(
                f"wall-clock bound of {self.duration:g}s was exceeded")
        self._controller_online = False
        return failures


def _default_session_factory(
    bundle: ArchIdentityBundle, *, duration: float = DEFAULT_DURATION,
) -> ArchIdentitySession:
    return ArchIdentityBoundary(bundle, duration=duration)


def run(
    bundle: Path,
    *,
    apply: bool,
    controller_state: Path,
    session_factory: SessionFactory | None = None,
    duration: float = DEFAULT_DURATION,
) -> int:
    """Validate the bundle, gate on ``--apply``, produce and judge evidence."""
    if not 60 <= duration <= MAX_DURATION:
        raise ArchIdentityError(
            f"duration must be between 60 and {MAX_DURATION:g} seconds")
    prepared = ArchIdentityBundle(bundle, controller_state)
    prepared.validate()

    print("Boundary: loopback-only live Arch identity acceptance")
    print(f"Bundle: {prepared.bundle}")
    print(f"Controller state: {prepared.controller_state}")
    print(f"Realm: {prepared.realm}")
    print(f"Maximum runtime: {duration:g} seconds")
    print("Installation media, PXE, host networking and UniFi: disabled")
    if not apply:
        print("dry run; repeat with --apply to drive the identity lifecycle")
        return 0

    factory = session_factory or (
        lambda ready: _default_session_factory(ready, duration=duration))
    with SignalGuard():
        session = factory(prepared)
        events = run_lifecycle(session)
        write_evidence(prepared.evidence_path, events)

    ok, summary = self_judge(prepared.evidence_path)
    if ok:
        print(f"PASS: {summary}")
        print(f"Evidence: {prepared.evidence_path}")
        return 0
    print(f"FAIL: {summary}", file=sys.stderr)
    print(f"Evidence: {prepared.evidence_path}", file=sys.stderr)
    return 2


def parser() -> argparse.ArgumentParser:
    from .bootstrap_dc import DEFAULT_STATE
    result = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument(
        "--controller-state", type=Path, default=DEFAULT_STATE)
    result.add_argument("--duration", type=float, default=DEFAULT_DURATION)
    result.add_argument("--apply", action="store_true")
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(
            args.bundle,
            apply=args.apply,
            controller_state=args.controller_state,
            duration=args.duration,
        )
    except RunInterrupted as error:
        print(f"arch identity run: {error}", file=sys.stderr)
        return error.exit_code
    except ArchIdentityError as error:
        print(f"arch identity run: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
