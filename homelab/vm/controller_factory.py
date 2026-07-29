#!/usr/bin/env python3
"""Build a disposable, local-only Controller convergence payload.

The payload is intended only for a copy-on-write Controller guest attached to
the userspace simulation gateway.  It contains a synthetic directory identity
and a short-lived synthetic Administrator credential.  It never contains a
private inventory or configures a host interface.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import argparse
from dataclasses import dataclass
from pathlib import Path

LABEL = "TELOS_FACTORY"


@dataclass(frozen=True)
class FactorySpec:
    hostname: str = "bootstrap-dc"
    domain: str = "ad.factory.test"
    netbios: str = "FACTORY"
    address: str = "10.1.31.2"
    prefix: int = 28
    gateway: str = "10.1.31.1"
    ntp_upstream: str = "198.51.100.10"
    network: str = "10.1.31.0"
    mask: str = "255.255.255.240"

    @property
    def fqdn(self) -> str:
        return f"{self.hostname}.{self.domain}"

    @property
    def realm(self) -> str:
        return self.domain.upper()


def tftp_unit(spec: FactorySpec) -> str:
    """Dedicated TFTP service; it has no DHCP or DNS implementation."""
    return f"""[Unit]
Description=Disposable factory TFTP
After=network-online.target

[Service]
ExecStart=/usr/bin/in.tftpd --foreground --address {spec.address}:69 --secure /srv/tftp
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""


def verification_commands(spec: FactorySpec) -> tuple[str, ...]:
    return (
        "samba-tool domain info 127.0.0.1",
        "samba-tool dbcheck --cross-ncs",
        f"host -t SRV _ldap._tcp.{spec.domain} 127.0.0.1",
        "systemctl is-active telos-factory-tftp.service",
        "nginx -t -c /etc/homelab/factory-nginx.conf",
        "test -s /srv/http/homelab/boot/boot.ipxe",
        "ss -H -lun | grep -E ':(53|69|123)[[:space:]]'",
        "ss -H -ltn | grep -E ':(53|80|88|389|445)[[:space:]]'",
        "! ss -H -lunp | grep ':53 ' | grep dnsmasq",
        "! ss -H -lunp | grep -E ':(67|4011)[[:space:]]'",
    )


def _script(spec: FactorySpec) -> str:
    checks = "\n".join(
        f"check verify-{index:02d} {json.dumps(command)}"
        for index, command in enumerate(verification_commands(spec), 1))
    return f"""#!/usr/bin/bash
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || {{ echo "factory convergence requires root" >&2; exit 2; }}
[[ -f /run/telos-factory-authorized ]] || {{
  echo "missing disposable-guest authorization marker" >&2; exit 2;
}}
root=${{1:-/run/telos-factory}}
[[ $(findmnt -no LABEL "$root") == {LABEL} ]] || {{
  echo "payload is not mounted from {LABEL}" >&2; exit 2;
}}
expected=$(cat "$root/authorization.sha256")
actual=$(sha256sum /run/telos-factory-authorized | cut -d' ' -f1)
[[ "$actual" == "$expected" ]] || {{
  echo "disposable-guest authorization nonce mismatch" >&2; exit 2;
}}
echo 'TELOS FACTORY STEP network'
iface=$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\\n' |
  grep -Ev '^(lo|docker|virbr|br-|tap|veth)' | head -1)
[[ -n "$iface" ]] || {{ echo "no isolated guest NIC" >&2; exit 2; }}
systemctl stop NetworkManager.service
ip link set "$iface" down
ip link set "$iface" name sim0
ip addr flush dev sim0
ip addr add {spec.address}/{spec.prefix} dev sim0
ip link set sim0 up
ip route replace default via {spec.gateway} dev sim0
hostnamectl hostname {spec.hostname}
printf '127.0.0.1 localhost\\n{spec.address} {spec.fqdn} {spec.hostname}\\n' >/etc/hosts
echo 'TELOS FACTORY STEP time-sync'
systemctl stop ntpd.service
install -d -m 0700 /run/telos-factory-state
python3 - <<'PY'
import os
import socket
import struct
import time

request = bytearray(48)
request[0] = 0x23
request[40:48] = os.urandom(8)
response = None
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
    probe.settimeout(5)
    for _attempt in range(5):
        probe.sendto(request, ("{spec.ntp_upstream}", 123))
        try:
            candidate, source = probe.recvfrom(512)
        except TimeoutError:
            continue
        if (
            source == ("{spec.ntp_upstream}", 123)
            and len(candidate) == 48
            and candidate[0] >> 6 != 3
            and (candidate[0] >> 3) & 0x7 == 4
            and candidate[0] & 0x7 == 4
            and 1 <= candidate[1] <= 15
            and candidate[24:32] == request[40:48]
            and candidate[40:48] != bytes(8)
        ):
            response = candidate
            break
if response is None:
    raise SystemExit("simulated-gateway NTP measurement failed")
print("TELOS FACTORY STEP time-sync-response", flush=True)
seconds, fraction = struct.unpack("!II", response[40:48])
measured = seconds - 2_208_988_800 + fraction / 2**32
time.clock_settime(time.CLOCK_REALTIME, measured)
print("TELOS FACTORY STEP time-sync-clock", flush=True)
PY
printf 'ntpd measurement passed\\n' >/run/telos-factory-state/clock.receipt
chmod 0600 /run/telos-factory-state/clock.receipt
echo 'TELOS FACTORY STEP payload-stage'
install -d -m 0700 /run/secrets
install -m 0600 "$root/secret/ad-admin" /run/secrets/factory-ad-admin
trap 'shred -u /run/secrets/factory-ad-admin 2>/dev/null || rm -f /run/secrets/factory-ad-admin' EXIT
install -d -m 0755 /opt/telos-factory
cp -a "$root/ansible" /opt/telos-factory/
install -o root -g root -m 0700 "$root/controller-auth-diagnostic.py" \
  /opt/telos-factory/controller-auth-diagnostic.py
install -d -m 0755 /etc/homelab
printf '%s\\n' \
  '{{"profile":"controller","hostname":"{spec.hostname}","development_proof":true}}' \
  >/etc/homelab/manifest.json
chmod 0644 /etc/homelab/manifest.json
systemctl unmask samba.service ntpd.service nginx.service
echo 'TELOS FACTORY STEP package-preflight'
for package in samba krb5 ntp python-cryptography python-dnspython \
  python-markdown openresolv bind; do
  if ! pacman -Q "$package" >/dev/null; then
    echo "TELOS FACTORY STEP package-missing-$package"
    exit 1
  fi
done
echo 'TELOS FACTORY STEP ansible'
if ! ANSIBLE_CONFIG="$root/factory-ansible.cfg" \
  ansible-playbook -i "$root/inventory.ini" \
  -e @"$root/factory-vars.json" \
  /opt/telos-factory/ansible/playbooks/bootstrap-controller.yml; then
  if [[ -f /run/homelab-provision-domain.status ]]; then
    echo 'TELOS FACTORY PROVISION DIAGNOSTIC'
    cat /run/homelab-provision-domain.status
  fi
  exit 2
fi
install -d -m 0755 /etc/homelab /srv/tftp /srv/http/homelab/boot
install -m 0644 "$root/telos-factory-tftp.service" /etc/systemd/system/telos-factory-tftp.service
install -m 0644 "$root/factory-nginx.conf" /etc/homelab/factory-nginx.conf
install -m 0644 "$root/boot.ipxe" /srv/http/homelab/boot/boot.ipxe
install -m 0644 /usr/share/ipxe/x86_64/ipxe.efi /srv/tftp/ipxe.efi
echo 'TELOS FACTORY STEP services'
systemctl daemon-reload
systemctl restart samba.service ntpd.service
systemctl restart telos-factory-tftp.service
nginx -c /etc/homelab/factory-nginx.conf
echo 'TELOS FACTORY STEP auth-audit'
echo 'TELOS FACTORY STEP auth-audit-preflight'
smbd -b | awk '
  $1 == "HAVE_JSON_OBJECT" && NF == 1 {{ found++ }}
  END {{ exit found == 1 ? 0 : 1 }}
'
echo 'TELOS FACTORY STEP auth-audit-sink-create'
install -d -o root -g root -m 0700 /run/telos-factory-auth-audit
install -o root -g root -m 0600 /dev/null \
  /run/telos-factory-auth-audit/auth.jsonl
echo 'TELOS FACTORY STEP auth-audit-config-write'
test "$(grep -c '^\\[global\\]$' /etc/samba/smb.conf)" == 1
sed -i \
  '/^\\[global\\]$/a\\\tlog level = 0 auth_json_audit:3@/run/telos-factory-auth-audit/auth.jsonl' \
  /etc/samba/smb.conf
chmod 0600 /etc/samba/smb.conf
echo 'TELOS FACTORY STEP auth-audit-config-verify'
test "$(grep -Fxc $'\\tlog level = 0 auth_json_audit:3@/run/telos-factory-auth-audit/auth.jsonl' \
  /etc/samba/smb.conf)" == 1
testparm -s /etc/samba/smb.conf >/dev/null 2>&1
echo 'TELOS FACTORY STEP auth-audit-restart'
systemctl restart samba.service
auth_audit_live=$(smbcontrol all debuglevel)
mapfile -t auth_audit_levels < <(
  awk '
    {{
      for (field = 1; field <= NF; field++) {{
        token = $field
        gsub(/^[,;()\\[\\]{{}}]+|[,;()\\[\\]{{}}]+$/, "", token)
        if (token == "auth_json_audit:") {{
          print $(field + 1)
        }} else if (token ~ /^auth_json_audit:/) {{
          sub(/^auth_json_audit:/, "", token)
          print token
        }}
      }}
    }}
  ' <<<"$auth_audit_live"
)
[[ ${{#auth_audit_levels[@]}} -gt 0 ]]
for auth_audit_level in "${{auth_audit_levels[@]}}"; do
  [[ "$auth_audit_level" == 3 ]]
done
echo 'TELOS FACTORY STEP auth-audit-sink-verify'
test -d /run/telos-factory-auth-audit
test ! -L /run/telos-factory-auth-audit
test "$(stat -c '%u:%g:%a' /run/telos-factory-auth-audit)" == '0:0:700'
test -f /run/telos-factory-auth-audit/auth.jsonl
test ! -L /run/telos-factory-auth-audit/auth.jsonl
test "$(stat -c '%u:%g:%a:%h' \
  /run/telos-factory-auth-audit/auth.jsonl)" == '0:0:600:1'
echo 'TELOS FACTORY STEP verify'
check() {{
  echo "TELOS FACTORY STEP $1"
  shift
  /usr/bin/bash -o pipefail -c "$1"
}}
{checks}
echo 'TELOS FACTORY STEP administrator-disable'
samba-tool user disable Administrator
echo 'TELOS FACTORY STEP administrator-disabled-proof'
administrator_uac=$(
  samba-tool user show Administrator --attributes=userAccountControl |
    sed -n 's/^userAccountControl: //p'
)
[[ "$administrator_uac" =~ ^[0-9]+$ ]]
(( administrator_uac & 2 ))
touch /var/lib/telos-factory-converged
echo 'TELOS FACTORY CONTROLLER PASS'
"""


def nginx_config(spec: FactorySpec) -> str:
    return f"""pid /run/factory-nginx.pid;
error_log stderr notice;
events {{}}
http {{
  access_log /var/log/nginx/factory-access.log;
  server {{
    listen {spec.address}:80;
    root /srv/http/homelab;
    location / {{ try_files $uri =404; }}
  }}
}}
"""


class FactoryBundle:
    def __init__(
        self,
        repo: Path,
        output: Path,
        *,
        authorization_nonce: str,
        password: str | None = None,
        spec: FactorySpec | None = None,
    ) -> None:
        self.repo = Path(repo).resolve()
        self.output = Path(output).absolute()
        self.password = password or (
            "Synthetic-" + secrets.token_urlsafe(24) + "-47!")
        self.authorization_nonce = authorization_nonce
        if "\n" in self.password or not self.password:
            raise ValueError("synthetic password must be one non-empty line")
        if not re.fullmatch(r"[0-9a-f]{64}", self.authorization_nonce):
            raise ValueError("authorization nonce must be 64 lowercase hex digits")
        self.spec = spec or FactorySpec()

    def stage(self, destination: Path) -> Path:
        destination = Path(destination)
        try:
            mode = destination.lstat().st_mode
        except FileNotFoundError:
            mode = None
        if mode is not None and (
                stat.S_ISLNK(mode) or not stat.S_ISDIR(mode)):
            raise ValueError(
                "factory staging path must be a real directory")
        if destination.exists() and any(destination.iterdir()):
            raise ValueError("factory staging directory is not empty")
        destination.mkdir(parents=True, mode=0o700, exist_ok=True)
        destination.chmod(0o700, follow_symlinks=False)
        for relative in ("homelab/ansible",):
            source = self.repo / relative
            if not source.is_dir():
                raise FileNotFoundError(source)
            shutil.copytree(source, destination / Path(relative).name,
                            symlinks=False)
        shutil.copyfile(
            self.repo / "homelab/vm/controller_auth_diagnostic.py",
            destination / "controller-auth-diagnostic.py",
            follow_symlinks=False,
        )
        (destination / "controller-auth-diagnostic.py").chmod(0o600)
        secret_dir = destination / "secret"
        secret_dir.mkdir(mode=0o700)
        secret = secret_dir / "ad-admin"
        secret.write_text(self.password + "\n", encoding="utf-8")
        secret.chmod(0o600)
        variables = {
            "homelab_ad_dns_domain": self.spec.domain,
            "homelab_ad_realm": self.spec.realm,
            "homelab_ad_netbios_domain": self.spec.netbios,
            "homelab_ad_expected_hostname": self.spec.hostname,
            "homelab_ad_provision_enabled": True,
            "homelab_ad_admin_password_file": "/run/secrets/factory-ad-admin",
            "homelab_ad_ntp_upstreams": [self.spec.ntp_upstream],
            "homelab_ad_development_clock_receipt_file":
                "/run/telos-factory-state/clock.receipt",
            "homelab_ad_manage_packages": False,
        }
        (destination / "factory-vars.json").write_text(
            json.dumps(variables, sort_keys=True) + "\n", encoding="utf-8")
        (destination / "inventory.ini").write_text(
            "[bootstrap_controllers]\nlocalhost ansible_connection=local\n",
            encoding="utf-8")
        (destination / "factory-ansible.cfg").write_text(
            "[defaults]\n"
            "roles_path = /opt/telos-factory/ansible/roles\n"
            "stdout_callback = ansible.builtin.default\n"
            "callback_result_format = yaml\n"
            "retry_files_enabled = false\n"
            "interpreter_python = /usr/bin/python3\n",
            encoding="utf-8")
        (destination / "authorization.sha256").write_text(
            hashlib.sha256(self.authorization_nonce.encode()).hexdigest() + "\n",
            encoding="utf-8")
        (destination / "telos-factory-tftp.service").write_text(
            tftp_unit(self.spec), encoding="utf-8")
        (destination / "factory-nginx.conf").write_text(
            nginx_config(self.spec), encoding="utf-8")
        (destination / "boot.ipxe").write_text(
            f"#!ipxe\nchain http://{self.spec.address}/arch/boot.ipxe\n",
            encoding="utf-8")
        script = destination / "converge-controller"
        script.write_text(_script(self.spec), encoding="utf-8")
        script.chmod(0o700)
        return destination

    def build(self) -> Path:
        if self.output.is_symlink():
            raise ValueError("factory ISO output must not be a symlink")
        if not shutil.which("xorriso"):
            raise RuntimeError("xorriso is required")
        work = self.output.with_name(self.output.name + ".stage")
        if work.exists():
            shutil.rmtree(work)
        try:
            self.stage(work)
            self.output.parent.mkdir(parents=True, exist_ok=True)
            partial = self.output.with_suffix(self.output.suffix + ".partial")
            partial.unlink(missing_ok=True)
            subprocess.run(
                ["xorriso", "-as", "mkisofs", "-quiet", "-uid", "0",
                 "-gid", "0", "-V", LABEL,
                 "-o", str(partial), str(work)],
                check=True,
            )
            os.chmod(partial, 0o600)
            os.replace(partial, self.output)
        finally:
            partial = self.output.with_suffix(self.output.suffix + ".partial")
            partial.unlink(missing_ok=True)
            shutil.rmtree(work, ignore_errors=True)
        return self.output

    def close(self) -> None:
        """Remove the secret-bearing payload after the disposable run."""
        if self.output.exists() and not self.output.is_symlink():
            self.output.unlink()

    def __enter__(self) -> "FactoryBundle":
        self.build()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @staticmethod
    def guest_command(authorization_nonce: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{64}", authorization_nonce):
            raise ValueError("authorization nonce must be 64 lowercase hex digits")
        return (
            f"printf %s {authorization_nonce} > /run/telos-factory-authorized; "
            "mkdir -p /run/telos-factory; "
            "__telos_factory_device=''; "
            "for __telos_try in $(seq 1 60); do "
            f"__telos_factory_device=$(blkid -L {LABEL} || true); "
            "if [ -n \"$__telos_factory_device\" ]; then break; fi; "
            "sleep 1; done; "
            "test -b \"$__telos_factory_device\"; "
            "mount -o ro \"$__telos_factory_device\" /run/telos-factory; "
            "/run/telos-factory/converge-controller /run/telos-factory"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build an ephemeral local-only Controller factory ISO")
    parser.add_argument(
        "--output", type=Path,
        default=Path("homelab/var/factory/controller-convergence.iso"))
    parser.add_argument(
        "--repo", type=Path,
        default=Path(__file__).resolve().parents[2])
    parser.add_argument(
        "--authorization-nonce",
        help="64 lowercase hex digits generated by the lifecycle orchestrator")
    parser.add_argument(
        "--print-guest-command", action="store_true",
        help="print the fixed serial command instead of building")
    args = parser.parse_args()
    if args.print_guest_command:
        if not args.authorization_nonce:
            parser.error("--print-guest-command requires --authorization-nonce")
        print(FactoryBundle.guest_command(args.authorization_nonce))
        return 0
    if not args.authorization_nonce:
        parser.error("building requires --authorization-nonce")
    output = FactoryBundle(
        args.repo, args.output,
        authorization_nonce=args.authorization_nonce).build()
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
