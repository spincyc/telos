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


def stage_dns_repair(repo: Path, destination: Path) -> dict:
    """Bind the offline-verified repair to this payload, never the source role."""
    try:
        from ..lib import samba_dns
    except ImportError:  # Direct script entry point.
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))
        import samba_dns
    cache = Path(os.environ.get(
        "TELOS_SAMBA_DNS_CACHE", str(repo / "homelab/var/media/samba-dns")))
    return samba_dns.stage(cache, destination)


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
    """Dedicated TFTP service; it has no DHCP or DNS implementation.

    ``Wants=`` as well as ``After=network-online.target``: in.tftpd binds the
    Controller's own address, and on a boot of a persistent instance that
    address exists only once systemd-networkd has configured the link. An
    ``After=`` alone orders against the target only if something else happens
    to pull it into the boot transaction.
    """
    return f"""[Unit]
Description=Disposable factory TFTP
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/bin/in.tftpd --foreground --address {spec.address}:69 --secure /srv/tftp
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""


#: The unit that serves the PXE HTTP boot chain. The name is the one the
#: published PXE image already uses for the same job (``factory_publication.py``)
#: and the one ``package-contract.json`` declares for the controller-factory
#: layer, so a Controller that carries both never has two units bound to :80.
HTTP_UNIT_NAME = "telos-factory-http.service"
NGINX_CONFIG_PATH = "/etc/homelab/factory-nginx.conf"
NGINX_PID_FILE = "/run/factory-nginx.pid"


def http_unit() -> str:
    """nginx on the factory configuration, owned by systemd across reboots.

    ``Type=forking`` with the configuration's own pid file is how the packaged
    ``nginx.service`` runs nginx, and it keeps the property the ad hoc
    ``nginx -c`` start had: nginx binds before it daemonizes, so a listener it
    cannot open fails ``systemctl restart`` synchronously rather than leaving a
    unit that merely looked started. It has no DHCP implementation.
    """
    return f"""[Unit]
Description=Telos factory PXE HTTP
Wants=network-online.target
After=network-online.target

[Service]
Type=forking
PIDFile={NGINX_PID_FILE}
ExecStart=/usr/bin/nginx -c {NGINX_CONFIG_PATH}
ExecReload=/usr/bin/nginx -s reload -c {NGINX_CONFIG_PATH}
Restart=on-failure
KillMode=mixed
KillSignal=SIGQUIT
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
"""


#: The durable network configuration lives at a lower number than the
#: ``20-telos-factory.network`` a published PXE image bakes in
#: (``factory_publication.py``), so a payload-generated unit written for the NIC
#: this guest actually has always wins the first-match, and the baked-in one
#: stays behind it as an inert fallback rather than being clobbered.
NETWORK_UNIT_PATH = "/etc/systemd/network/10-telos-factory.network"


def network_unit(spec: FactorySpec, mac: str = "%s") -> str:
    """The Controller's durable network identity, owned by systemd-networkd.

    Only the guest knows the MAC the simulator gave its NIC, so the default
    leaves a single ``printf`` conversion for the convergence payload to fill
    in on the guest. Passing a MAC renders a concrete unit, which is what the
    tests assert against.

    Matching by MAC rather than by name is deliberate: it needs no ``.link``
    file and no interface rename, so the kernel name is left alone.

    ``DHCP=no`` and ``DHCPServer=no`` are stated rather than left to their
    defaults because they are a gate-4 invariant, not an implementation
    detail: the simulated gateway is the sole DHCP authority on the segment,
    and this Controller must neither take a lease nor answer one.
    ``IPv6AcceptRA=no`` closes the remaining route to a DHCPv6 client.

    No ``DNS=`` is set. Nothing on this image runs systemd-resolved or
    resolvconf, so the directive would be inert, and /etc/resolv.conf is not
    this file's business.
    """
    return f"""# Telos factory Controller: the durable network identity.
# systemd-networkd is the single owner of this link; the convergence payload
# masks NetworkManager so nothing else can claim it after a reboot.
[Match]
MACAddress={mac}

[Network]
Address={spec.address}/{spec.prefix}
Gateway={spec.gateway}
DHCP=no
DHCPServer=no
IPv6AcceptRA=no
LinkLocalAddressing=ipv6
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
mac=$(cat "/sys/class/net/$iface/address")
printf '%s' "$mac" |
  grep -Eq '^([0-9a-f]{{2}}:){{5}}[0-9a-f]{{2}}$' || {{
  echo "guest NIC $iface reports no usable MAC address" >&2; exit 2;
}}
# NetworkManager is *enabled* on the canonical Controller image
# (homelab/seed/install-controller), so merely stopping it lasts until the next
# boot: a persistent instance would come back with a second manager on this
# link and take a DHCP lease from the simulated gateway instead of keeping its
# static identity. Stop it, then mask it so no later boot can start it, then
# prove it is gone -- two managers on one interface is how a live run died with
# "Nexthop has invalid gateway". Stopping before masking is deliberate:
# whether systemd lets a masked unit be stopped is version-dependent, while
# stopping an already-masked inactive unit only has to be tolerated, and the
# fail-closed check below is what actually establishes the property.
systemctl stop NetworkManager.service 2>/dev/null || true
systemctl mask NetworkManager.service NetworkManager-wait-online.service
if systemctl is-active --quiet NetworkManager.service; then
  echo "NetworkManager still owns $iface" >&2; exit 2
fi
# One declarative source of truth for the address, the prefix and the default
# route, applied by systemd-networkd now and re-applied by it on every later
# boot without re-convergence. Nothing renames the link: sim0 was a
# runtime-only name that no gate, role, test or document ever referred to, and
# matching by MAC needs neither a .link file nor a rename.
install -d -m 0755 /etc/systemd/network
network_unit={NETWORK_UNIT_PATH}
printf '{network_unit(spec)}' "$mac" >"$network_unit.new"
chmod 0644 "$network_unit.new"
if cmp -s "$network_unit.new" "$network_unit"; then
  rm -f "$network_unit.new"
  network_changed=0
else
  mv -f "$network_unit.new" "$network_unit"
  network_changed=1
fi
systemctl unmask systemd-networkd.service
systemctl enable systemd-networkd.service
# Touch the link only when the observed state is not already the intended one,
# so a persistent instance's second convergence does not thrash it.
if [[ "$network_changed" == 1 ]] ||
   ! systemctl is-active --quiet systemd-networkd.service ||
   ! ip -4 addr show dev "$iface" |
     grep -q 'inet {spec.address}/{spec.prefix} ' ||
   ! ip route show default | grep -q 'via {spec.gateway}'; then
  # Hand the link over while no manager is running: an installer-time DHCP
  # lease outlives NetworkManager being stopped, and systemd-networkd must be
  # the only writer from here on.
  systemctl stop systemd-networkd.service 2>/dev/null || true
  ip addr flush dev "$iface"
  systemctl restart systemd-networkd.service
fi
for _ in $(seq 1 60); do
  if ip -4 addr show dev "$iface" |
       grep -q 'inet {spec.address}/{spec.prefix} ' &&
     ip route show default | grep -q 'via {spec.gateway}'; then
    break
  fi
  sleep 0.5
done
ip -4 addr show dev "$iface" |
  grep -q 'inet {spec.address}/{spec.prefix} ' || {{
  echo "{spec.address}/{spec.prefix} was not installed on $iface" >&2
  ip -4 addr show
  systemctl --no-pager --full status systemd-networkd.service || true
  exit 2
}}
ip route show default | grep -q 'via {spec.gateway}' || {{
  echo "default route via {spec.gateway} was not installed" >&2
  ip route show
  systemctl --no-pager --full status systemd-networkd.service || true
  exit 2
}}
# Gate 4 invariant, proved on the durable configuration itself: the simulated
# gateway is the sole DHCP authority. No DHCP client (UDP 68) may be running
# and no DHCP or ProxyDHCP answer (UDP 67, 4011) may be served.
if ss -H -lun | grep -Eq ':(67|68|4011)[[:space:]]'; then
  echo "a DHCP socket is open on the Controller" >&2
  ss -H -lunp
  exit 2
fi
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
  # Inert on this payload -- it declares no durable directory accounts -- but
  # the file is written by a task whose own output is no_log, so if a durable
  # roster is ever converged from a payload this is the only place its reason
  # would surface. Both drivers redact every credential they read.
  if [[ -f /run/homelab-provision-accounts.status ]]; then
    echo 'TELOS FACTORY ACCOUNTS DIAGNOSTIC'
    cat /run/homelab-provision-accounts.status
  fi
  exit 2
fi
install -d -m 0755 /etc/homelab /srv/tftp /srv/http/homelab/boot
install -m 0644 "$root/telos-factory-tftp.service" /etc/systemd/system/telos-factory-tftp.service
install -m 0644 "$root/{HTTP_UNIT_NAME}" /etc/systemd/system/{HTTP_UNIT_NAME}
install -m 0644 "$root/factory-nginx.conf" {NGINX_CONFIG_PATH}
install -m 0644 "$root/boot.ipxe" /srv/http/homelab/boot/boot.ipxe
install -m 0644 /usr/share/ipxe/x86_64/ipxe.efi /srv/tftp/ipxe.efi
echo 'TELOS FACTORY STEP services'
systemctl daemon-reload
# samba and ntpd are only restarted here because the domain_controller role
# already enabled both during the play above.
systemctl restart samba.service ntpd.service
# PXE -- TFTP and the HTTP boot chain -- is ENABLED, not only started. The seed
# image masks every packaged TFTP and nginx unit, so on a persistent Controller
# (a rehearsal instance, later the keeper) a start that is not also an enable
# serves PXE until the first reboot and then silently never again. nginx runs
# under its own unit on the factory configuration rather than ad hoc, so systemd
# owns it on every later boot and a reconvergence restarts it instead of
# colliding with a copy already bound to :80. `restart`, not `enable --now`, so a
# reconvergence also applies a changed unit or configuration. Neither unit
# answers DHCP or ProxyDHCP: the gateway is the sole DHCP authority (ADR 0066).
systemctl enable telos-factory-tftp.service {HTTP_UNIT_NAME}
systemctl restart telos-factory-tftp.service {HTTP_UNIT_NAME}
for unit in telos-factory-tftp.service {HTTP_UNIT_NAME}; do
  [[ $(systemctl is-enabled "$unit") == enabled ]] || {{
    echo "$unit is not enabled, so PXE would not survive a reboot" >&2; exit 2;
  }}
  systemctl is-active --quiet "$unit" || {{
    echo "$unit is not running" >&2
    systemctl --no-pager --full status "$unit" || true
    exit 2
  }}
done
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
# CONVERGES the audit setting; it does not append it. On a PERSISTENT instance
# /etc/samba/smb.conf is durable and no role ever templates it, so a second
# convergence used to insert a second copy and then fail its own verify -- after
# the write, which left the durable file carrying two copies and every later run
# failing identically until somebody hand-edited it over the console.
#
# The old guard was `! grep -Eq ...` on a line of its own. Bash exempts a
# `!`-prefixed pipeline from `set -e`, so that line could never stop anything:
# it was a comment with a process behind it. The counts below are taken into
# variables and compared explicitly, which is what makes the decision able to
# fail.
auth_audit_line=$'\\tlog level = 0 auth_json_audit:3@/run/telos-factory-auth-audit/auth.jsonl'
test "$(grep -c '^\\[global\\]$' /etc/samba/smb.conf)" == 1
auth_audit_any=$(grep -Ec '^[[:space:]]*[^#;].*auth_json_audit' /etc/samba/smb.conf || true)
auth_audit_ours=$(grep -Fxc "$auth_audit_line" /etc/samba/smb.conf || true)
if [[ "$auth_audit_any" != "$auth_audit_ours" ]]; then
  echo 'an auth_json_audit setting this payload did not write is already in /etc/samba/smb.conf' >&2
  grep -En '^[[:space:]]*[^#;].*auth_json_audit' /etc/samba/smb.conf >&2 || true
  exit 2
fi
# Strip every copy and insert exactly one, so a file that arrived with none,
# with one, or with the two a pre-2026-08-17 payload left behind all converge
# to the same single line. `cat` back into place rather than mv: the inode, its
# ownership and anything else pointing at it are left alone.
grep -Fxv "$auth_audit_line" /etc/samba/smb.conf >/etc/samba/smb.conf.telos-audit || true
sed -i \
  '/^\\[global\\]$/a\\\tlog level = 0 auth_json_audit:3@/run/telos-factory-auth-audit/auth.jsonl' \
  /etc/samba/smb.conf.telos-audit
cat /etc/samba/smb.conf.telos-audit >/etc/samba/smb.conf
rm -f /etc/samba/smb.conf.telos-audit
chmod 0600 /etc/samba/smb.conf
echo 'TELOS FACTORY STEP auth-audit-config-verify'
test "$(grep -Fxc "$auth_audit_line" /etc/samba/smb.conf)" == 1
test "$(grep -Ec '^[[:space:]]*[^#;].*auth_json_audit' /etc/samba/smb.conf)" == 1
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
    return f"""pid {NGINX_PID_FILE};
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
                            symlinks=False,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        stage_dns_repair(
            self.repo,
            destination / "ansible/roles/domain_controller/files/samba-dns")
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
            "homelab_ad_dns_repair_source":
                "/opt/telos-factory/ansible/roles/domain_controller/files/samba-dns",
            "homelab_storage_address": self.spec.address,
            # Stated, not left to the role default, because it is the property
            # that keeps this payload hermetic: the disposable acceptance
            # Controller's roster is synthetic, per-run and staged much later
            # over the serial console by homelab/vm/controller_principals.py,
            # and the role's whole durable-account section is gated on this
            # list being non-empty.
            #
            # It stays empty on purpose and there is deliberately no way to fill
            # it in here. Durable accounts are converged from the Ansible
            # CONTROL HOST (playbooks/bootstrap-controller.yml against the
            # private inventory), which is the only place the one roster loader,
            # the private identity overlay and an operator who can stage a
            # credential file all exist at once. Carrying them on this medium
            # would mean putting the owner's real account names -- and a
            # credential per account -- onto an ISO built for a disposable
            # guest, and into a serial transcript.
            "homelab_ad_directory_accounts": [],
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
        (destination / HTTP_UNIT_NAME).write_text(
            http_unit(), encoding="utf-8")
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
