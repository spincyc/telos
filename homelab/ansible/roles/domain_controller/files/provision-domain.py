#!/usr/bin/env python3
"""Feed the first AD password to samba-tool without placing it in argv."""

import argparse
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--password-file", required=True)
parser.add_argument("--realm", required=True)
parser.add_argument("--domain", required=True)
parser.add_argument("--server-role", required=True)
parser.add_argument("--dns-backend", required=True)
rfc2307 = parser.add_mutually_exclusive_group(required=True)
rfc2307.add_argument("--use-rfc2307", action="store_true")
rfc2307.add_argument("--without-rfc2307", action="store_true")
args = parser.parse_args()

try:
    first_line = Path(args.password_file).read_text(encoding="utf-8").splitlines()[0]
except (OSError, IndexError, UnicodeError) as error:
    parser.error(f"cannot read a first line from --password-file: {error}")
password = first_line.strip()
if not password:
    parser.error("--password-file must have a nonempty first line")

import pexpect  # Imported only after rejecting malformed secret input.
command = [
    "/usr/bin/samba-tool", "domain", "provision",
    f"--realm={args.realm}",
    f"--domain={args.domain}",
    f"--server-role={args.server_role}",
    f"--dns-backend={args.dns_backend}",
]
if args.use_rfc2307:
    command.append("--use-rfc2307")

child = pexpect.spawn(command[0], command[1:], encoding="utf-8", timeout=300)
child.expect(r"(?i)administrator password:")
child.sendline(password)
child.expect(r"(?i)retype password:")
child.sendline(password)
child.expect(pexpect.EOF)
child.close()
raise SystemExit(child.exitstatus if child.exitstatus is not None else 1)
