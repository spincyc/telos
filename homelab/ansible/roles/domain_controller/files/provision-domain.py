#!/usr/bin/env python3
"""Provision AD through Samba's API without placing its password in argv."""

import argparse
import logging
import os
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--password-file", required=True)
parser.add_argument("--realm", required=True)
parser.add_argument("--domain", required=True)
parser.add_argument("--server-role", required=True)
parser.add_argument("--dns-backend", required=True)
parser.add_argument("--diagnostic-file", required=True)
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

status = ""
returncode = 1
try:
    # Samba 4.24 no longer promises interactive password prompts.  Use its
    # supported in-process provisioning API so the credential is never in
    # argv, the environment, a prompt transcript, or generated randomly.
    from samba.auth import system_session
    from samba.provision import provision

    provision(
        logging.getLogger("homelab-provision-domain"),
        system_session(),
        realm=args.realm,
        domain=args.domain,
        serverrole=args.server_role,
        dns_backend=args.dns_backend,
        adminpass=password,
        use_rfc2307=args.use_rfc2307,
    )
    returncode = 0
    status = "exit=0\n"
except Exception as error:
    status = f"error={type(error).__name__}: {error}\n"
finally:
    status = status.replace(password, "[REDACTED]")
    diagnostic = Path(args.diagnostic_file)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(diagnostic, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(status[-16384:])
raise SystemExit(returncode)
