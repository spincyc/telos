"""Synthetic EDK2 variable stores, built byte by byte for the unit tests.

Every runner that carries an ``OVMF_VARS.fd`` into a boot parses it
(``homelab.vm.ovmf_vars``), so a fixture store must be a real one; these
builders make the smallest stores the parser accepts.
"""

import struct
import uuid

from homelab.vm import ovmf_vars

NV_FV_GUID = uuid.UUID("fff12b8d-7696-4c8b-a985-2747075b4f50")
#: A synthetic expanded device path; only its presence is ever judged.
HDDP_PATH = b"\x02\x01\x0c\x00\xd0\x41\x08\x0a\x00\x00\x00\x00\x7f\xff\x04\x00"


def efi_variable(name: str, vendor: uuid.UUID, data: bytes, *,
                 state: int = ovmf_vars.VAR_ADDED,
                 authenticated: bool = True) -> bytes:
    encoded = (name + "\0").encode("utf-16-le")
    if authenticated:
        header = struct.pack(
            "<HBBIQ16sIII16s", ovmf_vars.VARIABLE_START_ID, state, 0, 7, 0,
            bytes(16), 0, len(encoded), len(data), vendor.bytes_le)
    else:
        header = struct.pack(
            "<HBBIII16s", ovmf_vars.VARIABLE_START_ID, state, 0, 7,
            len(encoded), len(data), vendor.bytes_le)
    body = header + encoded + data
    return body + b"\xff" * (-len(body) % 4)


def load_option_bytes(description: str, *, active: bool = True) -> bytes:
    path = b"\x7f\xff\x04\x00"  # the end-of-device-path node
    return (struct.pack("<IH", 1 if active else 0, len(path))
            + (description + "\0").encode("utf-16-le") + path)


def variable_store(variables, *, authenticated: bool = True,
                   size: int = 0x4000) -> bytes:
    fv = (bytes(16) + NV_FV_GUID.bytes_le + struct.pack("<Q", 72 + size)
          + ovmf_vars.FV_SIGNATURE
          + struct.pack("<IHHHBB", 0x4FEFF, 72, 0, 0, 0, 2)
          + struct.pack("<IIII", 1, 72 + size, 0, 0))
    assert len(fv) == 72
    guid = (ovmf_vars.AUTHENTICATED_STORE if authenticated
            else ovmf_vars.PLAIN_STORE)
    header = guid.bytes_le + struct.pack(
        "<IBBHI", size, ovmf_vars.STORE_FORMATTED, 0xFE, 0, 0)
    body = b"".join(variables)
    data = fv + header + body
    return data + b"\xff" * (72 + size - len(data))


def hddp_variable(*, state: int = ovmf_vars.VAR_ADDED,
                  authenticated: bool = True) -> bytes:
    return efi_variable(
        ovmf_vars.HDDP_NAME, ovmf_vars.HDDP_VENDOR, HDDP_PATH, state=state,
        authenticated=authenticated)


def store(label: str = "synthetic", *, hddp: bool = False) -> bytes:
    """A small authenticated store, told apart from others by *label*.

    *hddp* adds a live boot-path cache after the boot entry, the way a boot
    through a short-form ``HD()`` entry leaves one.
    """
    glob = ovmf_vars.EFI_GLOBAL_VARIABLE
    return variable_store([
        efi_variable("Boot0000", glob, load_option_bytes(label)),
        efi_variable("BootOrder", glob, b"\x00\x00"),
        *((hddp_variable(),) if hddp else ()),
    ])
