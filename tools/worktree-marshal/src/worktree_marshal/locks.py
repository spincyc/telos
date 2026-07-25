"""Lock-descriptor bookkeeping and inherited-descriptor validation."""

from __future__ import annotations

import os
import weakref
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, MutableMapping, TextIO


@dataclass(frozen=True)
class RegisteredLockDescriptor:
    stream: weakref.ReferenceType[TextIO]
    device: int
    inode: int


LockRegistry = MutableMapping[int, RegisteredLockDescriptor]
LockRegistryResolver = Callable[[], LockRegistry]
LockRecordFactory = Callable[..., RegisteredLockDescriptor]
LockRecordFactoryResolver = Callable[[], LockRecordFactory]


@contextmanager
def file_lock(
    path: Path,
    *,
    blocking: bool,
    private_directory: Callable[[], Callable[[Path], None]],
    file_open: Callable[[], Callable[..., TextIO]],
    file_chmod: Callable[[], Callable[[Path, int], None]],
    exclusive_flag: Callable[[], int],
    nonblocking_flag: Callable[[], int],
    lock_operation: Callable[[], Callable[[int, int], None]],
    blocking_error_type: Callable[[], type[BaseException]],
    register_descriptor: Callable[[], Callable[[TextIO], None]],
    unregister_descriptor: Callable[[], Callable[[TextIO], None]],
    unlock_flag: Callable[[], int],
) -> Iterator[TextIO]:
    """Acquire, register, yield, and release one advisory file lock."""

    private_directory()(path.parent)
    stream = file_open()("a+", encoding="utf-8")
    file_chmod()(path, 0o600)
    flags = exclusive_flag()
    if not blocking:
        flags |= nonblocking_flag()
    try:
        lock_operation()(stream.fileno(), flags)
    except blocking_error_type():
        stream.close()
        raise
    register_descriptor()(stream)
    try:
        yield stream
    finally:
        unregister_descriptor()(stream)
        lock_operation()(stream.fileno(), unlock_flag())
        stream.close()


def register_lock_descriptor(
    stream: TextIO,
    *,
    registry: LockRegistryResolver,
    record_factory: LockRecordFactoryResolver,
) -> None:
    """Record one lock stream using dependencies resolved at legacy call points."""

    descriptor = stream.fileno()
    metadata = os.fstat(descriptor)
    registry()[descriptor] = record_factory()(
        stream=weakref.ref(stream),
        device=metadata.st_dev,
        inode=metadata.st_ino,
    )


def unregister_lock_descriptor(
    stream: TextIO,
    *,
    registry: LockRegistryResolver,
) -> None:
    """Forget a descriptor only when its current registry still owns the stream."""

    try:
        descriptor = stream.fileno()
    except (OSError, ValueError):
        return
    registered = registry().get(descriptor)
    if registered is not None and registered.stream() is stream:
        registry().pop(descriptor, None)


def inherited_lock_descriptors(
    *,
    registry: LockRegistryResolver,
) -> tuple[int, ...]:
    """Return sorted, still-authenticated lock descriptors and prune stale entries."""

    inherited: list[int] = []
    for descriptor, registered in list(registry().items()):
        stream = registered.stream()
        if stream is None or stream.closed:
            registry().pop(descriptor, None)
            continue
        try:
            if stream.fileno() != descriptor:
                raise OSError
            metadata = os.fstat(descriptor)
        except (OSError, ValueError):
            registry().pop(descriptor, None)
            continue
        if (metadata.st_dev, metadata.st_ino) != (
            registered.device,
            registered.inode,
        ):
            registry().pop(descriptor, None)
            continue
        inherited.append(descriptor)
    return tuple(sorted(inherited))
