#!/usr/bin/env python3
"""Direct parity tests for lock-descriptor bookkeeping and inheritance."""

from __future__ import annotations

import gc
import importlib
import inspect
import os
import subprocess
import sys
import tempfile
import unittest
import weakref
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src"


class StreamStub:
    def __init__(
        self,
        descriptor: int,
        *,
        closed: bool = False,
        error: BaseException | None = None,
        events: list[tuple[str, object]] | None = None,
    ) -> None:
        self.descriptor = descriptor
        self.closed = closed
        self.error = error
        self.events = events

    def fileno(self) -> int:
        if self.events is not None:
            self.events.append(("fileno", self.descriptor))
        if self.error is not None:
            raise self.error
        return self.descriptor


class ReferenceStub:
    def __init__(
        self,
        value: object | None,
        descriptor: int,
        events: list[tuple[str, object]],
    ) -> None:
        self.value = value
        self.descriptor = descriptor
        self.events = events

    def __call__(self) -> object | None:
        self.events.append(("reference", self.descriptor))
        return self.value


class RecordingRegistry(dict[int, object]):
    def __init__(
        self,
        values: dict[int, object] | None = None,
        *,
        events: list[tuple[str, object]],
        fail_set: int | None = None,
        fail_pop: int | None = None,
    ) -> None:
        super().__init__(values or {})
        self.events = events
        self.fail_set = fail_set
        self.fail_pop = fail_pop

    def __setitem__(self, descriptor: int, value: object) -> None:
        self.events.append(("set", descriptor))
        if descriptor == self.fail_set:
            raise RuntimeError(f"set failed for {descriptor}")
        super().__setitem__(descriptor, value)

    def get(self, descriptor: int, default: object = None) -> object:
        self.events.append(("get", descriptor))
        return super().get(descriptor, default)

    def items(self):
        self.events.append(("items", None))
        return super().items()

    def pop(self, descriptor: int, default: object = None) -> object:
        self.events.append(("pop", descriptor))
        if descriptor == self.fail_pop:
            raise RuntimeError(f"pop failed for {descriptor}")
        return super().pop(descriptor, default)


class LockPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(SOURCE_ROOT))
        cls.locks = importlib.import_module("worktree_marshal.locks")
        cls.engine = importlib.import_module("worktree_marshal.engine")

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            sys.path.remove(str(SOURCE_ROOT))
        except ValueError:
            pass

    def record(
        self,
        stream: object,
        *,
        descriptor: int,
        device: int = 1,
        inode: int | None = None,
        events: list[tuple[str, object]] | None = None,
    ):
        reference = (
            ReferenceStub(stream, descriptor, events)
            if events is not None
            else weakref.ref(stream)
        )
        return self.locks.RegisteredLockDescriptor(
            stream=reference,
            device=device,
            inode=descriptor if inode is None else inode,
        )

    def test_locks_import_is_engine_free_and_environment_neutral(self) -> None:
        script = (
            "import os, sys; "
            "before = dict(os.environ); "
            f"sys.path.insert(0, {str(SOURCE_ROOT)!r}); "
            "import worktree_marshal.locks; "
            "raise SystemExit("
            "'worktree_marshal.engine' in sys.modules or dict(os.environ) != before"
            ")"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=PACKAGE_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_record_type_and_engine_alias_are_exact(self) -> None:
        self.assertIs(
            self.engine.RegisteredLockDescriptor,
            self.locks.RegisteredLockDescriptor,
        )
        self.assertEqual(
            tuple(field.name for field in fields(self.locks.RegisteredLockDescriptor)),
            ("stream", "device", "inode"),
        )
        stream = StreamStub(7)
        record = self.record(stream, descriptor=7)
        with self.assertRaises(FrozenInstanceError):
            record.device = 8

    def test_registration_order_record_and_failure_boundaries_are_exact(
        self,
    ) -> None:
        descriptor = 41
        events: list[tuple[str, object]] = []
        stream = StreamStub(descriptor, events=events)
        old_record = object()
        registry = RecordingRegistry(
            {descriptor: old_record},
            events=events,
        )

        def fstat(value: int):
            events.append(("fstat", value))
            return SimpleNamespace(st_dev=7, st_ino=9)

        def record_factory(**values):
            events.append(("factory", values["stream"]() is stream))
            return self.locks.RegisteredLockDescriptor(**values)

        def resolve_record_factory():
            events.append(("factory lookup", None))
            return record_factory

        def make_reference(value):
            events.append(("weakref", value is stream))
            return weakref.ref(value)

        def resolve_registry():
            events.append(("registry lookup", None))
            return registry

        with (
            mock.patch.object(self.locks.os, "fstat", side_effect=fstat),
            mock.patch.object(
                self.locks,
                "weakref",
                SimpleNamespace(ref=make_reference),
            ),
        ):
            self.locks.register_lock_descriptor(
                stream,
                registry=resolve_registry,
                record_factory=resolve_record_factory,
            )

        self.assertEqual(
            events,
            [
                ("fileno", descriptor),
                ("fstat", descriptor),
                ("factory lookup", None),
                ("weakref", True),
                ("factory", True),
                ("registry lookup", None),
                ("set", descriptor),
            ],
        )
        record = registry[descriptor]
        self.assertIs(record.stream(), stream)
        self.assertEqual((record.device, record.inode), (7, 9))

        failure_cases = (
            ("fileno", StreamStub(descriptor, error=OSError("fileno")), None),
            ("fstat", StreamStub(descriptor), OSError("fstat")),
            ("factory", StreamStub(descriptor), None),
            ("set", StreamStub(descriptor), None),
        )
        for failure, failing_stream, fstat_error in failure_cases:
            with self.subTest(failure=failure):
                events = []
                failing_stream.events = events
                registry = RecordingRegistry(
                    {descriptor: old_record},
                    events=events,
                    fail_set=descriptor if failure == "set" else None,
                )

                def failing_fstat(value: int):
                    events.append(("fstat", value))
                    if fstat_error is not None:
                        raise fstat_error
                    return SimpleNamespace(st_dev=7, st_ino=9)

                def failing_factory(**values):
                    events.append(("factory", values["stream"]() is failing_stream))
                    if failure == "factory":
                        raise RuntimeError("factory failed")
                    return self.locks.RegisteredLockDescriptor(**values)

                def resolve_failing_factory():
                    events.append(("factory lookup", None))
                    return failing_factory

                def make_failing_reference(value):
                    events.append(("weakref", value is failing_stream))
                    return weakref.ref(value)

                def resolve_failing_registry():
                    events.append(("registry lookup", None))
                    return registry

                with (
                    mock.patch.object(
                        self.locks.os,
                        "fstat",
                        side_effect=failing_fstat,
                    ),
                    mock.patch.object(
                        self.locks,
                        "weakref",
                        SimpleNamespace(ref=make_failing_reference),
                    ),
                    self.assertRaises(
                        OSError if failure in {"fileno", "fstat"} else RuntimeError
                    ),
                ):
                    self.locks.register_lock_descriptor(
                        failing_stream,
                        registry=resolve_failing_registry,
                        record_factory=resolve_failing_factory,
                    )

                self.assertIs(registry[descriptor], old_record)
                expected_prefix = [("fileno", descriptor)]
                if failure != "fileno":
                    expected_prefix.append(("fstat", descriptor))
                if failure in {"factory", "set"}:
                    expected_prefix.extend(
                        (
                            ("factory lookup", None),
                            ("weakref", True),
                            ("factory", True),
                        )
                    )
                if failure == "set":
                    expected_prefix.extend(
                        (
                            ("registry lookup", None),
                            ("set", descriptor),
                        )
                    )
                self.assertEqual(events, expected_prefix)

        events = []

        class NonWeakReferenceableStream:
            __slots__ = ("descriptor", "events")

            def __init__(
                self,
                value: int,
                observed: list[tuple[str, object]],
            ) -> None:
                self.descriptor = value
                self.events = observed

            def fileno(self) -> int:
                self.events.append(("fileno", self.descriptor))
                return self.descriptor

        non_weak_referenceable = NonWeakReferenceableStream(descriptor, events)
        registry = RecordingRegistry(
            {descriptor: old_record},
            events=events,
        )
        record_factory = mock.Mock()

        def successful_fstat(value: int):
            events.append(("fstat", value))
            return SimpleNamespace(st_dev=7, st_ino=9)

        def resolve_non_weak_factory():
            events.append(("factory lookup", None))
            return record_factory

        registry_resolver = mock.Mock(return_value=registry)
        with (
            mock.patch.object(
                self.locks.os,
                "fstat",
                side_effect=successful_fstat,
            ),
            self.assertRaisesRegex(TypeError, "weak reference"),
        ):
            self.locks.register_lock_descriptor(
                non_weak_referenceable,
                registry=registry_resolver,
                record_factory=resolve_non_weak_factory,
            )

        self.assertEqual(
            events,
            [
                ("fileno", descriptor),
                ("fstat", descriptor),
                ("factory lookup", None),
            ],
        )
        record_factory.assert_not_called()
        registry_resolver.assert_not_called()
        self.assertIs(registry[descriptor], old_record)

    def test_registration_releases_factory_before_registry_resolution(
        self,
    ) -> None:
        initial_registry: dict[int, object] = {}
        finalized_registry: dict[int, object] = {}
        current_registry = [initial_registry]
        events: list[str] = []
        sentinel = object()

        class CyclicFactory:
            def __init__(inner_self) -> None:
                inner_self.cycle = inner_self

            def __call__(inner_self, **values):
                events.append("factory call")
                return sentinel

        factory = CyclicFactory()

        def factory_finalized(reference) -> None:
            events.append("factory finalized")
            current_registry[0] = finalized_registry

        factory_reference = weakref.ref(factory, factory_finalized)
        factory_holder = [factory]
        del factory

        def resolve_factory():
            events.append("factory lookup")
            return factory_holder.pop()

        def resolve_registry():
            events.append("registry lookup")
            gc.collect()
            events.append("registry resolved")
            return current_registry[0]

        with tempfile.TemporaryFile(mode="w+") as stream:
            descriptor = stream.fileno()
            self.locks.register_lock_descriptor(
                stream,
                registry=resolve_registry,
                record_factory=resolve_factory,
            )

        self.assertIsNone(factory_reference())
        self.assertEqual(initial_registry, {})
        self.assertIs(finalized_registry[descriptor], sentinel)
        self.assertEqual(
            events,
            [
                "factory lookup",
                "factory call",
                "registry lookup",
                "factory finalized",
                "registry resolved",
            ],
        )

    def test_engine_wrappers_forward_rebound_registry_and_record_factory(
        self,
    ) -> None:
        registry: dict[int, object] = {}
        with (
            tempfile.TemporaryFile(mode="w+") as stream,
            mock.patch.object(self.engine, "_LOCK_FD_REGISTRY", registry),
        ):
            descriptor = stream.fileno()
            self.engine.register_lock_descriptor(stream)
            self.assertEqual(
                self.engine.inherited_lock_descriptors(),
                (descriptor,),
            )
            self.engine.unregister_lock_descriptor(stream)
            self.assertEqual(registry, {})

        sentinel = object()
        factory_calls: list[dict[str, object]] = []

        def replacement_factory(**values):
            factory_calls.append(values)
            return sentinel

        registry = {}
        with (
            tempfile.TemporaryFile(mode="w+") as stream,
            mock.patch.object(self.engine, "_LOCK_FD_REGISTRY", registry),
            mock.patch.object(
                self.engine,
                "RegisteredLockDescriptor",
                replacement_factory,
            ),
        ):
            self.engine.register_lock_descriptor(stream)
            descriptor = stream.fileno()

        self.assertIs(registry[descriptor], sentinel)
        self.assertEqual(len(factory_calls), 1)
        self.assertIs(factory_calls[0]["stream"](), stream)

    def test_engine_registration_resolves_reentrant_rebindings_at_legacy_points(
        self,
    ) -> None:
        initial_registry: dict[int, object] = {}
        after_fileno_registry: dict[int, object] = {}
        after_factory_registry: dict[int, object] = {}
        sentinel = object()
        factory_calls: list[dict[str, object]] = []
        initial_factory = mock.Mock()

        def rebound_factory(**values):
            factory_calls.append(values)
            self.engine._LOCK_FD_REGISTRY = after_factory_registry
            return sentinel

        with tempfile.TemporaryFile(mode="w+") as backing:
            descriptor = backing.fileno()

            class RebindingStream:
                closed = False

                def fileno(inner_self) -> int:
                    self.engine._LOCK_FD_REGISTRY = after_fileno_registry
                    self.engine.RegisteredLockDescriptor = rebound_factory
                    return descriptor

            stream = RebindingStream()
            with (
                mock.patch.object(
                    self.engine,
                    "_LOCK_FD_REGISTRY",
                    initial_registry,
                ),
                mock.patch.object(
                    self.engine,
                    "RegisteredLockDescriptor",
                    initial_factory,
                ),
            ):
                self.engine.register_lock_descriptor(stream)

        initial_factory.assert_not_called()
        self.assertEqual(initial_registry, {})
        self.assertEqual(after_fileno_registry, {})
        self.assertIs(after_factory_registry[descriptor], sentinel)
        self.assertEqual(len(factory_calls), 1)
        self.assertIs(factory_calls[0]["stream"](), stream)

    def test_unregistration_requires_the_same_live_stream(self) -> None:
        descriptor = 51
        events: list[tuple[str, object]] = []
        owner = StreamStub(descriptor, events=events)
        other = StreamStub(descriptor, events=events)
        registry = RecordingRegistry(events=events)
        dict.__setitem__(
            registry,
            descriptor,
            self.locks.RegisteredLockDescriptor(
                stream=ReferenceStub(owner, descriptor, events),
                device=1,
                inode=2,
            ),
        )

        self.locks.unregister_lock_descriptor(other, registry=lambda: registry)
        self.assertIn(descriptor, registry)
        self.assertEqual(
            events,
            [
                ("fileno", descriptor),
                ("get", descriptor),
                ("reference", descriptor),
            ],
        )

        events.clear()
        self.locks.unregister_lock_descriptor(owner, registry=lambda: registry)
        self.assertEqual(registry, {})
        self.assertEqual(
            events,
            [
                ("fileno", descriptor),
                ("get", descriptor),
                ("reference", descriptor),
                ("pop", descriptor),
            ],
        )

        for error in (OSError("closed"), ValueError("closed")):
            with self.subTest(caught=type(error).__name__):
                registry = {descriptor: object()}
                self.locks.unregister_lock_descriptor(
                    StreamStub(descriptor, error=error),
                    registry=lambda: registry,
                )
                self.assertIn(descriptor, registry)

        registry = {descriptor: object()}
        with self.assertRaisesRegex(TypeError, "^unexpected$"):
            self.locks.unregister_lock_descriptor(
                StreamStub(descriptor, error=TypeError("unexpected")),
                registry=lambda: registry,
            )
        self.assertIn(descriptor, registry)

    def test_unregistration_pop_failure_preserves_exact_partial_state(self) -> None:
        descriptor = 52
        events: list[tuple[str, object]] = []
        owner = StreamStub(descriptor, events=events)
        registry = RecordingRegistry(events=events, fail_pop=descriptor)
        dict.__setitem__(
            registry,
            descriptor,
            self.locks.RegisteredLockDescriptor(
                stream=ReferenceStub(owner, descriptor, events),
                device=1,
                inode=2,
            ),
        )

        def resolve_registry():
            events.append(("registry lookup", None))
            return registry

        with self.assertRaisesRegex(RuntimeError, "^pop failed for 52$"):
            self.locks.unregister_lock_descriptor(
                owner,
                registry=resolve_registry,
            )

        self.assertEqual(
            events,
            [
                ("fileno", descriptor),
                ("registry lookup", None),
                ("get", descriptor),
                ("reference", descriptor),
                ("registry lookup", None),
                ("pop", descriptor),
            ],
        )
        self.assertIn(descriptor, registry)

    def test_inherited_descriptor_stream_errors_are_pruned_exactly(self) -> None:
        descriptor = 53
        for error in (OSError("unavailable"), ValueError("closed")):
            with self.subTest(caught=type(error).__name__):
                events: list[tuple[str, object]] = []
                stream = StreamStub(
                    descriptor,
                    error=error,
                    events=events,
                )
                registry = RecordingRegistry(events=events)
                dict.__setitem__(
                    registry,
                    descriptor,
                    self.locks.RegisteredLockDescriptor(
                        stream=ReferenceStub(stream, descriptor, events),
                        device=1,
                        inode=2,
                    ),
                )

                self.assertEqual(
                    self.locks.inherited_lock_descriptors(
                        registry=lambda: registry,
                    ),
                    (),
                )
                self.assertEqual(
                    events,
                    [
                        ("items", None),
                        ("reference", descriptor),
                        ("fileno", descriptor),
                        ("pop", descriptor),
                    ],
                )
                self.assertEqual(registry, {})

    def test_inherited_descriptors_prune_stale_entries_and_sort_valid_ones(
        self,
    ) -> None:
        events: list[tuple[str, object]] = []
        registry = RecordingRegistry(events=events)
        streams: list[StreamStub] = []

        def add(
            descriptor: int,
            stream: StreamStub | None,
            *,
            device: int = 1,
            inode: int | None = None,
        ) -> None:
            if stream is not None:
                streams.append(stream)
            dict.__setitem__(
                registry,
                descriptor,
                self.locks.RegisteredLockDescriptor(
                    stream=ReferenceStub(stream, descriptor, events),
                    device=device,
                    inode=descriptor if inode is None else inode,
                ),
            )

        add(70, None)
        add(60, StreamStub(60, closed=True, events=events))
        add(50, StreamStub(500, events=events))
        add(40, StreamStub(40, events=events))
        add(39, StreamStub(39, events=events))
        add(30, StreamStub(30, events=events), device=3, inode=30)
        add(20, StreamStub(20, events=events))
        add(10, StreamStub(10, events=events))

        def fstat(descriptor: int):
            events.append(("fstat", descriptor))
            if descriptor == 40:
                raise OSError("unavailable")
            if descriptor == 39:
                raise ValueError("invalid")
            return SimpleNamespace(st_dev=1, st_ino=descriptor)

        with mock.patch.object(self.locks.os, "fstat", side_effect=fstat):
            inherited = self.locks.inherited_lock_descriptors(
                registry=lambda: registry,
            )

        self.assertEqual(inherited, (10, 20))
        self.assertEqual(set(registry), {10, 20})
        self.assertEqual(
            events,
            [
                ("items", None),
                ("reference", 70),
                ("pop", 70),
                ("reference", 60),
                ("pop", 60),
                ("reference", 50),
                ("fileno", 500),
                ("pop", 50),
                ("reference", 40),
                ("fileno", 40),
                ("fstat", 40),
                ("pop", 40),
                ("reference", 39),
                ("fileno", 39),
                ("fstat", 39),
                ("pop", 39),
                ("reference", 30),
                ("fileno", 30),
                ("fstat", 30),
                ("pop", 30),
                ("reference", 20),
                ("fileno", 20),
                ("fstat", 20),
                ("reference", 10),
                ("fileno", 10),
                ("fstat", 10),
            ],
        )

    def test_inherited_pruning_failure_preserves_exact_partial_state(self) -> None:
        events: list[tuple[str, object]] = []
        registry = RecordingRegistry(events=events, fail_pop=2)
        for descriptor in (1, 2, 3):
            dict.__setitem__(
                registry,
                descriptor,
                self.locks.RegisteredLockDescriptor(
                    stream=ReferenceStub(None, descriptor, events),
                    device=1,
                    inode=descriptor,
                ),
            )

        with self.assertRaisesRegex(RuntimeError, "^pop failed for 2$"):
            self.locks.inherited_lock_descriptors(
                registry=lambda: registry,
            )

        self.assertEqual(
            events,
            [
                ("items", None),
                ("reference", 1),
                ("pop", 1),
                ("reference", 2),
                ("pop", 2),
            ],
        )
        self.assertEqual(set(registry), {2, 3})

        descriptor = 8
        stream = StreamStub(descriptor)
        registry = {
            descriptor: self.record(
                stream,
                descriptor=descriptor,
            )
        }
        with (
            mock.patch.object(
                self.locks.os,
                "fstat",
                side_effect=TypeError("unexpected"),
            ),
            self.assertRaisesRegex(TypeError, "^unexpected$"),
        ):
            self.locks.inherited_lock_descriptors(
                registry=lambda: registry,
            )
        self.assertIn(descriptor, registry)

    def test_inherited_descriptors_prune_an_actual_dead_weak_reference(self) -> None:
        descriptor = 11
        stream = StreamStub(descriptor)
        registry = {
            descriptor: self.record(
                stream,
                descriptor=descriptor,
            )
        }
        del stream
        gc.collect()

        self.assertEqual(
            self.locks.inherited_lock_descriptors(
                registry=lambda: registry,
            ),
            (),
        )
        self.assertEqual(registry, {})

    def test_inherited_pruning_keeps_snapshot_replacement_behavior(self) -> None:
        descriptor = 12
        replacement = StreamStub(descriptor)
        replacement_record = self.record(
            replacement,
            descriptor=descriptor,
        )
        registry: dict[int, object] = {}

        class ReplacingClosedStream:
            def __init__(self, value: int) -> None:
                self.descriptor = value

            @property
            def closed(self) -> bool:
                registry[descriptor] = replacement_record
                return True

            def fileno(self) -> int:
                return self.descriptor

        stale = ReplacingClosedStream(descriptor)
        registry[descriptor] = self.record(
            stale,
            descriptor=descriptor,
        )

        self.assertEqual(
            self.locks.inherited_lock_descriptors(
                registry=lambda: registry,
            ),
            (),
        )
        self.assertEqual(registry, {})

    def test_inherited_pruning_resolves_registry_again_after_snapshot(
        self,
    ) -> None:
        descriptor = 13
        snapshot_registry: dict[int, object] = {}
        current_registry: list[dict[int, object]] = [snapshot_registry]
        replacement_registry = {descriptor: object()}

        class RebindingDeadReference:
            def __call__(inner_self):
                current_registry[0] = replacement_registry
                return None

        snapshot_record = self.locks.RegisteredLockDescriptor(
            stream=RebindingDeadReference(),
            device=1,
            inode=descriptor,
        )
        snapshot_registry[descriptor] = snapshot_record

        self.assertEqual(
            self.locks.inherited_lock_descriptors(
                registry=lambda: current_registry[0],
            ),
            (),
        )
        self.assertIs(snapshot_registry[descriptor], snapshot_record)
        self.assertEqual(replacement_registry, {})

    def test_inherited_descriptors_reject_reused_file_identity(self) -> None:
        registry: dict[int, object] = {}
        with (
            tempfile.TemporaryFile() as original,
            tempfile.TemporaryFile() as replacement,
        ):
            descriptor = original.fileno()
            before = os.fstat(descriptor)
            replacement_identity = os.fstat(replacement.fileno())
            self.assertNotEqual(
                (before.st_dev, before.st_ino),
                (replacement_identity.st_dev, replacement_identity.st_ino),
            )
            self.locks.register_lock_descriptor(
                original,
                registry=lambda: registry,
                record_factory=lambda: self.locks.RegisteredLockDescriptor,
            )
            os.dup2(replacement.fileno(), descriptor)

            self.assertEqual(
                self.locks.inherited_lock_descriptors(
                    registry=lambda: registry,
                ),
                (),
            )
            self.assertEqual(registry, {})

    def test_engine_file_lock_and_command_keep_dynamic_wrapper_lookups(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock_path = Path(temporary) / "test.lock"
            with (
                mock.patch.object(
                    self.engine,
                    "register_lock_descriptor",
                ) as register,
                mock.patch.object(
                    self.engine,
                    "unregister_lock_descriptor",
                ) as unregister,
            ):
                with self.engine.file_lock(lock_path) as stream:
                    register.assert_called_once_with(stream)
                    unregister.assert_not_called()
                unregister.assert_called_once_with(stream)

                register.reset_mock()
                unregister.reset_mock()
                with self.assertRaisesRegex(RuntimeError, "^context failed$"):
                    with self.engine.file_lock(lock_path) as stream:
                        raise RuntimeError("context failed")
                register.assert_called_once_with(stream)
                unregister.assert_called_once_with(stream)

        completed = subprocess.CompletedProcess(
            args=["example"],
            returncode=0,
            stdout="",
            stderr="",
        )
        with (
            mock.patch.object(
                self.engine,
                "inherited_lock_descriptors",
                return_value=(9, 3),
            ) as inherited,
            mock.patch.object(
                self.engine.subprocess,
                "run",
                return_value=completed,
            ) as run,
        ):
            observed = self.engine.command(
                ("example",),
                cwd=PACKAGE_ROOT,
            )

        self.assertIs(observed, completed)
        inherited.assert_called_once_with()
        self.assertEqual(run.call_args.kwargs["pass_fds"], (9, 3))

    def test_file_lock_kernel_and_wrapper_surfaces_are_exact(self) -> None:
        self.assertEqual(
            tuple(inspect.signature(self.locks.file_lock).parameters),
            (
                "path",
                "blocking",
                "private_directory",
                "file_open",
                "file_chmod",
                "exclusive_flag",
                "nonblocking_flag",
                "lock_operation",
                "blocking_error_type",
                "register_descriptor",
                "unregister_descriptor",
                "unlock_flag",
            ),
        )
        self.assertEqual(
            str(inspect.signature(self.engine.file_lock)),
            "(path: 'Path', *, blocking: 'bool' = True) -> "
            "'Iterator[TextIO]'",
        )

    def test_real_file_lock_is_inherited_and_released_on_every_exit(self) -> None:
        registry: dict[int, object] = {}
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(self.engine, "_LOCK_FD_REGISTRY", registry),
        ):
            lock_path = Path(temporary) / "real.lock"
            with self.engine.file_lock(lock_path) as stream:
                descriptor = stream.fileno()
                self.assertIn(descriptor, registry)
                completed = self.engine.command(
                    (
                        sys.executable,
                        "-c",
                        "import os, sys; os.fstat(int(sys.argv[1]))",
                        str(descriptor),
                    ),
                    cwd=PACKAGE_ROOT,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

            self.assertTrue(stream.closed)
            self.assertEqual(registry, {})

            with self.assertRaisesRegex(RuntimeError, "^context failed$"):
                with self.engine.file_lock(
                    lock_path,
                    blocking=False,
                ) as exceptional_stream:
                    self.assertIn(exceptional_stream.fileno(), registry)
                    raise RuntimeError("context failed")

            self.assertTrue(exceptional_stream.closed)
            self.assertEqual(registry, {})
            with self.engine.file_lock(lock_path, blocking=False):
                pass
            self.assertEqual(registry, {})


if __name__ == "__main__":
    unittest.main()
