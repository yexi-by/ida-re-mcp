from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue

from ida_re_mcp.application import Application
from ida_re_mcp.config import AppConfig, RuntimePaths
from ida_re_mcp.constants import MAX_INLINE_RESULT_BYTES
from ida_re_mcp.domain.address import ImageAddress
from ida_re_mcp.domain.base import JsonObject
from ida_re_mcp.domain.errors import BusinessErrorCode, ToolExecutionError
from ida_re_mcp.domain.tools import (
    BreakpointSpec,
    DebugBreakpointsInput,
    DebugBreakpointsOutput,
    DebugControlInput,
    DebugControlOutput,
    DebugEstablishInput,
    DebugEstablishOutput,
    DebugEventsInput,
    DebugEventsOutput,
    DebugLaunchTarget,
)
from ida_re_mcp.supervisor.artifacts import parse_artifact_uri
from ida_re_mcp.supervisor.backend import AnalysisBackend, DebugBackend
from ida_re_mcp.supervisor.changes import ChangeSetStore
from ida_re_mcp.supervisor.cursors import CursorCodec
from ida_re_mcp.supervisor.storage import SupervisorStorage
from ida_re_mcp.supervisor.workspaces import (
    ColdValidationReceipt,
    ImageIdentity,
    hash_staging_payload,
)

_SESSION_ID = "session_debug_events"
_STOP_ID = "stop_debug_events"


def _pe_image_identity() -> ImageIdentity:
    return ImageIdentity.model_validate(
        {
            "container": "pe",
            "architecture": "x86_64",
            "bitness": 64,
            "endian": "little",
            "image_size": 0x4000,
        },
        strict=True,
    )


class _FakeDebugBackend:
    def __init__(self) -> None:
        self.events = self._initial_events()
        self.state = "suspended"
        self.stop_id: str | None = _STOP_ID
        self.closed = False
        self.close_count = 0

    async def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        timeout_seconds: float,
    ) -> JsonObject:
        del timeout_seconds
        if operation == "debug.establish":
            return self.session_payload(owned_pid=4242)
        if operation == "debug.events":
            after = input.get("after_sequence")
            limit = input.get("limit")
            assert isinstance(after, int) and not isinstance(after, bool)
            assert isinstance(limit, int) and not isinstance(limit, bool)
            page = [event for event in self.events if cast(int, event["sequence"]) > after][:limit]
            return self.session_payload(events=cast(list[JsonValue], page))
        if operation == "debug.control":
            assert input.get("action") == "continue"
            assert input.get("stop_id") == _STOP_ID
            self.state = "running"
            self.stop_id = None
            event: JsonObject = {
                "sequence": len(self.events) + 1,
                "kind": "execution_resumed",
                "state": "running",
                "timestamp_ns": len(self.events) + 1,
                "provenance": "state_observation",
                "payload": {
                    "action": "continue",
                    "observed_debugger_state": "DSTATE_RUN",
                },
            }
            self.events.append(event)
            return self.session_payload(event=event)
        if operation == "debug.breakpoints" and input.get("action") == "list":
            return self.session_payload(breakpoints=[])
        raise AssertionError(f"测试不应调用 {operation}")

    async def close(self) -> None:
        self.closed = True
        self.close_count += 1

    def session_payload(self, **extra: JsonValue) -> JsonObject:
        return {
            "debug_session_id": _SESSION_ID,
            "state": self.state,
            "stop_id": self.stop_id,
            "latest_sequence": len(self.events),
            "mode": "launch",
            "establish_event": self.events[0],
            **extra,
        }

    @staticmethod
    def _initial_events() -> list[JsonObject]:
        events: list[JsonObject] = [
            {
                "sequence": 1,
                "kind": "process_started",
                "state": "suspended",
                "timestamp_ns": 1,
                "provenance": "ida_event",
                "stop_id": _STOP_ID,
                "payload": {
                    "pid": 4242,
                    "event_id": 1,
                    "address": "0x140001000",
                    "process_state": "suspended",
                    "module": {
                        "name": r"C:\fixtures\debug_target_x64.exe",
                        "base": "0x140000000",
                        "size": 0x4000,
                    },
                },
            }
        ]
        events.extend(
            {
                "sequence": sequence,
                "kind": "information",
                "state": "suspended",
                "timestamp_ns": sequence,
                "provenance": "ida_event",
                "stop_id": _STOP_ID,
                "payload": {
                    "event_id": 13,
                    "reason": f"information-{sequence:03d}-" + "界" * 500,
                },
            }
            for sequence in range(2, 207)
        )
        return events


class _FakeIdaBackend:
    def __init__(self) -> None:
        self.debug = _FakeDebugBackend()

    async def bootstrap(
        self,
        *,
        sample_path: Path,
        staging_path: Path,
        timeout_seconds: float,
    ) -> JsonObject:
        del sample_path, staging_path, timeout_seconds
        raise AssertionError("测试不应调用 bootstrap")

    async def open_analysis(
        self,
        *,
        checkout_path: Path,
        revision: str,
    ) -> AnalysisBackend:
        del checkout_path, revision
        raise AssertionError("测试不应调用 analysis")

    async def mutate(
        self,
        *,
        staging_path: Path,
        operations: Sequence[Mapping[str, JsonValue]],
        timeout_seconds: float,
    ) -> JsonObject:
        del staging_path, operations, timeout_seconds
        raise AssertionError("测试不应调用 mutation")

    async def refine(
        self,
        *,
        staging_path: Path,
        input: Mapping[str, JsonValue],
        timeout_seconds: float,
    ) -> JsonObject:
        del staging_path, input, timeout_seconds
        raise AssertionError("测试不应调用 refine")

    async def expert(
        self,
        *,
        staging_path: Path,
        code: str,
        timeout_seconds: float,
    ) -> JsonObject:
        del staging_path, code, timeout_seconds
        raise AssertionError("测试不应调用 expert")

    async def open_debug(
        self,
        *,
        checkout_path: Path,
        sample_path: Path,
        revision: str,
        allow_attach: bool,
    ) -> DebugBackend:
        assert checkout_path.is_file()
        assert sample_path.is_file()
        assert revision
        assert allow_attach is False
        return self.debug

    async def doctor(self) -> JsonObject:
        return {"available": True}


def _paths(tmp_path: Path) -> RuntimePaths:
    root = tmp_path / "runtime"
    return RuntimePaths(
        data_root=root,
        log_root=root / "logs",
        workspace_root=root / "workspaces",
        artifact_root=root / "artifacts",
        checkout_root=root / "checkouts",
        temp_root=root / "temp",
    )


async def _open_debug_application(
    tmp_path: Path,
    debug_backend: _FakeDebugBackend,
    *,
    idle_seconds: int = 300,
) -> tuple[Application, str]:
    config = AppConfig.model_validate({"workers": {"idle_seconds": idle_seconds}})
    paths = _paths(tmp_path)
    storage = SupervisorStorage.open(config=config, paths=paths)
    source = tmp_path / "debug_target_x64.exe"
    source.write_bytes(b"MZ" + b"\0" * 510)
    workspace = storage.workspaces.create(source)
    staging = storage.workspaces.begin_staging(workspace.workspace_id, expected_revision=None)
    staging.database_path.write_bytes(b"cold-debug-idb")
    receipt = ColdValidationReceipt.create(
        validator="fake_ida_9_3_headless",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )
    revision = storage.workspaces.publish_staging(staging, receipt=receipt)
    backend = _FakeIdaBackend()
    backend.debug = debug_backend
    application = Application(
        config=config,
        storage=storage,
        changes=ChangeSetStore(paths.data_root / "change-sets"),
        cursors=CursorCodec(paths.data_root / "cursor.key"),
        backend=backend,
    )
    try:
        await application.execute_tool(
            "debug.establish",
            DebugEstablishInput(
                workspace_id=workspace.workspace_id,
                revision=revision.revision,
                target=DebugLaunchTarget(kind="launch", stop_on_entry=True),
            ),
        )
    except BaseException:
        await application.aclose()
        raise
    return application, f"image~{workspace.sample_sha256}"


class _QueuedDebugBackend(_FakeDebugBackend):
    """和真实 WorkerProcess 一样，只为单条 worker 命令提供互斥。"""

    def __init__(self) -> None:
        super().__init__()
        self.command_lock = asyncio.Lock()
        self.first_started = asyncio.Event()
        self.release_first = asyncio.Event()
        self.second_started = asyncio.Event()
        self.release_second = asyncio.Event()
        self.close_started = asyncio.Event()
        self.calls: list[tuple[str, str]] = []
        self.breakpoints: dict[str, JsonObject] = {}
        self.next_breakpoint = 0

    async def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        timeout_seconds: float,
    ) -> JsonObject:
        async with self.command_lock:
            task = asyncio.current_task()
            assert task is not None
            name = task.get_name()
            action = input.get("action")
            if operation == "debug.breakpoints":
                assert isinstance(action, str)
                self.calls.append((name, action))
                if len(self.calls) == 1:
                    self.first_started.set()
                    await self.release_first.wait()
                if action == "list":
                    return self.session_payload(breakpoints=list(self.breakpoints.values()))
                if action == "add":
                    location = input.get("location")
                    assert isinstance(location, dict)
                    module = location.get("module")
                    rva = location.get("rva")
                    assert isinstance(module, str) and isinstance(rva, str)
                    self.next_breakpoint += 1
                    identifier = f"breakpoint_{self.next_breakpoint}"
                    value: JsonObject = {
                        "breakpoint_id": identifier,
                        "module": module,
                        "rva": rva,
                        "enabled": True,
                        "active": True,
                        "runtime_address": f"0x{0x140000000 + int(rva, 16):x}",
                    }
                    self.breakpoints[identifier] = value
                    return self.session_payload(breakpoint=value)
                if action == "remove":
                    identifier = input.get("breakpoint_id")
                    assert isinstance(identifier, str)
                    del self.breakpoints[identifier]
                    return self.session_payload(removed=identifier)
                raise AssertionError(action)
            if operation == "debug.events" and name in {"first-events", "second-events"}:
                started, released = (
                    (self.first_started, self.release_first)
                    if name == "first-events"
                    else (self.second_started, self.release_second)
                )
                started.set()
                await released.wait()
            return await super().execute(operation, input, timeout_seconds=timeout_seconds)

    async def close(self) -> None:
        self.close_started.set()
        await super().close()


def test_debug_breakpoint_replacements_are_serialized_as_complete_tools(tmp_path: Path) -> None:
    async def scenario() -> None:
        backend = _QueuedDebugBackend()
        application, image_id = await _open_debug_application(tmp_path, backend)
        tasks: list[asyncio.Task[object]] = []
        try:
            for index, name in enumerate(("first", "second"), start=1):
                tasks.append(
                    asyncio.create_task(
                        application.execute_tool(
                            "debug.breakpoints",
                            DebugBreakpointsInput(
                                debug_session_id=_SESSION_ID,
                                stop_id=_STOP_ID,
                                replace=[
                                    BreakpointSpec(
                                        address=ImageAddress(
                                            kind="image",
                                            image_id=image_id,
                                            rva=f"0x{index * 0x1000:x}",
                                        ),
                                    )
                                ],
                            ),
                        ),
                        name=name,
                    )
                )
                if index == 1:
                    await asyncio.wait_for(backend.first_started.wait(), timeout=1)
            await asyncio.sleep(0)
            backend.release_first.set()
            results = await asyncio.gather(*tasks, return_exceptions=True)
            assert all(isinstance(result, DebugBreakpointsOutput) for result in results)
            assert backend.calls == [
                ("first", "list"),
                ("first", "add"),
                ("first", "list"),
                ("second", "list"),
                ("second", "remove"),
                ("second", "add"),
                ("second", "list"),
            ]
        finally:
            backend.release_first.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            await application.aclose()

    asyncio.run(scenario())


def test_queued_debug_request_cancels_idle_timer_when_it_starts(tmp_path: Path) -> None:
    async def scenario() -> None:
        backend = _QueuedDebugBackend()
        application, _image_id = await _open_debug_application(tmp_path, backend, idle_seconds=1)
        tasks: list[asyncio.Task[object]] = []
        try:
            for name in ("first-events", "second-events"):
                tasks.append(
                    asyncio.create_task(
                        application.execute_tool(
                            "debug.events",
                            DebugEventsInput(
                                debug_session_id=_SESSION_ID,
                                after_sequence=206,
                            ),
                        ),
                        name=name,
                    )
                )
                if name == "first-events":
                    await asyncio.wait_for(backend.first_started.wait(), timeout=1)
            await asyncio.sleep(0)
            backend.release_first.set()
            await asyncio.wait_for(backend.second_started.wait(), timeout=1)
            await tasks[0]
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(backend.close_started.wait(), timeout=1.1)
            assert not tasks[1].done()
            backend.release_second.set()
            assert isinstance(await tasks[1], DebugEventsOutput)
        finally:
            backend.release_first.set()
            backend.release_second.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            await application.aclose()
        assert backend.close_count == 1

    asyncio.run(scenario())


def test_debug_close_waits_for_active_tool_and_rejects_queued_tool(tmp_path: Path) -> None:
    async def scenario() -> None:
        backend = _QueuedDebugBackend()
        application, _image_id = await _open_debug_application(tmp_path, backend)
        tasks: list[asyncio.Task[object]] = []
        closing: asyncio.Task[None] | None = None
        try:
            for name in ("first-events", "second-events"):
                tasks.append(
                    asyncio.create_task(
                        application.execute_tool(
                            "debug.events",
                            DebugEventsInput(
                                debug_session_id=_SESSION_ID,
                                after_sequence=206,
                            ),
                        ),
                        name=name,
                    )
                )
                if name == "first-events":
                    await asyncio.wait_for(backend.first_started.wait(), timeout=1)
            await asyncio.sleep(0)
            closing = asyncio.create_task(application.aclose())
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(backend.close_started.wait(), timeout=0.05)
            assert not closing.done()
            backend.release_first.set()
            assert isinstance(await tasks[0], DebugEventsOutput)
            with pytest.raises(ToolExecutionError) as rejected:
                await tasks[1]
            assert rejected.value.code == BusinessErrorCode.DEBUG_STATE_CONFLICT
            assert not backend.second_started.is_set()
            await closing
        finally:
            backend.release_first.set()
            backend.release_second.set()
            await asyncio.gather(*tasks, return_exceptions=True)
            if closing is not None:
                await closing
            await application.aclose()
        assert backend.close_count == 1

    asyncio.run(scenario())


def test_application_pages_all_debug_events_within_inline_budget(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = AppConfig()
        paths = _paths(tmp_path)
        storage = SupervisorStorage.open(config=config, paths=paths)
        source = tmp_path / "debug_target_x64.exe"
        source.write_bytes(b"MZ" + b"\0" * 510)
        workspace = storage.workspaces.create(source)
        staging = storage.workspaces.begin_staging(
            workspace.workspace_id,
            expected_revision=None,
        )
        staging.database_path.write_bytes(b"cold-debug-idb")
        receipt = ColdValidationReceipt.create(
            validator="fake_ida_9_3_headless",
            component_hashes=hash_staging_payload(staging),
            image_identity=_pe_image_identity(),
        )
        revision = storage.workspaces.publish_staging(staging, receipt=receipt)
        backend = _FakeIdaBackend()
        application = Application(
            config=config,
            storage=storage,
            changes=ChangeSetStore(paths.data_root / "change-sets"),
            cursors=CursorCodec(paths.data_root / "cursor.key"),
            backend=backend,
        )
        try:
            established = await application.execute_tool(
                "debug.establish",
                DebugEstablishInput(
                    workspace_id=workspace.workspace_id,
                    revision=revision.revision,
                    target=DebugLaunchTarget(
                        kind="launch",
                        stop_on_entry=True,
                    ),
                ),
            )
            assert isinstance(established, DebugEstablishOutput)
            assert established.debug_session_id == _SESSION_ID
            assert established.stop_id == _STOP_ID

            cursor = 0
            collected: list[int] = []
            while cursor < 206:
                output = await application.execute_tool(
                    "debug.events",
                    DebugEventsInput(
                        debug_session_id=_SESSION_ID,
                        after_sequence=cursor,
                        limit=200,
                    ),
                )
                assert isinstance(output, DebugEventsOutput)
                serialized = json.dumps(
                    output.model_dump(mode="json"),
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                assert len(serialized) <= MAX_INLINE_RESULT_BYTES
                assert output.events
                assert output.last_sequence == output.events[-1].sequence
                assert output.observed_latest_sequence == 206
                collected.extend(event.sequence for event in output.events)
                cursor = output.last_sequence

            assert collected == list(range(1, 207))
            assert len(collected) == len(set(collected))

            controlled = await application.execute_tool(
                "debug.control",
                DebugControlInput(
                    debug_session_id=_SESSION_ID,
                    action="continue",
                    stop_id=_STOP_ID,
                ),
            )
            assert isinstance(controlled, DebugControlOutput)
            assert controlled.state == "running"
            assert controlled.completion_kind == "execution_resumed"
            assert controlled.completion_provenance == "state_observation"
            assert controlled.observed_debugger_state == "DSTATE_RUN"
        finally:
            await asyncio.gather(application.aclose(), application.aclose())
        assert backend.debug.closed
        assert backend.debug.close_count == 1

    asyncio.run(scenario())


def test_application_stores_oversized_breakpoint_result_as_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        config = AppConfig()
        paths = _paths(tmp_path)
        storage = SupervisorStorage.open(config=config, paths=paths)
        source = tmp_path / "debug_target_x64.exe"
        source.write_bytes(b"MZ" + b"\0" * 510)
        workspace = storage.workspaces.create(source)
        staging = storage.workspaces.begin_staging(
            workspace.workspace_id,
            expected_revision=None,
        )
        staging.database_path.write_bytes(b"cold-debug-idb")
        receipt = ColdValidationReceipt.create(
            validator="fake_ida_9_3_headless",
            component_hashes=hash_staging_payload(staging),
            image_identity=_pe_image_identity(),
        )
        revision = storage.workspaces.publish_staging(staging, receipt=receipt)
        backend = _FakeIdaBackend()
        application = Application(
            config=config,
            storage=storage,
            changes=ChangeSetStore(paths.data_root / "change-sets"),
            cursors=CursorCodec(paths.data_root / "cursor.key"),
            backend=backend,
        )
        try:
            established = await application.execute_tool(
                "debug.establish",
                DebugEstablishInput(
                    workspace_id=workspace.workspace_id,
                    revision=revision.revision,
                    target=DebugLaunchTarget(kind="launch", stop_on_entry=True),
                ),
            )
            assert isinstance(established, DebugEstablishOutput)
            image_id = f"image~{workspace.sample_sha256}"
            specifications = [
                BreakpointSpec(
                    address=ImageAddress(
                        kind="image",
                        image_id=image_id,
                        rva=f"0x{0x1000 + index * 4:x}",
                    )
                )
                for index in range(300)
            ]

            async def fake_apply(_session: object, _plan: object) -> JsonObject:
                return backend.debug.session_payload(
                    breakpoints=[
                        {
                            "breakpoint_id": f"breakpoint_{index:04d}",
                            "module": source.name,
                            "rva": specification.address.rva,
                            "enabled": True,
                            "active": True,
                            "runtime_address": (
                                f"0x{0x140000000 + int(specification.address.rva, 16):x}"
                            ),
                        }
                        for index, specification in enumerate(specifications)
                    ]
                )

            monkeypatch.setattr(application, "_apply_breakpoint_plan", fake_apply)
            output = await application.execute_tool(
                "debug.breakpoints",
                DebugBreakpointsInput(
                    debug_session_id=_SESSION_ID,
                    stop_id=_STOP_ID,
                    replace=specifications,
                ),
            )
            assert isinstance(output, DebugBreakpointsOutput)
            assert output.breakpoints == []
            assert output.result_artifact is not None
            serialized = json.dumps(
                output.model_dump(mode="json"),
                separators=(",", ":"),
            ).encode()
            assert len(serialized) <= MAX_INLINE_RESULT_BYTES
            payload = storage.artifacts.read_all(
                *parse_artifact_uri(output.result_artifact.uri),
            )
            full = DebugBreakpointsOutput.model_validate_json(payload, strict=True)
            assert len(full.breakpoints) == len(specifications)
        finally:
            await application.aclose()

    asyncio.run(scenario())
