from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import threading
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue, ValidationError

from ida_re_mcp.application import Application
from ida_re_mcp.config import AppConfig, PolicyConfig, RuntimePaths, StorageConfig, WorkerConfig
from ida_re_mcp.constants import MAX_INLINE_RESULT_BYTES, RESOURCE_CHUNK_BYTES
from ida_re_mcp.domain.address import DatabaseAddress
from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.errors import BusinessErrorCode, ToolExecutionError
from ida_re_mcp.domain.tools import (
    AnalysisRefineInput,
    AnalysisRefineOutput,
    ChangeApplyInput,
    ChangeApplyOutput,
    ChangeConflict,
    ChangeImpact,
    ChangePrepareInput,
    ChangePrepareOutput,
    ExpertExecuteInput,
    ExpertExecuteOutput,
    ImageSummary,
    OperationCancelInput,
    OperationCancelOutput,
    OperationWaitInput,
    OperationWaitOutput,
    ProgramOverviewInput,
    ProgramOverviewOutput,
    ProgramSearchInput,
    ProgramSearchOutput,
    RenameOperation,
    WorkspaceAnalysisOutcome,
    WorkspaceCreateInput,
    WorkspaceCreateOutput,
    WorkspaceExportInput,
    WorkspaceExportOutput,
    WorkspaceGetInput,
    WorkspaceGetOutput,
    WorkspaceListInput,
    WorkspaceListOutput,
    WorkspaceRetryInput,
    WorkspaceRetryOutput,
    WorkspaceSummary,
)
from ida_re_mcp.supervisor._fs import atomic_write_json
from ida_re_mcp.supervisor._process_lock import (
    AsyncInterprocessFileLock,
    AsyncInterprocessSlotLease,
)
from ida_re_mcp.supervisor.artifacts import (
    ArtifactChunk,
    ArtifactMetadata,
    ArtifactNotFoundError,
    ArtifactStore,
    parse_artifact_uri,
)
from ida_re_mcp.supervisor.backend import AnalysisBackend, DebugBackend
from ida_re_mcp.supervisor.changes import ChangeSetStore
from ida_re_mcp.supervisor.cursors import CursorCodec
from ida_re_mcp.supervisor.native_formats import NativeImageIdentity, inspect_native_image
from ida_re_mcp.supervisor.storage import SupervisorStorage
from ida_re_mcp.supervisor.workers import WorkerProcessError
from ida_re_mcp.supervisor.workspaces import (
    ColdValidationReceipt,
    ImageIdentity,
    RevisionCheckout,
    RevisionSnapshot,
    WorkspaceSnapshot,
    hash_staging_payload,
)
from ida_re_mcp.worker.errors import WorkerError


class _FakeAnalysisBackend:
    def __init__(
        self,
        owner: _FakeIdaBackend,
        checkout_path: Path,
        revision: str,
    ) -> None:
        self._owner = owner
        self._checkout_path = checkout_path
        self._revision = revision
        self._closed = False

    async def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        timeout_seconds: float,
    ) -> JsonObject:
        return await self._owner.execute_analysis(
            checkout_path=self._checkout_path,
            revision=self._revision,
            operation=operation,
            input=input,
            timeout_seconds=timeout_seconds,
        )

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._owner.analysis_close_count += 1


class _FakeIdaBackend:
    def __init__(
        self,
        sample_sha256: str,
        *,
        fail_mutation_call: int | None = None,
        block_refine: bool = False,
        successful_refine: bool = False,
        analysis_error_code: str | None = None,
        analysis_runtime_error: bool = False,
        large_overview_count: int = 0,
        cold_sample_sha256: str | None = None,
        cold_mismatch_call: int | None = None,
        cold_container: str | None = None,
        successful_expert: bool = False,
        fail_expert_with_timeout: bool = False,
    ) -> None:
        self.sample_sha256 = sample_sha256
        self.fail_mutation_call = fail_mutation_call
        self.block_refine = block_refine
        self.successful_refine = successful_refine
        self.analysis_error_code = analysis_error_code
        self.analysis_runtime_error = analysis_runtime_error
        self.large_overview_count = large_overview_count
        self.cold_sample_sha256 = cold_sample_sha256
        self.cold_mismatch_call = cold_mismatch_call
        self.cold_container = cold_container
        self.successful_expert = successful_expert
        self.fail_expert_with_timeout = fail_expert_with_timeout
        self.cold_analysis_calls = 0
        self.mutation_calls = 0
        self.search_requests: list[tuple[int, int]] = []
        self.refine_started = threading.Event()
        self.analysis_open_count = 0
        self.analysis_close_count = 0
        self.analysis_timeouts: list[float] = []
        self.expert_timeouts: list[float] = []

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
        self.analysis_open_count += 1
        return _FakeAnalysisBackend(self, checkout_path, revision)

    async def execute_analysis(
        self,
        *,
        checkout_path: Path,
        revision: str,
        operation: str,
        input: Mapping[str, JsonValue],
        timeout_seconds: float,
    ) -> JsonObject:
        self.analysis_timeouts.append(timeout_seconds)
        assert checkout_path.is_file()
        is_cold_staging = ".staging" in checkout_path.parts and operation == "program.overview"
        if is_cold_staging:
            self.cold_analysis_calls += 1
        if self.analysis_error_code is not None:
            raise WorkerError(self.analysis_error_code, "公开 worker 失败")
        if self.analysis_runtime_error:
            raise RuntimeError("sensitive internal backend detail")
        if operation == "program.search":
            offset = input.get("offset")
            limit = input.get("limit")
            domains = input.get("domains")
            assert isinstance(offset, int)
            assert isinstance(limit, int)
            assert isinstance(domains, list)
            self.search_requests.append((offset, limit))
            total = 80
            returned = min(limit, max(0, total - offset))
            has_more = offset + returned < total
            items: list[JsonValue] = [
                {
                    "domain": "name",
                    "address": f"0x{0x140001000 + offset + index:x}",
                    "name": f"match-{offset + index}-" + "x" * 3_000,
                }
                for index in range(returned)
            ]
            return {
                "domains": domains,
                "items": items,
                "page": {
                    "offset": offset,
                    "limit": limit,
                    "returned": returned,
                    "has_more": has_more,
                    "next_offset": offset + limit if has_more else None,
                },
                "coverage": {
                    "complete": not has_more,
                    "truncated": has_more,
                    "reasons": ["page_has_more"] if has_more else [],
                },
                "provenance": {
                    "checkout_sha256": _sha256(checkout_path),
                    "database_change_count": 0,
                    "backend": "fake-ida-9.3-headless",
                    "revision": revision,
                    "processor": "metapc",
                },
            }
        assert operation == "program.overview"
        functions: list[JsonValue] = [
            {
                "address": f"0x{0x140001000 + index:x}",
                "name": f"function_{index:03d}_" + "x" * 512,
            }
            for index in range(self.large_overview_count)
        ]
        return {
            "image": {
                "input_name": "sample.exe",
                "sha256": (
                    self.cold_sample_sha256
                    if (
                        is_cold_staging
                        and self.cold_sample_sha256 is not None
                        and (
                            self.cold_mismatch_call is None
                            or self.cold_analysis_calls == self.cold_mismatch_call
                        )
                    )
                    else self.sample_sha256
                ),
                "imagebase": "0x140000000",
                "minimum_address": "0x140001000",
                "maximum_address": "0x140003000",
                "processor": "metapc",
                "architecture": "x86_64",
                "image_size": 0x3000,
                "bitness": 64,
                "endianness": "little",
                "container": (
                    self.cold_container
                    if (
                        is_cold_staging
                        and self.cold_container is not None
                        and (
                            self.cold_mismatch_call is None
                            or self.cold_analysis_calls == self.cold_mismatch_call
                        )
                    )
                    else "pe"
                ),
            },
            "segments": [],
            "entry_points": [],
            "exports": [],
            "imports": [],
            "fixups": [],
            "unwind_regions": [],
            "functions": functions,
            "strings": [],
            "counts": {
                "segments": 0,
                "entry_points": 0,
                "exports": 0,
                "import_modules": 0,
                "imports": 0,
                "functions": self.large_overview_count,
                "strings": 0,
                "fixups": 0,
                "unwind_functions": 0,
                "catch_functions": 0,
            },
            "coverage": {"complete": True, "truncated": False},
            "provenance": {
                "checkout_sha256": _sha256(checkout_path),
                "database_change_count": 0,
                "backend": "fake-ida-9.3-headless",
                "revision": revision,
                "processor": "metapc",
            },
        }

    async def mutate(
        self,
        *,
        staging_path: Path,
        operations: Sequence[Mapping[str, JsonValue]],
        timeout_seconds: float,
    ) -> JsonObject:
        del timeout_seconds
        self.mutation_calls += 1
        if self.mutation_calls == self.fail_mutation_call:
            raise RuntimeError("injected mutation failure")
        staging_path.write_bytes(
            staging_path.read_bytes() + f"|mutation-{self.mutation_calls}".encode()
        )
        applied: list[JsonValue] = []
        for operation in operations:
            assert operation["kind"] == "rename"
            address = operation["address"]
            assert isinstance(address, dict)
            ea = address.get("ea")
            assert isinstance(ea, str)
            applied.append({"kind": "rename", "address": ea})
        return {
            "staging_path": str(staging_path.resolve()),
            "staging_sha256": _sha256(staging_path),
            "operations": applied,
            "cold_verification_required": True,
            "saved": True,
        }

    async def refine(
        self,
        *,
        staging_path: Path,
        input: Mapping[str, JsonValue],
        timeout_seconds: float,
    ) -> JsonObject:
        del timeout_seconds
        if self.block_refine:
            self.refine_started.set()
            await asyncio.Future[None]()
        if self.successful_refine:
            staging_path.write_bytes(staging_path.read_bytes() + b"|refined")
            actions = input.get("actions")
            assert isinstance(actions, list)
            return {
                "staging_path": str(staging_path.resolve()),
                "staging_sha256": _sha256(staging_path),
                "actions": [
                    {
                        "action": action,
                        "target_count": 0,
                        "function_count": 0,
                    }
                    for action in actions
                ],
                "database_change_count_before": 0,
                "database_change_count_after": 1,
                "cold_verification_required": True,
                "saved": True,
            }
        raise AssertionError("测试不应调用 refine")

    async def expert(
        self,
        *,
        staging_path: Path,
        code: str,
        timeout_seconds: float,
    ) -> JsonObject:
        self.expert_timeouts.append(timeout_seconds)
        if self.fail_expert_with_timeout:
            raise WorkerProcessError("worker_timeout", "worker 操作超时并已终止")
        if not self.successful_expert:
            raise AssertionError("测试不应调用 expert")
        staging_path.write_bytes(staging_path.read_bytes() + b"|expert")
        return {
            "staging_path": str(staging_path.resolve()),
            "staging_sha256": _sha256(staging_path),
            "saved": True,
            "stdout": "",
            "stderr": "",
            "result_repr": repr(code),
            "cold_verification_required": True,
        }

    async def open_debug(
        self,
        *,
        checkout_path: Path,
        sample_path: Path,
        revision: str,
        allow_attach: bool,
    ) -> DebugBackend:
        del checkout_path, sample_path, revision, allow_attach
        raise AssertionError("测试不应调用 debug")

    async def doctor(self) -> JsonObject:
        return {"available": True}


class _ControlledOpenIdaBackend(_FakeIdaBackend):
    def __init__(self, sample_sha256: str) -> None:
        super().__init__(sample_sha256)
        self.open_entered = asyncio.Event()
        self.allow_open_return = asyncio.Event()

    async def open_analysis(
        self,
        *,
        checkout_path: Path,
        revision: str,
    ) -> AnalysisBackend:
        self.analysis_open_count += 1
        self.open_entered.set()
        await self.allow_open_return.wait()
        return _FakeAnalysisBackend(self, checkout_path, revision)


class _TestApplication(Application):
    def __init__(
        self,
        *,
        config: AppConfig,
        storage: SupervisorStorage,
        changes: ChangeSetStore,
        cursors: CursorCodec,
        backend: _FakeIdaBackend,
    ) -> None:
        super().__init__(
            config=config,
            storage=storage,
            changes=changes,
            cursors=cursors,
            backend=backend,
        )
        self.analysis_opening_finish_entered = asyncio.Event()

    @property
    def analysis_opening_count_for_test(self) -> int:
        return self._analysis_opening_count

    def tool_input_model_for_test(self, name: str) -> type[StrictModel]:
        return self._catalog_by_name[name].input_model

    async def hold_analysis_opening_guard_for_test(self) -> None:
        await self._analysis_sessions_guard.acquire()

    def release_analysis_opening_guard_for_test(self) -> None:
        self._analysis_sessions_guard.release()

    async def open_transient_analysis_for_test(
        self,
        checkout_path: Path,
        revision: str,
    ) -> tuple[AnalysisBackend, AsyncInterprocessSlotLease]:
        return await self._open_transient_analysis(checkout_path, revision)

    async def acquire_analysis_session_for_test(
        self,
        workspace_id: str,
        revision: str,
    ) -> None:
        await self._acquire_analysis_session(workspace_id, revision)

    async def acquire_global_analysis_slot_for_test(self) -> AsyncInterprocessSlotLease:
        return await self._analysis_worker_slots.acquire()

    async def acquire_local_analysis_slot_for_test(self) -> None:
        await self._analysis_slots.acquire()

    def release_local_analysis_slot_for_test(self) -> None:
        self._analysis_slots.release()

    def set_close_task_for_test(self, task: asyncio.Task[None] | None) -> None:
        self._close_task = task

    async def _finish_analysis_opening(self) -> None:
        self.analysis_opening_finish_entered.set()
        await super()._finish_analysis_opening()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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


def _session_paths(tmp_path: Path, session_id: str) -> RuntimePaths:
    data_root = tmp_path / "runtime"
    session_root = data_root / "sessions" / session_id
    return RuntimePaths(
        data_root=data_root,
        log_root=data_root / "logs" / "sessions" / session_id,
        workspace_root=data_root / "workspaces",
        artifact_root=data_root / "artifacts",
        checkout_root=session_root / "checkouts",
        temp_root=session_root / "temp",
        session_root=session_root,
    )


def _application(
    tmp_path: Path,
    *,
    fail_mutation_call: int | None = None,
    block_refine: bool = False,
    successful_refine: bool = False,
    analysis_error_code: str | None = None,
    analysis_runtime_error: bool = False,
    large_overview_count: int = 0,
    cold_sample_sha256: str | None = None,
    cold_mismatch_call: int | None = None,
    cold_container: str | None = None,
    operation_timeout_seconds: int = 3_600,
    successful_expert: bool = False,
    fail_expert_with_timeout: bool = False,
) -> tuple[_TestApplication, WorkspaceSnapshot, bytes, _FakeIdaBackend]:
    config = AppConfig(
        policy=PolicyConfig(expert=successful_expert or fail_expert_with_timeout),
        workers=WorkerConfig(operation_timeout_seconds=operation_timeout_seconds),
    )
    paths = _paths(tmp_path)
    storage = SupervisorStorage.open(config=config, paths=paths)
    sample_bytes = b"MZ" + b"\0" * 510
    source = tmp_path / "sample.exe"
    source.write_bytes(sample_bytes)
    workspace = storage.workspaces.create(source)
    staging = storage.workspaces.begin_staging(
        workspace.workspace_id,
        expected_revision=None,
    )
    staging.database_path.write_bytes(b"cold-base")
    receipt = ColdValidationReceipt.create(
        validator="fake_ida_9_3_headless",
        component_hashes=hash_staging_payload(staging),
        image_identity=ImageIdentity(
            container="pe",
            architecture="x86_64",
            bitness=64,
            endian="little",
            image_size=0x3000,
        ),
    )
    revision = storage.workspaces.publish_staging(staging, receipt=receipt)
    workspace = storage.workspaces.get(workspace.workspace_id)
    assert workspace.current_revision == revision.revision
    backend = _FakeIdaBackend(
        workspace.sample_sha256,
        fail_mutation_call=fail_mutation_call,
        block_refine=block_refine,
        successful_refine=successful_refine,
        analysis_error_code=analysis_error_code,
        analysis_runtime_error=analysis_runtime_error,
        large_overview_count=large_overview_count,
        cold_sample_sha256=cold_sample_sha256,
        cold_mismatch_call=cold_mismatch_call,
        cold_container=cold_container,
        successful_expert=successful_expert,
        fail_expert_with_timeout=fail_expert_with_timeout,
    )
    application = _TestApplication(
        config=config,
        storage=storage,
        changes=ChangeSetStore(
            paths.data_root / "change-sets",
            workspace_lease_root=storage.workspaces.lease_root,
        ),
        cursors=CursorCodec(paths.data_root / "cursor.key"),
        backend=backend,
    )
    return application, workspace, sample_bytes, backend


def test_expert_uses_configured_worker_timeout_and_shorter_override(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, backend = _application(
            tmp_path,
            operation_timeout_seconds=37,
            successful_expert=True,
        )
        assert workspace.current_revision is not None
        input_model = application.tool_input_model_for_test("expert.execute")
        default_arguments = input_model.model_validate(
            {
                "workspace_id": workspace.workspace_id,
                "revision": workspace.current_revision,
                "code": "1 + 1",
            }
        )
        assert isinstance(default_arguments, ExpertExecuteInput)
        assert default_arguments.timeout_seconds == 37

        first = await application.execute_tool("expert.execute", default_arguments)
        assert isinstance(first, ExpertExecuteOutput)
        shorter_arguments = input_model.model_validate(
            {
                "workspace_id": workspace.workspace_id,
                "revision": first.revision,
                "code": "2 + 2",
                "timeout_seconds": 11,
            }
        )
        second = await application.execute_tool("expert.execute", shorter_arguments)

        assert isinstance(second, ExpertExecuteOutput)
        assert backend.expert_timeouts == [37, 11]
        assert backend.analysis_timeouts == [37, 37]
        with pytest.raises(ToolExecutionError) as rejected:
            await application.execute_tool(
                "expert.execute",
                ExpertExecuteInput(
                    workspace_id=workspace.workspace_id,
                    revision=second.revision,
                    code="3 + 3",
                    timeout_seconds=38,
                ),
            )
        assert rejected.value.code == BusinessErrorCode.PRECONDITION_FAILED
        assert rejected.value.details == {"maximum_timeout_seconds": 37}
        await application.aclose()

    asyncio.run(scenario())


def test_expert_timeout_aborts_staging_and_keeps_head_unchanged(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, workspace, sample_bytes, backend = _application(
            tmp_path,
            operation_timeout_seconds=37,
            fail_expert_with_timeout=True,
        )
        assert workspace.current_revision is not None
        base_revision = workspace.current_revision
        base = application.storage.workspaces.get_revision(
            workspace.workspace_id,
            base_revision,
        )
        input_model = application.tool_input_model_for_test("expert.execute")
        arguments = input_model.model_validate(
            {
                "workspace_id": workspace.workspace_id,
                "revision": base_revision,
                "code": "while True:\n    pass",
            }
        )

        with pytest.raises(ToolExecutionError) as raised:
            await application.execute_tool("expert.execute", arguments)

        assert raised.value.code == BusinessErrorCode.WORKER_CRASHED
        assert backend.expert_timeouts == [37]
        current = application.storage.workspaces.get(workspace.workspace_id)
        assert current.current_revision == base_revision
        assert base.database_path.read_bytes() == b"cold-base"
        assert workspace.sample_path.read_bytes() == sample_bytes
        staging_root = (
            application.storage.paths.workspace_root / workspace.workspace_id / ".staging"
        )
        assert not tuple(staging_root.iterdir())
        await application.aclose()

    asyncio.run(scenario())


def _prepare(workspace: WorkspaceSnapshot) -> ChangePrepareInput:
    assert workspace.current_revision is not None
    return ChangePrepareInput(
        workspace_id=workspace.workspace_id,
        base_revision=workspace.current_revision,
        operations=[
            RenameOperation(
                kind="rename",
                target=DatabaseAddress(kind="database", ea="0x140001000"),
                new_name="renamed_entry",
            )
        ],
    )


def test_doctor_reports_plain_result_and_shared_locations(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, _workspace, _sample_bytes, _backend = _application(tmp_path)

        healthy, report = await application.doctor()

        assert healthy is True
        assert report["summary"] == ("检查通过：配置、数据目录、日志目录和 IDA 都可以正常使用。")
        assert report["next_step"] == "现在可以启动 MCP 服务。"
        runtime_paths = cast(dict[str, JsonValue], report["runtime_paths"])
        assert runtime_paths["data"] == str(application.storage.paths.data_root)
        assert runtime_paths["logs"] == str(application.storage.paths.shared_log_root)
        assert runtime_paths["session_logs"] == str(application.storage.paths.log_root)
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_create_rejects_shell_wrapper_before_worker_launch(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = AppConfig()
        paths = _paths(tmp_path)
        storage = SupervisorStorage.open(config=config, paths=paths)
        source = tmp_path / "self-extracting.sh"
        source.write_bytes(b"#!/system/bin/sh\n" + b"\x1f\x8b\x08" + b"\0" * 64)
        source_before = source.read_bytes()
        source_sha256 = hashlib.sha256(source_before).hexdigest()
        backend = _FakeIdaBackend(source_sha256)
        application = Application(
            config=config,
            storage=storage,
            changes=ChangeSetStore(
                paths.data_root / "change-sets",
                workspace_lease_root=storage.workspaces.lease_root,
            ),
            cursors=CursorCodec(paths.data_root / "cursor.key"),
            backend=backend,
        )
        try:
            with pytest.raises(ToolExecutionError) as raised:
                await application.execute_tool(
                    "workspace.create",
                    WorkspaceCreateInput(sample_path=str(source)),
                )

            assert raised.value.code is BusinessErrorCode.UNSUPPORTED
            assert raised.value.details["detected"] == "shell_script"
            assert storage.workspaces.list() == ()
            assert tuple((paths.workspace_root / ".creating").iterdir()) == ()
            assert source.read_bytes() == source_before
            assert hashlib.sha256(source.read_bytes()).hexdigest() == source_sha256
        finally:
            await application.aclose()

    asyncio.run(scenario())


def test_change_prepare_apply_and_inverse_preserve_all_revision_invariants(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, sample_bytes, backend = _application(tmp_path)
        assert workspace.current_revision is not None
        base_revision = workspace.current_revision
        base = application.storage.workspaces.get_revision(
            workspace.workspace_id,
            base_revision,
        )
        prepared = await application.execute_tool(
            "change.prepare",
            _prepare(workspace),
        )
        assert isinstance(prepared, ChangePrepareOutput)
        assert prepared.base_revision == base_revision
        assert backend.mutation_calls == 1
        after_prepare = application.storage.workspaces.get(workspace.workspace_id)
        assert after_prepare.current_revision == base_revision
        assert base.database_path.read_bytes() == b"cold-base"

        applied = await application.execute_tool(
            "change.apply",
            ChangeApplyInput(
                workspace_id=workspace.workspace_id,
                expected_revision=base_revision,
                change_set_id=prepared.change_set_id,
                digest=prepared.digest,
            ),
        )
        assert isinstance(applied, ChangeApplyOutput)
        assert backend.mutation_calls == 2
        assert applied.previous_revision == base_revision
        changed = application.storage.workspaces.get_revision(
            workspace.workspace_id,
            applied.revision,
        )
        assert changed.parent_revision == base_revision
        assert changed.change_id == applied.change_id
        assert changed.database_path.read_bytes().endswith(b"|mutation-2")
        assert base.database_path.read_bytes() == b"cold-base"

        inverse = await application.execute_tool(
            "change.prepare",
            ChangePrepareInput(
                workspace_id=workspace.workspace_id,
                base_revision=applied.revision,
                inverse_of_change_id=applied.change_id,
            ),
        )
        assert isinstance(inverse, ChangePrepareOutput)
        assert inverse.impact.renamed_entities == 0
        restored = await application.execute_tool(
            "change.apply",
            ChangeApplyInput(
                workspace_id=workspace.workspace_id,
                expected_revision=applied.revision,
                change_set_id=inverse.change_set_id,
                digest=inverse.digest,
            ),
        )
        assert isinstance(restored, ChangeApplyOutput)
        restored_revision = application.storage.workspaces.get_revision(
            workspace.workspace_id,
            restored.revision,
        )
        assert restored_revision.parent_revision == applied.revision
        assert restored_revision.database_path.read_bytes() == b"cold-base"
        assert changed.database_path.read_bytes().endswith(b"|mutation-2")
        assert workspace.sample_path.read_bytes() == sample_bytes
        staging_root = (
            application.storage.paths.workspace_root / workspace.workspace_id / ".staging"
        )
        assert not tuple(staging_root.iterdir())
        await application.aclose()

    asyncio.run(scenario())


def test_change_prepare_stores_oversized_conflicts_as_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _backend = _application(tmp_path)

        def oversized_impact(
            _arguments: ChangePrepareInput,
            _sources: Sequence[object],
            _raw: Mapping[str, object],
        ) -> ChangeImpact:
            return ChangeImpact(
                renamed_entities=0,
                comments_changed=0,
                types_changed=100,
                patched_bytes=0,
                imported_symbols=100,
                conflicts=[
                    ChangeConflict(
                        kind="user_name_preserved",
                        operation_index=0,
                        source_id=f"symbol_{index:04d}",
                        address=f"0x{0x140001000 + index:x}",
                        existing_value="用户名称" * 100,
                    )
                    for index in range(100)
                ],
            )

        monkeypatch.setattr(
            "ida_re_mcp.application.parse_preflight_impact",
            oversized_impact,
        )
        output = await application.execute_tool(
            "change.prepare",
            _prepare(workspace),
        )
        assert isinstance(output, ChangePrepareOutput)
        assert output.impact.conflicts == []
        assert output.impact.conflicts_artifact is not None
        serialized = json.dumps(
            output.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        assert len(serialized) <= MAX_INLINE_RESULT_BYTES
        payload = application.storage.artifacts.read_all(
            *parse_artifact_uri(output.impact.conflicts_artifact.uri)
        )
        full = ChangePrepareOutput.model_validate_json(payload, strict=True)
        assert len(full.impact.conflicts) == 100
        assert full.change_set_id == output.change_set_id
        await application.aclose()

    asyncio.run(scenario())


def test_change_apply_worker_failure_keeps_head_sample_and_base_unchanged(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, sample_bytes, _backend = _application(
            tmp_path,
            fail_mutation_call=2,
        )
        assert workspace.current_revision is not None
        base_revision = workspace.current_revision
        base = application.storage.workspaces.get_revision(
            workspace.workspace_id,
            base_revision,
        )
        prepared = await application.execute_tool(
            "change.prepare",
            _prepare(workspace),
        )
        assert isinstance(prepared, ChangePrepareOutput)

        with pytest.raises(RuntimeError, match="injected mutation failure"):
            await application.execute_tool(
                "change.apply",
                ChangeApplyInput(
                    workspace_id=workspace.workspace_id,
                    expected_revision=base_revision,
                    change_set_id=prepared.change_set_id,
                    digest=prepared.digest,
                ),
            )

        current = application.storage.workspaces.get(workspace.workspace_id)
        assert current.current_revision == base_revision
        assert base.database_path.read_bytes() == b"cold-base"
        assert workspace.sample_path.read_bytes() == sample_bytes
        staging_root = (
            application.storage.paths.workspace_root / workspace.workspace_id / ".staging"
        )
        assert not tuple(staging_root.iterdir())
        await application.aclose()

    asyncio.run(scenario())


def test_change_apply_cold_identity_mismatch_keeps_head_sample_and_base_unchanged(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, sample_bytes, _backend = _application(
            tmp_path,
            cold_sample_sha256="f" * 64,
            cold_mismatch_call=2,
        )
        assert workspace.current_revision is not None
        base_revision = workspace.current_revision
        base = application.storage.workspaces.get_revision(
            workspace.workspace_id,
            base_revision,
        )
        prepared = await application.execute_tool(
            "change.prepare",
            _prepare(workspace),
        )
        assert isinstance(prepared, ChangePrepareOutput)

        with pytest.raises(RuntimeError, match="原样本 SHA-256"):
            await application.execute_tool(
                "change.apply",
                ChangeApplyInput(
                    workspace_id=workspace.workspace_id,
                    expected_revision=base_revision,
                    change_set_id=prepared.change_set_id,
                    digest=prepared.digest,
                ),
            )

        current = application.storage.workspaces.get(workspace.workspace_id)
        assert current.current_revision == base_revision
        assert base.database_path.read_bytes() == b"cold-base"
        assert workspace.sample_path.read_bytes() == sample_bytes
        staging_root = (
            application.storage.paths.workspace_root / workspace.workspace_id / ".staging"
        )
        assert not tuple(staging_root.iterdir())
        await application.aclose()

    asyncio.run(scenario())


def test_change_apply_cold_container_mismatch_keeps_head_unchanged(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, sample_bytes, _backend = _application(
            tmp_path,
            cold_container="elf",
            cold_mismatch_call=2,
        )
        assert workspace.current_revision is not None
        base_revision = workspace.current_revision
        prepared = await application.execute_tool(
            "change.prepare",
            _prepare(workspace),
        )
        assert isinstance(prepared, ChangePrepareOutput)

        with pytest.raises(RuntimeError, match="base revision"):
            await application.execute_tool(
                "change.apply",
                ChangeApplyInput(
                    workspace_id=workspace.workspace_id,
                    expected_revision=base_revision,
                    change_set_id=prepared.change_set_id,
                    digest=prepared.digest,
                ),
            )

        current = application.storage.workspaces.get(workspace.workspace_id)
        assert current.current_revision == base_revision
        assert workspace.sample_path.read_bytes() == sample_bytes
        staging_root = (
            application.storage.paths.workspace_root / workspace.workspace_id / ".staging"
        )
        assert not tuple(staging_root.iterdir())
        await application.aclose()

    asyncio.run(scenario())


def test_static_cursor_binds_query_and_automatically_shrinks_oversized_page(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, backend = _application(tmp_path)
        assert workspace.current_revision is not None
        query = ProgramSearchInput(
            workspace_id=workspace.workspace_id,
            revision=workspace.current_revision,
            domains=["name"],
            text_query="match",
            page_size=50,
        )
        first = await application.execute_tool(
            "program.search",
            query,
        )
        assert isinstance(first, ProgramSearchOutput)
        assert first.matches == []
        assert first.result_artifact is not None
        assert first.next_cursor is not None
        assert backend.search_requests == [(0, 50)]
        artifact_scope = parse_artifact_uri(first.result_artifact.uri)
        full_first = ProgramSearchOutput.model_validate_json(
            application.storage.artifacts.read_all(*artifact_scope),
            strict=True,
        )
        assert len(full_first.matches) == 50
        assert full_first.next_cursor == first.next_cursor

        backend.search_requests.clear()
        second = await application.execute_tool(
            "program.search",
            query.model_copy(update={"cursor": first.next_cursor}),
        )
        assert isinstance(second, ProgramSearchOutput)
        assert backend.search_requests == [(50, 50)]
        assert second.result_artifact is not None
        full_second = ProgramSearchOutput.model_validate_json(
            application.storage.artifacts.read_all(*parse_artifact_uri(second.result_artifact.uri)),
            strict=True,
        )
        assert len(full_second.matches) == 30
        assert full_second.matches[0].preview.startswith("match-50-")

        last = first.next_cursor[-1]
        tampered = first.next_cursor[:-1] + ("A" if last != "A" else "B")
        with pytest.raises(ToolExecutionError):
            await application.execute_tool(
                "program.search",
                query.model_copy(update={"cursor": tampered}),
            )
        await application.aclose()

    asyncio.run(scenario())


def test_oversized_unpaged_overview_preserves_full_requested_result_in_artifact(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _backend = _application(
            tmp_path,
            large_overview_count=100,
        )
        assert workspace.current_revision is not None
        result = await application.execute_tool(
            "program.overview",
            ProgramOverviewInput(
                workspace_id=workspace.workspace_id,
                revision=workspace.current_revision,
                include=["functions"],
            ),
        )
        assert isinstance(result, ProgramOverviewOutput)
        assert result.functions == []
        assert result.result_artifact is not None
        full_result = ProgramOverviewOutput.model_validate_json(
            application.storage.artifacts.read_all(*parse_artifact_uri(result.result_artifact.uri)),
            strict=True,
        )
        assert len(full_result.functions) == 100
        assert full_result.counts.functions == 100
        assert full_result.coverage.status == "complete"
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_list_shrinks_page_to_inline_byte_budget(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _backend = _application(tmp_path)
        source = tmp_path / (("workspace-" + "界" * 80) + ".exe")
        source.write_bytes(b"MZ" + b"\0" * 510)
        for _index in range(199):
            application.storage.workspaces.create(source)

        cursor: str | None = None
        seen: list[str] = []
        while True:
            output = await application.execute_tool(
                "workspace.list",
                WorkspaceListInput(cursor=cursor, page_size=200),
            )
            assert isinstance(output, WorkspaceListOutput)
            serialized = json.dumps(
                output.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            assert len(serialized) <= MAX_INLINE_RESULT_BYTES
            seen.extend(item.workspace_id for item in output.workspaces)
            cursor = output.next_cursor
            if cursor is None:
                break

        assert len(seen) == 200
        assert len(seen) == len(set(seen))
        assert workspace.workspace_id in seen
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_get_paginates_revisions_with_inline_budget(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _backend = _application(tmp_path)
        current_revision = workspace.current_revision
        assert current_revision is not None
        application.storage.workspaces.pin_revision(
            workspace.workspace_id,
            current_revision,
        )
        for index in range(200):
            staging = application.storage.workspaces.begin_staging(
                workspace.workspace_id,
                expected_revision=current_revision,
            )
            staging.database_path.write_bytes(f"revision-{index}".encode())
            receipt = ColdValidationReceipt.create(
                validator="fake_ida_9_3_headless",
                component_hashes=hash_staging_payload(staging),
                image_identity=ImageIdentity(
                    container="pe",
                    architecture="x86_64",
                    bitness=64,
                    endian="little",
                    image_size=0x3000,
                ),
            )
            published = application.storage.workspaces.publish_staging(
                staging,
                receipt=receipt,
                change_id=f"change_{index:08d}",
            )
            current_revision = published.revision
            application.storage.workspaces.pin_revision(
                workspace.workspace_id,
                current_revision,
            )

        expected = [
            item.revision
            for item in application.storage.workspaces.get(workspace.workspace_id).revisions
        ]
        assert len(expected) == 201
        requested_page_size = 200
        cursor: str | None = None
        pages: list[WorkspaceGetOutput] = []
        seen: list[str] = []
        while True:
            output = await application.execute_tool(
                "workspace.get",
                WorkspaceGetInput(
                    workspace_id=workspace.workspace_id,
                    cursor=cursor,
                    page_size=requested_page_size,
                ),
            )
            assert isinstance(output, WorkspaceGetOutput)
            serialized = json.dumps(
                output.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            assert len(serialized) <= MAX_INLINE_RESULT_BYTES
            assert 0 < len(output.revisions) <= requested_page_size
            pages.append(output)
            seen.extend(item.revision for item in output.revisions)
            cursor = output.next_cursor
            if cursor is None:
                break

        assert len(pages[0].revisions) < requested_page_size
        assert pages[0].next_cursor is not None
        assert seen == expected
        assert len(seen) == len(set(seen))
        assert current_revision in seen
        assert {page.history_truncated for page in pages} == {False}
        await application.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "manifest_identity",
    ["complete", "absent", "missing_container", "conflicting_legacy"],
)
def test_workspace_metadata_does_not_consume_analysis_slot_or_open_backend(
    tmp_path: Path,
    manifest_identity: str,
) -> None:
    async def scenario() -> None:
        config = AppConfig(workers=WorkerConfig(analysis_limit=1))
        paths = _paths(tmp_path)
        storage = SupervisorStorage.open(config=config, paths=paths)
        source = tmp_path / "native_pe_x64.dll"
        source.write_bytes(
            (Path(__file__).parents[1] / "fixtures" / "bin" / "native_pe_x64.dll").read_bytes()
        )
        workspace = storage.workspaces.create(source)
        staging = storage.workspaces.begin_staging(
            workspace.workspace_id,
            expected_revision=None,
        )
        staging.database_path.write_bytes(b"cold-base")
        receipt = ColdValidationReceipt.create(
            validator="fake_ida_9_3_headless",
            component_hashes=hash_staging_payload(staging),
            image_identity=ImageIdentity(
                container="pe",
                architecture="x86_64",
                bitness=64,
                endian="little",
                image_size=0x4000,
            ),
        )
        published = storage.workspaces.publish_staging(staging, receipt=receipt)
        manifest_path = published.path / "revision.json"
        if manifest_identity != "complete":
            raw = cast(
                dict[str, object],
                json.loads(manifest_path.read_text(encoding="utf-8")),
            )
            if manifest_identity == "absent":
                raw.pop("image_identity")
            else:
                identity = cast(dict[str, object], raw["image_identity"])
                identity.pop("container")
                if manifest_identity == "conflicting_legacy":
                    identity["architecture"] = "aarch64"
            atomic_write_json(manifest_path, raw)
        manifest_before = manifest_path.read_bytes()

        reopened = SupervisorStorage.open(config=config, paths=paths)
        backend = _FakeIdaBackend(workspace.sample_sha256)
        application = _TestApplication(
            config=config,
            storage=reopened,
            changes=ChangeSetStore(
                paths.data_root / "change-sets",
                workspace_lease_root=reopened.workspaces.lease_root,
            ),
            cursors=CursorCodec(paths.data_root / "cursor.key"),
            backend=backend,
        )
        await application.acquire_local_analysis_slot_for_test()
        try:
            if manifest_identity == "conflicting_legacy":
                with pytest.raises(ToolExecutionError) as raised:
                    await asyncio.wait_for(
                        application.execute_tool(
                            "workspace.list",
                            WorkspaceListInput(),
                        ),
                        timeout=2,
                    )
                assert raised.value.code is BusinessErrorCode.EXECUTION_FAILED
                listed = None
                details = None
            else:
                listed = await asyncio.wait_for(
                    application.execute_tool("workspace.list", WorkspaceListInput()),
                    timeout=2,
                )
                details = await asyncio.wait_for(
                    application.execute_tool(
                        "workspace.get",
                        WorkspaceGetInput(workspace_id=workspace.workspace_id),
                    ),
                    timeout=2,
                )
        finally:
            application.release_local_analysis_slot_for_test()
            await application.aclose()

        assert backend.analysis_open_count == 0
        assert backend.cold_analysis_calls == 0
        assert manifest_path.read_bytes() == manifest_before
        if manifest_identity == "conflicting_legacy":
            return
        assert isinstance(listed, WorkspaceListOutput)
        assert listed.workspaces[0].architecture == "x86_64"
        assert isinstance(details, WorkspaceGetOutput)
        assert details.architecture == "x86_64"
        assert details.bitness == 64
        assert details.endian == "little"

    asyncio.run(scenario())


def test_text_resource_decode_failure_remains_an_internal_failure(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _backend = _application(tmp_path)
        assert workspace.current_revision is not None
        artifact = application.storage.artifacts.put_bytes(
            workspace_id=workspace.workspace_id,
            revision=workspace.current_revision,
            data=b"\xff",
            media_type="text/plain",
            name="invalid-utf8.txt",
        )

        with pytest.raises(UnicodeDecodeError):
            await application.read_resource(artifact.uri)
        await application.aclose()

    asyncio.run(scenario())


def test_resource_read_finishes_before_other_store_collects_its_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _backend = _application(tmp_path)
        store = application.storage.artifacts
        collector = ArtifactStore(
            store.root,
            workspace_lease_root=application.storage.workspaces.lease_root,
        )
        data = b"r" * (RESOURCE_CHUNK_BYTES + 31)
        artifact = store.put_bytes(
            workspace_id=workspace.workspace_id,
            revision="rev_retired",
            data=data,
            media_type="application/octet-stream",
        )
        reading_second_chunk = threading.Event()
        continue_read = threading.Event()
        gc_started = threading.Event()
        original_read = store.read_verified_chunk

        def delayed_read(
            metadata: ArtifactMetadata,
            *,
            offset: int = 0,
            limit: int = RESOURCE_CHUNK_BYTES,
        ) -> ArtifactChunk:
            if offset:
                reading_second_chunk.set()
                assert continue_read.wait(timeout=5)
            return original_read(metadata, offset=offset, limit=limit)

        def retained_revisions(_workspace_id: str) -> set[str]:
            gc_started.set()
            return set()

        monkeypatch.setattr(store, "read_verified_chunk", delayed_read)
        reading = asyncio.create_task(application.read_resource(artifact.uri))
        collecting = None
        try:
            assert await asyncio.to_thread(reading_second_chunk.wait, 1)
            collecting = asyncio.create_task(
                asyncio.to_thread(
                    collector.collect_garbage,
                    retained_scopes=set(),
                    retained_revision_provider=retained_revisions,
                    dry_run=False,
                )
            )
            assert await asyncio.to_thread(gc_started.wait, 1)
            await asyncio.sleep(0.05)
            assert not collecting.done()
        finally:
            continue_read.set()
            await asyncio.gather(
                reading,
                *([collecting] if collecting is not None else []),
                return_exceptions=True,
            )
            await application.aclose()

        resource = reading.result()
        assert (
            b"".join(
                base64.b64decode(part.blob) for part in resource.contents if part.kind == "blob"
            )
            == data
        )
        assert collecting is not None
        assert collecting.result().removed_paths == (
            store.root / workspace.workspace_id / "rev_retired",
        )

    asyncio.run(scenario())


def test_analysis_worker_and_private_checkout_are_reused_until_application_close(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, backend = _application(tmp_path)
        assert workspace.current_revision is not None
        request = ProgramOverviewInput(
            workspace_id=workspace.workspace_id,
            revision=workspace.current_revision,
            include=[],
        )
        first = await application.execute_tool("program.overview", request)
        second = await application.execute_tool("program.overview", request)
        assert isinstance(first, ProgramOverviewOutput)
        assert isinstance(second, ProgramOverviewOutput)
        assert backend.analysis_open_count == 1
        assert backend.analysis_close_count == 0
        assert len(tuple(application.storage.paths.checkout_root.rglob("chk_*"))) == 1

        await application.aclose()

        assert backend.analysis_close_count == 1
        assert tuple(application.storage.paths.checkout_root.rglob("chk_*")) == ()

    asyncio.run(scenario())


def test_remote_waiter_preempts_idle_analysis_worker_across_sessions(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = AppConfig(
            workers=WorkerConfig(
                analysis_limit=1,
                debug_limit=1,
                idle_seconds=300,
            )
        )
        first_paths = _session_paths(tmp_path, "session_first")
        second_paths = _session_paths(tmp_path, "session_second")
        first_storage = SupervisorStorage.open(config=config, paths=first_paths)

        source = tmp_path / "shared-sample.exe"
        source.write_bytes(b"MZ" + b"\0" * 510)
        workspace = first_storage.workspaces.create(source)
        staging = first_storage.workspaces.begin_staging(
            workspace.workspace_id,
            expected_revision=None,
        )
        staging.database_path.write_bytes(b"cold-base")
        receipt = ColdValidationReceipt.create(
            validator="fake_ida_9_3_headless",
            component_hashes=hash_staging_payload(staging),
            image_identity=ImageIdentity(
                container="pe",
                architecture="x86_64",
                bitness=64,
                endian="little",
                image_size=0x3000,
            ),
        )
        published = first_storage.workspaces.publish_staging(staging, receipt=receipt)
        workspace = first_storage.workspaces.get(workspace.workspace_id)
        assert workspace.current_revision == published.revision

        second_storage = SupervisorStorage.open(config=config, paths=second_paths)
        first_backend = _FakeIdaBackend(workspace.sample_sha256)
        second_backend = _FakeIdaBackend(workspace.sample_sha256)
        first_application = _TestApplication(
            config=config,
            storage=first_storage,
            changes=ChangeSetStore(
                first_paths.change_root,
                workspace_lease_root=first_storage.workspaces.lease_root,
            ),
            cursors=CursorCodec(first_paths.cursor_key_path),
            backend=first_backend,
        )
        second_application = _TestApplication(
            config=config,
            storage=second_storage,
            changes=ChangeSetStore(
                second_paths.change_root,
                workspace_lease_root=second_storage.workspaces.lease_root,
            ),
            cursors=CursorCodec(second_paths.cursor_key_path),
            backend=second_backend,
        )
        request = ProgramOverviewInput(
            workspace_id=workspace.workspace_id,
            revision=published.revision,
            include=[],
        )

        try:
            first = await first_application.execute_tool("program.overview", request)
            assert isinstance(first, ProgramOverviewOutput)
            assert first_backend.analysis_open_count == 1
            assert first_backend.analysis_close_count == 0

            second = await asyncio.wait_for(
                second_application.execute_tool("program.overview", request),
                timeout=2,
            )

            assert isinstance(second, ProgramOverviewOutput)
            assert first_backend.analysis_close_count == 1
            assert second_backend.analysis_open_count == 1
        finally:
            await second_application.aclose()
            await first_application.aclose()

    asyncio.run(scenario())


def test_cancelled_transient_analysis_open_releases_backend_slot_and_opening_count(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _unused_backend = _application(tmp_path)
        assert workspace.current_revision is not None
        backend = _ControlledOpenIdaBackend(workspace.sample_sha256)
        application.backend = backend
        checkout_path = tmp_path / "transient-analysis.i64"
        checkout_path.write_bytes(b"cold-checkout")
        task = asyncio.create_task(
            application.open_transient_analysis_for_test(
                checkout_path,
                workspace.current_revision,
            )
        )
        guard_held = False
        try:
            await asyncio.wait_for(backend.open_entered.wait(), timeout=1)
            await application.hold_analysis_opening_guard_for_test()
            guard_held = True
            backend.allow_open_return.set()
            await asyncio.wait_for(
                application.analysis_opening_finish_entered.wait(),
                timeout=1,
            )

            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            application.release_analysis_opening_guard_for_test()
            guard_held = False

            with pytest.raises(asyncio.CancelledError):
                await task

            assert backend.analysis_open_count == 1
            assert backend.analysis_close_count == 1
            assert application.analysis_opening_count_for_test == 0
            replacement_slot = await asyncio.wait_for(
                application.acquire_global_analysis_slot_for_test(),
                timeout=1,
            )
            await replacement_slot.release()
        finally:
            backend.allow_open_return.set()
            if guard_held:
                application.release_analysis_opening_guard_for_test()
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await application.aclose()

    asyncio.run(scenario())


def test_cancelled_analysis_checkout_copy_is_discarded_after_thread_returns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, backend = _application(tmp_path)
        assert workspace.current_revision is not None
        checkout_created = threading.Event()
        allow_create_return = threading.Event()
        created: list[RevisionCheckout] = []
        original_create = cast(
            Callable[..., RevisionCheckout],
            application.storage.workspaces.create_checkout,
        )

        def blocked_create_checkout(
            workspace_id: str,
            revision: str,
            *,
            purpose: str,
        ) -> RevisionCheckout:
            checkout = original_create(
                workspace_id,
                revision,
                purpose=purpose,
            )
            created.append(checkout)
            checkout_created.set()
            if not allow_create_return.wait(timeout=5):
                raise TimeoutError("测试未释放 checkout 创建线程")
            return checkout

        monkeypatch.setattr(
            application.storage.workspaces,
            "create_checkout",
            blocked_create_checkout,
        )
        task = asyncio.create_task(
            application.acquire_analysis_session_for_test(
                workspace.workspace_id,
                workspace.current_revision,
            )
        )
        try:
            assert await asyncio.to_thread(checkout_created.wait, 1)
            assert len(created) == 1
            checkout = created[0]
            assert checkout.path.is_dir()

            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            allow_create_return.set()

            with pytest.raises(asyncio.CancelledError):
                await task

            assert backend.analysis_open_count == 0
            assert application.analysis_opening_count_for_test == 0
            assert not checkout.path.exists()
            assert tuple(application.storage.paths.checkout_root.rglob("chk_*")) == ()

            checkout.path.mkdir(parents=True)
            (checkout.path / "orphan-probe").write_bytes(b"orphan")
            preview = application.storage.workspaces.collect_garbage(
                workspace_id=workspace.workspace_id,
                dry_run=True,
            )
            assert checkout.path in preview.removed_paths
            applied = application.storage.workspaces.collect_garbage(
                workspace_id=workspace.workspace_id,
                dry_run=False,
            )
            assert checkout.path in applied.removed_paths
            assert not checkout.path.exists()
        finally:
            allow_create_return.set()
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await application.aclose()

    asyncio.run(scenario())


def test_application_close_propagates_an_already_cancelled_close_task(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, _workspace, _sample_bytes, _backend = _application(tmp_path)
        cancelled_close = asyncio.create_task(asyncio.sleep(60))
        cancelled_close.cancel()
        await asyncio.gather(cancelled_close, return_exceptions=True)
        assert cancelled_close.cancelled()

        application.set_close_task_for_test(cancelled_close)
        try:
            with pytest.raises(asyncio.CancelledError):
                await application.aclose()
        finally:
            application.set_close_task_for_test(None)
            await application.aclose()

    asyncio.run(scenario())


def test_workspace_export_pins_revision_and_returns_chunk_index(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _backend = _application(tmp_path)
        assert workspace.current_revision is not None
        started = await application.execute_tool(
            "workspace.export",
            WorkspaceExportInput(
                workspace_id=workspace.workspace_id,
                revision=workspace.current_revision,
                format="idb",
            ),
        )
        assert isinstance(started, WorkspaceExportOutput)
        completed = await application.execute_tool(
            "operation.wait",
            OperationWaitInput(operation_id=started.operation_id, wait_ms=1_000),
        )
        assert isinstance(completed, OperationWaitOutput)
        assert completed.state == "succeeded"
        assert isinstance(completed.result, dict)
        assert completed.result["encoding"] == "chunked_artifact_index"
        exported = application.storage.workspaces.get_revision(
            workspace.workspace_id,
            workspace.current_revision,
        )
        assert exported.pinned is True
        assert len(application.storage.artifacts.list()) == 1
        await application.aclose()

    asyncio.run(scenario())


def test_application_gc_reports_reclaimable_and_protected_bytes(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _backend = _application(tmp_path)
        orphan = application.storage.artifacts.put_bytes(
            workspace_id=workspace.workspace_id,
            revision="rev_orphan",
            data=b"orphan artifact",
            media_type="application/octet-stream",
        )

        preview = await application.gc(apply=False)
        preview_storage = cast(dict[str, JsonValue], preview["storage"])
        preview_bytes = preview_storage["bytes"]
        preview_protected = preview_storage["protected_bytes"]
        reclaimed = preview["reclaimed_bytes"]
        assert "找到" in cast(str, preview["summary"])
        assert "gc --apply" in cast(str, preview["next_step"])
        assert isinstance(preview_bytes, int)
        assert isinstance(preview_protected, int)
        assert isinstance(reclaimed, int)
        assert reclaimed > 0
        assert preview_protected == preview_bytes - reclaimed
        assert (
            application.storage.artifacts.get(
                workspace.workspace_id,
                "rev_orphan",
                orphan.artifact_id,
            )
            == orphan
        )

        applied = await application.gc(apply=True)
        applied_storage = cast(dict[str, JsonValue], applied["storage"])
        assert cast(str, applied["summary"]).startswith("清理完成")
        assert isinstance(applied["next_step"], str)
        assert applied_storage["protected_bytes"] == applied_storage["bytes"]
        with pytest.raises(ArtifactNotFoundError):
            application.storage.artifacts.get(
                workspace.workspace_id,
                "rev_orphan",
                orphan.artifact_id,
            )
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_list_restores_failed_initialization_state_after_restart(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        config = AppConfig()
        paths = _paths(tmp_path)
        first_storage = SupervisorStorage.open(config=config, paths=paths)
        source = tmp_path / "pending.exe"
        source.write_bytes(b"MZ" + b"\0" * 510)
        workspace = first_storage.workspaces.create(source)
        operation = first_storage.operations.create(
            "workspace_create",
            workspace_id=workspace.workspace_id,
        )
        first_storage.operations.start(operation.operation_id)

        restored_storage = SupervisorStorage.open(config=config, paths=paths)
        application = Application(
            config=config,
            storage=restored_storage,
            changes=ChangeSetStore(paths.data_root / "change-sets"),
            cursors=CursorCodec(paths.data_root / "cursor.key"),
            backend=_FakeIdaBackend(workspace.sample_sha256),
        )
        result = await application.execute_tool(
            "workspace.list",
            WorkspaceListInput(),
        )
        assert isinstance(result, WorkspaceListOutput)
        assert len(result.workspaces) == 1
        assert result.workspaces[0].workspace_id == workspace.workspace_id
        assert result.workspaces[0].state == "failed"
        assert result.workspaces[0].analysis_outcome is not None
        assert result.workspaces[0].analysis_outcome.state == "failed"
        assert result.workspaces[0].analysis_outcome.reason == "服务重启前的操作未完成"
        await application.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("worker_code", "expected_code"),
    [
        ("cursor_stale", BusinessErrorCode.CURSOR_STALE),
        ("ambiguous_reference", BusinessErrorCode.AMBIGUOUS_REFERENCE),
        ("slice_seed_not_found", BusinessErrorCode.UNSUPPORTED),
        ("unsupported", BusinessErrorCode.UNSUPPORTED),
        ("capability_unavailable", BusinessErrorCode.CAPABILITY_UNAVAILABLE),
        ("private_worker_detail", BusinessErrorCode.EXECUTION_FAILED),
    ],
)
def test_worker_failures_use_stable_public_business_codes(
    tmp_path: Path,
    worker_code: str,
    expected_code: BusinessErrorCode,
) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _backend = _application(
            tmp_path,
            analysis_error_code=worker_code,
        )
        assert workspace.current_revision is not None
        with pytest.raises(ToolExecutionError) as raised:
            await application.execute_tool(
                "program.search",
                ProgramSearchInput(
                    workspace_id=workspace.workspace_id,
                    revision=workspace.current_revision,
                    domains=["name"],
                    text_query="match",
                ),
            )
        assert raised.value.code is expected_code
        assert raised.value.message != "公开 worker 失败"
        assert "请" in raised.value.message
        assert raised.value.details == {}
        await application.aclose()

    asyncio.run(scenario())


def test_operation_cancel_aborts_refine_and_preserves_current_revision(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, workspace, sample_bytes, backend = _application(
            tmp_path,
            block_refine=True,
        )
        assert workspace.current_revision is not None
        base_revision = workspace.current_revision
        base = application.storage.workspaces.get_revision(
            workspace.workspace_id,
            base_revision,
        )
        started = await application.execute_tool(
            "analysis.refine",
            AnalysisRefineInput(
                workspace_id=workspace.workspace_id,
                revision=base_revision,
                actions=["autoanalysis"],
            ),
        )
        assert isinstance(started, AnalysisRefineOutput)
        assert await asyncio.to_thread(backend.refine_started.wait, 1)

        requested = await application.execute_tool(
            "operation.cancel",
            OperationCancelInput(operation_id=started.operation_id),
        )
        assert isinstance(requested, OperationCancelOutput)
        assert requested.state == "cancel_requested"
        assert requested.cancellation_requested

        completed = await application.execute_tool(
            "operation.wait",
            OperationWaitInput(operation_id=started.operation_id, wait_ms=1_000),
        )
        assert isinstance(completed, OperationWaitOutput)
        assert completed.state == "cancelled"
        current = application.storage.workspaces.get(workspace.workspace_id)
        assert current.current_revision == base_revision
        assert base.database_path.read_bytes() == b"cold-base"
        assert workspace.sample_path.read_bytes() == sample_bytes
        staging_root = (
            application.storage.paths.workspace_root / workspace.workspace_id / ".staging"
        )
        assert not tuple(staging_root.iterdir())
        await application.aclose()

    asyncio.run(scenario())


def test_cancelled_operation_waits_do_not_exhaust_thread_pool(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, _workspace, _sample_bytes, _backend = _application(tmp_path)
        operation = application.storage.operations.create("wait_probe")
        application.storage.operations.start(operation.operation_id)
        waiters = [
            asyncio.create_task(
                application.execute_tool(
                    "operation.wait",
                    OperationWaitInput(
                        operation_id=operation.operation_id,
                        wait_ms=30_000,
                    ),
                )
            )
            for _index in range(64)
        ]
        await asyncio.sleep(0.2)
        for waiter in waiters:
            waiter.cancel()
        results = await asyncio.gather(*waiters, return_exceptions=True)

        assert all(isinstance(result, asyncio.CancelledError) for result in results)
        assert (
            await asyncio.wait_for(
                asyncio.to_thread(lambda: "thread-pool-responsive"),
                timeout=1,
            )
            == "thread-pool-responsive"
        )
        await application.aclose()

    asyncio.run(scenario())


def test_operation_cancel_during_publish_waits_for_commit_and_reports_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        application, workspace, sample_bytes, _backend = _application(
            tmp_path,
            successful_refine=True,
        )
        assert workspace.current_revision is not None
        base_revision = workspace.current_revision
        publish_entered = threading.Event()
        allow_publish = threading.Event()
        original_publish = cast(
            Callable[..., RevisionSnapshot],
            application.storage.workspaces.publish_staging,
        )

        def blocked_publish(*args: object, **kwargs: object) -> RevisionSnapshot:
            publish_entered.set()
            if not allow_publish.wait(timeout=5):
                raise TimeoutError("测试未释放 revision publish")
            return original_publish(*args, **kwargs)

        monkeypatch.setattr(
            application.storage.workspaces,
            "publish_staging",
            blocked_publish,
        )
        try:
            started = await application.execute_tool(
                "analysis.refine",
                AnalysisRefineInput(
                    workspace_id=workspace.workspace_id,
                    revision=base_revision,
                    actions=["autoanalysis"],
                ),
            )
            assert isinstance(started, AnalysisRefineOutput)
            assert await asyncio.to_thread(publish_entered.wait, 2)

            requested = await application.execute_tool(
                "operation.cancel",
                OperationCancelInput(operation_id=started.operation_id),
            )
            assert isinstance(requested, OperationCancelOutput)
            assert requested.state == "cancel_requested"

            still_running = await application.execute_tool(
                "operation.wait",
                OperationWaitInput(operation_id=started.operation_id, wait_ms=0),
            )
            assert isinstance(still_running, OperationWaitOutput)
            assert still_running.state == "cancel_requested"

            allow_publish.set()
            completed = await application.execute_tool(
                "operation.wait",
                OperationWaitInput(operation_id=started.operation_id, wait_ms=1_000),
            )
            assert isinstance(completed, OperationWaitOutput)
            assert completed.state == "succeeded"
            assert isinstance(completed.result, dict)
            committed_revision = completed.result["revision"]
            assert isinstance(committed_revision, str)
            assert committed_revision != base_revision

            current = application.storage.workspaces.get(workspace.workspace_id)
            assert current.current_revision == committed_revision
            committed = application.storage.workspaces.get_revision(
                workspace.workspace_id,
                committed_revision,
            )
            assert committed.operation_id == started.operation_id
            assert committed.operation_result == completed.result
            assert workspace.sample_path.read_bytes() == sample_bytes
        finally:
            allow_publish.set()
            await application.aclose()

    asyncio.run(scenario())


def _publish_cold_revision(
    storage: SupervisorStorage,
    workspace_id: str,
    *,
    expected_revision: str | None,
    content: bytes,
) -> str:
    staging = storage.workspaces.begin_staging(
        workspace_id,
        expected_revision=expected_revision,
    )
    staging.database_path.write_bytes(content)
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=ImageIdentity(
            container="pe",
            architecture="x86_64",
            bitness=64,
            endian="little",
            image_size=0x3000,
        ),
    )
    return storage.workspaces.publish_staging(staging, receipt=receipt).revision


def test_missing_revision_reports_revision_not_found_not_conflict(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, workspace, _sample_bytes, _backend = _application(tmp_path)
        # 查询不存在(或已被 GC)的 revision 必须是 revision_not_found, 而非 CAS
        # 语义的 revision_conflict, 否则会诱导 Agent 对不存在的 revision 无限重试。
        with pytest.raises(ToolExecutionError) as raised:
            await application.execute_tool(
                "program.overview",
                ProgramOverviewInput(
                    workspace_id=workspace.workspace_id,
                    revision="rev_00000000000000000000000000000000",
                    include=[],
                ),
            )
        assert raised.value.code is BusinessErrorCode.REVISION_NOT_FOUND
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_list_reports_unknown_without_proof_of_progress(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = AppConfig()
        paths = _paths(tmp_path)
        storage = SupervisorStorage.open(config=config, paths=paths)
        source = tmp_path / "pending.exe"
        source.write_bytes(b"MZ" + b"\0" * 510)
        workspace = storage.workspaces.create(source)
        # 无 current revision、无持久化 analysis_outcome、无可见 operation:
        # 服务无法证明它仍在分析, 只能诚实报告 unknown。
        application = Application(
            config=config,
            storage=storage,
            changes=ChangeSetStore(paths.data_root / "change-sets"),
            cursors=CursorCodec(paths.data_root / "cursor.key"),
            backend=_FakeIdaBackend(workspace.sample_sha256),
        )
        result = await application.execute_tool("workspace.list", WorkspaceListInput())
        assert isinstance(result, WorkspaceListOutput)
        assert len(result.workspaces) == 1
        assert result.workspaces[0].state == "unknown"
        assert result.workspaces[0].architecture is None
        assert result.workspaces[0].analysis_outcome is None
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_get_flags_history_truncated_after_retention(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = AppConfig(storage=StorageConfig(retained_revisions=1))
        paths = _paths(tmp_path)
        storage = SupervisorStorage.open(config=config, paths=paths)
        source = tmp_path / "sample.exe"
        source.write_bytes(b"MZ" + b"\0" * 510)
        workspace = storage.workspaces.create(source)
        first = _publish_cold_revision(
            storage,
            workspace.workspace_id,
            expected_revision=None,
            content=b"cold idb 1",
        )
        second = _publish_cold_revision(
            storage,
            workspace.workspace_id,
            expected_revision=first,
            content=b"cold idb 2",
        )
        third = _publish_cold_revision(
            storage,
            workspace.workspace_id,
            expected_revision=second,
            content=b"cold idb 3",
        )
        application = Application(
            config=config,
            storage=storage,
            changes=ChangeSetStore(paths.data_root / "change-sets"),
            cursors=CursorCodec(paths.data_root / "cursor.key"),
            backend=_FakeIdaBackend(workspace.sample_sha256),
        )
        result = await application.execute_tool(
            "workspace.get",
            WorkspaceGetInput(
                workspace_id=workspace.workspace_id,
                page_size=1,
            ),
        )
        assert isinstance(result, WorkspaceGetOutput)
        assert result.current_revision == third
        assert result.next_cursor is not None
        second_page = await application.execute_tool(
            "workspace.get",
            WorkspaceGetInput(
                workspace_id=workspace.workspace_id,
                cursor=result.next_cursor,
                page_size=1,
            ),
        )
        assert isinstance(second_page, WorkspaceGetOutput)
        # retained_revisions=1 只保留 current 与 1 条历史(third、second), 丢弃 first;
        # 最早保留的 second 的 parent 指向已回收的 first -> 历史被截断。
        retained = {
            revision.revision for page in (result, second_page) for revision in page.revisions
        }
        assert retained == {second, third}
        assert first not in retained
        assert result.history_truncated is True
        assert second_page.history_truncated is True
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_get_detects_gap_before_pinned_history(tmp_path: Path) -> None:
    async def scenario() -> None:
        config = AppConfig(storage=StorageConfig(retained_revisions=1))
        paths = _paths(tmp_path)
        storage = SupervisorStorage.open(config=config, paths=paths)
        source = tmp_path / "sample.exe"
        source.write_bytes(b"MZ" + b"\0" * 510)
        workspace = storage.workspaces.create(source)
        first = _publish_cold_revision(
            storage,
            workspace.workspace_id,
            expected_revision=None,
            content=b"cold idb 1",
        )
        storage.workspaces.pin_revision(workspace.workspace_id, first, pinned=True)
        second = _publish_cold_revision(
            storage,
            workspace.workspace_id,
            expected_revision=first,
            content=b"cold idb 2",
        )
        third = _publish_cold_revision(
            storage,
            workspace.workspace_id,
            expected_revision=second,
            content=b"cold idb 3",
        )
        fourth = _publish_cold_revision(
            storage,
            workspace.workspace_id,
            expected_revision=third,
            content=b"cold idb 4",
        )
        application = Application(
            config=config,
            storage=storage,
            changes=ChangeSetStore(paths.data_root / "change-sets"),
            cursors=CursorCodec(paths.data_root / "cursor.key"),
            backend=_FakeIdaBackend(workspace.sample_sha256),
        )

        result = await application.execute_tool(
            "workspace.get",
            WorkspaceGetInput(workspace_id=workspace.workspace_id),
        )
        assert isinstance(result, WorkspaceGetOutput)
        assert {item.revision for item in result.revisions} == {first, third, fourth}
        assert second not in {item.revision for item in result.revisions}
        assert result.history_truncated is True
        await application.aclose()

    asyncio.run(scenario())


class _LifecycleBootstrapBackend(_FakeIdaBackend):
    def __init__(
        self,
        sample_sha256: str,
        *,
        block_bootstrap: bool = False,
        fail_bootstrap: bool = False,
    ) -> None:
        super().__init__(sample_sha256)
        self.block_bootstrap = block_bootstrap
        self.fail_bootstrap = fail_bootstrap
        self.bootstrap_started = asyncio.Event()
        self.allow_bootstrap = asyncio.Event()
        self.bootstrap_timeout_seconds: float | None = None

    async def bootstrap(
        self,
        *,
        sample_path: Path,
        staging_path: Path,
        timeout_seconds: float,
    ) -> JsonObject:
        del sample_path
        self.bootstrap_timeout_seconds = timeout_seconds
        self.bootstrap_started.set()
        if self.block_bootstrap:
            await self.allow_bootstrap.wait()
        if self.fail_bootstrap:
            raise RuntimeError("sensitive bootstrap implementation detail")
        staging_path.write_bytes(b"bootstrap idb")
        return {"input_sha256": self.sample_sha256}


class _LifecycleApplication(_TestApplication):
    def schedule_initialization_for_test(
        self,
        workspace: WorkspaceSnapshot,
        native_identity: NativeImageIdentity,
    ) -> str:
        return self._schedule_workspace_initialization(
            workspace,
            native_identity=native_identity,
        )

    async def acquire_workspace_lock_for_test(
        self,
        workspace_id: str,
    ) -> AsyncInterprocessFileLock:
        lock = self._workspace_lock(workspace_id)
        await lock.acquire()
        return lock

    async def acquire_local_analysis_slot_for_test(self) -> None:
        await self._analysis_slots.acquire()

    def release_local_analysis_slot_for_test(self) -> None:
        self._analysis_slots.release()

    def workspace_summary_for_test(
        self,
        workspace: WorkspaceSnapshot,
    ) -> WorkspaceSummary:
        return self._workspace_summary(workspace)

    async def close_runtime_resources_for_test(self) -> None:
        await self._close_runtime_resources_once()


def _lifecycle_application(
    tmp_path: Path,
    *,
    paths: RuntimePaths | None = None,
    block_bootstrap: bool = False,
    fail_bootstrap: bool = False,
    operation_timeout_seconds: int = 3_600,
    initial_analysis_timeout_seconds: int = 10_800,
) -> tuple[_LifecycleApplication, Path, _LifecycleBootstrapBackend]:
    config = AppConfig(
        workers=WorkerConfig(
            analysis_limit=1,
            operation_timeout_seconds=operation_timeout_seconds,
            initial_analysis_timeout_seconds=initial_analysis_timeout_seconds,
        )
    )
    runtime_paths = paths or _paths(tmp_path)
    storage = SupervisorStorage.open(config=config, paths=runtime_paths)
    source = tmp_path / f"lifecycle-{runtime_paths.session_data_root.name}.dll"
    source.write_bytes(
        (Path(__file__).parents[1] / "fixtures" / "bin" / "native_pe_x64.dll").read_bytes()
    )
    backend = _LifecycleBootstrapBackend(
        hashlib.sha256(source.read_bytes()).hexdigest(),
        block_bootstrap=block_bootstrap,
        fail_bootstrap=fail_bootstrap,
    )
    application = _LifecycleApplication(
        config=config,
        storage=storage,
        changes=ChangeSetStore(
            runtime_paths.data_root / "change-sets",
            workspace_lease_root=storage.workspaces.lease_root,
        ),
        cursors=CursorCodec(runtime_paths.data_root / "cursor.key"),
        backend=backend,
    )
    return application, source, backend


def test_workspace_create_uses_configured_worker_timeouts(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, source, backend = _lifecycle_application(
            tmp_path,
            operation_timeout_seconds=37,
            initial_analysis_timeout_seconds=7_200,
        )
        started = await application.execute_tool(
            "workspace.create",
            WorkspaceCreateInput(sample_path=str(source)),
        )
        assert isinstance(started, WorkspaceCreateOutput)
        completed = await application.execute_tool(
            "operation.wait",
            OperationWaitInput(operation_id=started.analysis_operation_id, wait_ms=1_000),
        )
        assert isinstance(completed, OperationWaitOutput)
        assert completed.state == "succeeded"
        assert backend.bootstrap_timeout_seconds == 7_200
        assert backend.analysis_timeouts == [37]
        await application.aclose()

    asyncio.run(scenario())


async def _wait_for_operation_state(
    application: Application,
    operation_id: str,
    expected: str,
) -> None:
    async with asyncio.timeout(2):
        while application.storage.operations.get(operation_id).state.value != expected:
            await asyncio.sleep(0)


async def _wait_for_analysis_outcome(
    application: Application,
    workspace_id: str,
) -> None:
    async with asyncio.timeout(2):
        while application.storage.workspaces.get(workspace_id).analysis_outcome is None:
            await asyncio.sleep(0)


def test_workspace_summary_requires_consistent_analysis_outcome() -> None:
    outcome = WorkspaceAnalysisOutcome(
        state="cancelled",
        reason="首次分析已取消",
        recorded_at=1.0,
    )

    with pytest.raises(ValidationError, match="analysis_outcome"):
        WorkspaceSummary.model_validate(
            {
                "workspace_id": "ws_test00",
                "revision": None,
                "sample_name": "sample.bin",
                "sample_sha256": "0" * 64,
                "architecture": None,
                "state": "failed",
            },
            strict=True,
        )
    with pytest.raises(ValidationError, match="failed 状态"):
        WorkspaceSummary(
            workspace_id="ws_test00",
            revision=None,
            sample_name="sample.bin",
            sample_sha256="0" * 64,
            architecture=None,
            state="unknown",
            analysis_outcome=outcome,
        )

    schema = WorkspaceSummary.model_json_schema()
    required = schema.get("required")
    assert isinstance(required, list)
    assert "analysis_outcome" in required

    workspace_get_schema = WorkspaceGetOutput.model_json_schema()
    workspace_get_required = workspace_get_schema.get("required")
    assert isinstance(workspace_get_required, list)
    assert "history_truncated" in workspace_get_required

    image_schema = ImageSummary.model_json_schema()
    format_schema = cast(dict[str, object], image_schema["properties"])["format"]
    assert isinstance(format_schema, dict)
    assert format_schema["enum"] == ["elf32", "elf64", "pe32", "pe32+", "unknown"]
    architecture_schema = cast(dict[str, object], image_schema["properties"])["architecture"]
    assert isinstance(architecture_schema, dict)
    assert architecture_schema["enum"] == ["x86", "x86_64", "arm", "aarch64"]


def test_workspace_create_queued_cancel_persists_public_outcome(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, source, backend = _lifecycle_application(tmp_path)
        workspace = application.storage.workspaces.create(source)
        operation_id = application.schedule_initialization_for_test(
            workspace,
            inspect_native_image(workspace.sample_path),
        )

        cancelled = application.storage.operations.cancel(operation_id)
        assert cancelled.state.value == "cancelled"
        await _wait_for_analysis_outcome(application, workspace.workspace_id)

        summary = application.workspace_summary_for_test(
            application.storage.workspaces.get(workspace.workspace_id)
        )
        assert summary.state == "failed"
        assert summary.analysis_outcome is not None
        assert summary.analysis_outcome.state == "cancelled"
        assert summary.analysis_outcome.reason == "首次分析已取消"
        assert backend.bootstrap_started.is_set() is False
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_create_cancel_while_waiting_for_workspace_lock(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, source, backend = _lifecycle_application(tmp_path)
        workspace = application.storage.workspaces.create(source)
        held_lock = await application.acquire_workspace_lock_for_test(workspace.workspace_id)
        try:
            operation_id = application.schedule_initialization_for_test(
                workspace,
                inspect_native_image(workspace.sample_path),
            )
            await _wait_for_operation_state(application, operation_id, "running")
            cancelled = await application.execute_tool(
                "operation.cancel",
                OperationCancelInput(operation_id=operation_id),
            )
            assert isinstance(cancelled, OperationCancelOutput)
            completed = await application.execute_tool(
                "operation.wait",
                OperationWaitInput(operation_id=operation_id, wait_ms=1_000),
            )
            assert isinstance(completed, OperationWaitOutput)
            assert completed.state == "cancelled"
        finally:
            await held_lock.release()

        outcome = application.storage.workspaces.get(workspace.workspace_id).analysis_outcome
        assert outcome is not None
        assert outcome.state == "cancelled"
        assert outcome.reason == "首次分析已取消"
        assert backend.bootstrap_started.is_set() is False
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_create_cancel_while_waiting_for_analysis_slot(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, source, backend = _lifecycle_application(tmp_path)
        workspace = application.storage.workspaces.create(source)
        await application.acquire_local_analysis_slot_for_test()
        try:
            operation_id = application.schedule_initialization_for_test(
                workspace,
                inspect_native_image(workspace.sample_path),
            )
            await _wait_for_operation_state(application, operation_id, "running")
            cancelled = await application.execute_tool(
                "operation.cancel",
                OperationCancelInput(operation_id=operation_id),
            )
            assert isinstance(cancelled, OperationCancelOutput)
            completed = await application.execute_tool(
                "operation.wait",
                OperationWaitInput(operation_id=operation_id, wait_ms=1_000),
            )
            assert isinstance(completed, OperationWaitOutput)
            assert completed.state == "cancelled"
        finally:
            application.release_local_analysis_slot_for_test()

        outcome = application.storage.workspaces.get(workspace.workspace_id).analysis_outcome
        assert outcome is not None
        assert outcome.state == "cancelled"
        assert backend.bootstrap_started.is_set() is False
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_create_running_cancel_persists_cancelled_outcome(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, source, backend = _lifecycle_application(
            tmp_path,
            block_bootstrap=True,
        )
        started = await application.execute_tool(
            "workspace.create",
            WorkspaceCreateInput(sample_path=str(source)),
        )
        assert isinstance(started, WorkspaceCreateOutput)
        await asyncio.wait_for(backend.bootstrap_started.wait(), timeout=2)

        cancelled = await application.execute_tool(
            "operation.cancel",
            OperationCancelInput(operation_id=started.analysis_operation_id),
        )
        assert isinstance(cancelled, OperationCancelOutput)
        assert cancelled.state == "cancel_requested"
        completed = await application.execute_tool(
            "operation.wait",
            OperationWaitInput(operation_id=started.analysis_operation_id, wait_ms=1_000),
        )
        assert isinstance(completed, OperationWaitOutput)
        assert completed.state == "cancelled"

        summary = application.workspace_summary_for_test(
            application.storage.workspaces.get(started.workspace_id)
        )
        assert summary.analysis_outcome is not None
        assert summary.analysis_outcome.state == "cancelled"
        assert summary.analysis_outcome.reason == "首次分析已取消"
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_create_service_close_persists_failed_outcome(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, source, backend = _lifecycle_application(
            tmp_path,
            block_bootstrap=True,
        )
        started = await application.execute_tool(
            "workspace.create",
            WorkspaceCreateInput(sample_path=str(source)),
        )
        assert isinstance(started, WorkspaceCreateOutput)
        await asyncio.wait_for(backend.bootstrap_started.wait(), timeout=2)

        await application.aclose()

        operation = application.storage.operations.get(started.analysis_operation_id)
        assert operation.state.value == "failed"
        assert operation.failure is not None
        assert operation.failure.message == "操作因服务关闭而中止"
        outcome = application.storage.workspaces.get(started.workspace_id).analysis_outcome
        assert outcome is not None
        assert outcome.state == "failed"
        assert outcome.reason == "操作因服务关闭而中止"

    asyncio.run(scenario())


def test_workspace_create_service_close_before_dispatch_is_failed(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, source, backend = _lifecycle_application(tmp_path)
        workspace = application.storage.workspaces.create(source)
        operation_id = application.schedule_initialization_for_test(
            workspace,
            inspect_native_image(workspace.sample_path),
        )
        assert application.storage.operations.get(operation_id).state.value == "queued"

        # 直接执行关闭协程, 确保调度任务尚未获得事件循环时间片。
        await application.close_runtime_resources_for_test()

        operation = application.storage.operations.get(operation_id)
        assert operation.state.value == "failed"
        assert operation.failure is not None
        assert operation.failure.code == "worker_crashed"
        assert operation.failure.message == "操作因服务关闭而中止"
        outcome = application.storage.workspaces.get(workspace.workspace_id).analysis_outcome
        assert outcome is not None
        assert outcome.state == "failed"
        assert outcome.reason == "操作因服务关闭而中止"
        assert backend.bootstrap_started.is_set() is False

    asyncio.run(scenario())


def test_workspace_create_late_cancel_after_publish_started_reports_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        application, source, _backend = _lifecycle_application(tmp_path)
        publish_entered = threading.Event()
        allow_publish = threading.Event()
        original_publish = cast(
            Callable[..., RevisionSnapshot],
            application.storage.workspaces.publish_staging,
        )

        def blocked_publish(*args: object, **kwargs: object) -> RevisionSnapshot:
            publish_entered.set()
            if not allow_publish.wait(timeout=5):
                raise TimeoutError("测试未释放首次分析 revision publish")
            return original_publish(*args, **kwargs)

        monkeypatch.setattr(
            application.storage.workspaces,
            "publish_staging",
            blocked_publish,
        )
        try:
            started = await application.execute_tool(
                "workspace.create",
                WorkspaceCreateInput(sample_path=str(source)),
            )
            assert isinstance(started, WorkspaceCreateOutput)
            assert await asyncio.to_thread(publish_entered.wait, 2)

            cancelled = await application.execute_tool(
                "operation.cancel",
                OperationCancelInput(operation_id=started.analysis_operation_id),
            )
            assert isinstance(cancelled, OperationCancelOutput)
            assert cancelled.state == "cancel_requested"
            allow_publish.set()

            completed = await application.execute_tool(
                "operation.wait",
                OperationWaitInput(
                    operation_id=started.analysis_operation_id,
                    wait_ms=1_000,
                ),
            )
            assert isinstance(completed, OperationWaitOutput)
            assert completed.state == "succeeded"
            workspace = application.storage.workspaces.get(started.workspace_id)
            assert workspace.current_revision is not None
            assert workspace.analysis_outcome is None
            summary = application.workspace_summary_for_test(workspace)
            assert summary.state == "ready"
            assert summary.analysis_outcome is None
        finally:
            allow_publish.set()
            await application.aclose()

    asyncio.run(scenario())


def test_workspace_create_failure_is_sanitized_and_visible_across_sessions(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        first_paths = _session_paths(tmp_path, "session_first")
        first, source, _backend = _lifecycle_application(
            tmp_path,
            paths=first_paths,
            fail_bootstrap=True,
        )
        started = await first.execute_tool(
            "workspace.create",
            WorkspaceCreateInput(sample_path=str(source)),
        )
        assert isinstance(started, WorkspaceCreateOutput)
        completed = await first.execute_tool(
            "operation.wait",
            OperationWaitInput(operation_id=started.analysis_operation_id, wait_ms=1_000),
        )
        assert isinstance(completed, OperationWaitOutput)
        assert completed.state == "failed"
        assert completed.failure is not None
        assert completed.failure.message == (
            "IDA 没有完成这项操作。请查看 logs 目录中的本次运行日志，然后重试。"
        )
        await first.aclose()

        second_paths = _session_paths(tmp_path, "session_second")
        config = AppConfig(workers=WorkerConfig(analysis_limit=1))
        second_storage = SupervisorStorage.open(config=config, paths=second_paths)
        second = Application(
            config=config,
            storage=second_storage,
            changes=ChangeSetStore(
                second_paths.data_root / "change-sets",
                workspace_lease_root=second_storage.workspaces.lease_root,
            ),
            cursors=CursorCodec(second_paths.data_root / "cursor.key"),
            backend=_LifecycleBootstrapBackend(started.sample_sha256),
        )
        listed = await second.execute_tool("workspace.list", WorkspaceListInput())
        assert isinstance(listed, WorkspaceListOutput)
        summary = next(
            item for item in listed.workspaces if item.workspace_id == started.workspace_id
        )
        assert summary.state == "failed"
        assert summary.analysis_outcome is not None
        assert summary.analysis_outcome.state == "failed"
        assert summary.analysis_outcome.reason == (
            "IDA 没有完成这项操作。请查看 logs 目录中的本次运行日志，然后重试。"
        )
        assert "sensitive" not in summary.analysis_outcome.reason
        assert summary.analysis_outcome.recorded_at > 0
        await second.aclose()

    asyncio.run(scenario())


def test_workspace_create_cancelled_outcome_is_visible_across_sessions(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        first_paths = _session_paths(tmp_path, "session_first")
        first, source, backend = _lifecycle_application(
            tmp_path,
            paths=first_paths,
            block_bootstrap=True,
        )
        started = await first.execute_tool(
            "workspace.create",
            WorkspaceCreateInput(sample_path=str(source)),
        )
        assert isinstance(started, WorkspaceCreateOutput)
        await asyncio.wait_for(backend.bootstrap_started.wait(), timeout=2)

        cancelled = await first.execute_tool(
            "operation.cancel",
            OperationCancelInput(operation_id=started.analysis_operation_id),
        )
        assert isinstance(cancelled, OperationCancelOutput)
        completed = await first.execute_tool(
            "operation.wait",
            OperationWaitInput(operation_id=started.analysis_operation_id, wait_ms=1_000),
        )
        assert isinstance(completed, OperationWaitOutput)
        assert completed.state == "cancelled"
        await first.aclose()

        second_paths = _session_paths(tmp_path, "session_second")
        config = AppConfig(workers=WorkerConfig(analysis_limit=1))
        second_storage = SupervisorStorage.open(config=config, paths=second_paths)
        second = Application(
            config=config,
            storage=second_storage,
            changes=ChangeSetStore(
                second_paths.data_root / "change-sets",
                workspace_lease_root=second_storage.workspaces.lease_root,
            ),
            cursors=CursorCodec(second_paths.data_root / "cursor.key"),
            backend=_LifecycleBootstrapBackend(started.sample_sha256),
        )
        listed = await second.execute_tool("workspace.list", WorkspaceListInput())
        assert isinstance(listed, WorkspaceListOutput)
        summary = next(
            item for item in listed.workspaces if item.workspace_id == started.workspace_id
        )
        assert summary.state == "failed"
        assert summary.analysis_outcome is not None
        assert summary.analysis_outcome.state == "cancelled"
        assert summary.analysis_outcome.reason == "首次分析已取消"
        assert summary.analysis_outcome.recorded_at > 0
        await second.aclose()

    asyncio.run(scenario())


def test_workspace_retry_reuses_failed_workspace_and_rejects_duplicate(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        application, source, backend = _lifecycle_application(
            tmp_path,
            fail_bootstrap=True,
        )
        started = await application.execute_tool(
            "workspace.create",
            WorkspaceCreateInput(sample_path=str(source)),
        )
        assert isinstance(started, WorkspaceCreateOutput)
        failed = await application.execute_tool(
            "operation.wait",
            OperationWaitInput(operation_id=started.analysis_operation_id, wait_ms=1_000),
        )
        assert isinstance(failed, OperationWaitOutput)
        assert failed.state == "failed"

        backend.fail_bootstrap = False
        backend.block_bootstrap = True
        backend.bootstrap_started.clear()
        retried = await application.execute_tool(
            "workspace.retry",
            WorkspaceRetryInput(workspace_id=started.workspace_id),
        )
        assert isinstance(retried, WorkspaceRetryOutput)
        assert retried.workspace_id == started.workspace_id
        assert retried.sample_sha256 == started.sample_sha256
        assert retried.analysis_operation_id != started.analysis_operation_id
        await asyncio.wait_for(backend.bootstrap_started.wait(), timeout=2)

        listed = await application.execute_tool("workspace.list", WorkspaceListInput())
        assert isinstance(listed, WorkspaceListOutput)
        summary = next(
            item for item in listed.workspaces if item.workspace_id == started.workspace_id
        )
        assert summary.state == "analyzing"
        assert summary.analysis_outcome is None

        with pytest.raises(ToolExecutionError) as duplicate:
            await application.execute_tool(
                "workspace.retry",
                WorkspaceRetryInput(workspace_id=started.workspace_id),
            )
        assert duplicate.value.code is BusinessErrorCode.PRECONDITION_FAILED
        assert "正在执行其他操作" in duplicate.value.message

        backend.allow_bootstrap.set()
        completed = await application.execute_tool(
            "operation.wait",
            OperationWaitInput(operation_id=retried.analysis_operation_id, wait_ms=1_000),
        )
        assert isinstance(completed, OperationWaitOutput)
        assert completed.state == "succeeded"
        workspace = application.storage.workspaces.get(started.workspace_id)
        assert workspace.current_revision is not None
        assert workspace.analysis_outcome is None

        with pytest.raises(ToolExecutionError) as ready:
            await application.execute_tool(
                "workspace.retry",
                WorkspaceRetryInput(workspace_id=started.workspace_id),
            )
        assert ready.value.code is BusinessErrorCode.PRECONDITION_FAILED
        assert ready.value.details == {"current_revision": workspace.current_revision}
        await application.aclose()

    async def bounded_scenario() -> None:
        await asyncio.wait_for(scenario(), timeout=10)

    asyncio.run(bounded_scenario())


def test_workspace_retry_rejects_changed_saved_sample(tmp_path: Path) -> None:
    async def scenario() -> None:
        application, source, _backend = _lifecycle_application(
            tmp_path,
            fail_bootstrap=True,
        )
        started = await application.execute_tool(
            "workspace.create",
            WorkspaceCreateInput(sample_path=str(source)),
        )
        assert isinstance(started, WorkspaceCreateOutput)
        failed = await application.execute_tool(
            "operation.wait",
            OperationWaitInput(operation_id=started.analysis_operation_id, wait_ms=1_000),
        )
        assert isinstance(failed, OperationWaitOutput)
        assert failed.state == "failed"

        workspace = application.storage.workspaces.get(started.workspace_id)
        tampered = bytearray(workspace.sample_path.read_bytes())
        tampered[-1] ^= 0xFF
        workspace.sample_path.write_bytes(tampered)
        with pytest.raises(ToolExecutionError) as raised:
            await application.execute_tool(
                "workspace.retry",
                WorkspaceRetryInput(workspace_id=started.workspace_id),
            )
        assert raised.value.code is BusinessErrorCode.EXECUTION_FAILED
        assert "完整性检查" in raised.value.message
        await application.aclose()

    asyncio.run(scenario())


def test_workspace_retry_schedule_failure_restores_failed_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        application, source, _backend = _lifecycle_application(
            tmp_path,
            fail_bootstrap=True,
        )
        started = await application.execute_tool(
            "workspace.create",
            WorkspaceCreateInput(sample_path=str(source)),
        )
        assert isinstance(started, WorkspaceCreateOutput)
        failed = await application.execute_tool(
            "operation.wait",
            OperationWaitInput(operation_id=started.analysis_operation_id, wait_ms=1_000),
        )
        assert isinstance(failed, OperationWaitOutput)
        assert failed.state == "failed"

        def fail_schedule(
            workspace: WorkspaceSnapshot,
            *,
            native_identity: NativeImageIdentity,
        ) -> str:
            del workspace, native_identity
            raise RuntimeError("schedule failed")

        monkeypatch.setattr(application, "_schedule_workspace_initialization", fail_schedule)
        with pytest.raises(RuntimeError, match="schedule failed"):
            await application.execute_tool(
                "workspace.retry",
                WorkspaceRetryInput(workspace_id=started.workspace_id),
            )

        workspace = application.storage.workspaces.get(started.workspace_id)
        assert workspace.current_revision is None
        assert workspace.analysis_outcome is not None
        assert workspace.analysis_outcome.state == "failed"
        assert workspace.analysis_outcome.reason == (
            "首次分析重试任务未能启动。请查看 logs 目录中的本次运行日志，然后重试。"
        )
        await application.aclose()

    asyncio.run(scenario())
