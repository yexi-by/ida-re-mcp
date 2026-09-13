"""标准 MCP、外部存储与隔离 IDA worker 的应用编排。"""

from __future__ import annotations

import asyncio
import base64
import codecs
import json
import shutil
import tempfile
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Literal, cast

from pydantic import JsonValue

from ida_re_mcp.config import AppConfig, RuntimePaths, default_config_path, load_config
from ida_re_mcp.constants import (
    MAX_INLINE_RESULT_BYTES,
    OPERATION_RETENTION_SECONDS,
    RESOURCE_CHUNK_BYTES,
)
from ida_re_mcp.diagnostics import write_exception_log
from ida_re_mcp.domain.base import JsonObject, StrictModel
from ida_re_mcp.domain.catalog import build_tool_catalog
from ida_re_mcp.domain.errors import (
    BusinessErrorCode,
    ResourceNotFoundError,
    ResourceRequestError,
    ToolExecutionError,
)
from ida_re_mcp.domain.resources import (
    BinaryResourceData,
    ResourceData,
    ResourceDescriptor,
    ResourcePage,
    ResourceRead,
    TextResourceData,
)
from ida_re_mcp.domain.tools import (
    AddressInspectOutput,
    AnalysisRefineInput,
    AnalysisRefineOutput,
    ArtifactReference,
    ChangeApplyInput,
    ChangeApplyOutput,
    ChangeImpact,
    ChangePrepareInput,
    ChangePrepareOutput,
    DataflowSliceInput,
    DataflowSliceOutput,
    DebugBreakpointsInput,
    DebugControlInput,
    DebugEstablishInput,
    DebugEstablishOutput,
    DebugEventsInput,
    DebugFinishInput,
    DebugInspectInput,
    DebugLaunchTarget,
    ExpertExecuteInput,
    ExpertExecuteOutput,
    FunctionInspectInput,
    FunctionInspectOutput,
    GraphQueryInput,
    GraphQueryOutput,
    OperationCancelInput,
    OperationCancelOutput,
    OperationFailure,
    OperationWaitInput,
    OperationWaitOutput,
    ProgramOverviewInput,
    ProgramOverviewOutput,
    ProgramSearchInput,
    ProgramSearchOutput,
    ReportBuildInput,
    ReportBuildOutput,
    RevisionSummary,
    TypeInspectInput,
    TypeInspectOutput,
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
from ida_re_mcp.il2cpp.models import NativeBinding
from ida_re_mcp.protocol import McpRuntime
from ida_re_mcp.supervisor._fs import canonical_json_bytes
from ida_re_mcp.supervisor._process_lock import (
    AsyncInterprocessFileLock,
    AsyncInterprocessSlotLease,
    AsyncInterprocessSlotPool,
    InterprocessFileLock,
    exclusive_process_lease,
)
from ida_re_mcp.supervisor.artifacts import (
    ArtifactFileInput,
    ArtifactIntegrityError,
    ArtifactMetadata,
    ArtifactNotFoundError,
    parse_artifact_uri,
)
from ida_re_mcp.supervisor.backend import (
    AnalysisBackend,
    DebugBackend,
    DebugRequestCancelled,
    IdaBackend,
    SubprocessIdaBackend,
)
from ida_re_mcp.supervisor.change_adapter import (
    ArtifactMaterialization,
    ChangeAdapterInputError,
    ChangeAdapterResultError,
    ChangeContext,
    ChangeSourceError,
    InverseSource,
    SolidifiedSource,
    build_canonical_plan,
    build_mutation_execution,
    build_preflight_execution,
    parse_preflight_impact,
    parse_worker_impact,
    source_solidification_requests,
    validate_local_sources,
)
from ida_re_mcp.supervisor.changes import (
    ChangeSetError,
    ChangeSetStore,
    StoredChangeOperation,
    StoredImportIl2CppBundleOperation,
)
from ida_re_mcp.supervisor.cursors import (
    CursorCodec,
    CursorError,
    CursorPosition,
    query_digest,
)
from ida_re_mcp.supervisor.debug_adapter import (
    BreakpointReplacementPlan,
    DebugAdapterError,
    DebugContext,
    WorkerDebugCommand,
    adapt_debug_breakpoints,
    adapt_debug_cancelled,
    adapt_debug_control,
    adapt_debug_establish,
    adapt_debug_events,
    adapt_debug_finish,
    adapt_debug_inspect,
    build_debug_breakpoint_replacement,
    build_debug_breakpoint_rollback,
    prepare_debug_breakpoint_enable,
    prepare_debug_breakpoint_list,
    prepare_debug_control,
    prepare_debug_establish,
    prepare_debug_events,
    prepare_debug_finish,
    prepare_debug_inspect,
)
from ida_re_mcp.supervisor.errors import (
    AnalysisRetryUnavailableError,
    InvalidIdentifierError,
    OperationNotFoundError,
    OperationStateError,
    RevisionConflictError,
    RevisionNotFoundError,
    StagingIntegrityError,
    StorageCorruptionError,
    SupervisorAlreadyRunningError,
    SupervisorError,
    WorkspaceNotFoundError,
)
from ida_re_mcp.supervisor.expert_adapter import (
    ExpertAdapterError,
    adapt_expert_worker_result,
)
from ida_re_mcp.supervisor.native_formats import (
    NativeImageIdentity,
    UnsupportedNativeImageError,
    inspect_native_image,
)
from ida_re_mcp.supervisor.operations import OperationSnapshot, OperationState
from ida_re_mcp.supervisor.refine_adapter import (
    RefineAdapterInputError,
    RefineAdapterResultError,
    adapt_refine_worker_result,
    build_refine_worker_request,
)
from ida_re_mcp.supervisor.static_adapter import (
    AnalysisContext,
    StaticAdapterCapabilityError,
    StaticAdapterInput,
    StaticAdapterInputError,
    StaticAdapterResultError,
    static_page_facts,
)
from ida_re_mcp.supervisor.static_adapter import (
    adapt_worker_results as adapt_static_results,
)
from ida_re_mcp.supervisor.static_adapter import (
    build_worker_requests as build_static_requests,
)
from ida_re_mcp.supervisor.storage import SupervisorStorage
from ida_re_mcp.supervisor.workers import WorkerProcessError
from ida_re_mcp.supervisor.workspaces import (
    ColdValidationReceipt,
    ImageIdentity,
    RevisionCheckout,
    RevisionSnapshot,
    RevisionStaging,
    WorkspaceSnapshot,
    hash_staging_payload,
)
from ida_re_mcp.worker.errors import WorkerError

_STATIC_TOOL_NAMES = frozenset(
    {
        "program.overview",
        "program.search",
        "address.inspect",
        "function.inspect",
        "graph.query",
        "dataflow.slice",
        "type.inspect",
    }
)
_DEBUG_TOOL_NAMES = frozenset(
    {
        "debug.establish",
        "debug.control",
        "debug.events",
        "debug.inspect",
        "debug.breakpoints",
        "debug.finish",
    }
)
_MAX_RESOURCE_CONTENTS = 64
_OPERATION_WAIT_POLL_SECONDS = 0.05
_TERMINAL_OPERATION_STATES = frozenset(
    {
        OperationState.SUCCEEDED,
        OperationState.FAILED,
        OperationState.CANCELLED,
    }
)
_WORKER_BUSINESS_ERRORS: dict[str, BusinessErrorCode] = {
    "ambiguous_reference": BusinessErrorCode.AMBIGUOUS_REFERENCE,
    "capability_unavailable": BusinessErrorCode.CAPABILITY_UNAVAILABLE,
    "cursor_stale": BusinessErrorCode.CURSOR_STALE,
    "debug_state_conflict": BusinessErrorCode.DEBUG_STATE_CONFLICT,
    "policy_denied": BusinessErrorCode.POLICY_DENIED,
    "revision_conflict": BusinessErrorCode.REVISION_CONFLICT,
    "slice_seed_not_found": BusinessErrorCode.UNSUPPORTED,
    "unsupported": BusinessErrorCode.UNSUPPORTED,
    "worker_crashed": BusinessErrorCode.WORKER_CRASHED,
    "worker_timeout": BusinessErrorCode.WORKER_CRASHED,
}
_WORKER_PUBLIC_MESSAGES: dict[str, str] = {
    "ambiguous_reference": ("这个名称对应多个目标。请改用明确的编号或地址后重试。"),
    "capability_unavailable": (
        "当前 IDA 安装没有完成这项操作所需的功能。"
        "如果请求包含伪代码，请确认已经安装并授权 Hex-Rays Decompiler。"
    ),
    "cursor_stale": ("分页位置已经失效。请去掉 cursor，从第一页重新查询。"),
    "debug_state_conflict": (
        "调试会话的当前状态不允许这个操作。请先调用 debug.events 读取最新状态；"
        "程序暂停后，请使用最新的 stop_id。"
    ),
    "policy_denied": (
        "config.toml 当前禁止这项操作。确实需要时，请修改 [policy] 中对应的选项并重启服务。"
    ),
    "revision_conflict": (
        "分析项目已经产生新版本，当前操作不能继续。"
        "请调用 workspace.get 读取 current_revision，再用新版本重新发起操作。"
    ),
    "slice_seed_not_found": (
        "IDA 在这个地址没有找到可追踪的数据流指令。"
        "请先用 address.inspect 确认地址，或换一个指令地址。"
    ),
    "unsupported": ("IDA 无法按当前目标或参数完成这项操作。请检查工具说明、编号和地址后重试。"),
    "worker_crashed": ("IDA 后台进程意外退出。请查看 logs 目录中的本次运行日志，然后重试。"),
    "worker_timeout": ("IDA 后台处理超时，已经停止。请查看 logs 目录中的本次运行日志，然后重试。"),
}
_BUSINESS_PUBLIC_MESSAGES: dict[BusinessErrorCode, str] = {
    BusinessErrorCode.AMBIGUOUS_REFERENCE: ("这个引用对应多个目标。请改用明确的编号或地址后重试。"),
    BusinessErrorCode.CAPABILITY_UNAVAILABLE: (
        "当前 IDA 安装没有完成这项操作所需的功能。请检查工具说明和 IDA 许可证。"
    ),
    BusinessErrorCode.CHANGE_SET_INVALID: (
        "修改内容没有通过检查。请核对 change.prepare 的操作参数；"
        "只有准备成功后才能调用 change.apply。"
    ),
    BusinessErrorCode.CURSOR_STALE: ("分页位置已经失效。请去掉 cursor，从第一页重新查询。"),
    BusinessErrorCode.DEBUG_STATE_CONFLICT: (
        "调试会话的状态已经变化。请调用 debug.events 获取最新状态；"
        "程序暂停后，请使用最新的 stop_id。"
    ),
    BusinessErrorCode.EXECUTION_FAILED: (
        "IDA 没有完成这项操作。请查看 logs 目录中的本次运行日志，然后重试。"
    ),
    BusinessErrorCode.OPERATION_NOT_FOUND: (
        "找不到这个后台任务，或任务记录已经过期。"
        "如果它属于样本分析，请调用 workspace.get 检查是否已经产生 current_revision。"
    ),
    BusinessErrorCode.POLICY_DENIED: (
        "config.toml 当前禁止这项操作。确实需要时，请修改 [policy] 中对应的选项并重启服务。"
    ),
    BusinessErrorCode.PRECONDITION_FAILED: (
        "操作前提已经变化。请重新读取当前数据，并用最新编号、版本或校验值重试。"
    ),
    BusinessErrorCode.RESOURCE_NOT_FOUND: (
        "找不到这个工具生成的文件。请重新调用生成文件的工具，并使用它返回的新地址。"
    ),
    BusinessErrorCode.REVISION_CONFLICT: (
        "分析项目已经产生新版本，当前操作不能继续。"
        "请调用 workspace.get 读取 current_revision，再用新版本重新发起操作。"
    ),
    BusinessErrorCode.REVISION_NOT_FOUND: (
        "找不到这个分析版本，它可能已经被清理。"
        "请调用 workspace.get，并改用 current_revision 或仍然存在的历史版本。"
    ),
    BusinessErrorCode.UNSUPPORTED: ("当前目标或参数无法处理。请检查工具说明、编号和地址后重试。"),
    BusinessErrorCode.WORKER_CRASHED: (
        "IDA 后台进程没有正常完成操作。请查看 logs 目录中的本次运行日志，然后重试。"
    ),
    BusinessErrorCode.WORKSPACE_NOT_FOUND: (
        "找不到这个分析项目。请先调用 workspace.list 检查 workspace_id；"
        "找到后再用 workspace.get 读取 current_revision。"
    ),
}


def _is_utf8_resource(media_type: str) -> bool:
    """判断 artifact 是否应以 MCP 文本 resource 返回。"""

    normalized = media_type.partition(";")[0].strip().lower()
    return (
        normalized.startswith("text/")
        or normalized
        in {
            "application/json",
            "application/javascript",
            "application/x-ndjson",
            "application/xml",
        }
        or normalized.endswith(("+json", "+ndjson", "+xml"))
    )


@dataclass(slots=True)
class _DebugSession:
    checkout: RevisionCheckout
    backend: DebugBackend
    context: DebugContext
    workspace_lock: AsyncInterprocessFileLock
    worker_slot: AsyncInterprocessSlotLease
    owned_target: bool
    request_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    idle_task: asyncio.Task[None] | None = None
    close_task: asyncio.Task[None] | None = None


@dataclass(slots=True)
class _AnalysisSession:
    workspace_id: str
    revision: str
    checkout: RevisionCheckout
    backend: AnalysisBackend
    worker_slot: AsyncInterprocessSlotLease
    in_use: bool
    last_used: float
    idle_task: asyncio.Task[None] | None = None
    close_task: asyncio.Task[None] | None = None


@dataclass(frozen=True, slots=True)
class _ColdImageIdentity:
    """发布前必须由冷重开 IDB 再次证明的原生镜像身份。"""

    sample_sha256: str
    container: Literal["elf", "pe"] | None = None
    architecture: str | None = None
    bitness: int | None = None
    endianness: str | None = None
    image_size: int | None = None

    @classmethod
    def from_overview(
        cls,
        sample_sha256: str,
        overview: ProgramOverviewOutput,
    ) -> _ColdImageIdentity:
        container = {
            "elf32": "elf",
            "elf64": "elf",
            "pe32": "pe",
            "pe32+": "pe",
        }.get(overview.image.format)
        return cls(
            sample_sha256=sample_sha256,
            container=cast(Literal["elf", "pe"] | None, container),
            architecture=overview.image.architecture,
            bitness=overview.image.bitness,
            endianness=overview.image.endian,
            image_size=overview.image.image_size,
        )


@dataclass(frozen=True, slots=True)
class _SessionGarbageCollection:
    removed_paths: tuple[Path, ...]
    skipped_session_ids: tuple[str, ...]
    reclaimed_bytes: int


class Application:
    """负责处理 MCP 请求并管理本次服务运行所需的资源。"""

    def __init__(
        self,
        *,
        config: AppConfig,
        storage: SupervisorStorage,
        changes: ChangeSetStore,
        cursors: CursorCodec,
        backend: IdaBackend,
        owner_lease: InterprocessFileLock | None = None,
    ) -> None:
        self.config = config
        self.storage = storage
        self.changes = changes
        self.cursors = cursors
        self.backend = backend
        self._owner_lease = owner_lease
        catalog = build_tool_catalog(
            enable_authoring=config.policy.authoring,
            enable_debug=config.policy.debug_launch or config.policy.debug_attach,
            enable_expert=config.policy.expert,
            operation_timeout_seconds=config.workers.operation_timeout_seconds,
        )
        self._catalog_by_name = {spec.name: spec for spec in catalog}
        self._mcp = McpRuntime(
            self,
            catalog=catalog,
            data_root=storage.paths.data_root,
            log_root=storage.paths.shared_log_root,
            diagnostic_log_root=storage.paths.log_root,
        )
        self._operation_tasks: dict[str, asyncio.Task[None]] = {}
        self._operation_terminal_callbacks: dict[
            str,
            Callable[[Literal["failed", "cancelled"], str], None],
        ] = {}
        self._cancellable_operations: set[str] = set()
        self._workspace_operations: dict[str, str] = {}
        self._debug_sessions: dict[str, _DebugSession] = {}
        self._analysis_sessions: dict[tuple[str, str], _AnalysisSession] = {}
        self._analysis_sessions_guard = asyncio.Lock()
        self._analysis_opening_count = 0
        self._session_close_tasks: set[asyncio.Task[None]] = set()
        self._workspace_locks: dict[str, AsyncInterprocessFileLock] = {}
        self._analysis_slots = asyncio.Semaphore(config.workers.analysis_limit)
        self._debug_slots = asyncio.Semaphore(config.workers.debug_limit)
        worker_slot_root = storage.paths.data_root / "worker-slots"
        self._analysis_worker_slots = AsyncInterprocessSlotPool(
            worker_slot_root / "analysis",
            limit=config.workers.analysis_limit,
        )
        self._debug_worker_slots = AsyncInterprocessSlotPool(
            worker_slot_root / "debug",
            limit=config.workers.debug_limit,
        )
        self._close_task: asyncio.Task[None] | None = None
        self._closed = False

    @classmethod
    def open(
        cls,
        config_path: Path | None = None,
        *,
        paths: RuntimePaths | None = None,
        backend: IdaBackend | None = None,
    ) -> Application:
        config_source = (config_path or default_config_path()).resolve()
        config = load_config(config_path)
        runtime_paths = paths or RuntimePaths.discover(
            runtime=config.runtime,
            config_directory=config_source.parent,
        )
        runtime_paths.data_root.mkdir(parents=True, exist_ok=True)
        registry_lease = exclusive_process_lease(_session_registry_lease_path(runtime_paths))
        registry_lease.acquire()
        try:
            runtime_paths.ensure()
            owner_lease = exclusive_process_lease(runtime_paths.session_lease_path)
            if not owner_lease.try_acquire():
                raise SupervisorAlreadyRunningError(
                    "当前连接使用的运行目录正在被另一个 ida-re-mcp 使用。"
                    "请关闭重复启动的服务后重试。"
                )
            try:
                storage = SupervisorStorage.open(config=config, paths=runtime_paths)
                worker_environment = (
                    {"IDADIR": config.runtime.ida_dir}
                    if config.runtime.ida_dir is not None
                    else None
                )
                return cls(
                    config=config,
                    storage=storage,
                    changes=ChangeSetStore(
                        storage.paths.change_root,
                        workspace_lease_root=storage.workspaces.lease_root,
                    ),
                    cursors=CursorCodec(storage.paths.cursor_key_path),
                    backend=backend
                    or SubprocessIdaBackend(
                        log_root=storage.paths.log_root,
                        environment=worker_environment,
                    ),
                    owner_lease=owner_lease,
                )
            except BaseException as error:
                write_exception_log(
                    runtime_paths.log_root,
                    context="ida-re-mcp 启动失败",
                    error=error,
                )
                owner_lease.release()
                raise
        finally:
            registry_lease.release()

    async def serve(self) -> None:
        """通过官方 MCP stdio transport 运行服务。"""

        self._require_open()
        await self._mcp.serve_stdio()

    async def execute_tool(
        self,
        name: str,
        arguments: StrictModel,
    ) -> StrictModel | JsonObject:
        self._require_open()
        try:
            if name == "operation.wait":
                return await self._operation_wait(cast(OperationWaitInput, arguments))
            if name == "operation.cancel":
                return await self._operation_cancel(cast(OperationCancelInput, arguments))
            if name == "workspace.create":
                return await self._workspace_create(cast(WorkspaceCreateInput, arguments))
            if name == "workspace.retry":
                return await self._workspace_retry(cast(WorkspaceRetryInput, arguments))
            if name == "workspace.list":
                return await self._workspace_list(cast(WorkspaceListInput, arguments))
            if name == "workspace.get":
                return await self._workspace_get(cast(WorkspaceGetInput, arguments))
            if name == "workspace.export":
                return await self._workspace_export(cast(WorkspaceExportInput, arguments))
            if name in _STATIC_TOOL_NAMES:
                return await self._static_query(name, arguments)
            if name == "report.build":
                return await self._report_build(cast(ReportBuildInput, arguments))
            if name == "analysis.refine":
                return await self._analysis_refine(cast(AnalysisRefineInput, arguments))
            if name == "change.prepare":
                return await self._change_prepare(cast(ChangePrepareInput, arguments))
            if name == "change.apply":
                return await self._change_apply(cast(ChangeApplyInput, arguments))
            if name in _DEBUG_TOOL_NAMES:
                return await self._debug_tool(name, arguments)
            if name == "expert.execute":
                return await self._expert_execute(cast(ExpertExecuteInput, arguments))
            raise ToolExecutionError(
                BusinessErrorCode.UNSUPPORTED,
                f"当前服务没有提供工具 `{name}`。请先读取 tools/list，并使用其中列出的名称。",
            )
        except ToolExecutionError:
            raise
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            translated = _tool_error(exc)
            if translated is None:
                raise
            raise translated from exc

    async def list_resources(
        self,
        cursor: str | None,
    ) -> ResourcePage:
        artifacts = await asyncio.to_thread(self.storage.artifacts.list)
        digest = query_digest("\n".join(item.uri for item in artifacts).encode("utf-8"))
        offset = 0
        if cursor is not None:
            try:
                offset = self.cursors.decode(
                    cursor,
                    scope="resources",
                    workspace_id=None,
                    revision=None,
                    query_digest=digest,
                ).offset
            except CursorError as exc:
                raise ResourceRequestError(
                    "下一页位置已经失效。请从第一页重新读取生成文件列表。"
                ) from exc
        page_items = artifacts[offset : offset + 200]
        next_offset = offset + len(page_items)
        next_cursor = (
            self.cursors.encode(CursorPosition("resources", None, None, digest, next_offset))
            if next_offset < len(artifacts)
            else None
        )
        return ResourcePage(
            resources=[
                ResourceDescriptor(
                    uri=item.uri,
                    name=item.name or item.artifact_id,
                    title=item.name,
                    description=(f"工具生成的文件。内容校验值为 SHA-256 {item.content_sha256}。"),
                    mime_type=item.media_type,
                    size_bytes=item.size,
                )
                for item in page_items
            ],
            next_cursor=next_cursor,
        )

    async def read_resource(
        self,
        uri: str,
    ) -> ResourceRead:
        try:
            workspace_id, revision, artifact_id = parse_artifact_uri(uri)
        except ValueError as exc:
            raise ResourceRequestError(
                "文件地址格式不正确。请使用工具返回的完整文件地址。",
                uri=uri,
            ) from exc

        def read_contents() -> ResourceRead:
            contents: list[ResourceData] = []
            offset = 0
            with self.storage.artifacts.resource_read_lock(workspace_id):
                try:
                    metadata = self.storage.artifacts.get(
                        workspace_id,
                        revision,
                        artifact_id,
                        verify=True,
                    )
                    text_decoder = (
                        codecs.getincrementaldecoder("utf-8")(errors="strict")
                        if _is_utf8_resource(metadata.media_type)
                        else None
                    )
                    while len(contents) < _MAX_RESOURCE_CONTENTS:
                        chunk = self.storage.artifacts.read_verified_chunk(
                            metadata,
                            offset=offset,
                            limit=(
                                RESOURCE_CHUNK_BYTES - 4
                                if text_decoder is not None
                                else RESOURCE_CHUNK_BYTES
                            ),
                        )
                        if text_decoder is None:
                            contents.append(
                                BinaryResourceData(
                                    kind="blob",
                                    uri=uri,
                                    mime_type=chunk.metadata.media_type,
                                    blob=base64.b64encode(chunk.data).decode("ascii"),
                                )
                            )
                        else:
                            contents.append(
                                TextResourceData(
                                    kind="text",
                                    uri=uri,
                                    mime_type=chunk.metadata.media_type,
                                    text=text_decoder.decode(chunk.data, final=chunk.eof),
                                )
                            )
                        if chunk.eof:
                            return ResourceRead(contents=contents)
                        assert chunk.next_offset is not None
                        offset = chunk.next_offset
                except ArtifactNotFoundError as exc:
                    raise ResourceNotFoundError(uri=uri) from exc
                raise RuntimeError(
                    "生成文件过大，无法一次读完。"
                    "请使用生成该文件的工具返回的文件索引，并按索引中的分块地址读取。"
                )

        return await asyncio.to_thread(read_contents)

    async def doctor(self) -> tuple[bool, JsonObject]:
        self._require_open()
        worker = await self._run_analysis_worker(self.backend.doctor)
        usage = await asyncio.to_thread(self.storage.usage)
        healthy = bool(worker.get("available"))
        report: JsonObject = {
            "healthy": healthy,
            "summary": (
                "检查通过：配置、数据目录、日志目录和 IDA 都可以正常使用。"
                if healthy
                else "检查未通过：IDA 当前无法正常启动或响应。"
            ),
            "next_step": (
                "现在可以启动 MCP 服务。"
                if healthy
                else (
                    "请确认 config.toml 中的 ida_dir 指向 IDA Pro 9.3，"
                    "再查看 runtime_paths.session_logs 目录下由 "
                    "worker.log_file 指定的探测日志。"
                )
            ),
            "python": "3.13",
            "mcp": self._mcp.protocol_report(),
            "runtime_paths": {
                "data": str(self.storage.paths.data_root),
                "logs": str(self.storage.paths.shared_log_root),
                "session_logs": str(self.storage.paths.log_root),
                "session": str(self.storage.paths.session_data_root),
            },
            "storage": {
                "bytes": usage.total_bytes,
                "quota_bytes": usage.quota_bytes,
                "over_soft_quota": usage.over_soft_quota,
            },
            "worker": worker,
        }
        return healthy, report

    async def gc(self, *, apply: bool) -> JsonObject:
        self._require_open()
        workspace_result = await asyncio.to_thread(
            self.storage.workspaces.collect_garbage,
            dry_run=not apply,
        )
        workspaces = await asyncio.to_thread(self.storage.workspaces.list)
        retained_scopes = {
            (workspace.workspace_id, revision.revision)
            for workspace in workspaces
            for revision in workspace.revisions
        }
        artifact_result = await asyncio.to_thread(
            self.storage.artifacts.collect_garbage,
            retained_scopes=retained_scopes,
            retained_revision_provider=self._retained_revisions_for_gc,
            dry_run=not apply,
        )
        change_set_result = await asyncio.to_thread(
            self.changes.collect_garbage,
            retained_scopes=retained_scopes,
            retained_revision_provider=self._retained_revisions_for_gc,
            dry_run=not apply,
        )
        expired_operations = (
            await asyncio.to_thread(self.storage.operations.purge_expired) if apply else 0
        )
        session_result = await asyncio.to_thread(
            _collect_stale_sessions,
            self.storage.paths,
            dry_run=not apply,
        )
        usage = await asyncio.to_thread(self.storage.usage)
        skipped = sorted(
            {
                *workspace_result.skipped_workspace_ids,
                *artifact_result.skipped_workspace_ids,
                *change_set_result.skipped_workspace_ids,
            }
        )
        skipped_json = cast(list[JsonValue], skipped)
        reclaimed_bytes = (
            workspace_result.reclaimed_bytes
            + artifact_result.reclaimed_bytes
            + change_set_result.reclaimed_bytes
            + session_result.reclaimed_bytes
        )
        protected_bytes = (
            usage.total_bytes if apply else max(0, usage.total_bytes - reclaimed_bytes)
        )
        candidates: JsonObject = {
            "workspace": [str(path) for path in workspace_result.removed_paths],
            "artifact": [str(path) for path in artifact_result.removed_paths],
            "change_set": [str(path) for path in change_set_result.removed_change_set_paths],
            "change_set_staging": [str(path) for path in change_set_result.removed_staging_paths],
            "session": [str(path) for path in session_result.removed_paths],
        }
        storage: JsonObject = {
            "bytes": usage.total_bytes,
            "quota_bytes": usage.quota_bytes,
            "over_soft_quota": usage.over_soft_quota,
            "protected_bytes": protected_bytes,
            "protected_bytes_exceed_quota": protected_bytes > usage.quota_bytes,
        }
        candidate_count = (
            len(workspace_result.removed_paths)
            + len(artifact_result.removed_paths)
            + len(change_set_result.removed_change_set_paths)
            + len(change_set_result.removed_staging_paths)
            + len(session_result.removed_paths)
        )
        if apply:
            summary = (
                f"清理完成：删除了 {candidate_count} 项不再使用的数据，"
                f"共释放 {reclaimed_bytes} 字节。"
            )
            next_step = "无需继续操作。" if candidate_count == 0 else "可以继续使用当前分析项目。"
        else:
            summary = (
                f"检查完成：找到 {candidate_count} 项可以清理的数据，"
                f"预计可释放 {reclaimed_bytes} 字节。"
            )
            next_step = (
                "确认列表无误后，使用 gc --apply 执行清理。"
                if candidate_count
                else "当前没有需要清理的数据。"
            )
        return {
            "applied": apply,
            "summary": summary,
            "next_step": next_step,
            "candidates": candidates,
            "skipped_workspace_ids": skipped_json,
            "skipped_session_ids": list(session_result.skipped_session_ids),
            "reclaimed_bytes": reclaimed_bytes,
            "expired_operations_removed": expired_operations,
            "storage": storage,
        }

    def _retained_revisions_for_gc(self, workspace_id: str) -> set[str]:
        """在 workspace lifecycle lease 内解析当前已发布 revision。"""

        try:
            workspace = self.storage.workspaces.get(workspace_id)
        except WorkspaceNotFoundError:
            return set()
        return {revision.revision for revision in workspace.revisions}

    async def aclose(self) -> None:
        close_task = self._close_task
        if close_task is None:
            self._closed = True
            close_task = asyncio.create_task(
                self._aclose_once(),
                name=f"application-close:{self.storage.paths.session_data_root.name}",
            )
            self._close_task = close_task
        await _await_task_preserving_cancellation(close_task)

    async def _aclose_once(self) -> None:
        """无论资源清理成败, 都释放当前 stdio 连接的 owner lease。"""

        failures: list[BaseException] = []
        try:
            await self._close_runtime_resources_once()
        except BaseException as exc:
            failures.append(exc)
        try:
            self._release_owner_lease()
        except BaseException as exc:
            failures.append(exc)
        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("ida-re-mcp 关闭期间发生多个清理错误", failures)

    async def _close_runtime_resources_once(self) -> None:
        """尽量关闭全部任务、worker、checkout 与跨进程锁线程。"""

        failures: list[BaseException] = []

        def record_failures(
            results: Sequence[object],
            *,
            ignore_cancellation: bool = False,
        ) -> None:
            for result in results:
                if not isinstance(result, BaseException):
                    continue
                if ignore_cancellation and isinstance(result, asyncio.CancelledError):
                    continue
                failures.append(result)

        operation_tasks = tuple(self._operation_tasks.items())
        for operation_id, task in operation_tasks:
            if not task.done():
                try:
                    snapshot = self.storage.operations.get(operation_id)
                    callback = self._operation_terminal_callbacks.get(operation_id)
                    if snapshot.state is OperationState.QUEUED:
                        self.storage.operations.start(operation_id)
                        self.storage.operations.fail(
                            operation_id,
                            code="worker_crashed",
                            message="操作因服务关闭而中止",
                        )
                        task.cancel()
                        if callback is not None:
                            await _complete_thread_call(
                                partial(
                                    callback,
                                    "failed",
                                    "操作因服务关闭而中止",
                                )
                            )
                        continue
                    if snapshot.state is OperationState.CANCELLED:
                        task.cancel()
                        if callback is not None:
                            await _complete_thread_call(
                                partial(
                                    callback,
                                    "cancelled",
                                    "首次分析已取消",
                                )
                            )
                        continue
                except SupervisorError:
                    pass
                except BaseException as exc:
                    failures.append(exc)
                task.cancel()
        if operation_tasks:
            operation_results = await asyncio.gather(
                *(task for _operation_id, task in operation_tasks),
                return_exceptions=True,
            )
            record_failures(operation_results, ignore_cancellation=True)

        debug_sessions = tuple(self._debug_sessions.values())
        debug_results = await asyncio.gather(
            *(self._close_debug_session(session) for session in debug_sessions),
            return_exceptions=True,
        )
        record_failures(debug_results)

        async with self._analysis_sessions_guard:
            analysis_sessions = tuple(self._analysis_sessions.values())
            self._analysis_sessions.clear()
            for session in analysis_sessions:
                _cancel_idle_task(session.idle_task)
                session.idle_task = None
        analysis_results = await asyncio.gather(
            *(self._close_analysis_session(session) for session in analysis_sessions),
            return_exceptions=True,
        )
        record_failures(analysis_results)
        self._session_close_tasks.difference_update(
            task
            for task in (
                *(session.close_task for session in debug_sessions),
                *(session.close_task for session in analysis_sessions),
            )
            if task is not None
        )

        while self._session_close_tasks:
            closing_sessions = tuple(self._session_close_tasks)
            close_results = await asyncio.gather(
                *closing_sessions,
                return_exceptions=True,
            )
            self._session_close_tasks.difference_update(closing_sessions)
            record_failures(close_results)

        workspace_lock_results = await asyncio.gather(
            *(lock.aclose() for lock in tuple(self._workspace_locks.values())),
            return_exceptions=True,
        )
        record_failures(workspace_lock_results)
        pool_results = await asyncio.gather(
            self._analysis_worker_slots.aclose(),
            self._debug_worker_slots.aclose(),
            return_exceptions=True,
        )
        record_failures(pool_results)

        if len(failures) == 1:
            raise failures[0]
        if failures:
            raise BaseExceptionGroup("ida-re-mcp 关闭期间发生多个清理错误", failures)

    def _release_owner_lease(self) -> None:
        owner_lease = self._owner_lease
        self._owner_lease = None
        if owner_lease is None:
            return
        if self.storage.paths.session_root is None:
            owner_lease.release()
            return
        registry_lease = exclusive_process_lease(_session_registry_lease_path(self.storage.paths))
        registry_lease.acquire()
        try:
            owner_lease.release()
            self.storage.paths.session_lease_path.unlink(missing_ok=True)
        finally:
            registry_lease.release()

    async def _operation_wait(self, arguments: OperationWaitInput) -> OperationWaitOutput:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + (arguments.wait_ms / 1000)
        while True:
            snapshot = await asyncio.to_thread(
                self.storage.operations.get,
                arguments.operation_id,
            )
            if (
                snapshot.state in _TERMINAL_OPERATION_STATES
                or arguments.wait_ms == 0
                or loop.time() >= deadline
            ):
                return _operation_output(snapshot)
            await asyncio.sleep(
                min(
                    _OPERATION_WAIT_POLL_SECONDS,
                    max(0.0, deadline - loop.time()),
                )
            )

    async def _operation_cancel(
        self,
        arguments: OperationCancelInput,
    ) -> OperationCancelOutput:
        before = await asyncio.to_thread(
            self.storage.operations.get,
            arguments.operation_id,
        )
        snapshot = await asyncio.to_thread(
            self.storage.operations.cancel,
            arguments.operation_id,
        )
        if (
            snapshot.state is OperationState.CANCEL_REQUESTED
            and snapshot.operation_id in self._cancellable_operations
        ):
            task = self._operation_tasks.get(snapshot.operation_id)
            if task is not None and not task.done():
                task.cancel()
        elif snapshot.state is OperationState.CANCELLED:
            # queued operation 的 coordinator 会立即进入终态; 等待调度任务完成其
            # 持久化终态回调, 使 operation.cancel 返回时 workspace 也已可观察。
            task = self._operation_tasks.get(snapshot.operation_id)
            if task is not None:
                await _await_task_preserving_cancellation(task)
        return OperationCancelOutput(
            operation_id=snapshot.operation_id,
            state=snapshot.state.value,
            cancellation_requested=(
                before.state
                not in {
                    OperationState.SUCCEEDED,
                    OperationState.FAILED,
                    OperationState.CANCELLED,
                }
            ),
        )

    async def _workspace_create(
        self,
        arguments: WorkspaceCreateInput,
    ) -> WorkspaceCreateOutput:
        sample = Path(arguments.sample_path)
        native_identity: NativeImageIdentity | None = None

        def validate_copy(path: Path, sample_sha256: str, _sample_size: int) -> None:
            nonlocal native_identity
            if arguments.expected_sha256 is not None and sample_sha256 != arguments.expected_sha256:
                raise ToolExecutionError(
                    BusinessErrorCode.PRECONDITION_FAILED,
                    (
                        "文件的 SHA-256 与 expected_sha256 不一致。"
                        "请确认 sample_path 指向正确文件，并更新校验值后重试。"
                    ),
                    details={
                        "actual_sha256": sample_sha256,
                    },
                )
            try:
                native_identity = inspect_native_image(path)
            except UnsupportedNativeImageError as exc:
                raise ToolExecutionError(
                    BusinessErrorCode.UNSUPPORTED,
                    (
                        "无法导入这个文件。当前支持小端 ELF（x86、x86-64、ARM 或 "
                        "AArch64）和 PE（x86 或 x86-64）。如果输入是脚本或压缩文件，"
                        "请先提取实际程序。"
                    ),
                    details=cast(dict[str, JsonValue], exc.details),
                ) from exc

        workspace = await _complete_thread_call(
            lambda: self.storage.workspaces.create(sample, validate_copy=validate_copy)
        )
        validated_identity = native_identity
        if validated_identity is None:
            raise RuntimeError("workspace 候选样本缺少 Native 预检身份")
        operation_id = self._schedule_workspace_initialization(
            workspace,
            native_identity=validated_identity,
        )
        return WorkspaceCreateOutput(
            workspace_id=workspace.workspace_id,
            revision=None,
            sample_sha256=workspace.sample_sha256,
            analysis_operation_id=operation_id,
        )

    def _schedule_workspace_initialization(
        self,
        workspace: WorkspaceSnapshot,
        *,
        native_identity: NativeImageIdentity,
    ) -> str:
        """调度首次分析, 并在统一调度边界持久化所有非成功终态。"""

        operation_id = self._schedule_operation(
            "workspace_create",
            workspace.workspace_id,
            lambda current_operation_id: self._initialize_workspace(
                workspace,
                operation_id=current_operation_id,
                native_identity=native_identity,
            ),
            on_unsuccessful_terminal=lambda state, reason: (
                self.storage.workspaces.record_analysis_outcome(
                    workspace.workspace_id,
                    state=state,
                    reason=reason,
                )
            ),
            cancellable=True,
        )
        self._workspace_operations[workspace.workspace_id] = operation_id
        return operation_id

    async def _workspace_retry(
        self,
        arguments: WorkspaceRetryInput,
    ) -> WorkspaceRetryOutput:
        workspace_lock = self._workspace_lock(arguments.workspace_id)
        if not await workspace_lock.try_acquire():
            raise ToolExecutionError(
                BusinessErrorCode.PRECONDITION_FAILED,
                (
                    "这个分析项目正在执行其他操作，当前不能重试首次分析。"
                    "请先等待现有 operation 完成，再调用 workspace.list 查看最新状态。"
                ),
            )
        try:
            workspace = await asyncio.to_thread(
                self.storage.workspaces.get,
                arguments.workspace_id,
            )
            if workspace.current_revision is not None:
                raise ToolExecutionError(
                    BusinessErrorCode.PRECONDITION_FAILED,
                    (
                        "这个分析项目已经产生 current_revision，不需要重试首次分析。"
                        "请调用 workspace.get，并继续使用已有版本。"
                    ),
                    details={"current_revision": workspace.current_revision},
                )
            outcome = workspace.analysis_outcome
            if outcome is None:
                raise ToolExecutionError(
                    BusinessErrorCode.PRECONDITION_FAILED,
                    (
                        "无法确认这个分析项目的首次分析已经失败或取消。"
                        "它可能仍在运行；请先调用 workspace.list 或 operation.wait 查看状态。"
                    ),
                )
            native_identity = await asyncio.to_thread(self._trusted_native_identity, workspace)
            prepared = await _complete_thread_call(
                lambda: self.storage.workspaces.prepare_analysis_retry(
                    arguments.workspace_id,
                    expected_outcome=outcome,
                )
            )
            try:
                operation_id = self._schedule_workspace_initialization(
                    prepared,
                    native_identity=native_identity,
                )
            except BaseException:
                await _complete_thread_call(
                    lambda: self.storage.workspaces.record_analysis_outcome(
                        arguments.workspace_id,
                        state="failed",
                        reason=(
                            "首次分析重试任务未能启动。请查看 logs 目录中的本次运行日志，然后重试。"
                        ),
                    )
                )
                raise
        finally:
            await workspace_lock.release()
        return WorkspaceRetryOutput(
            workspace_id=prepared.workspace_id,
            sample_sha256=prepared.sample_sha256,
            analysis_operation_id=operation_id,
        )

    async def _workspace_list(
        self,
        arguments: WorkspaceListInput,
    ) -> WorkspaceListOutput:
        workspaces = await asyncio.to_thread(self.storage.workspaces.list)
        digest = query_digest(
            "\n".join(
                f"{item.workspace_id}:{item.current_revision or '-'}" for item in workspaces
            ).encode()
        )
        offset = 0
        if arguments.cursor is not None:
            try:
                offset = self.cursors.decode(
                    arguments.cursor,
                    scope="workspace.list",
                    workspace_id=None,
                    revision=None,
                    query_digest=digest,
                ).offset
            except CursorError as exc:
                raise ToolExecutionError(
                    BusinessErrorCode.CURSOR_STALE,
                    "分页位置已经失效。请去掉 cursor，从第一页重新调用 workspace.list。",
                ) from exc
        available = workspaces[offset : offset + arguments.page_size]
        summaries: list[WorkspaceSummary] = []
        output = WorkspaceListOutput(workspaces=[])
        for workspace in available:
            native_identity = (
                await asyncio.to_thread(self._trusted_native_identity, workspace)
                if workspace.current_revision is not None
                else None
            )
            candidate_summaries = [
                *summaries,
                self._workspace_summary(
                    workspace,
                    native_identity=native_identity,
                ),
            ]
            next_offset = offset + len(candidate_summaries)
            next_cursor = (
                self.cursors.encode(
                    CursorPosition("workspace.list", None, None, digest, next_offset)
                )
                if next_offset < len(workspaces)
                else None
            )
            candidate = WorkspaceListOutput(
                workspaces=candidate_summaries,
                next_cursor=next_cursor,
            )
            if _inline_model_size(candidate) > MAX_INLINE_RESULT_BYTES:
                break
            summaries = candidate_summaries
            output = candidate
        if available and not summaries:
            raise RuntimeError("单个 workspace 摘要超过 inline 上限")
        return output

    async def _workspace_get(
        self,
        arguments: WorkspaceGetInput,
    ) -> WorkspaceGetOutput:
        async with self._workspace_lock(arguments.workspace_id):
            workspace = await asyncio.to_thread(
                self.storage.workspaces.get,
                arguments.workspace_id,
            )
            if workspace.current_revision is None:
                raise ToolExecutionError(
                    BusinessErrorCode.EXECUTION_FAILED,
                    (
                        "这个分析项目还没有可用版本。"
                        "请调用 workspace.list 查看保存的首次分析结果；"
                        "分析失败时检查 logs 目录，再决定是否重新导入。"
                    ),
                )
            revision_summaries = [
                RevisionSummary(
                    revision=item.revision,
                    parent_revision=item.parent_revision,
                    idb_sha256=item.database_sha256,
                    reason=item.change_id or "initial_analysis",
                    pinned=item.pinned,
                )
                for item in workspace.revisions
            ]
            existing_revision_ids = {item.revision for item in workspace.revisions}
            history_truncated = any(
                item.parent_revision is not None
                and item.parent_revision not in existing_revision_ids
                for item in workspace.revisions
            )
            digest = query_digest(
                canonical_json_bytes(
                    {
                        "revisions": [
                            summary.model_dump(mode="json") for summary in revision_summaries
                        ]
                    }
                )
            )
            offset = 0
            if arguments.cursor is not None:
                offset = self.cursors.decode(
                    arguments.cursor,
                    scope="workspace.get",
                    workspace_id=workspace.workspace_id,
                    revision=workspace.current_revision,
                    query_digest=digest,
                ).offset
            native_identity = await asyncio.to_thread(
                self._trusted_native_identity,
                workspace,
            )
            architecture = native_identity.architecture
            bitness: Literal[32, 64] = native_identity.bitness
            endian: Literal["little", "big"] = native_identity.endian
        available = revision_summaries[offset : offset + arguments.page_size]
        selected: list[RevisionSummary] = []
        output = WorkspaceGetOutput(
            workspace_id=workspace.workspace_id,
            current_revision=workspace.current_revision,
            sample_name=workspace.sample_name,
            sample_sha256=workspace.sample_sha256,
            architecture=architecture,
            bitness=bitness,
            endian=endian,
            revisions=[],
            next_cursor=None,
            history_truncated=history_truncated,
        )
        for summary in available:
            candidate_revisions = [*selected, summary]
            next_offset = offset + len(candidate_revisions)
            next_cursor = (
                self.cursors.encode(
                    CursorPosition(
                        "workspace.get",
                        workspace.workspace_id,
                        workspace.current_revision,
                        digest,
                        next_offset,
                    )
                )
                if next_offset < len(revision_summaries)
                else None
            )
            candidate = WorkspaceGetOutput(
                workspace_id=workspace.workspace_id,
                current_revision=workspace.current_revision,
                sample_name=workspace.sample_name,
                sample_sha256=workspace.sample_sha256,
                architecture=architecture,
                bitness=bitness,
                endian=endian,
                revisions=candidate_revisions,
                next_cursor=next_cursor,
                history_truncated=history_truncated,
            )
            if _inline_model_size(candidate) > MAX_INLINE_RESULT_BYTES:
                break
            selected = candidate_revisions
            output = candidate
        if available and not selected:
            raise RuntimeError("单个 revision 摘要超过 inline 上限")
        return output

    async def _workspace_export(
        self,
        arguments: WorkspaceExportInput,
    ) -> WorkspaceExportOutput:
        await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            arguments.workspace_id,
            arguments.revision,
        )
        operation_id = self._schedule_operation(
            "workspace_export",
            arguments.workspace_id,
            lambda _operation_id: self._export_workspace(arguments),
        )
        return WorkspaceExportOutput(
            operation_id=operation_id,
            workspace_id=arguments.workspace_id,
            revision=arguments.revision,
        )

    async def _static_query(self, name: str, arguments: StrictModel) -> StrictModel:
        typed_arguments = cast(StaticAdapterInput, arguments)
        async with (
            self._workspace_lock(typed_arguments.workspace_id),
            self._analysis_slots,
        ):
            output = await self._static_query_unlocked(name, typed_arguments)
            if _inline_model_size(output) <= MAX_INLINE_RESULT_BYTES:
                return output
            return await self._store_static_artifact(
                name,
                typed_arguments.workspace_id,
                typed_arguments.revision,
                output,
            )

    async def _static_query_unlocked(
        self,
        name: str,
        typed_arguments: StaticAdapterInput,
    ) -> StrictModel:
        workspace_id = typed_arguments.workspace_id
        revision = typed_arguments.revision
        cursor: str | None = None
        requested_limit: int | None = None
        if isinstance(
            typed_arguments,
            (ProgramSearchInput, FunctionInspectInput, TypeInspectInput),
        ):
            cursor = typed_arguments.cursor
            requested_limit = typed_arguments.page_size
        elif isinstance(typed_arguments, ProgramOverviewInput):
            requested_limit = 200
        elif isinstance(typed_arguments, GraphQueryInput):
            requested_limit = typed_arguments.max_nodes
        elif isinstance(typed_arguments, DataflowSliceInput):
            requested_limit = typed_arguments.max_steps
        digest = query_digest(
            canonical_json_bytes(
                {
                    "arguments": typed_arguments.model_dump(
                        mode="json",
                        exclude={"cursor"},
                    ),
                    "tool": name,
                }
            )
        )
        offset = 0
        if cursor is not None:
            try:
                offset = self.cursors.decode(
                    cursor,
                    scope=f"static:{name}",
                    workspace_id=workspace_id,
                    revision=revision,
                    query_digest=digest,
                ).offset
            except CursorError as exc:
                raise ToolExecutionError(
                    BusinessErrorCode.CURSOR_STALE,
                    f"分页位置已经失效。请去掉 cursor，从第一页重新调用 {name}。",
                ) from exc
        workspace = await asyncio.to_thread(
            self.storage.workspaces.get,
            workspace_id,
        )
        revision_snapshot = await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            workspace_id,
            revision,
        )
        native_identity = await asyncio.to_thread(
            self._trusted_native_identity,
            workspace,
            revision_snapshot,
        )
        session = await self._acquire_analysis_session(workspace_id, revision)
        reusable = True
        try:
            requests = build_static_requests(
                name,
                typed_arguments,
                offset=offset,
                limit_override=requested_limit,
            )
            results: list[Mapping[str, object]] = []
            for request in requests:
                result = await session.backend.execute(
                    operation=request.operation,
                    input=request.input,
                    timeout_seconds=self.config.workers.operation_timeout_seconds,
                )
                results.append(cast(Mapping[str, object], result))
            output = adapt_static_results(
                name,
                typed_arguments,
                results,
                AnalysisContext(
                    workspace_id=workspace_id,
                    revision=revision,
                    sample_sha256=workspace.sample_sha256,
                    native_container=native_identity.container,
                ),
            )
            page = static_page_facts(name, typed_arguments, results)
            if page is not None and page.has_more:
                assert page.next_offset is not None
                next_cursor = self.cursors.encode(
                    CursorPosition(
                        f"static:{name}",
                        workspace_id,
                        revision,
                        digest,
                        page.next_offset,
                    )
                )
                output = output.model_copy(update={"next_cursor": next_cursor})
            return output
        except (WorkerProcessError, asyncio.CancelledError):
            reusable = False
            discard = asyncio.create_task(self._discard_analysis_session(session))
            await _await_task_preserving_cancellation(discard)
            raise
        finally:
            if reusable:
                release = asyncio.create_task(self._release_analysis_session(session))
                await _await_task_preserving_cancellation(release)

    async def _acquire_analysis_session(
        self,
        workspace_id: str,
        revision: str,
    ) -> _AnalysisSession:
        key = (workspace_id, revision)
        victim: _AnalysisSession | None = None
        async with self._analysis_sessions_guard:
            existing = self._analysis_sessions.get(key)
            if existing is not None:
                if existing.in_use:
                    raise RuntimeError("同一 analysis session 被并发复用")
                _cancel_idle_task(existing.idle_task)
                existing.idle_task = None
                existing.in_use = True
                return existing

            if (
                len(self._analysis_sessions) + self._analysis_opening_count
                >= self.config.workers.analysis_limit
            ):
                idle = [item for item in self._analysis_sessions.values() if not item.in_use]
                if not idle:
                    raise RuntimeError("analysis worker 池与并发信号量状态不一致")
                victim = min(idle, key=lambda item: item.last_used)
                victim.in_use = True
                _cancel_idle_task(victim.idle_task)
                victim.idle_task = None
            self._analysis_opening_count += 1

        if victim is not None:
            try:
                await self._close_analysis_session(victim)
            except BaseException:
                finish = asyncio.create_task(self._finish_analysis_opening())
                await _await_task_without_cancellation(finish)
                raise

        checkout: RevisionCheckout | None = None
        session: _AnalysisSession | None = None
        opening_finished = False
        try:
            checkout = await self._create_checkout(
                workspace_id,
                revision,
                purpose="analysis",
            )
            worker_slot: AsyncInterprocessSlotLease | None = None
            try:
                worker_slot = await self._acquire_analysis_worker_slot()
                backend = await self.backend.open_analysis(
                    checkout_path=checkout.database_path,
                    revision=revision,
                )
            except BaseException:
                try:
                    await _complete_thread_call(
                        lambda: self.storage.workspaces.discard_checkout(checkout)
                    )
                finally:
                    if worker_slot is not None:
                        release = asyncio.create_task(worker_slot.release())
                        await _await_task_without_cancellation(release)
                raise
            session = _AnalysisSession(
                workspace_id=workspace_id,
                revision=revision,
                checkout=checkout,
                backend=backend,
                worker_slot=worker_slot,
                in_use=True,
                last_used=asyncio.get_running_loop().time(),
            )
            async with self._analysis_sessions_guard:
                self._analysis_opening_count -= 1
                opening_finished = True
                if key in self._analysis_sessions:
                    raise RuntimeError("analysis session 在启动期间被重复创建")
                self._analysis_sessions[key] = session
            return session
        except BaseException:
            try:
                if session is not None and self._analysis_sessions.get(key) is not session:
                    await self._close_analysis_session(session)
                elif checkout is not None and session is None and checkout.path.exists():
                    await _complete_thread_call(
                        lambda: self.storage.workspaces.discard_checkout(checkout)
                    )
            finally:
                if not opening_finished:
                    finish = asyncio.create_task(self._finish_analysis_opening())
                    await _await_task_without_cancellation(finish)
            raise

    async def _finish_analysis_opening(self) -> None:
        async with self._analysis_sessions_guard:
            if self._analysis_opening_count <= 0:
                raise RuntimeError("analysis worker opening 计数失配")
            self._analysis_opening_count -= 1

    async def _create_checkout(
        self,
        workspace_id: str,
        revision: str,
        *,
        purpose: str,
    ) -> RevisionCheckout:
        """取消撞上复制时等待 checkout 身份落定, 完整删除后再传播取消。"""

        creation = asyncio.create_task(
            asyncio.to_thread(
                self.storage.workspaces.create_checkout,
                workspace_id,
                revision,
                purpose=purpose,
            )
        )
        try:
            return await asyncio.shield(creation)
        except asyncio.CancelledError as cancellation:
            checkout = await _await_task_without_cancellation(creation)
            await _complete_thread_call(lambda: self.storage.workspaces.discard_checkout(checkout))
            raise cancellation

    async def _release_analysis_session(self, session: _AnalysisSession) -> None:
        key = (session.workspace_id, session.revision)
        async with self._analysis_sessions_guard:
            if self._analysis_sessions.get(key) is not session:
                return
            session.in_use = False
            session.last_used = asyncio.get_running_loop().time()
            _cancel_idle_task(session.idle_task)

            async def expire() -> None:
                try:
                    loop = asyncio.get_running_loop()
                    deadline = loop.time() + self.config.workers.idle_seconds
                    while True:
                        if await self._analysis_worker_slots.has_waiters():
                            break
                        remaining = deadline - loop.time()
                        if remaining <= 0:
                            break
                        await asyncio.sleep(min(0.25, remaining))
                    await self._expire_analysis_session(key, session)
                except asyncio.CancelledError:
                    return
                except Exception:
                    # close task 会保留失败供 Application.aclose 聚合, idle wrapper 不再告警。
                    return

            session.idle_task = asyncio.create_task(
                expire(),
                name=f"analysis-idle:{session.workspace_id}:{session.revision}",
            )

    async def _expire_analysis_session(
        self,
        key: tuple[str, str],
        session: _AnalysisSession,
    ) -> None:
        async with self._analysis_sessions_guard:
            if self._analysis_sessions.get(key) is not session or session.in_use:
                return
            session.in_use = True
            session.idle_task = None
        await self._close_analysis_session(session)

    async def _discard_analysis_session(self, session: _AnalysisSession) -> None:
        async with self._analysis_sessions_guard:
            _cancel_idle_task(session.idle_task)
            session.idle_task = None
            session.in_use = True
        await self._close_analysis_session(session)

    async def _open_transient_analysis(
        self,
        checkout_path: Path,
        revision: str,
    ) -> tuple[AnalysisBackend, AsyncInterprocessSlotLease]:
        victim: _AnalysisSession | None = None
        async with self._analysis_sessions_guard:
            if (
                len(self._analysis_sessions) + self._analysis_opening_count
                >= self.config.workers.analysis_limit
            ):
                idle = [item for item in self._analysis_sessions.values() if not item.in_use]
                if not idle:
                    raise RuntimeError("没有可回收的 analysis worker 容量用于冷验证")
                victim = min(idle, key=lambda item: item.last_used)
                victim.in_use = True
                _cancel_idle_task(victim.idle_task)
                victim.idle_task = None
            self._analysis_opening_count += 1

        worker_slot: AsyncInterprocessSlotLease | None = None
        backend: AnalysisBackend | None = None
        opening_finished = False
        try:
            if victim is not None:
                await self._close_analysis_session(victim)
            worker_slot = await self._acquire_analysis_worker_slot()
            backend = await self.backend.open_analysis(
                checkout_path=checkout_path,
                revision=revision,
            )
            finish = asyncio.create_task(self._finish_analysis_opening())
            try:
                await asyncio.shield(finish)
            except asyncio.CancelledError as cancellation:
                await _await_task_without_cancellation(finish)
                opening_finished = True
                raise cancellation
            opening_finished = True
            return backend, worker_slot
        except BaseException:
            try:
                if backend is not None and worker_slot is not None:
                    cleanup = asyncio.create_task(
                        self._close_transient_analysis(backend, worker_slot)
                    )
                    await _await_task_without_cancellation(cleanup)
                elif worker_slot is not None:
                    release = asyncio.create_task(worker_slot.release())
                    await _await_task_without_cancellation(release)
            finally:
                if not opening_finished:
                    finish = asyncio.create_task(self._finish_analysis_opening())
                    await _await_task_without_cancellation(finish)
            raise

    @staticmethod
    async def _close_transient_analysis(
        backend: AnalysisBackend,
        worker_slot: AsyncInterprocessSlotLease,
    ) -> None:
        try:
            await backend.close()
        finally:
            await worker_slot.release()

    async def _run_analysis_worker[T](self, call: Callable[[], Awaitable[T]]) -> T:
        """在共享 data root 的全局 analysis 容量内运行一个 one-shot worker。"""

        worker_slot = await self._acquire_analysis_worker_slot()
        try:
            return await call()
        finally:
            await worker_slot.release()

    async def _acquire_analysis_worker_slot(self) -> AsyncInterprocessSlotLease:
        """优先复用空闲全局槽位; 容量满时先关闭本进程空闲 worker。"""

        worker_slot = await self._analysis_worker_slots.try_acquire()
        if worker_slot is not None:
            return worker_slot

        victim: _AnalysisSession | None = None
        async with self._analysis_sessions_guard:
            idle = [item for item in self._analysis_sessions.values() if not item.in_use]
            if idle:
                victim = min(idle, key=lambda item: item.last_used)
                victim.in_use = True
                _cancel_idle_task(victim.idle_task)
                victim.idle_task = None
        if victim is not None:
            await self._close_analysis_session(victim)
        return await self._analysis_worker_slots.acquire()

    async def _close_analysis_session(self, session: _AnalysisSession) -> None:
        close_task = session.close_task
        if close_task is None:
            close_task = asyncio.create_task(
                self._close_analysis_session_once(session),
                name=f"analysis-close:{session.workspace_id}:{session.revision}",
            )
            session.close_task = close_task
            self._track_session_close_task(close_task)
        await _await_task_preserving_cancellation(close_task)

    async def _close_analysis_session_once(self, session: _AnalysisSession) -> None:
        key = (session.workspace_id, session.revision)
        async with self._analysis_sessions_guard:
            if self._analysis_sessions.get(key) is session:
                del self._analysis_sessions[key]
        _cancel_idle_task(session.idle_task)
        session.idle_task = None
        try:
            await session.backend.close()
        finally:
            try:
                await asyncio.to_thread(
                    self.storage.workspaces.discard_checkout,
                    session.checkout,
                )
            finally:
                await session.worker_slot.release()

    async def _put_public_artifact(
        self,
        *,
        workspace_id: str,
        revision: str,
        data: bytes,
        media_type: str,
        name: str,
    ) -> ArtifactMetadata:
        """公开 payload 超过单块上限时只暴露可逐块读取的索引 resource。"""

        if len(data) <= RESOURCE_CHUNK_BYTES:
            return await _complete_thread_call(
                lambda: self.storage.artifacts.put_bytes(
                    workspace_id=workspace_id,
                    revision=revision,
                    data=data,
                    media_type=media_type,
                    name=name,
                )
            )
        temporary = Path(
            tempfile.mkdtemp(
                prefix="artifact-payload-",
                dir=self.storage.paths.temp_root,
            )
        ).resolve()
        source = temporary / "payload.bin"
        try:
            await _settle_thread_call_preserving_cancellation(lambda: source.write_bytes(data))
            chunked = await _complete_thread_call(
                lambda: self.storage.artifacts.put_chunked_file(
                    workspace_id=workspace_id,
                    revision=revision,
                    source=source,
                    media_type=media_type,
                    name=name,
                )
            )
            return chunked.index
        finally:
            await _complete_thread_call(
                lambda: _safe_remove_temp_directory(
                    temporary,
                    self.storage.paths.temp_root,
                )
            )

    async def _store_static_artifact(
        self,
        name: str,
        workspace_id: str,
        revision: str,
        output: StrictModel,
    ) -> StrictModel:
        payload = json.dumps(
            output.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
            sort_keys=True,
        ).encode("utf-8")
        artifact = await self._put_public_artifact(
            workspace_id=workspace_id,
            revision=revision,
            data=payload,
            media_type="application/json",
            name=f"static-{name.replace('.', '-')}.json",
        )
        reference = ArtifactReference(
            uri=artifact.uri,
            sha256=artifact.content_sha256,
            size=artifact.size,
            media_type=artifact.media_type,
        )
        if isinstance(output, ProgramOverviewOutput):
            compact = output.model_copy(
                update={
                    "segments": [],
                    "entry_points": [],
                    "imports": [],
                    "exports": [],
                    "fixups": [],
                    "unwind_regions": [],
                    "functions": [],
                    "strings": [],
                    "result_artifact": reference,
                }
            )
        elif isinstance(output, ProgramSearchOutput):
            compact = output.model_copy(update={"matches": [], "result_artifact": reference})
        elif isinstance(output, AddressInspectOutput):
            compact = output.model_copy(
                update={
                    "bytes_hex": None,
                    "instruction": None,
                    "data_rendering": None,
                    "symbol": None,
                    "function_id": None,
                    "xrefs": [],
                    "result_artifact": reference,
                }
            )
        elif isinstance(output, FunctionInspectOutput):
            compact = output.model_copy(
                update={
                    "name": "",
                    "prototype": None,
                    "chunks": [],
                    "instructions": [],
                    "pseudocode": [],
                    "ctree_map": [],
                    "blocks": [],
                    "calls": [],
                    "strings": [],
                    "stack": None,
                    "locals": [],
                    "type_view": None,
                    "result_artifact": reference,
                }
            )
        elif isinstance(output, GraphQueryOutput):
            compact = output.model_copy(
                update={"nodes": [], "edges": [], "result_artifact": reference}
            )
        elif isinstance(output, DataflowSliceOutput):
            compact = output.model_copy(
                update={
                    "nodes": [],
                    "edges": [],
                    "barriers": [],
                    "result_artifact": reference,
                }
            )
        elif isinstance(output, TypeInspectOutput):
            compact = output.model_copy(
                update={
                    "name": "",
                    "display": "",
                    "fields": [],
                    "result_artifact": reference,
                }
            )
        else:
            raise RuntimeError(f"{name} 未声明 artifact-backed 输出")
        if _inline_model_size(compact) > MAX_INLINE_RESULT_BYTES:
            raise RuntimeError(f"{name} 的 artifact 引用输出仍超过 inline 上限")
        return compact

    async def _report_build(
        self,
        arguments: ReportBuildInput,
    ) -> ReportBuildOutput:
        await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            arguments.workspace_id,
            arguments.revision,
        )
        operation_id = self._schedule_operation(
            "report_build",
            arguments.workspace_id,
            lambda _operation_id: self._build_report(arguments),
        )
        return ReportBuildOutput(
            operation_id=operation_id,
            workspace_id=arguments.workspace_id,
            revision=arguments.revision,
        )

    async def _analysis_refine(
        self,
        arguments: AnalysisRefineInput,
    ) -> AnalysisRefineOutput:
        await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            arguments.workspace_id,
            arguments.revision,
        )
        operation_id = self._schedule_operation(
            "analysis_refine",
            arguments.workspace_id,
            lambda current_operation_id: self._refine_workspace(
                arguments,
                operation_id=current_operation_id,
            ),
            cancellable=True,
        )
        return AnalysisRefineOutput(
            operation_id=operation_id,
            workspace_id=arguments.workspace_id,
            base_revision=arguments.revision,
        )

    async def _change_prepare(
        self,
        arguments: ChangePrepareInput,
    ) -> ChangePrepareOutput:
        async with (
            self._workspace_lock(arguments.workspace_id),
            self._analysis_slots,
        ):
            workspace, revision, context, cold_identity = await self._change_context_unlocked(
                arguments.workspace_id,
                arguments.base_revision,
            )
            if arguments.inverse_of_change_id is not None:
                if (
                    revision.change_id != arguments.inverse_of_change_id
                    or revision.parent_revision is None
                ):
                    raise ToolExecutionError(
                        BusinessErrorCode.PRECONDITION_FAILED,
                        (
                            "只能撤销当前分析版本最近保存的修改。"
                            "请先调用 workspace.get 读取 current_revision，再重新准备撤销操作。"
                        ),
                    )
                plan = build_canonical_plan(
                    arguments,
                    context,
                    inverse_source=InverseSource(
                        workspace_id=workspace.workspace_id,
                        change_id=arguments.inverse_of_change_id,
                        applied_revision=revision.revision,
                        parent_revision=revision.parent_revision,
                    ),
                )
                impact = _empty_change_impact()
            else:
                validated_sources = await asyncio.to_thread(
                    validate_local_sources,
                    arguments,
                    context,
                )
                execution = build_preflight_execution(
                    arguments,
                    context,
                    validated_sources,
                )
                staging = await self._begin_revision_staging(
                    arguments.workspace_id,
                    expected_revision=arguments.base_revision,
                )
                try:
                    raw = await self._run_analysis_worker(
                        lambda: self.backend.mutate(
                            staging_path=staging.database_path,
                            operations=execution.worker_operations,
                            timeout_seconds=self.config.workers.operation_timeout_seconds,
                        )
                    )
                    impact = parse_preflight_impact(
                        arguments,
                        validated_sources,
                        raw,
                    )
                    await self._cold_validate(staging, expected=cold_identity)
                finally:
                    if staging.path.exists():
                        await _complete_thread_call(
                            lambda: self.storage.workspaces.abort_staging(staging)
                        )

                requests = source_solidification_requests(validated_sources)
                solidified_sources: tuple[SolidifiedSource, ...] = ()
                if requests:
                    artifact_inputs = tuple(
                        ArtifactFileInput(
                            workspace_id=arguments.workspace_id,
                            revision=arguments.base_revision,
                            source=item.source,
                            media_type=item.media_type,
                            name=item.name,
                            expected_sha256=item.expected_sha256,
                            expected_size=item.size,
                            listed=False,
                        )
                        for item in requests
                    )
                    artifacts = await _complete_thread_call(
                        lambda: self.storage.artifacts.put_files_atomic(artifact_inputs)
                    )
                    solidified_sources = tuple(
                        SolidifiedSource(
                            operation_index=request.operation_index,
                            role=request.role,
                            artifact_uri=artifact.uri,
                            content_sha256=artifact.content_sha256,
                            size=artifact.size,
                        )
                        for request, artifact in zip(requests, artifacts, strict=True)
                    )
                plan = build_canonical_plan(
                    arguments,
                    context,
                    validated_sources=validated_sources,
                    solidified_sources=solidified_sources,
                )

            change_set = await _complete_thread_call(
                lambda: self.changes.prepare(
                    workspace_id=arguments.workspace_id,
                    base_revision=arguments.base_revision,
                    operations=plan.operations,
                    preimage=plan.preimage,
                    inverse_of_change_id=plan.inverse_of_change_id,
                )
            )
            output = ChangePrepareOutput(
                workspace_id=arguments.workspace_id,
                base_revision=arguments.base_revision,
                change_set_id=change_set.change_set_id,
                digest=change_set.digest,
                operation_count=len(change_set.operations),
                impact=impact,
            )
            if _inline_model_size(output) <= MAX_INLINE_RESULT_BYTES:
                return output
            payload = json.dumps(
                output.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
                sort_keys=True,
            ).encode("utf-8")
            artifact = await self._put_public_artifact(
                workspace_id=arguments.workspace_id,
                revision=arguments.base_revision,
                data=payload,
                media_type="application/vnd.ida-re.change-impact+json",
                name=f"{change_set.change_set_id}-impact.json",
            )
            compact = output.model_copy(
                update={
                    "impact": output.impact.model_copy(
                        update={
                            "conflicts": [],
                            "conflicts_artifact": ArtifactReference(
                                uri=artifact.uri,
                                sha256=artifact.content_sha256,
                                size=artifact.size,
                                media_type=artifact.media_type,
                            ),
                        }
                    )
                }
            )
            if _inline_model_size(compact) > MAX_INLINE_RESULT_BYTES:
                raise RuntimeError("change.prepare artifact 引用结果仍超过 inline 上限")
            return compact

    async def _change_apply(
        self,
        arguments: ChangeApplyInput,
    ) -> ChangeApplyOutput:
        async with (
            self._workspace_lock(arguments.workspace_id),
            self._analysis_slots,
        ):
            _workspace, revision, context, cold_identity = await self._change_context_unlocked(
                arguments.workspace_id,
                arguments.expected_revision,
            )
            change_set = await asyncio.to_thread(
                self.changes.load_for_apply,
                workspace_id=arguments.workspace_id,
                base_revision=arguments.expected_revision,
                change_set_id=arguments.change_set_id,
                digest=arguments.digest,
            )
            if (
                change_set.preimage.revision != revision.revision
                or change_set.preimage.database_sha256 != revision.database_sha256
                or change_set.preimage.component_hashes != dict(revision.component_hashes)
            ):
                raise RevisionConflictError("ChangeSet preimage 与当前冷 revision 不一致")

            temporary = Path(
                tempfile.mkdtemp(
                    prefix="change-apply-",
                    dir=self.storage.paths.temp_root,
                )
            ).resolve()
            try:
                materializations = await _settle_thread_call_preserving_cancellation(
                    lambda: self._materialize_change_artifacts(
                        change_set.operations,
                        temporary,
                    )
                )
                execution = build_mutation_execution(
                    change_set.operations,
                    context,
                    artifacts=materializations,
                )
                staging = await self._begin_revision_staging(
                    arguments.workspace_id,
                    expected_revision=arguments.expected_revision,
                    source_revision=execution.restore_revision,
                )
                try:
                    if execution.mode == "worker":
                        raw = await self._run_analysis_worker(
                            lambda: self.backend.mutate(
                                staging_path=staging.database_path,
                                operations=execution.worker_operations,
                                timeout_seconds=self.config.workers.operation_timeout_seconds,
                            )
                        )
                        parse_worker_impact(change_set.operations, raw)
                    receipt = await self._cold_validate(staging, expected=cold_identity)
                    change_id = f"change_{uuid.uuid4().hex}"
                    published = await _complete_thread_call(
                        lambda: self.storage.workspaces.publish_staging(
                            staging,
                            receipt=receipt,
                            change_id=change_id,
                        )
                    )
                except BaseException:
                    if staging.path.exists():
                        await _complete_thread_call(
                            lambda: self.storage.workspaces.abort_staging(staging)
                        )
                    raise
            finally:
                await _complete_thread_call(
                    lambda: _safe_remove_temp_directory(
                        temporary,
                        self.storage.paths.temp_root,
                    )
                )
            return ChangeApplyOutput(
                workspace_id=arguments.workspace_id,
                previous_revision=arguments.expected_revision,
                revision=published.revision,
                change_id=change_id,
            )

    async def _change_context_unlocked(
        self,
        workspace_id: str,
        base_revision: str,
    ) -> tuple[
        WorkspaceSnapshot,
        RevisionSnapshot,
        ChangeContext,
        _ColdImageIdentity,
    ]:
        workspace = await asyncio.to_thread(
            self.storage.workspaces.get,
            workspace_id,
        )
        if workspace.current_revision != base_revision:
            raise RevisionConflictError("base revision 不是 workspace 当前 HEAD")
        revision = await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            workspace_id,
            base_revision,
        )
        overview = cast(
            ProgramOverviewOutput,
            await self._static_query_unlocked(
                "program.overview",
                ProgramOverviewInput(
                    workspace_id=workspace_id,
                    revision=base_revision,
                    include=[],
                ),
            ),
        )
        native = await asyncio.to_thread(
            _native_binding,
            workspace,
            overview,
        )
        return (
            workspace,
            revision,
            ChangeContext(
                workspace_id=workspace_id,
                base_revision=base_revision,
                image_id=overview.image.image_id,
                sample_sha256=workspace.sample_sha256,
                database_sha256=revision.database_sha256,
                component_hashes=dict(revision.component_hashes),
                native=native,
            ),
            self._cold_identity_from_revision(
                workspace,
                revision,
                overview=overview,
            ),
        )

    def _materialize_change_artifacts(
        self,
        operations: tuple[StoredChangeOperation, ...],
        temporary: Path,
    ) -> tuple[ArtifactMaterialization, ...]:
        materialized: dict[str, ArtifactMaterialization] = {}
        for operation in operations:
            if not isinstance(operation, StoredImportIl2CppBundleOperation):
                continue
            references = (
                (
                    operation.bundle_artifact_uri,
                    operation.bundle_sha256,
                    operation.bundle_size,
                    ".ndjson",
                ),
                (
                    operation.metadata_artifact_uri,
                    operation.metadata_sha256,
                    operation.metadata_size,
                    ".metadata",
                ),
            )
            for uri, expected_sha256, expected_size, suffix in references:
                if uri in materialized:
                    continue
                target = temporary / f"source-{len(materialized)}{suffix}"
                metadata = self.storage.artifacts.materialize_uri(uri, target)
                if metadata.content_sha256 != expected_sha256 or metadata.size != expected_size:
                    raise ChangeSetError("ChangeSet artifact 身份与不可变计划不一致")
                materialized[uri] = ArtifactMaterialization(
                    artifact_uri=uri,
                    content_sha256=metadata.content_sha256,
                    size=metadata.size,
                    path=target,
                )
        return tuple(materialized.values())

    async def _debug_tool(self, name: str, arguments: StrictModel) -> StrictModel:
        if name == "debug.establish":
            return await self._debug_establish(cast(DebugEstablishInput, arguments))
        if name == "debug.control":
            request = cast(DebugControlInput, arguments)
            session_id = request.debug_session_id
        elif name == "debug.events":
            request = cast(DebugEventsInput, arguments)
            session_id = request.debug_session_id
        elif name == "debug.inspect":
            request = cast(DebugInspectInput, arguments)
            session_id = request.debug_session_id
        elif name == "debug.breakpoints":
            request = cast(DebugBreakpointsInput, arguments)
            session_id = request.debug_session_id
        elif name == "debug.finish":
            request = cast(DebugFinishInput, arguments)
            session_id = request.debug_session_id
        else:
            raise ToolExecutionError(
                BusinessErrorCode.UNSUPPORTED,
                f"当前服务没有提供调试工具 `{name}`。请先读取 tools/list。",
            )
        session = self._debug_sessions.get(session_id)
        if session is None:
            raise ToolExecutionError(
                BusinessErrorCode.DEBUG_STATE_CONFLICT,
                (
                    "找不到这个调试会话，或会话已经结束。"
                    "请使用 debug.establish 返回的 debug_session_id；已结束的会话不能继续使用。"
                ),
            )
        close_required = False
        try:
            async with session.request_lock:
                if (
                    self._debug_sessions.get(session_id) is not session
                    or session.close_task is not None
                ):
                    raise ToolExecutionError(
                        BusinessErrorCode.DEBUG_STATE_CONFLICT,
                        "调试会话已经结束或正在关闭。请重新调用 debug.establish 建立会话。",
                    )
                self._cancel_debug_idle(session)
                try:
                    output = await self._debug_session_tool(name, request, session)
                    close_required = name == "debug.finish"
                    return output
                except WorkerProcessError:
                    close_required = True
                    raise
                except DebugRequestCancelled as cancellation:
                    close_required = isinstance(
                        cancellation.failure, WorkerProcessError
                    ) or session.context.state in {"exited", "detached", "lost", "failed"}
                    raise
                finally:
                    if (
                        not close_required
                        and session.close_task is None
                        and self._debug_sessions.get(session_id) is session
                    ):
                        self._arm_debug_idle(session)
        finally:
            if close_required:
                await self._close_debug_session(session)

    async def _debug_session_tool(
        self,
        name: str,
        request: StrictModel,
        session: _DebugSession,
    ) -> StrictModel:
        if name == "debug.control":
            typed = cast(DebugControlInput, request)
            raw = await self._execute_debug(
                session,
                prepare_debug_control(session.context, typed),
                timeout_seconds=typed.timeout_ms / 1000 + 5,
            )
            adapted = adapt_debug_control(session.context, raw)
            session.context = adapted.context
            return adapted.output
        if name == "debug.events":
            typed = cast(DebugEventsInput, request)
            raw = await self._execute_debug(
                session,
                prepare_debug_events(session.context, typed),
                timeout_seconds=typed.wait_ms / 1000 + 5,
            )
            adapted = adapt_debug_events(session.context, typed, raw)
            session.context = adapted.context
            return adapted.output
        if name == "debug.inspect":
            typed = cast(DebugInspectInput, request)
            raw_results = [
                await self._execute_debug(session, command, timeout_seconds=35)
                for command in prepare_debug_inspect(session.context, typed)
            ]
            adapted = adapt_debug_inspect(session.context, typed, raw_results)
            session.context = adapted.context
            output = adapted.output
            if _inline_model_size(output) > MAX_INLINE_RESULT_BYTES:
                if output.memory_bytes is not None:
                    memory = bytes.fromhex(output.memory_bytes)
                    artifact = await asyncio.to_thread(
                        self.storage.artifacts.put_bytes,
                        workspace_id=session.checkout.workspace_id,
                        revision=session.checkout.revision,
                        data=memory,
                        media_type="application/octet-stream",
                        name=f"debug-memory-{typed.stop_id}.bin",
                    )
                    output = output.model_copy(
                        update={
                            "memory_bytes": None,
                            "memory_artifact": ArtifactReference(
                                uri=artifact.uri,
                                sha256=artifact.content_sha256,
                                size=artifact.size,
                                media_type=artifact.media_type,
                            ),
                        }
                    )
                if _inline_model_size(output) > MAX_INLINE_RESULT_BYTES:
                    snapshot_data = json.dumps(
                        output.model_dump(mode="json"),
                        ensure_ascii=False,
                        separators=(",", ":"),
                        allow_nan=False,
                        sort_keys=True,
                    ).encode("utf-8")
                    snapshot = await self._put_public_artifact(
                        workspace_id=session.checkout.workspace_id,
                        revision=session.checkout.revision,
                        data=snapshot_data,
                        media_type="application/vnd.ida-re.debug-snapshot+json",
                        name=f"debug-snapshot-{typed.stop_id}.json",
                    )
                    output = type(output)(
                        debug_session_id=output.debug_session_id,
                        stop_id=output.stop_id,
                        state="suspended",
                        modules=[],
                        threads=[],
                        registers=[],
                        stack=[],
                        snapshot_artifact=ArtifactReference(
                            uri=snapshot.uri,
                            sha256=snapshot.content_sha256,
                            size=snapshot.size,
                            media_type=snapshot.media_type,
                        ),
                    )
            return output
        if name == "debug.breakpoints":
            return await self._debug_replace_breakpoints(
                session,
                cast(DebugBreakpointsInput, request),
            )

        typed = cast(DebugFinishInput, request)
        if typed.action == "terminate" and not session.owned_target:
            raise ToolExecutionError(
                BusinessErrorCode.POLICY_DENIED,
                (
                    "不能结束这个外部进程。terminate 只适用于由本服务启动的目标；"
                    "外部进程请使用 detach。"
                ),
            )
        if typed.action == "detach" and session.owned_target:
            raise ToolExecutionError(
                BusinessErrorCode.POLICY_DENIED,
                "这个进程由本服务启动，不能只断开连接。请使用 terminate 结束进程。",
            )
        raw = await self._execute_debug(
            session,
            prepare_debug_finish(session.context, typed),
            timeout_seconds=typed.timeout_ms / 1000 + 5,
        )
        adapted = adapt_debug_finish(session.context, raw)
        session.context = adapted.context
        return adapted.output

    async def _debug_establish(
        self,
        arguments: DebugEstablishInput,
    ) -> DebugEstablishOutput:
        workspace = await asyncio.to_thread(
            self.storage.workspaces.get,
            arguments.workspace_id,
        )
        revision_snapshot = await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            arguments.workspace_id,
            arguments.revision,
        )
        native_identity = await asyncio.to_thread(
            self._trusted_native_identity,
            workspace,
            revision_snapshot,
        )
        target_kind = arguments.target.kind
        if target_kind == "launch" and not self.config.policy.debug_launch:
            raise ToolExecutionError(
                BusinessErrorCode.POLICY_DENIED,
                (
                    "config.toml 当前不允许启动调试目标。"
                    "确实需要时，请将 policy.debug_launch 设为 true 并重启服务。"
                ),
            )
        if target_kind == "attach" and not self.config.policy.debug_attach:
            raise ToolExecutionError(
                BusinessErrorCode.POLICY_DENIED,
                (
                    "config.toml 当前不允许连接已经运行的进程。"
                    "确实需要时，请将 policy.debug_attach 设为 true 并重启服务。"
                ),
            )
        runtime_sample_name = (
            workspace.sample_path.name
            if isinstance(arguments.target, DebugLaunchTarget)
            else workspace.sample_name
        )
        workspace_lock = self._workspace_lock(workspace.workspace_id)
        await workspace_lock.acquire()
        debug_slot_acquired = False
        worker_slot: AsyncInterprocessSlotLease | None = None
        checkout: RevisionCheckout | None = None
        backend: DebugBackend | None = None
        try:
            await self._debug_slots.acquire()
            debug_slot_acquired = True
            worker_slot = await self._debug_worker_slots.acquire()
            checkout = await self._create_checkout(
                workspace.workspace_id,
                arguments.revision,
                purpose="debug",
            )
            backend = await self.backend.open_debug(
                checkout_path=checkout.database_path,
                sample_path=workspace.sample_path,
                revision=arguments.revision,
                allow_attach=self.config.policy.debug_attach,
            )
            command = prepare_debug_establish(arguments)
            try:
                raw = await backend.execute(
                    command.operation,
                    command.input,
                    timeout_seconds=arguments.timeout_ms / 1000 + 5,
                )
            except DebugRequestCancelled as cancellation:
                if cancellation.result is not None:
                    # 确认 worker 在取消完成前确实观察到了合法运行态或停点。
                    adapt_debug_establish(
                        arguments,
                        cancellation.result,
                        sample_name=runtime_sample_name,
                        image_id=f"image~{workspace.sample_sha256}",
                        bitness=native_identity.bitness,
                    )
                raise
            adapted = adapt_debug_establish(
                arguments,
                raw,
                sample_name=runtime_sample_name,
                image_id=f"image~{workspace.sample_sha256}",
                bitness=native_identity.bitness,
            )
            session = _DebugSession(
                checkout=checkout,
                backend=backend,
                context=adapted.context,
                workspace_lock=workspace_lock,
                worker_slot=worker_slot,
                owned_target=isinstance(arguments.target, DebugLaunchTarget),
            )
            # 读取一次不可消费的事件快照, 以建立 module/RVA 映射事实。
            event_request = DebugEventsInput(
                debug_session_id=adapted.context.debug_session_id,
                after_sequence=0,
                wait_ms=0,
                limit=200,
            )
            event_command = prepare_debug_events(session.context, event_request)
            event_raw = await self._execute_debug(session, event_command, timeout_seconds=5)
            session.context = adapt_debug_events(
                session.context,
                event_request,
                event_raw,
            ).context
            self._debug_sessions[session.context.debug_session_id] = session
            self._arm_debug_idle(session)
            return adapted.output
        except BaseException:
            cleanup = asyncio.create_task(
                self._cleanup_failed_debug_open(
                    backend=backend,
                    checkout=checkout,
                    worker_slot=worker_slot,
                    debug_slot_acquired=debug_slot_acquired,
                    workspace_lock=workspace_lock,
                )
            )
            await _await_task_without_cancellation(cleanup)
            raise

    async def _cleanup_failed_debug_open(
        self,
        *,
        backend: DebugBackend | None,
        checkout: RevisionCheckout | None,
        worker_slot: AsyncInterprocessSlotLease | None,
        debug_slot_acquired: bool,
        workspace_lock: AsyncInterprocessFileLock,
    ) -> None:
        try:
            if backend is not None:
                await backend.close()
        finally:
            try:
                if checkout is not None:
                    await asyncio.to_thread(
                        self.storage.workspaces.discard_checkout,
                        checkout,
                    )
            finally:
                try:
                    if worker_slot is not None:
                        await worker_slot.release()
                finally:
                    try:
                        if debug_slot_acquired:
                            self._debug_slots.release()
                    finally:
                        await workspace_lock.release()

    async def _execute_debug(
        self,
        session: _DebugSession,
        command: WorkerDebugCommand,
        *,
        timeout_seconds: float,
    ) -> Mapping[str, object]:
        try:
            return await session.backend.execute(
                command.operation,
                command.input,
                timeout_seconds=timeout_seconds,
            )
        except DebugRequestCancelled as cancellation:
            if cancellation.result is not None:
                session.context = adapt_debug_cancelled(
                    session.context,
                    cancellation.result,
                )
            raise

    async def _debug_replace_breakpoints(
        self,
        session: _DebugSession,
        request: DebugBreakpointsInput,
    ) -> StrictModel:
        current = await self._execute_debug(
            session,
            prepare_debug_breakpoint_list(session.context, request),
            timeout_seconds=35,
        )
        replacement = build_debug_breakpoint_replacement(
            session.context,
            request,
            current,
        )
        try:
            final = await self._apply_breakpoint_plan(session, replacement)
            output = adapt_debug_breakpoints(session.context, request, final)
            if _inline_model_size(output) <= MAX_INLINE_RESULT_BYTES:
                return output
            payload = json.dumps(
                output.model_dump(mode="json"),
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
                sort_keys=True,
            ).encode("utf-8")
            artifact = await self._put_public_artifact(
                workspace_id=session.checkout.workspace_id,
                revision=session.checkout.revision,
                data=payload,
                media_type="application/vnd.ida-re.debug-breakpoints+json",
                name=f"debug-breakpoints-{request.stop_id}.json",
            )
            compact = output.model_copy(
                update={
                    "breakpoints": [],
                    "result_artifact": ArtifactReference(
                        uri=artifact.uri,
                        sha256=artifact.content_sha256,
                        size=artifact.size,
                        media_type=artifact.media_type,
                    ),
                }
            )
            if _inline_model_size(compact) > MAX_INLINE_RESULT_BYTES:
                raise RuntimeError("debug.breakpoints artifact 引用结果仍超过 inline 上限")
            return compact
        except BaseException:
            try:
                current_after_failure = await self._execute_debug(
                    session,
                    replacement.verify_command,
                    timeout_seconds=35,
                )
                rollback = build_debug_breakpoint_rollback(
                    session.context,
                    replacement,
                    current_after_failure,
                )
                await self._apply_breakpoint_plan(session, rollback)
            except BaseException as rollback_error:
                raise ToolExecutionError(
                    BusinessErrorCode.EXECUTION_FAILED,
                    (
                        "断点没有全部设置成功，并且原来的断点也未能恢复。"
                        "请调用 debug.events 确认程序状态，再用最新 stop_id 读取断点。"
                    ),
                ) from rollback_error
            raise

    async def _apply_breakpoint_plan(
        self,
        session: _DebugSession,
        plan: BreakpointReplacementPlan,
    ) -> Mapping[str, object]:
        for command in plan.remove_commands:
            await self._execute_debug(session, command, timeout_seconds=35)
        for step in plan.add_steps:
            add_result = await self._execute_debug(
                session,
                step.command,
                timeout_seconds=35,
            )
            enable = prepare_debug_breakpoint_enable(
                add_result,
                enabled=step.enabled,
            )
            if enable is not None:
                await self._execute_debug(session, enable, timeout_seconds=35)
        return await self._execute_debug(
            session,
            plan.verify_command,
            timeout_seconds=35,
        )

    async def _close_debug_session(self, session: _DebugSession) -> None:
        close_task = session.close_task
        if close_task is None:
            close_task = asyncio.create_task(
                self._close_debug_session_once(session),
                name=f"debug-close:{session.context.debug_session_id}",
            )
            session.close_task = close_task
            self._track_session_close_task(close_task)
        await _await_task_preserving_cancellation(close_task)

    def _track_session_close_task(self, task: asyncio.Task[None]) -> None:
        self._session_close_tasks.add(task)
        task.add_done_callback(self._finish_tracking_session_close_task)

    def _finish_tracking_session_close_task(self, task: asyncio.Task[None]) -> None:
        if task.cancelled():
            return
        if task.exception() is None:
            self._session_close_tasks.discard(task)

    async def _close_debug_session_once(self, session: _DebugSession) -> None:
        async with session.request_lock:
            session_id = session.context.debug_session_id
            if self._debug_sessions.get(session_id) is session:
                del self._debug_sessions[session_id]
            self._cancel_debug_idle(session)
            try:
                await session.backend.close()
            finally:
                try:
                    await asyncio.to_thread(
                        self.storage.workspaces.discard_checkout,
                        session.checkout,
                    )
                finally:
                    try:
                        await session.workspace_lock.release()
                    finally:
                        try:
                            await session.worker_slot.release()
                        finally:
                            self._debug_slots.release()

    def _cancel_debug_idle(self, session: _DebugSession) -> None:
        task = session.idle_task
        session.idle_task = None
        if task is not None and task is not asyncio.current_task() and not task.done():
            task.cancel()

    def _arm_debug_idle(self, session: _DebugSession) -> None:
        self._cancel_debug_idle(session)

        async def expire() -> None:
            try:
                await asyncio.sleep(self.config.workers.idle_seconds)
                if self._debug_sessions.get(session.context.debug_session_id) is session:
                    await self._close_debug_session(session)
            except asyncio.CancelledError:
                return
            except Exception:
                # close task 会保留失败供 Application.aclose 聚合, idle wrapper 不再告警。
                return

        session.idle_task = asyncio.create_task(
            expire(),
            name=f"debug-idle:{session.context.debug_session_id}",
        )

    async def _expert_execute(
        self,
        arguments: ExpertExecuteInput,
    ) -> ExpertExecuteOutput:
        maximum_timeout = self.config.workers.operation_timeout_seconds
        if arguments.timeout_seconds > maximum_timeout:
            raise ToolExecutionError(
                BusinessErrorCode.PRECONDITION_FAILED,
                (
                    "timeout_seconds 超过当前服务允许的普通操作时限。"
                    "请重新读取 tools/list，并使用其中列出的最大值。"
                ),
                details={"maximum_timeout_seconds": maximum_timeout},
            )
        await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            arguments.workspace_id,
            arguments.revision,
        )
        async with (
            self._workspace_lock(arguments.workspace_id),
            self._analysis_slots,
        ):
            cold_identity = await self._revision_cold_identity_unlocked(
                arguments.workspace_id,
                arguments.revision,
            )
            staging = await self._begin_revision_staging(
                arguments.workspace_id,
                expected_revision=arguments.revision,
            )
            try:
                raw = await self._run_analysis_worker(
                    lambda: self.backend.expert(
                        staging_path=staging.database_path,
                        code=arguments.code,
                        timeout_seconds=float(arguments.timeout_seconds),
                    )
                )
                result = adapt_expert_worker_result(raw, staging.database_path)
                receipt = await self._cold_validate(staging, expected=cold_identity)
                output = ExpertExecuteOutput(
                    workspace_id=arguments.workspace_id,
                    base_revision=arguments.revision,
                    revision=staging.candidate_revision,
                    output_mode="inline",
                    stdout=result.stdout,
                    stderr=result.stderr,
                    result_repr=result.result_repr,
                )
                output_artifact: ArtifactMetadata | None = None
                if _inline_model_size(output) > MAX_INLINE_RESULT_BYTES:
                    payload = json.dumps(
                        {
                            "result_repr": result.result_repr,
                            "stderr": result.stderr,
                            "stdout": result.stdout,
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                        allow_nan=False,
                        sort_keys=True,
                    ).encode("utf-8")
                    output_artifact = await _complete_thread_call(
                        lambda: self.storage.artifacts.put_bytes(
                            workspace_id=arguments.workspace_id,
                            revision=staging.candidate_revision,
                            data=payload,
                            media_type="application/vnd.ida-re.expert-output+json",
                            name="expert-output.json",
                        )
                    )
                    output = ExpertExecuteOutput(
                        workspace_id=arguments.workspace_id,
                        base_revision=arguments.revision,
                        revision=staging.candidate_revision,
                        output_mode="artifact",
                        artifact=ArtifactReference(
                            uri=output_artifact.uri,
                            sha256=output_artifact.content_sha256,
                            size=output_artifact.size,
                            media_type=output_artifact.media_type,
                        ),
                    )
                try:
                    revision = await _complete_thread_call(
                        lambda: self.storage.workspaces.publish_staging(
                            staging,
                            receipt=receipt,
                            change_id=f"expert_{uuid.uuid4().hex}",
                        )
                    )
                except BaseException:
                    if output_artifact is not None:
                        await _complete_thread_call(
                            lambda: self.storage.artifacts.discard_unpublished(output_artifact)
                        )
                    raise
                if revision.revision != output.revision:
                    raise RuntimeError("expert 发布的 revision 与候选身份不一致")
                return output
            except BaseException:
                if staging.path.exists():
                    await _complete_thread_call(
                        lambda: self.storage.workspaces.abort_staging(staging)
                    )
                raise

    async def _refine_workspace(
        self,
        arguments: AnalysisRefineInput,
        *,
        operation_id: str,
    ) -> JsonObject:
        async with (
            self._workspace_lock(arguments.workspace_id),
            self._analysis_slots,
        ):
            cold_identity = await self._revision_cold_identity_unlocked(
                arguments.workspace_id,
                arguments.revision,
            )
            staging = await self._begin_revision_staging(
                arguments.workspace_id,
                expected_revision=arguments.revision,
            )
            try:
                request = build_refine_worker_request(arguments, staging.database_path)
                raw = await self._run_analysis_worker(
                    lambda: self.backend.refine(
                        staging_path=staging.database_path,
                        input=request.input,
                        timeout_seconds=self.config.workers.operation_timeout_seconds,
                    )
                )
                result = adapt_refine_worker_result(
                    arguments,
                    raw,
                    staging.database_path,
                )
                receipt = await self._cold_validate(staging, expected=cold_identity)
                operation_result: JsonObject = {
                    "workspace_id": arguments.workspace_id,
                    "previous_revision": arguments.revision,
                    "revision": staging.candidate_revision,
                    "actions": [item.model_dump(mode="json") for item in result.actions],
                }
                revision = await _complete_thread_call(
                    lambda: self.storage.workspaces.publish_staging(
                        staging,
                        receipt=receipt,
                        change_id=f"refine_{uuid.uuid4().hex}",
                        operation_id=operation_id,
                        operation_result=operation_result,
                    )
                )
                if revision.revision != staging.candidate_revision:
                    raise RuntimeError("refine 发布的 revision 与候选身份不一致")
                return operation_result
            except BaseException:
                if staging.path.exists():
                    await _complete_thread_call(
                        lambda: self.storage.workspaces.abort_staging(staging)
                    )
                raise

    async def _initialize_workspace(
        self,
        workspace: WorkspaceSnapshot,
        *,
        operation_id: str,
        native_identity: NativeImageIdentity,
    ) -> JsonObject:
        async with (
            self._workspace_lock(workspace.workspace_id),
            self._analysis_slots,
        ):
            return await self._initialize_workspace_unlocked(
                workspace,
                operation_id=operation_id,
                native_identity=native_identity,
            )

    async def _initialize_workspace_unlocked(
        self,
        workspace: WorkspaceSnapshot,
        *,
        operation_id: str,
        native_identity: NativeImageIdentity,
    ) -> JsonObject:
        current_workspace = await asyncio.to_thread(
            self.storage.workspaces.get,
            workspace.workspace_id,
        )
        current_identity = await asyncio.to_thread(
            inspect_native_image,
            current_workspace.sample_path,
        )
        if (
            current_workspace.sample_sha256 != workspace.sample_sha256
            or current_identity != native_identity
        ):
            raise RuntimeError("workspace 样本身份在 Native 预检后发生变化")
        workspace = current_workspace
        staging = await self._begin_revision_staging(
            workspace.workspace_id,
            expected_revision=None,
        )
        try:
            result = await self._run_analysis_worker(
                lambda: self.backend.bootstrap(
                    sample_path=workspace.sample_path,
                    staging_path=staging.database_path,
                    timeout_seconds=self.config.workers.initial_analysis_timeout_seconds,
                )
            )
            if result.get("input_sha256") != workspace.sample_sha256:
                raise RuntimeError("bootstrap worker 返回的样本摘要不一致")
            receipt = await self._cold_validate(
                staging,
                expected=_ColdImageIdentity(
                    sample_sha256=workspace.sample_sha256,
                    container=native_identity.container,
                    architecture=native_identity.architecture,
                    bitness=native_identity.bitness,
                    endianness=native_identity.endian,
                ),
            )
            operation_result: JsonObject = {
                "workspace_id": workspace.workspace_id,
                "revision": staging.candidate_revision,
                "sample_sha256": workspace.sample_sha256,
            }
            revision = await _complete_thread_call(
                lambda: self.storage.workspaces.publish_staging(
                    staging,
                    receipt=receipt,
                    operation_id=operation_id,
                    operation_result=operation_result,
                )
            )
            if revision.revision != staging.candidate_revision:
                raise RuntimeError("bootstrap 发布的 revision 与候选身份不一致")
            return operation_result
        except BaseException:
            if staging.path.exists():
                await _complete_thread_call(lambda: self.storage.workspaces.abort_staging(staging))
            raise

    async def _begin_revision_staging(
        self,
        workspace_id: str,
        *,
        expected_revision: str | None,
        source_revision: str | None = None,
    ) -> RevisionStaging:
        """取消若撞上 staging 创建; 先取得句柄并完整回滚再传播取消。"""

        future = asyncio.create_task(
            asyncio.to_thread(
                self.storage.workspaces.begin_staging,
                workspace_id,
                expected_revision=expected_revision,
                source_revision=source_revision,
            )
        )
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError as cancellation:
            staging = await _await_task_without_cancellation(future)
            await _complete_thread_call(lambda: self.storage.workspaces.abort_staging(staging))
            raise cancellation

    async def _revision_cold_identity_unlocked(
        self,
        workspace_id: str,
        revision: str,
    ) -> _ColdImageIdentity:
        workspace = await asyncio.to_thread(
            self.storage.workspaces.get,
            workspace_id,
        )
        revision_snapshot = await asyncio.to_thread(
            self.storage.workspaces.get_revision,
            workspace_id,
            revision,
        )
        if revision_snapshot.image_identity is not None:
            return self._cold_identity_from_revision(workspace, revision_snapshot)
        overview = cast(
            ProgramOverviewOutput,
            await self._static_query_unlocked(
                "program.overview",
                ProgramOverviewInput(
                    workspace_id=workspace_id,
                    revision=revision,
                    include=[],
                ),
            ),
        )
        return self._cold_identity_from_revision(
            workspace,
            revision_snapshot,
            overview=overview,
        )

    def _cold_identity_from_revision(
        self,
        workspace: WorkspaceSnapshot,
        revision: RevisionSnapshot,
        *,
        overview: ProgramOverviewOutput | None = None,
    ) -> _ColdImageIdentity:
        """从持久 receipt 固定发布身份; legacy revision 才依赖冷查询补 image_size。"""

        identity = revision.image_identity
        if identity is not None:
            return _ColdImageIdentity(
                sample_sha256=workspace.sample_sha256,
                container=identity.container,
                architecture=identity.architecture,
                bitness=identity.bitness,
                endianness=identity.endian,
                image_size=identity.image_size,
            )
        if overview is None:
            raise RuntimeError("legacy revision 缺少冷查询镜像身份")
        cold_identity = _ColdImageIdentity.from_overview(
            workspace.sample_sha256,
            overview,
        )
        native_identity = self._trusted_native_identity(workspace, revision)
        if (
            cold_identity.container != native_identity.container
            or cold_identity.architecture != native_identity.architecture
            or cold_identity.bitness != native_identity.bitness
            or cold_identity.endianness != native_identity.endian
        ):
            raise RuntimeError("legacy revision 的 IDA 镜像身份与 Native 预检冲突")
        legacy_identity = revision.legacy_image_identity
        if legacy_identity is not None and (
            cold_identity.architecture != legacy_identity.architecture
            or cold_identity.bitness != legacy_identity.bitness
            or cold_identity.endianness != legacy_identity.endian
            or cold_identity.image_size != legacy_identity.image_size
        ):
            raise RuntimeError("legacy revision 的 IDA 镜像身份与持久证据冲突")
        return cold_identity

    async def _cold_validate(
        self,
        staging: RevisionStaging,
        *,
        expected: _ColdImageIdentity,
    ) -> ColdValidationReceipt:
        backend, worker_slot = await self._open_transient_analysis(
            staging.database_path,
            staging.candidate_revision,
        )
        try:
            overview = await backend.execute(
                operation="program.overview",
                input={"limit": 1},
                timeout_seconds=self.config.workers.operation_timeout_seconds,
            )
        finally:
            try:
                await backend.close()
            finally:
                await worker_slot.release()
        image = overview.get("image")
        if not isinstance(image, dict):
            raise RuntimeError("冷验证未返回可信镜像身份")
        if image.get("sha256") != expected.sample_sha256:
            raise RuntimeError("冷验证原样本 SHA-256 与 workspace 身份不一致")
        architecture = image.get("architecture")
        bitness = image.get("bitness")
        endianness = image.get("endianness")
        image_size = image.get("image_size")
        container = image.get("container")
        if (
            container not in {"elf", "pe"}
            or not isinstance(architecture, str)
            or isinstance(bitness, bool)
            or not isinstance(bitness, int)
            or (architecture, bitness)
            not in {
                ("x86", 32),
                ("x86_64", 64),
                ("arm", 32),
                ("aarch64", 64),
            }
            or (container == "pe" and architecture not in {"x86", "x86_64"})
            or endianness != "little"
            or isinstance(image_size, bool)
            or not isinstance(image_size, int)
            or image_size < 1
        ):
            raise RuntimeError("冷验证镜像不满足当前 Native 产品边界")
        if (
            (expected.container is not None and container != expected.container)
            or (expected.architecture is not None and architecture != expected.architecture)
            or (expected.bitness is not None and bitness != expected.bitness)
            or (expected.endianness is not None and endianness != expected.endianness)
            or (expected.image_size is not None and image_size != expected.image_size)
        ):
            raise RuntimeError("冷验证镜像身份与 base revision 不一致")
        hashes = await _settle_thread_call_preserving_cancellation(
            lambda: hash_staging_payload(staging)
        )
        # 冷验证已证明的镜像身份随 revision 一并持久化, 让 workspace.list/get
        # 免于为读取架构再冷开一次 IDB.
        image_identity = ImageIdentity.model_validate(
            {
                "container": container,
                "architecture": architecture,
                "bitness": bitness,
                "endian": endianness,
                "image_size": image_size,
            }
        )
        return ColdValidationReceipt.create(
            validator="ida_9_3_headless",
            component_hashes=hashes,
            image_identity=image_identity,
        )

    async def _export_workspace(
        self,
        arguments: WorkspaceExportInput,
    ) -> JsonObject:
        async with self._workspace_lock(arguments.workspace_id):
            revision = await asyncio.to_thread(
                self.storage.workspaces.get_revision,
                arguments.workspace_id,
                arguments.revision,
            )
            added_pin = not revision.pinned
            if added_pin:
                await _complete_thread_call(
                    lambda: self.storage.workspaces.pin_revision(
                        arguments.workspace_id,
                        arguments.revision,
                        pinned=True,
                    )
                )
            try:
                artifact = await _complete_thread_call(
                    lambda: self.storage.artifacts.put_chunked_file(
                        workspace_id=arguments.workspace_id,
                        revision=arguments.revision,
                        source=revision.database_path,
                        media_type="application/vnd.hex-rays.idb",
                        name=f"{arguments.workspace_id}-{arguments.revision}.i64",
                    )
                )
            except BaseException:
                if added_pin:
                    try:
                        await _complete_thread_call(
                            lambda: self.storage.workspaces.pin_revision(
                                arguments.workspace_id,
                                arguments.revision,
                                pinned=False,
                            )
                        )
                    except BaseException as rollback_failure:
                        raise RuntimeError(
                            "workspace export 失败且无法撤销新增 revision pin"
                        ) from rollback_failure
                raise
        return {
            "artifact_uri": artifact.index.uri,
            "sha256": artifact.content_sha256,
            "size": artifact.size,
            "media_type": artifact.media_type,
            "encoding": "chunked_artifact_index",
            "chunk_count": len(artifact.chunks),
        }

    async def _build_report(self, arguments: ReportBuildInput) -> JsonObject:
        async with self._workspace_lock(arguments.workspace_id):
            return await self._build_report_unlocked(arguments)

    async def _build_report_unlocked(self, arguments: ReportBuildInput) -> JsonObject:
        include: list[Literal["entry_points", "imports", "exports"]] = []
        if "entry_points" in arguments.sections:
            include.append("entry_points")
        if "imports_exports" in arguments.sections:
            include.extend(("imports", "exports"))
        async with self._analysis_slots:
            overview = cast(
                ProgramOverviewOutput,
                await self._static_query_unlocked(
                    "program.overview",
                    ProgramOverviewInput(
                        workspace_id=arguments.workspace_id,
                        revision=arguments.revision,
                        include=[*include],
                    ),
                ),
            )
        document: dict[str, object] = {
            "title": arguments.title or "逆向分析报告",
            "workspace_id": arguments.workspace_id,
            "revision": arguments.revision,
            "sections": arguments.sections,
        }
        overview_json = overview.model_dump(mode="json")
        if "overview" in arguments.sections:
            document["overview"] = {
                "image": overview_json["image"],
                "counts": overview_json["counts"],
                "coverage": overview_json["coverage"],
                "provenance": overview_json["provenance"],
            }
        if "entry_points" in arguments.sections:
            document["entry_points"] = overview_json["entry_points"]
        if "imports_exports" in arguments.sections:
            document["imports"] = overview_json["imports"]
            document["exports"] = overview_json["exports"]
        if arguments.format == "json":
            data = json.dumps(
                document,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            media_type = "application/json"
            name = "report.json"
        else:
            lines = [
                f"# {document['title']}\n\n"
                f"- 分析项目编号：`{arguments.workspace_id}`\n"
                f"- 分析版本：`{arguments.revision}`\n"
            ]
            if "overview" in arguments.sections:
                lines.extend(
                    (
                        "\n## 概览\n\n",
                        f"- 处理器架构：`{overview.image.architecture}`\n",
                        f"- 文件格式：`{overview.image.format}`\n",
                        f"- 默认加载地址：`{overview.image.image_base}`\n",
                        f"- 文件映像大小：`{overview.image.image_size}`\n",
                        f"- SHA-256: `{overview.image.sha256}`\n",
                        f"- 函数数量：`{overview.counts.functions}`\n",
                        f"- 字符串数量：`{overview.counts.strings}`\n",
                    )
                )
            if "entry_points" in arguments.sections:
                lines.append("\n## 入口点\n\n")
                lines.extend(
                    f"- `{item.name}`，地址 "
                    f"`{_address_text(item.address.model_dump(mode='json'))}`\n"
                    for item in overview.entry_points
                )
            if "imports_exports" in arguments.sections:
                for heading, items in (
                    ("导入项", overview.imports),
                    ("导出项", overview.exports),
                ):
                    lines.append(f"\n## {heading}\n\n")
                    lines.extend(
                        f"- `{item.name}`，地址 "
                        f"`{_address_text(item.address.model_dump(mode='json'))}`\n"
                        for item in items
                    )
            data = "".join(lines).encode("utf-8")
            media_type = "text/markdown"
            name = "report.md"
        artifact = await self._put_public_artifact(
            workspace_id=arguments.workspace_id,
            revision=arguments.revision,
            data=data,
            media_type=media_type,
            name=name,
        )
        return {
            "artifact_uri": artifact.uri,
            "sha256": artifact.content_sha256,
            "size": artifact.size,
        }

    def _workspace_summary(
        self,
        workspace: WorkspaceSnapshot,
        *,
        native_identity: NativeImageIdentity | None = None,
    ) -> WorkspaceSummary:
        # 状态阶梯只陈述可证明的事实, 不把无法证明的进行时冒充为 analyzing:
        # 1) 有 current revision -> ready;
        # 2) manifest 已持久化失败/取消终态 -> failed(跨会话持久可见);
        # 3) 可见 operation 处于终态失败/取消 -> failed, 处于排队/运行 -> analyzing
        #    (仅当 operation 存储对本会话可见时成立; session 私有存储跨会话查不到即跳过);
        # 4) 其余 -> unknown(Supervisor 曾被强杀, 或该 workspace 属于另一条活动连接)。
        state: Literal["analyzing", "ready", "failed", "unknown"]
        architecture: str | None = None
        analysis_outcome: WorkspaceAnalysisOutcome | None = None
        if workspace.current_revision is not None:
            state = "ready"
            architecture = (
                native_identity.architecture
                if native_identity is not None
                else self._workspace_architecture(workspace)
            )
        elif workspace.analysis_outcome is not None:
            state = "failed"
            analysis_outcome = WorkspaceAnalysisOutcome(
                state=workspace.analysis_outcome.state,
                reason=workspace.analysis_outcome.reason,
                recorded_at=workspace.analysis_outcome.recorded_at,
            )
        else:
            operation_status = self._operation_backed_status(workspace.workspace_id)
            if operation_status is None:
                state = "unknown"
            else:
                state, analysis_outcome = operation_status
        return WorkspaceSummary(
            workspace_id=workspace.workspace_id,
            revision=workspace.current_revision,
            sample_name=workspace.sample_name,
            sample_sha256=workspace.sample_sha256,
            architecture=architecture,
            state=state,
            analysis_outcome=analysis_outcome,
        )

    def _current_revision_identity(self, workspace: WorkspaceSnapshot) -> ImageIdentity | None:
        """返回 current revision 已持久化的镜像身份; 旧 revision 或未初始化返回 None。"""

        revision = self._current_revision_snapshot(workspace)
        return revision.image_identity if revision is not None else None

    def _current_revision_snapshot(
        self,
        workspace: WorkspaceSnapshot,
    ) -> RevisionSnapshot | None:
        """返回 current revision 快照; 未初始化 workspace 返回 None。"""

        if workspace.current_revision is None:
            return None
        for revision in workspace.revisions:
            if revision.revision == workspace.current_revision:
                return revision
        return None

    def _trusted_native_identity(
        self,
        workspace: WorkspaceSnapshot,
        revision: RevisionSnapshot | None = None,
    ) -> NativeImageIdentity:
        """优先使用完整冷验证身份; legacy revision 回退有界文件头预检。"""

        selected_revision = revision or self._current_revision_snapshot(workspace)
        persisted = selected_revision.image_identity if selected_revision is not None else None
        if persisted is not None:
            return NativeImageIdentity(
                container=persisted.container,
                architecture=persisted.architecture,
                endian=persisted.endian,
                bitness=persisted.bitness,
            )
        try:
            native_identity = inspect_native_image(workspace.sample_path)
        except (OSError, UnsupportedNativeImageError) as exc:
            raise StorageCorruptionError("workspace 原样本无法通过 Native 文件头预检") from exc
        legacy_identity = (
            selected_revision.legacy_image_identity if selected_revision is not None else None
        )
        if legacy_identity is not None and (
            legacy_identity.architecture != native_identity.architecture
            or legacy_identity.bitness != native_identity.bitness
            or legacy_identity.endian != native_identity.endian
        ):
            raise StorageCorruptionError("legacy revision 镜像身份与 Native 文件头冲突")
        return native_identity

    def _workspace_architecture(self, workspace: WorkspaceSnapshot) -> str | None:
        """从 current revision 已持久化的镜像身份读取架构; 旧 revision 缺省返回 None。"""

        identity = self._current_revision_identity(workspace)
        return identity.architecture if identity is not None else None

    def _operation_backed_status(
        self,
        workspace_id: str,
    ) -> (
        tuple[
            Literal["failed", "analyzing"],
            WorkspaceAnalysisOutcome | None,
        ]
        | None
    ):
        """由可见的首次分析 operation 推导公开状态与安全终态。

        优先本会话登记的 operation, 其次读取 operation 存储中同 workspace 的最新
        `workspace_create` 记录。session 私有存储在新会话下查不到旧记录, 因此该证据
        只在存储对当前会话可见时生效, 不会跨会话伪造进行时或失败。
        """

        operation = None
        operation_id = self._workspace_operations.get(workspace_id)
        if operation_id is not None:
            try:
                operation = self.storage.operations.get(operation_id)
            except OperationNotFoundError:
                operation = None
        if operation is None:
            operation = self.storage.operations.latest(
                workspace_id=workspace_id,
                kind="workspace_create",
            )
        if operation is None:
            return None
        if operation.state is OperationState.FAILED:
            reason = (
                operation.failure.message
                if operation.failure is not None
                else _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.EXECUTION_FAILED]
            )
            return (
                "failed",
                WorkspaceAnalysisOutcome(
                    state="failed",
                    reason=reason,
                    recorded_at=operation.finished_at or operation.updated_at,
                ),
            )
        if operation.state is OperationState.CANCELLED:
            return (
                "failed",
                WorkspaceAnalysisOutcome(
                    state="cancelled",
                    reason="首次分析已取消",
                    recorded_at=operation.finished_at or operation.updated_at,
                ),
            )
        if operation.state in {
            OperationState.QUEUED,
            OperationState.RUNNING,
            OperationState.CANCEL_REQUESTED,
        }:
            return "analyzing", None
        return None

    def _schedule_operation(
        self,
        kind: str,
        workspace_id: str,
        work: Callable[[str], Awaitable[JsonObject]],
        *,
        on_unsuccessful_terminal: (
            Callable[[Literal["failed", "cancelled"], str], None] | None
        ) = None,
        cancellable: bool = False,
    ) -> str:
        snapshot = self.storage.operations.create(kind, workspace_id=workspace_id)

        async def record_unsuccessful_terminal(
            state: Literal["failed", "cancelled"],
            reason: str,
        ) -> None:
            callback = on_unsuccessful_terminal
            if callback is None:
                return
            await _complete_thread_call(lambda: callback(state, reason))

        async def run() -> None:
            try:
                current = self.storage.operations.get(snapshot.operation_id)
                if current.state is OperationState.CANCELLED:
                    await record_unsuccessful_terminal(
                        "cancelled",
                        "首次分析已取消",
                    )
                    return
                self.storage.operations.start(snapshot.operation_id)
                result = await work(snapshot.operation_id)
                # Worker 调用一旦进入不可中断区, 只能在真实完成后报告成功;
                # 已迟到的取消请求不能把已经发布的副作用伪装成 cancelled。
                self.storage.operations.succeed(snapshot.operation_id, result)
            except asyncio.CancelledError:
                try:
                    state = self.storage.operations.get(snapshot.operation_id).state
                except SupervisorError:
                    return
                if state is OperationState.CANCEL_REQUESTED:
                    try:
                        await record_unsuccessful_terminal(
                            "cancelled",
                            "首次分析已取消",
                        )
                    finally:
                        self.storage.operations.acknowledge_cancel(snapshot.operation_id)
                elif state is OperationState.RUNNING:
                    try:
                        await record_unsuccessful_terminal(
                            "failed",
                            "操作因服务关闭而中止",
                        )
                    finally:
                        self.storage.operations.fail(
                            snapshot.operation_id,
                            code="worker_crashed",
                            message="操作因服务关闭而中止",
                        )
            except Exception as exc:
                diagnostic_details = (
                    exc.details
                    if isinstance(exc, (ToolExecutionError, WorkerProcessError, WorkerError))
                    else None
                )
                write_exception_log(
                    self.storage.paths.log_root,
                    context=(f"后台任务 {kind}（{snapshot.operation_id}）执行失败"),
                    error=exc,
                    details=diagnostic_details,
                )
                code, message, details = _operation_failure(exc)
                try:
                    await record_unsuccessful_terminal("failed", message)
                finally:
                    self.storage.operations.fail(
                        snapshot.operation_id,
                        code=code,
                        message=message,
                        details=details,
                    )

        task = asyncio.create_task(run(), name=f"{kind}:{snapshot.operation_id}")
        self._operation_tasks[snapshot.operation_id] = task
        if on_unsuccessful_terminal is not None:
            self._operation_terminal_callbacks[snapshot.operation_id] = on_unsuccessful_terminal
        if cancellable:
            self._cancellable_operations.add(snapshot.operation_id)

        def forget_operation(_task: asyncio.Task[None]) -> None:
            self._operation_tasks.pop(snapshot.operation_id, None)
            self._operation_terminal_callbacks.pop(snapshot.operation_id, None)
            self._cancellable_operations.discard(snapshot.operation_id)

        task.add_done_callback(forget_operation)
        return snapshot.operation_id

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("Application 已关闭")

    def _workspace_lock(self, workspace_id: str) -> AsyncInterprocessFileLock:
        lock = self._workspace_locks.get(workspace_id)
        if lock is None:
            lock = AsyncInterprocessFileLock(
                self.storage.workspaces.workspace_lease_lock(workspace_id)
            )
            self._workspace_locks[workspace_id] = lock
        return lock


def _operation_output(snapshot: OperationSnapshot) -> OperationWaitOutput:
    failure = snapshot.failure
    return OperationWaitOutput(
        operation_id=snapshot.operation_id,
        state=snapshot.state.value,
        result=cast(JsonValue, snapshot.result),
        failure=(
            OperationFailure(
                code=failure.code,
                message=failure.message,
                retryable=failure.code in {"worker_crashed", "worker_timeout"},
            )
            if failure is not None
            else None
        ),
    )


def _empty_change_impact() -> ChangeImpact:
    return ChangeImpact(
        renamed_entities=0,
        comments_changed=0,
        types_changed=0,
        patched_bytes=0,
        imported_symbols=0,
        conflicts=[],
    )


def _inline_model_size(value: StrictModel) -> int:
    return len(
        json.dumps(
            value.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def _address_text(value: Mapping[str, object]) -> str:
    kind = value.get("kind")
    if kind == "image":
        return f"{value.get('image_id')}+{value.get('rva')}"
    if kind == "database":
        return str(value.get("ea"))
    if kind == "file":
        return f"file+{value.get('offset')}"
    if kind == "runtime":
        return f"{value.get('module_id')}@{value.get('va')}"
    raise RuntimeError("报告收到未知 AddressRef")


def _native_binding(
    workspace: WorkspaceSnapshot,
    overview: ProgramOverviewOutput,
) -> NativeBinding | None:
    image = overview.image
    if image.endian != "little":
        return None
    with workspace.sample_path.open("rb") as stream:
        header = stream.read(64)
    abi: str | None = None
    if header.startswith(b"MZ"):
        if image.architecture == "x86" and image.bitness == 32:
            abi = "msvc-x86"
        elif image.architecture == "x86_64" and image.bitness == 64:
            abi = "msvc-x64"
    elif header.startswith(b"\x7fELF") and len(header) >= 20 and header[5] == 1:
        elf_class = header[4]
        machine = int.from_bytes(header[18:20], "little")
        if elf_class == 1 and machine == 0x03 and image.architecture == "x86":
            abi = "sysv-x86"
        elif elf_class == 1 and machine == 0x28 and image.architecture == "arm":
            abi = "aapcs32"
        elif elf_class == 2 and machine == 0x3E and image.architecture == "x86_64":
            abi = "sysv-x64"
        elif elf_class == 2 and machine == 0xB7 and image.architecture == "aarch64":
            abi = "aapcs64"
    if abi is None:
        return None
    return NativeBinding.model_validate(
        {
            "sha256": workspace.sample_sha256,
            "size": workspace.sample_size,
            "image_size": image.image_size,
            "architecture": image.architecture,
            "abi": abi,
            "pointer_width": image.bitness,
            "endianness": "little",
        },
        strict=True,
    )


def _cancel_idle_task(task: asyncio.Task[None] | None) -> None:
    if task is not None and task is not asyncio.current_task() and not task.done():
        task.cancel()


async def _complete_thread_call[T](call: Callable[[], T]) -> T:
    """线程中的存储提交一旦开始; 调用方取消也必须等待确定结果。"""

    future = asyncio.create_task(asyncio.to_thread(call))
    return await _await_task_without_cancellation(future)


async def _settle_thread_call_preserving_cancellation[T](call: Callable[[], T]) -> T:
    """线程调用开始后等待其落定, 再传播调用方取消。"""

    future = asyncio.create_task(asyncio.to_thread(call))
    return await _await_task_preserving_cancellation(future)


async def _await_task_without_cancellation[T](task: asyncio.Task[T]) -> T:
    while True:
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            if task.done():
                return task.result()
            continue


async def _await_task_preserving_cancellation[T](task: asyncio.Task[T]) -> T:
    """调用方取消时先等清理任务结束, 再传播原始取消。"""

    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError as cancellation:
        await _await_task_without_cancellation(task)
        raise cancellation


def _session_registry_lease_path(paths: RuntimePaths) -> Path:
    """返回协调 session 创建、回收和 lease 文件删除的全局锁。"""

    return paths.data_root.resolve() / "session-registry.lease.lock"


def _safe_remove_temp_directory(path: Path, root: Path) -> None:
    if not path.exists():
        return
    resolved = path.resolve()
    root_resolved = root.resolve()
    try:
        relative = resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise RuntimeError(f"拒绝清理临时目录边界外路径: {resolved}") from exc
    if not relative.parts:
        raise RuntimeError(f"拒绝清理临时目录根: {resolved}")
    shutil.rmtree(resolved)


def _collect_stale_sessions(
    paths: RuntimePaths,
    *,
    dry_run: bool,
) -> _SessionGarbageCollection:
    """回收超过 operation 保留期且未被进程持有的连接私有目录。"""

    if paths.session_root is None:
        return _SessionGarbageCollection((), (), 0)
    sessions_root = paths.session_root.parent.resolve()
    data_root = paths.data_root.resolve()
    if sessions_root.name != "sessions" or sessions_root.parent != data_root:
        raise RuntimeError("MCP 会话目录不在 data_root/sessions 边界内")
    if not sessions_root.is_dir():
        return _SessionGarbageCollection((), (), 0)

    current = paths.session_root.resolve()
    lease_root = paths.session_lease_root.resolve()
    if lease_root.parent != data_root or lease_root.name != "session-leases":
        raise RuntimeError("MCP 会话 lease 目录不在 data_root/session-leases 边界内")
    log_sessions_root = (
        paths.log_root.parent.resolve() if paths.log_root.name == current.name else None
    )
    cutoff = time.time() - OPERATION_RETENTION_SECONDS
    removed: list[Path] = []
    skipped: list[str] = []
    reclaimed = 0
    registry = exclusive_process_lease(_session_registry_lease_path(paths))
    registry.acquire()
    try:
        session_names = _session_entry_names(sessions_root, label="会话根目录")
        if log_sessions_root is not None and log_sessions_root.is_dir():
            session_names.update(_session_entry_names(log_sessions_root, label="会话日志根目录"))
        session_names.discard(current.name)

        for session_name in sorted(session_names):
            data_candidate = sessions_root / session_name
            log_candidate = (
                log_sessions_root / session_name if log_sessions_root is not None else None
            )
            lease_path = lease_root / f"{session_name}.lease.lock"
            lease = exclusive_process_lease(lease_path)
            if not lease.try_acquire():
                skipped.append(session_name)
                continue
            remove_lease_file = False
            try:
                roots: list[Path] = []
                if data_candidate.exists():
                    roots.append(
                        _validated_session_directory(
                            data_candidate,
                            parent=sessions_root,
                            label="会话根目录",
                        )
                    )
                if log_candidate is not None and log_candidate.exists():
                    assert log_sessions_root is not None
                    roots.append(
                        _validated_session_directory(
                            log_candidate,
                            parent=log_sessions_root,
                            label="会话日志根目录",
                        )
                    )
                if not roots:
                    remove_lease_file = not dry_run
                    continue

                facts = [_directory_tree_facts(root) for root in roots]
                latest_activity = max(latest for _size, latest in facts)
                if latest_activity > cutoff:
                    continue
                removed.extend(roots)
                reclaimed += sum(size for size, _latest in facts)
                if not dry_run:
                    # 先删日志; 即使随后数据目录暂时删除失败, 下次仍能从数据侧发现。
                    if log_candidate is not None and log_candidate.exists():
                        shutil.rmtree(log_candidate.resolve(strict=True))
                    if data_candidate.exists():
                        shutil.rmtree(data_candidate.resolve(strict=True))
                    remove_lease_file = True
            finally:
                lease.release()
                if remove_lease_file:
                    lease_path.unlink(missing_ok=True)

        if not dry_run:
            _remove_orphan_session_lease_files(
                lease_root,
                current_session_id=current.name,
                known_session_ids=session_names,
            )
    finally:
        registry.release()
    return _SessionGarbageCollection(tuple(removed), tuple(skipped), reclaimed)


def _session_entry_names(root: Path, *, label: str) -> set[str]:
    names: set[str] = set()
    for candidate in root.iterdir():
        if candidate.is_symlink():
            raise RuntimeError(f"{label}包含非法条目: {candidate}")
        if (
            not candidate.is_dir()
            or not candidate.name.startswith("session_")
            or not candidate.name.replace("_", "").isalnum()
            or not candidate.name.isascii()
        ):
            raise RuntimeError(f"{label}包含非法条目: {candidate}")
        names.add(candidate.name)
    return names


def _validated_session_directory(candidate: Path, *, parent: Path, label: str) -> Path:
    if candidate.is_symlink() or not candidate.is_dir():
        raise RuntimeError(f"{label}包含非法条目: {candidate}")
    resolved = candidate.resolve(strict=True)
    if resolved.parent != parent:
        raise RuntimeError(f"拒绝清理{label}边界外路径: {resolved}")
    return resolved


def _remove_orphan_session_lease_files(
    lease_root: Path,
    *,
    current_session_id: str,
    known_session_ids: set[str],
) -> None:
    for lease_path in lease_root.iterdir():
        suffix = ".lease.lock"
        if (
            lease_path.is_symlink()
            or not lease_path.is_file()
            or not lease_path.name.endswith(suffix)
        ):
            raise RuntimeError(f"会话 lease 目录包含非法条目: {lease_path}")
        session_id = lease_path.name[: -len(suffix)]
        if session_id == current_session_id or session_id in known_session_ids:
            continue
        if (
            not session_id.startswith("session_")
            or not session_id.replace("_", "").isalnum()
            or not session_id.isascii()
        ):
            raise RuntimeError(f"会话 lease 目录包含非法条目: {lease_path}")
        lease = exclusive_process_lease(lease_path)
        if not lease.try_acquire():
            continue
        lease.release()
        lease_path.unlink(missing_ok=True)


def _directory_tree_facts(root: Path) -> tuple[int, float]:
    total = 0
    latest_activity = root.stat().st_mtime
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            raise RuntimeError(f"拒绝计算包含 symlink 的会话目录: {root}")
        stat = candidate.stat()
        latest_activity = max(latest_activity, stat.st_mtime)
        if candidate.is_file():
            total += stat.st_size
        elif not candidate.is_dir():
            raise RuntimeError(f"会话目录包含非法文件类型: {candidate}")
    return total, latest_activity


def _operation_failure(exc: Exception) -> tuple[str, str, JsonValue]:
    if isinstance(exc, ToolExecutionError):
        return exc.code.value, exc.message, cast(JsonValue, exc.details)
    if isinstance(exc, WorkerProcessError):
        if exc.code == "worker_timeout":
            details: JsonValue = {"reason": "timeout"}
            message = _WORKER_PUBLIC_MESSAGES["worker_timeout"]
        else:
            details = {"reason": "process_exited"}
            message = _WORKER_PUBLIC_MESSAGES["worker_crashed"]
        return (
            BusinessErrorCode.WORKER_CRASHED.value,
            message,
            details,
        )
    translated = _tool_error(exc)
    if translated is not None:
        return (
            translated.code.value,
            translated.message,
            cast(JsonValue, translated.details),
        )
    return (
        BusinessErrorCode.EXECUTION_FAILED.value,
        _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.EXECUTION_FAILED],
        None,
    )


def _tool_error(exc: Exception) -> ToolExecutionError | None:
    if isinstance(exc, AnalysisRetryUnavailableError):
        return ToolExecutionError(
            BusinessErrorCode.PRECONDITION_FAILED,
            (
                "这个分析项目的状态已经变化，不能按当前失败记录重试。"
                "请重新调用 workspace.list，并根据最新 state 和 revision 决定下一步。"
            ),
        )
    if isinstance(exc, WorkspaceNotFoundError):
        return ToolExecutionError(
            BusinessErrorCode.WORKSPACE_NOT_FOUND,
            _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.WORKSPACE_NOT_FOUND],
        )
    if isinstance(exc, RevisionNotFoundError):
        return ToolExecutionError(
            BusinessErrorCode.REVISION_NOT_FOUND,
            _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.REVISION_NOT_FOUND],
        )
    if isinstance(exc, RevisionConflictError):
        return ToolExecutionError(
            BusinessErrorCode.REVISION_CONFLICT,
            _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.REVISION_CONFLICT],
        )
    if isinstance(exc, OperationNotFoundError):
        return ToolExecutionError(
            BusinessErrorCode.OPERATION_NOT_FOUND,
            _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.OPERATION_NOT_FOUND],
        )
    if isinstance(exc, ArtifactNotFoundError):
        return ToolExecutionError(
            BusinessErrorCode.RESOURCE_NOT_FOUND,
            _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.RESOURCE_NOT_FOUND],
        )
    if isinstance(exc, CursorError):
        return ToolExecutionError(
            BusinessErrorCode.CURSOR_STALE,
            _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.CURSOR_STALE],
        )
    if isinstance(exc, (WorkerProcessError, WorkerError)):
        code = getattr(exc, "code", "worker_crashed")
        business = _WORKER_BUSINESS_ERRORS.get(
            code,
            BusinessErrorCode.EXECUTION_FAILED,
        )
        message = _WORKER_PUBLIC_MESSAGES.get(
            code,
            _BUSINESS_PUBLIC_MESSAGES[business],
        )
        return ToolExecutionError(business, message)
    if isinstance(
        exc,
        (
            ChangeAdapterInputError,
            ChangeSourceError,
            ChangeSetError,
        ),
    ):
        return ToolExecutionError(
            BusinessErrorCode.CHANGE_SET_INVALID,
            _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.CHANGE_SET_INVALID],
        )
    if isinstance(exc, StaticAdapterCapabilityError):
        return ToolExecutionError(
            BusinessErrorCode.CAPABILITY_UNAVAILABLE,
            _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.CAPABILITY_UNAVAILABLE],
        )
    if isinstance(exc, StaticAdapterInputError):
        return ToolExecutionError(
            BusinessErrorCode.UNSUPPORTED,
            (
                "无法按这组参数执行查询。"
                "请检查 workspace_id、revision、编号和地址，并按工具说明修改后重试。"
            ),
        )
    if isinstance(exc, DebugAdapterError):
        return ToolExecutionError(
            BusinessErrorCode.DEBUG_STATE_CONFLICT,
            _BUSINESS_PUBLIC_MESSAGES[BusinessErrorCode.DEBUG_STATE_CONFLICT],
        )
    if isinstance(exc, RefineAdapterInputError):
        return ToolExecutionError(
            BusinessErrorCode.UNSUPPORTED,
            (
                "无法按这些目标和动作重新分析。"
                "请先用 address.inspect 确认地址，并按 analysis.refine 的工具说明修改后重试。"
            ),
        )
    if isinstance(
        exc,
        (
            ChangeAdapterResultError,
            StaticAdapterResultError,
            RefineAdapterResultError,
            ExpertAdapterError,
        ),
    ):
        return ToolExecutionError(
            BusinessErrorCode.WORKER_CRASHED,
            (
                "IDA 返回的数据未通过检查，服务没有使用这些数据。"
                "请查看 logs 目录中的本次运行日志，然后重试。"
            ),
        )
    if isinstance(
        exc,
        (
            ArtifactIntegrityError,
            InvalidIdentifierError,
            OperationStateError,
            StagingIntegrityError,
            StorageCorruptionError,
        ),
    ):
        return ToolExecutionError(
            BusinessErrorCode.EXECUTION_FAILED,
            (
                "保存的数据未通过完整性检查，服务已经停止使用它。"
                "请不要继续修改这个分析项目；查看 logs 目录，必要时重新导入样本。"
            ),
        )
    return None
