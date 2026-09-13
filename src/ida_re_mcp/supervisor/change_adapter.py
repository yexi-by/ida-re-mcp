"""公共 change 工具与不可变计划、MutationWorker JSON 之间的适配层。"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Final, Literal, Self, cast

from pydantic import (
    Field,
    JsonValue,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from ida_re_mcp.constants import IL2CPP_MEDIA_TYPE
from ida_re_mcp.domain.address import ImageAddress, RevisionAddress, U64Hex
from ida_re_mcp.domain.base import StrictModel
from ida_re_mcp.domain.identifiers import ChangeId, ImageId, RevisionId, WorkspaceId
from ida_re_mcp.domain.tools import (
    ArrayTypeRef,
    CanonicalTypeRef,
    ChangeConflict,
    ChangeImpact,
    ChangePrepareInput,
    CommentOperation,
    FunctionTypeRef,
    ImportIl2CppBundleOperation,
    NamedTypeRef,
    PatchBytesOperation,
    PointerTypeRef,
    PrimitiveTypeRef,
    RenameOperation,
    SetTypeOperation,
    Sha256,
)
from ida_re_mcp.il2cpp import BundleValidationError, parse_il2cpp_bundle
from ida_re_mcp.il2cpp.models import NativeBinding
from ida_re_mcp.supervisor._fs import sha256_file
from ida_re_mcp.supervisor.artifacts import parse_artifact_uri
from ida_re_mcp.supervisor.changes import (
    RevisionPreimage,
    StoredChangeOperation,
    StoredCommentOperation,
    StoredIl2CppTypeResolution,
    StoredImportIl2CppBundleOperation,
    StoredPatchBytesOperation,
    StoredRenameOperation,
    StoredRestoreRevisionOperation,
    StoredSetTypeOperation,
)

_METADATA_MEDIA_TYPE: Final = "application/octet-stream"
_TYPE_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$")

type SourceRole = Literal["bundle", "metadata"]
_SOURCE_ROLES: Final[tuple[SourceRole, SourceRole]] = ("bundle", "metadata")


class ChangeAdapterError(RuntimeError):
    """写事务适配层的稳定失败基类。"""


class ChangeAdapterInputError(ChangeAdapterError):
    """公共参数、上下文或计划彼此不一致。"""


class ChangeSourceError(ChangeAdapterError):
    """本地 IL2CPP 输入无法验证或无法安全固化。"""


class ChangeAdapterResultError(ChangeAdapterError):
    """worker 结果不满足当前严格契约。"""


class ChangeContext(StrictModel):
    """一次 prepare 绑定的 workspace、revision 与原生镜像身份。"""

    workspace_id: WorkspaceId
    base_revision: RevisionId
    image_id: ImageId
    sample_sha256: Sha256
    database_sha256: Sha256
    component_hashes: dict[str, Sha256] = Field(min_length=1)
    native: NativeBinding | None = None

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        if self.component_hashes.get("database.i64") != self.database_sha256:
            raise ValueError("component_hashes 必须包含匹配的 database.i64")
        if self.native is not None and self.native.sha256 != self.sample_sha256:
            raise ValueError("native.sha256 必须等于 workspace 原样本 SHA-256")
        return self


class InverseSource(StrictModel):
    """允许撤销的已发布 change 线性位置。"""

    workspace_id: WorkspaceId
    change_id: ChangeId
    applied_revision: RevisionId
    parent_revision: RevisionId


class SolidifiedSource(StrictModel):
    """ArtifactStore 返回的不可变输入身份。"""

    operation_index: int = Field(ge=0)
    role: SourceRole
    artifact_uri: str = Field(
        pattern=r"^ida-re://workspaces/[^/\s]+/revisions/[^/\s]+/artifacts/[^/\s]+$"
    )
    content_sha256: Sha256
    size: int = Field(ge=1)


@dataclass(frozen=True, slots=True)
class ValidatedIl2CppSource:
    """已完成路径、摘要、bundle schema 与绑定验证的本地输入。"""

    operation_index: int
    bundle_path: Path
    bundle_sha256: str
    bundle_size: int
    metadata_path: Path
    metadata_sha256: str
    metadata_size: int
    record_count: int
    type_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class SourceSolidificationRequest:
    """交给 ArtifactStore.put_file 的精确请求。"""

    operation_index: int
    role: SourceRole
    source: Path
    expected_sha256: str
    size: int
    media_type: str
    name: str


@dataclass(frozen=True, slots=True)
class CanonicalChangePlan:
    """可直接交给 ChangeSetStore.prepare 的 canonical 内容。"""

    operations: tuple[StoredChangeOperation, ...]
    preimage: RevisionPreimage
    inverse_of_change_id: str | None


@dataclass(frozen=True, slots=True)
class ArtifactMaterialization:
    """执行期从不可变 artifact 得到的已验证本地文件。"""

    artifact_uri: str
    content_sha256: str
    size: int
    path: Path


@dataclass(frozen=True, slots=True)
class MutationExecution:
    """worker mutation 或 revision restore 两种互斥执行模式。"""

    mode: Literal["worker", "restore_revision"]
    worker_operations: tuple[Mapping[str, JsonValue], ...]
    restore_revision: str | None


@dataclass(frozen=True, slots=True)
class _ImpactExpectation:
    kind: Literal["rename", "comment", "type", "patch", "import_il2cpp_bundle"]
    patch_size: int | None = None
    bundle_sha256: str | None = None


def validate_local_sources(
    arguments: ChangePrepareInput,
    context: ChangeContext,
) -> tuple[ValidatedIl2CppSource, ...]:
    """验证 prepare 引用的本地 bundle 与 metadata, 且不产生持久状态。"""

    _validate_context(arguments, context)
    if arguments.inverse_of_change_id is not None:
        return ()

    validated: list[ValidatedIl2CppSource] = []
    for operation_index, operation in enumerate(arguments.operations):
        if not isinstance(operation, ImportIl2CppBundleOperation):
            continue
        if context.native is None:
            raise ChangeSourceError("IL2CPP import 需要完整 native binding 上下文")
        metadata_path, metadata_sha256, metadata_size = _validate_source_file(
            operation.metadata_path,
            operation.metadata_sha256,
            "metadata",
        )
        bundle_path, bundle_sha256, bundle_size = _validate_source_file(
            operation.bundle_path,
            operation.bundle_sha256,
            "bundle",
        )
        try:
            bundle = parse_il2cpp_bundle(
                bundle_path,
                context.native.model_dump(mode="python"),
                {"sha256": metadata_sha256, "size": metadata_size},
            )
        except (BundleValidationError, OSError) as error:
            raise ChangeSourceError("IL2CPP bundle 未通过当前 canonical 契约验证") from error
        if bundle.sha256 != bundle_sha256:
            raise ChangeSourceError("IL2CPP bundle 解析内容与声明摘要不一致")
        type_ids = frozenset(record.id for record in bundle.types)
        unresolved = {resolution.type_id for resolution in operation.type_resolutions} - type_ids
        if unresolved:
            raise ChangeSourceError("type_resolutions 引用了 bundle 外类型")
        validated.append(
            ValidatedIl2CppSource(
                operation_index=operation_index,
                bundle_path=bundle_path,
                bundle_sha256=bundle_sha256,
                bundle_size=bundle_size,
                metadata_path=metadata_path,
                metadata_sha256=metadata_sha256,
                metadata_size=metadata_size,
                record_count=bundle.record_count,
                type_ids=type_ids,
            )
        )
    return tuple(validated)


def source_solidification_requests(
    sources: Sequence[ValidatedIl2CppSource],
) -> tuple[SourceSolidificationRequest, ...]:
    """按操作位置和角色生成确定顺序的 ArtifactStore 写入请求。"""

    requests: list[SourceSolidificationRequest] = []
    for source in sorted(sources, key=lambda item: item.operation_index):
        requests.extend(
            (
                SourceSolidificationRequest(
                    operation_index=source.operation_index,
                    role="bundle",
                    source=source.bundle_path,
                    expected_sha256=source.bundle_sha256,
                    size=source.bundle_size,
                    media_type=IL2CPP_MEDIA_TYPE,
                    name=f"il2cpp-{source.operation_index}.ndjson",
                ),
                SourceSolidificationRequest(
                    operation_index=source.operation_index,
                    role="metadata",
                    source=source.metadata_path,
                    expected_sha256=source.metadata_sha256,
                    size=source.metadata_size,
                    media_type=_METADATA_MEDIA_TYPE,
                    name=f"il2cpp-{source.operation_index}.metadata",
                ),
            )
        )
    return tuple(requests)


def build_canonical_plan(
    arguments: ChangePrepareInput,
    context: ChangeContext,
    *,
    validated_sources: Sequence[ValidatedIl2CppSource] = (),
    solidified_sources: Sequence[SolidifiedSource] = (),
    inverse_source: InverseSource | None = None,
) -> CanonicalChangePlan:
    """把公共 prepare 输入转换为不含本地路径的不可变计划。"""

    _validate_context(arguments, context)
    preimage = build_revision_preimage(context)
    if arguments.inverse_of_change_id is not None:
        if validated_sources or solidified_sources:
            raise ChangeAdapterInputError("inverse prepare 不接受本地 source")
        if inverse_source is None:
            raise ChangeAdapterInputError("inverse prepare 缺少 source change 身份")
        _validate_inverse_source(arguments, context, inverse_source)
        restore = StoredRestoreRevisionOperation(
            kind="restore_revision",
            restore_revision=inverse_source.parent_revision,
            source_change_id=inverse_source.change_id,
        )
        return CanonicalChangePlan((restore,), preimage, inverse_source.change_id)

    if inverse_source is not None:
        raise ChangeAdapterInputError("普通 prepare 不接受 inverse source")
    validated_by_index = _unique_by_index(validated_sources, "validated_sources")
    solidified_by_key = _unique_solidified(solidified_sources)
    expected_import_indexes = {
        index
        for index, operation in enumerate(arguments.operations)
        if isinstance(operation, ImportIl2CppBundleOperation)
    }
    if set(validated_by_index) != expected_import_indexes:
        raise ChangeAdapterInputError("validated_sources 与 IL2CPP 操作集合不一致")
    expected_solidified = {
        (index, role) for index in expected_import_indexes for role in _SOURCE_ROLES
    }
    if set(solidified_by_key) != expected_solidified:
        raise ChangeAdapterInputError("solidified_sources 与 IL2CPP 操作集合不一致")

    stored: list[StoredChangeOperation] = []
    for index, operation in enumerate(arguments.operations):
        if isinstance(operation, RenameOperation):
            _validate_target(operation.target, context)
            stored.append(
                StoredRenameOperation(
                    kind="rename",
                    target=operation.target,
                    expected_name=operation.expected_name,
                    new_name=operation.new_name,
                )
            )
        elif isinstance(operation, CommentOperation):
            _validate_target(operation.target, context)
            stored.append(
                StoredCommentOperation(
                    kind="comment",
                    target=operation.target,
                    placement=operation.placement,
                    expected_text=operation.expected_text,
                    text=operation.text,
                )
            )
        elif isinstance(operation, SetTypeOperation):
            _validate_target(operation.target, context)
            _type_declaration(operation.type_ref, context.base_revision)
            stored.append(
                StoredSetTypeOperation(
                    kind="set_type",
                    target=operation.target,
                    type_ref=operation.type_ref,
                )
            )
        elif isinstance(operation, PatchBytesOperation):
            _validate_target(operation.target, context)
            stored.append(
                StoredPatchBytesOperation(
                    kind="patch_bytes",
                    target=operation.target,
                    expected_bytes=operation.expected_bytes,
                    replacement_bytes=operation.replacement_bytes,
                )
            )
        else:
            if context.native is None:
                raise ChangeAdapterInputError("IL2CPP import 缺少 native binding")
            source = validated_by_index[index]
            bundle_artifact = solidified_by_key[(index, "bundle")]
            metadata_artifact = solidified_by_key[(index, "metadata")]
            _validate_solidified_source(
                bundle_artifact,
                source.bundle_sha256,
                source.bundle_size,
                context,
            )
            _validate_solidified_source(
                metadata_artifact,
                source.metadata_sha256,
                source.metadata_size,
                context,
            )
            resolutions = tuple(
                StoredIl2CppTypeResolution(
                    type_id=resolution.type_id,
                    action=resolution.action,
                )
                for resolution in sorted(
                    operation.type_resolutions,
                    key=lambda item: item.type_id,
                )
            )
            stored.append(
                StoredImportIl2CppBundleOperation(
                    kind="import_il2cpp_bundle",
                    bundle_artifact_uri=bundle_artifact.artifact_uri,
                    bundle_sha256=bundle_artifact.content_sha256,
                    bundle_size=bundle_artifact.size,
                    metadata_artifact_uri=metadata_artifact.artifact_uri,
                    metadata_sha256=metadata_artifact.content_sha256,
                    metadata_size=metadata_artifact.size,
                    expected_native=context.native,
                    type_resolutions=resolutions,
                )
            )
    return CanonicalChangePlan(tuple(stored), preimage, None)


def build_revision_preimage(context: ChangeContext) -> RevisionPreimage:
    """从可信 revision snapshot 上下文构造完整 preimage。"""

    return RevisionPreimage(
        revision=context.base_revision,
        database_sha256=context.database_sha256,
        component_hashes=dict(context.component_hashes),
    )


def build_preflight_execution(
    arguments: ChangePrepareInput,
    context: ChangeContext,
    validated_sources: Sequence[ValidatedIl2CppSource] = (),
) -> MutationExecution:
    """在固化 artifact 前使用已验证本地输入构造 staging 预检请求。"""

    _validate_context(arguments, context)
    if arguments.inverse_of_change_id is not None:
        raise ChangeAdapterInputError("inverse prepare 使用 revision restore, 不运行 mutation 预检")
    validated_by_index = _unique_by_index(validated_sources, "validated_sources")
    expected_import_indexes = {
        index
        for index, operation in enumerate(arguments.operations)
        if isinstance(operation, ImportIl2CppBundleOperation)
    }
    if set(validated_by_index) != expected_import_indexes:
        raise ChangeAdapterInputError("validated_sources 与 IL2CPP 操作集合不一致")

    worker_operations: list[Mapping[str, JsonValue]] = []
    for index, operation in enumerate(arguments.operations):
        if isinstance(operation, RenameOperation):
            value: dict[str, JsonValue] = {
                "kind": "rename",
                "address": _worker_address(operation.target, context),
                "name": operation.new_name,
            }
            if operation.expected_name is not None:
                value["expected_name"] = operation.expected_name
            worker_operations.append(value)
        elif isinstance(operation, CommentOperation):
            value = {
                "kind": "comment",
                "address": _worker_address(operation.target, context),
                "text": operation.text,
                "repeatable": operation.placement == "repeatable",
            }
            if operation.expected_text is not None:
                value["expected_text"] = operation.expected_text
            worker_operations.append(value)
        elif isinstance(operation, SetTypeOperation):
            worker_operations.append(
                {
                    "kind": "type",
                    "address": _worker_address(operation.target, context),
                    "declaration": _type_declaration(
                        operation.type_ref,
                        context.base_revision,
                    ),
                }
            )
        elif isinstance(operation, PatchBytesOperation):
            worker_operations.append(
                {
                    "kind": "patch",
                    "address": _worker_address(operation.target, context),
                    "bytes_hex": operation.replacement_bytes,
                    "expected_bytes_hex": operation.expected_bytes,
                }
            )
        else:
            if context.native is None:
                raise ChangeAdapterInputError("IL2CPP import 缺少 native binding")
            source = validated_by_index[index]
            _verify_validated_source(source)
            worker_operations.append(
                {
                    "kind": "import_il2cpp_bundle",
                    "path": str(source.bundle_path),
                    "expected_native": cast(
                        JsonValue,
                        context.native.model_dump(mode="json"),
                    ),
                    "expected_metadata": {
                        "sha256": source.metadata_sha256,
                        "size": source.metadata_size,
                    },
                    "type_resolutions": {
                        resolution.type_id: resolution.action
                        for resolution in sorted(
                            operation.type_resolutions,
                            key=lambda item: item.type_id,
                        )
                    },
                }
            )
    return MutationExecution("worker", tuple(worker_operations), None)


def build_mutation_execution(
    operations: Sequence[StoredChangeOperation],
    context: ChangeContext,
    *,
    artifacts: Sequence[ArtifactMaterialization] = (),
) -> MutationExecution:
    """将 canonical 计划映射成 worker JSON 或明确的 revision restore。"""

    if len(operations) == 1 and isinstance(operations[0], StoredRestoreRevisionOperation):
        if artifacts:
            raise ChangeAdapterInputError("restore_revision 不接受 artifact materialization")
        return MutationExecution("restore_revision", (), operations[0].restore_revision)
    if any(isinstance(operation, StoredRestoreRevisionOperation) for operation in operations):
        raise ChangeAdapterInputError("restore_revision 不得与 worker mutation 混合")

    materialized = _unique_materializations(artifacts)
    required_uris = {
        uri
        for operation in operations
        if isinstance(operation, StoredImportIl2CppBundleOperation)
        for uri in (operation.bundle_artifact_uri, operation.metadata_artifact_uri)
    }
    if set(materialized) != required_uris:
        raise ChangeAdapterInputError("artifact materialization 与计划引用集合不一致")

    worker_operations: list[Mapping[str, JsonValue]] = []
    for operation in operations:
        if isinstance(operation, StoredRenameOperation):
            value: dict[str, JsonValue] = {
                "kind": "rename",
                "address": _worker_address(operation.target, context),
                "name": operation.new_name,
            }
            if operation.expected_name is not None:
                value["expected_name"] = operation.expected_name
            worker_operations.append(value)
        elif isinstance(operation, StoredCommentOperation):
            value = {
                "kind": "comment",
                "address": _worker_address(operation.target, context),
                "text": operation.text,
                "repeatable": operation.placement == "repeatable",
            }
            if operation.expected_text is not None:
                value["expected_text"] = operation.expected_text
            worker_operations.append(value)
        elif isinstance(operation, StoredSetTypeOperation):
            worker_operations.append(
                {
                    "kind": "type",
                    "address": _worker_address(operation.target, context),
                    "declaration": _type_declaration(
                        operation.type_ref,
                        context.base_revision,
                    ),
                }
            )
        elif isinstance(operation, StoredPatchBytesOperation):
            worker_operations.append(
                {
                    "kind": "patch",
                    "address": _worker_address(operation.target, context),
                    "bytes_hex": operation.replacement_bytes,
                    "expected_bytes_hex": operation.expected_bytes,
                }
            )
        elif isinstance(operation, StoredImportIl2CppBundleOperation):
            if context.native is None or operation.expected_native != context.native:
                raise ChangeAdapterInputError("IL2CPP 计划的 native binding 与当前 revision 不一致")
            bundle = materialized[operation.bundle_artifact_uri]
            metadata = materialized[operation.metadata_artifact_uri]
            _verify_materialization(
                bundle,
                expected_sha256=operation.bundle_sha256,
                expected_size=operation.bundle_size,
            )
            _verify_materialization(
                metadata,
                expected_sha256=operation.metadata_sha256,
                expected_size=operation.metadata_size,
            )
            worker_operations.append(
                {
                    "kind": "import_il2cpp_bundle",
                    "path": str(bundle.path),
                    "expected_native": cast(
                        JsonValue,
                        operation.expected_native.model_dump(mode="json"),
                    ),
                    "expected_metadata": {
                        "sha256": operation.metadata_sha256,
                        "size": operation.metadata_size,
                    },
                    "type_resolutions": {
                        resolution.type_id: resolution.action
                        for resolution in operation.type_resolutions
                    },
                }
            )
        else:
            raise AssertionError(type(operation))
    return MutationExecution("worker", tuple(worker_operations), None)


def parse_worker_impact(
    operations: Sequence[StoredChangeOperation],
    raw_result: Mapping[str, object],
) -> ChangeImpact:
    """严格校验 mutation 回读结果并生成公共 impact。"""

    if any(isinstance(operation, StoredRestoreRevisionOperation) for operation in operations):
        raise ChangeAdapterInputError("restore_revision 不产生 MutationWorker impact")
    expectations: list[_ImpactExpectation] = []
    for operation in operations:
        if isinstance(operation, StoredPatchBytesOperation):
            expectations.append(
                _ImpactExpectation("patch", patch_size=len(operation.replacement_bytes) // 2)
            )
        elif isinstance(operation, StoredImportIl2CppBundleOperation):
            expectations.append(
                _ImpactExpectation(
                    "import_il2cpp_bundle",
                    bundle_sha256=operation.bundle_sha256,
                )
            )
        elif isinstance(operation, StoredRenameOperation):
            expectations.append(_ImpactExpectation("rename"))
        elif isinstance(operation, StoredCommentOperation):
            expectations.append(_ImpactExpectation("comment"))
        else:
            expectations.append(_ImpactExpectation("type"))
    return _parse_impact(expectations, raw_result)


def parse_preflight_impact(
    arguments: ChangePrepareInput,
    validated_sources: Sequence[ValidatedIl2CppSource],
    raw_result: Mapping[str, object],
) -> ChangeImpact:
    """验证预检结果, 包括 worker 实际读取的 bundle 内容摘要。"""

    if arguments.inverse_of_change_id is not None:
        raise ChangeAdapterInputError("inverse prepare 不产生 MutationWorker impact")
    validated_by_index = _unique_by_index(validated_sources, "validated_sources")
    expected_import_indexes = {
        index
        for index, operation in enumerate(arguments.operations)
        if isinstance(operation, ImportIl2CppBundleOperation)
    }
    if set(validated_by_index) != expected_import_indexes:
        raise ChangeAdapterInputError("validated_sources 与 IL2CPP 操作集合不一致")
    expectations: list[_ImpactExpectation] = []
    for index, operation in enumerate(arguments.operations):
        if isinstance(operation, PatchBytesOperation):
            expectations.append(
                _ImpactExpectation("patch", patch_size=len(operation.replacement_bytes) // 2)
            )
        elif isinstance(operation, ImportIl2CppBundleOperation):
            expectations.append(
                _ImpactExpectation(
                    "import_il2cpp_bundle",
                    bundle_sha256=validated_by_index[index].bundle_sha256,
                )
            )
        elif isinstance(operation, RenameOperation):
            expectations.append(_ImpactExpectation("rename"))
        elif isinstance(operation, CommentOperation):
            expectations.append(_ImpactExpectation("comment"))
        else:
            expectations.append(_ImpactExpectation("type"))
    return _parse_impact(expectations, raw_result)


def _parse_impact(
    expectations: Sequence[_ImpactExpectation],
    raw_result: Mapping[str, object],
) -> ChangeImpact:
    try:
        result = _MUTATION_RESULT_ADAPTER.validate_python(raw_result, strict=True)
    except ValidationError as error:
        raise ChangeAdapterResultError("MutationWorker 结果不符合严格契约") from error
    if len(result.operations) != len(expectations):
        raise ChangeAdapterResultError("MutationWorker 返回的操作数量不匹配")

    renamed = 0
    comments = 0
    types = 0
    patched = 0
    imported = 0
    conflicts: list[ChangeConflict] = []
    for index, (expectation, applied) in enumerate(
        zip(expectations, result.operations, strict=True)
    ):
        if applied.kind != expectation.kind:
            raise ChangeAdapterResultError("MutationWorker 返回的操作顺序或 kind 不匹配")
        if isinstance(applied, _AppliedRename):
            renamed += 1
        elif isinstance(applied, _AppliedComment):
            comments += 1
        elif isinstance(applied, _AppliedType):
            types += 1
        elif isinstance(applied, _AppliedPatch):
            if applied.size != expectation.patch_size:
                raise ChangeAdapterResultError("patch impact 字节数与计划不匹配")
            patched += applied.size
        else:
            if applied.bundle_sha256 != expectation.bundle_sha256:
                raise ChangeAdapterResultError("worker 实际读取的 bundle SHA-256 与计划不匹配")
            types += applied.types_applied + applied.symbols_typed
            imported += applied.symbols_named
            for conflict in applied.name_conflicts:
                conflicts.append(
                    ChangeConflict(
                        kind="user_name_preserved",
                        operation_index=index,
                        source_id=conflict.symbol_id,
                        address=conflict.address,
                        existing_value=conflict.existing_name,
                    )
                )
    return ChangeImpact(
        renamed_entities=renamed,
        comments_changed=comments,
        types_changed=types,
        patched_bytes=patched,
        imported_symbols=imported,
        conflicts=conflicts,
    )


def _validate_context(arguments: ChangePrepareInput, context: ChangeContext) -> None:
    if (
        arguments.workspace_id != context.workspace_id
        or arguments.base_revision != context.base_revision
    ):
        raise ChangeAdapterInputError("ChangeContext 与 prepare 的 workspace/base_revision 不一致")


def _validate_inverse_source(
    arguments: ChangePrepareInput,
    context: ChangeContext,
    source: InverseSource,
) -> None:
    if (
        source.workspace_id != context.workspace_id
        or source.change_id != arguments.inverse_of_change_id
        or source.applied_revision != context.base_revision
    ):
        raise ChangeAdapterInputError("inverse 只允许撤销当前 base HEAD 对应的 source change")


def _validate_source_file(
    raw_path: str,
    expected_sha256: str,
    label: str,
) -> tuple[Path, str, int]:
    source = Path(raw_path)
    if not source.is_absolute():
        raise ChangeSourceError(f"{label}_path 必须是绝对路径")
    try:
        resolved = source.resolve(strict=True)
        before = resolved.stat()
    except OSError as error:
        raise ChangeSourceError(f"{label}_path 不可读") from error
    if not resolved.is_file():
        raise ChangeSourceError(f"{label}_path 必须是普通文件")
    try:
        actual_sha256 = sha256_file(resolved)
        after = resolved.stat()
    except OSError as error:
        raise ChangeSourceError(f"{label}_path 读取失败") from error
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or actual_sha256 != expected_sha256
    ):
        raise ChangeSourceError(f"{label} 内容摘要不匹配或读取期间发生变化")
    if after.st_size < 1:
        raise ChangeSourceError(f"{label} 文件不能为空")
    return resolved, actual_sha256, after.st_size


def _validate_target(target: RevisionAddress, context: ChangeContext) -> None:
    if isinstance(target, ImageAddress) and target.image_id != context.image_id:
        raise ChangeAdapterInputError("image address 不属于 prepare 对应镜像")


def _worker_address(
    target: RevisionAddress,
    context: ChangeContext,
) -> dict[str, JsonValue]:
    _validate_target(target, context)
    if isinstance(target, ImageAddress):
        return {"space": "image", "rva": target.rva}
    return {"space": "database", "ea": target.ea}


def _validate_solidified_source(
    source: SolidifiedSource,
    expected_sha256: str,
    expected_size: int,
    context: ChangeContext,
) -> None:
    try:
        workspace_id, revision, _ = parse_artifact_uri(source.artifact_uri)
    except ValueError as error:
        raise ChangeAdapterInputError("solidified artifact URI 无效") from error
    if workspace_id != context.workspace_id or revision != context.base_revision:
        raise ChangeAdapterInputError("solidified artifact 不属于 prepare workspace/revision")
    if source.content_sha256 != expected_sha256 or source.size != expected_size:
        raise ChangeAdapterInputError("solidified artifact 身份与已验证 source 不一致")


def _unique_by_index(
    sources: Sequence[ValidatedIl2CppSource],
    label: str,
) -> dict[int, ValidatedIl2CppSource]:
    result: dict[int, ValidatedIl2CppSource] = {}
    for source in sources:
        if source.operation_index in result:
            raise ChangeAdapterInputError(f"{label} 包含重复 operation_index")
        result[source.operation_index] = source
    return result


def _unique_solidified(
    sources: Sequence[SolidifiedSource],
) -> dict[tuple[int, SourceRole], SolidifiedSource]:
    result: dict[tuple[int, SourceRole], SolidifiedSource] = {}
    for source in sources:
        key = (source.operation_index, source.role)
        if key in result:
            raise ChangeAdapterInputError("solidified_sources 包含重复操作角色")
        result[key] = source
    return result


def _unique_materializations(
    artifacts: Sequence[ArtifactMaterialization],
) -> dict[str, ArtifactMaterialization]:
    result: dict[str, ArtifactMaterialization] = {}
    for artifact in artifacts:
        if artifact.artifact_uri in result:
            raise ChangeAdapterInputError("artifact materialization URI 重复")
        result[artifact.artifact_uri] = artifact
    return result


def _verify_materialization(
    artifact: ArtifactMaterialization,
    *,
    expected_sha256: str,
    expected_size: int,
) -> None:
    try:
        path = artifact.path.resolve(strict=True)
        size = path.stat().st_size
        digest = sha256_file(path)
    except OSError as error:
        raise ChangeSourceError("artifact materialization 不可读") from error
    if (
        artifact.content_sha256 != expected_sha256
        or artifact.size != expected_size
        or size != expected_size
        or digest != expected_sha256
    ):
        raise ChangeSourceError("artifact materialization 身份校验失败")


def _verify_validated_source(source: ValidatedIl2CppSource) -> None:
    bundle_path, bundle_sha256, bundle_size = _validate_source_file(
        str(source.bundle_path),
        source.bundle_sha256,
        "bundle",
    )
    metadata_path, metadata_sha256, metadata_size = _validate_source_file(
        str(source.metadata_path),
        source.metadata_sha256,
        "metadata",
    )
    if (
        bundle_path != source.bundle_path
        or bundle_sha256 != source.bundle_sha256
        or bundle_size != source.bundle_size
        or metadata_path != source.metadata_path
        or metadata_sha256 != source.metadata_sha256
        or metadata_size != source.metadata_size
    ):
        raise ChangeSourceError("已验证 IL2CPP source 身份发生变化")


def _type_declaration(type_ref: CanonicalTypeRef, revision: str) -> str:
    declaration = _render_type(type_ref, "__ida_re_value", revision) + ";"
    if len(declaration.encode("utf-8")) > 16_384:
        raise ChangeAdapterInputError("set_type 展开后的声明超过 16 KiB")
    return declaration


def _render_type(type_ref: CanonicalTypeRef, declarator: str, revision: str) -> str:
    if isinstance(type_ref, PrimitiveTypeRef):
        base = {
            "void": "void",
            "bool": "bool",
            "i8": "__int8",
            "u8": "unsigned __int8",
            "i16": "__int16",
            "u16": "unsigned __int16",
            "i32": "__int32",
            "u32": "unsigned __int32",
            "i64": "__int64",
            "u64": "unsigned __int64",
            "f32": "float",
            "f64": "double",
        }[type_ref.name]
        return f"{base} {declarator}".strip()
    if isinstance(type_ref, NamedTypeRef):
        return f"{_decode_named_type(type_ref.type_id, revision)} {declarator}".strip()
    if isinstance(type_ref, PointerTypeRef):
        pointer = f"*{declarator}"
        if isinstance(type_ref.to, (ArrayTypeRef, FunctionTypeRef)):
            pointer = f"({pointer})"
        if type_ref.pointee_const:
            return _render_const_base(type_ref.to, pointer, revision)
        return _render_type(type_ref.to, pointer, revision)
    if isinstance(type_ref, ArrayTypeRef):
        if isinstance(type_ref.element, FunctionTypeRef) or (
            isinstance(type_ref.element, PrimitiveTypeRef) and type_ref.element.name == "void"
        ):
            raise ChangeAdapterInputError("array element 必须是完整对象类型")
        return _render_type(type_ref.element, f"{declarator}[{type_ref.count}]", revision)
    if isinstance(type_ref.return_type, (ArrayTypeRef, FunctionTypeRef)):
        raise ChangeAdapterInputError("function return_type 不得是 array 或 function")
    if type_ref.variadic and not type_ref.parameters:
        raise ChangeAdapterInputError("variadic function 至少需要一个固定参数")
    parameters = [
        _render_type(
            parameter.type,
            parameter.name or f"arg_{index}",
            revision,
        )
        for index, parameter in enumerate(type_ref.parameters)
    ]
    if type_ref.variadic:
        parameters.append("...")
    elif not parameters:
        parameters.append("void")
    convention = {
        "default": "",
        "cdecl": "__cdecl ",
        "stdcall": "__stdcall ",
        "fastcall": "__fastcall ",
    }[type_ref.calling_convention]
    function_declarator = f"{convention}{declarator}({', '.join(parameters)})"
    return _render_type(type_ref.return_type, function_declarator, revision)


def _render_const_base(type_ref: CanonicalTypeRef, declarator: str, revision: str) -> str:
    if isinstance(type_ref, PrimitiveTypeRef):
        rendered = _render_type(type_ref, declarator, revision)
    elif isinstance(type_ref, NamedTypeRef):
        rendered = _render_type(type_ref, declarator, revision)
    else:
        raise ChangeAdapterInputError("pointee_const 的 target 类型不可表示")
    return f"const {rendered}"


def _decode_named_type(type_id: str, revision: str) -> str:
    parts = type_id.split("~")
    expected_tag = hashlib.sha256(revision.encode("utf-8")).hexdigest()[:16]
    if len(parts) != 4 or parts[:2] != ["entity", "tn"] or parts[2] != expected_tag:
        raise ChangeAdapterInputError("named type_id 不属于 prepare base_revision")
    encoded = parts[3]
    try:
        padded = encoded + ("=" * (-len(encoded) % 4))
        name = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError, binascii.Error) as error:
        raise ChangeAdapterInputError("named type_id 编码无效") from error
    if _TYPE_NAME.fullmatch(name) is None:
        raise ChangeAdapterInputError("named type 无法无损映射为 IDA 类型声明")
    canonical = base64.urlsafe_b64encode(name.encode("utf-8")).decode("ascii").rstrip("=")
    if canonical != encoded:
        raise ChangeAdapterInputError("named type_id 不是 canonical 编码")
    return name


type _RecordTypeId = Annotated[
    str,
    StringConstraints(pattern=r"^type_[0-9a-f]{64}$", strict=True),
]


class _AppliedRename(StrictModel):
    kind: Literal["rename"]
    address: U64Hex


class _AppliedComment(StrictModel):
    kind: Literal["comment"]
    address: U64Hex


class _AppliedType(StrictModel):
    kind: Literal["type"]
    address: U64Hex


class _AppliedPatch(StrictModel):
    kind: Literal["patch"]
    address: U64Hex
    size: int = Field(ge=1)


class _NameConflict(StrictModel):
    symbol_id: str = Field(min_length=1, max_length=256)
    address: U64Hex
    existing_name: str = Field(max_length=1_024)


class _AppliedIl2Cpp(StrictModel):
    kind: Literal["import_il2cpp_bundle"]
    bundle_sha256: Sha256
    types_applied: int = Field(ge=0)
    types_kept: list[_RecordTypeId]
    symbols_named: int = Field(ge=0)
    symbols_typed: int = Field(ge=0)
    name_conflicts: list[_NameConflict]


type _AppliedOperation = Annotated[
    _AppliedRename | _AppliedComment | _AppliedType | _AppliedPatch | _AppliedIl2Cpp,
    Field(discriminator="kind"),
]


class _MutationResult(StrictModel):
    staging_path: str
    staging_sha256: Sha256
    operations: list[_AppliedOperation]
    cold_verification_required: Literal[True]
    saved: Literal[True]


_MUTATION_RESULT_ADAPTER: TypeAdapter[_MutationResult] = TypeAdapter(_MutationResult)
