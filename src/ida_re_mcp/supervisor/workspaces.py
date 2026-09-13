"""Workspace、冷 revision 与 staging 原子发布。"""

from __future__ import annotations

import hashlib
import math
import os
import shutil
import stat
import threading
import time
import uuid
from collections.abc import Callable, Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from ida_re_mcp.constants import (
    DEFAULT_RETAINED_REVISIONS,
    OPERATION_RETENTION_SECONDS,
    STORAGE_SCHEMA_VERSION,
)
from ida_re_mcp.supervisor._fs import (
    atomic_write_json,
    sha256_file,
    validate_identifier,
    validate_sha256,
)
from ida_re_mcp.supervisor._process_lock import (
    InterprocessFileLock,
    interprocess_file_lock,
)
from ida_re_mcp.supervisor.errors import (
    AnalysisRetryUnavailableError,
    InvalidIdentifierError,
    RevisionConflictError,
    RevisionNotFoundError,
    StagingIntegrityError,
    StorageCorruptionError,
    WorkspaceNotFoundError,
)

_DATABASE_NAME = "database.i64"
_WORKSPACE_MANIFEST_NAME = "workspace.json"
_REVISION_MANIFEST_NAME = "revision.json"
_STAGING_MANIFEST_NAME = "stage.json"
_SAMPLE_NAME = "sample.bin"


class ImageIdentity(BaseModel):
    """冷验证已证明的原生镜像身份, 随 revision manifest 一并持久化。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    container: Literal["elf", "pe"]
    architecture: Literal["x86", "x86_64", "arm", "aarch64"]
    bitness: Literal[32, 64]
    endian: Literal["little"]
    image_size: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_architecture_bitness(self) -> Self:
        expected = {
            "x86": 32,
            "x86_64": 64,
            "arm": 32,
            "aarch64": 64,
        }
        if self.bitness != expected[self.architecture]:
            raise ValueError("architecture 与 bitness 不匹配")
        if self.container == "pe" and self.architecture not in {"x86", "x86_64"}:
            raise ValueError("PE architecture 必须是 x86 或 x86_64")
        return self


class _LegacyImageIdentity(BaseModel):
    """缺少 container 的中间版本身份; 只用于严格读取与冲突检测。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    architecture: Literal["x86_64", "aarch64"]
    bitness: Literal[64]
    endian: Literal["little"]
    image_size: int = Field(ge=1)


class AnalysisOutcome(BaseModel):
    """首次分析的持久化终态; 位于共享 workspace manifest, 跨会话可见。"""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    state: Literal["failed", "cancelled"]
    reason: str = Field(min_length=1, max_length=2_048)
    recorded_at: float = Field(ge=0, allow_inf_nan=False)


@dataclass(frozen=True, slots=True)
class ColdValidationReceipt:
    """worker 冷启动验证后返回、由 Supervisor 复核的内容摘要。"""

    validator: str
    component_hashes: Mapping[str, str]
    image_identity: ImageIdentity

    @classmethod
    def create(
        cls,
        *,
        validator: str,
        component_hashes: Mapping[str, str],
        image_identity: ImageIdentity,
    ) -> ColdValidationReceipt:
        validate_identifier(validator, field="validator")
        checked = _validate_component_hashes(component_hashes)
        return cls(
            validator=validator,
            component_hashes=MappingProxyType(checked),
            image_identity=_strict_image_identity(image_identity),
        )


@dataclass(frozen=True, slots=True)
class RevisionSnapshot:
    """已发布冷 revision。"""

    workspace_id: str
    revision: str
    parent_revision: str | None
    created_at: float
    database_sha256: str
    component_hashes: Mapping[str, str]
    validator: str
    change_id: str | None
    operation_id: str | None
    operation_result: Mapping[str, JsonValue] | None
    pinned: bool
    path: Path
    image_identity: ImageIdentity | None = None
    legacy_image_identity: _LegacyImageIdentity | None = None

    @property
    def database_path(self) -> Path:
        return self.path / _DATABASE_NAME


@dataclass(frozen=True, slots=True)
class WorkspaceSnapshot:
    """Workspace manifest 的不可变公开快照。"""

    workspace_id: str
    sample_name: str
    sample_sha256: str
    sample_size: int
    created_at: float
    current_revision: str | None
    sample_path: Path
    revisions: tuple[RevisionSnapshot, ...]
    analysis_outcome: AnalysisOutcome | None = None


@dataclass(frozen=True, slots=True)
class RevisionStaging:
    """尚未发布、仅供一个 Mutation/Analysis worker 使用的 staging。"""

    workspace_id: str
    staging_id: str
    candidate_revision: str
    expected_revision: str | None
    source_revision: str | None
    path: Path

    @property
    def database_path(self) -> Path:
        return self.path / _DATABASE_NAME


@dataclass(frozen=True, slots=True)
class RevisionCheckout:
    """Analysis/Debug worker 使用的可丢弃私有 checkout。"""

    workspace_id: str
    revision: str
    checkout_id: str
    purpose: str
    path: Path

    @property
    def database_path(self) -> Path:
        return self.path / _DATABASE_NAME


@dataclass(frozen=True, slots=True)
class GarbageCollectionResult:
    """显式垃圾回收结果。"""

    dry_run: bool
    removed_paths: tuple[Path, ...]
    reclaimed_bytes: int
    skipped_workspace_ids: tuple[str, ...]


class _WorkspaceManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1"]
    workspace_id: str
    sample_name: str
    sample_sha256: str
    sample_size: int
    created_at: float
    current_revision: str | None
    revision_ids: list[str]
    pinned_revisions: list[str]
    # 可选; 记录首次分析的持久化失败/取消终态, 供 workspace.list 跨会话诚实报告状态.
    analysis_outcome: AnalysisOutcome | None = None


class _RevisionManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1"]
    workspace_id: str
    revision: str
    parent_revision: str | None
    created_at: float
    database_sha256: str
    component_hashes: dict[str, str]
    validator: str
    change_id: str | None
    operation_id: str | None
    operation_result: dict[str, JsonValue] | None
    # 可选; 旧 manifest 可完全缺失身份, 中间版本也可能只缺 container.
    image_identity: ImageIdentity | _LegacyImageIdentity | None = None

    @model_validator(mode="after")
    def validate_operation_commit(self) -> Self:
        if (self.operation_id is None) != (self.operation_result is None):
            raise ValueError("operation_id 与 operation_result 必须同时存在")
        if self.operation_result is not None and (
            self.operation_result.get("workspace_id") != self.workspace_id
            or self.operation_result.get("revision") != self.revision
        ):
            raise ValueError("operation_result 必须绑定当前 workspace/revision")
        return self


class _StagingManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1"]
    workspace_id: str
    staging_id: str
    candidate_revision: str
    expected_revision: str | None
    source_revision: str | None


class WorkspaceRegistry:
    """线程与进程安全的 workspace registry 与 revision 发布器。"""

    def __init__(
        self,
        root: Path,
        *,
        checkout_root: Path | None = None,
        retained_revisions: int = DEFAULT_RETAINED_REVISIONS,
    ) -> None:
        if isinstance(retained_revisions, bool) or retained_revisions < 0:
            raise ValueError("retained_revisions 必须为非负整数")
        self.root = root.resolve()
        self.checkout_root = (
            checkout_root.resolve()
            if checkout_root is not None
            else (self.root.parent / "checkouts").resolve()
        )
        self.root.mkdir(parents=True, exist_ok=True)
        self.checkout_root.mkdir(parents=True, exist_ok=True)
        (self.root / ".creating").mkdir(exist_ok=True)
        self._lock_root = (self.root / ".locks").resolve()
        self._lock_root.mkdir(exist_ok=True)
        self._retained_revisions = retained_revisions
        self._locks_guard = threading.RLock()
        self._workspace_locks: dict[str, InterprocessFileLock] = {}
        self._active_creating: set[Path] = set()
        self._active_staging: set[Path] = set()
        self._active_checkouts: set[Path] = set()
        self._sample_identities: dict[str, tuple[int, int, int, int, str]] = {}

    @property
    def lease_root(self) -> Path:
        """跨进程 worker lifecycle lease 的私有目录。"""

        return self._lock_root

    def create(
        self,
        sample: Path,
        *,
        validate_copy: Callable[[Path, str, int], None] | None = None,
    ) -> WorkspaceSnapshot:
        """复制并哈希原样本; 源路径永远不会被写入。"""

        source = sample.resolve(strict=True)
        if not source.is_file():
            raise ValueError(f"样本不是普通文件: {source}")
        before = source.stat()
        workspace_id = f"ws_{uuid.uuid4().hex}"
        creating = self.root / ".creating" / workspace_id
        final = self.root / workspace_id
        creation_lease = self.workspace_lease_lock(workspace_id)
        if not creation_lease.try_acquire():
            raise StorageCorruptionError("新 workspace 的生命周期 lease 被意外占用")
        try:
            creating.mkdir(parents=False, exist_ok=False)
            with self._locks_guard:
                self._active_creating.add(creating)
            try:
                candidate = creating / _SAMPLE_NAME
                copied_sha256, copied_size = _copy_sample(source, candidate)
                after = source.stat()
                if (
                    copied_size != before.st_size
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                    or before.st_ctime_ns != after.st_ctime_ns
                    or before.st_ino != after.st_ino
                ):
                    raise StorageCorruptionError("原样本在复制期间发生变化")
                candidate_before_validation = candidate.stat()
                if validate_copy is not None:
                    validate_copy(candidate, copied_sha256, copied_size)
                candidate_after_validation = candidate.stat()
                if (
                    candidate_after_validation.st_size != copied_size
                    or candidate_before_validation.st_size != candidate_after_validation.st_size
                    or candidate_before_validation.st_mtime_ns
                    != candidate_after_validation.st_mtime_ns
                    or candidate_before_validation.st_ctime_ns
                    != candidate_after_validation.st_ctime_ns
                    or candidate_before_validation.st_ino != candidate_after_validation.st_ino
                    or sha256_file(candidate) != copied_sha256
                ):
                    raise StorageCorruptionError("workspace 候选样本在验证期间发生变化")
                sample_name = _validate_sample_name(source.name)
                manifest = _WorkspaceManifest(
                    schema_version=STORAGE_SCHEMA_VERSION,
                    workspace_id=workspace_id,
                    sample_name=sample_name,
                    sample_sha256=copied_sha256,
                    sample_size=copied_size,
                    created_at=time.time(),
                    current_revision=None,
                    revision_ids=[],
                    pinned_revisions=[],
                )
                atomic_write_json(
                    creating / _WORKSPACE_MANIFEST_NAME,
                    _workspace_dict(manifest),
                )
                snapshot = WorkspaceSnapshot(
                    workspace_id=workspace_id,
                    sample_name=sample_name,
                    sample_sha256=copied_sha256,
                    sample_size=copied_size,
                    created_at=manifest.created_at,
                    current_revision=None,
                    sample_path=final / _SAMPLE_NAME,
                    revisions=(),
                )
                os.replace(creating, final)
            except BaseException:
                _safe_remove_tree(creating, parent=self.root / ".creating")
                raise
            finally:
                with self._locks_guard:
                    self._active_creating.discard(creating)
        finally:
            creation_lease.release()
        return snapshot

    def list(self) -> tuple[WorkspaceSnapshot, ...]:
        snapshots: list[WorkspaceSnapshot] = []
        for path in sorted(self.root.iterdir(), key=lambda item: item.name):
            try:
                mode = path.lstat().st_mode
            except FileNotFoundError:
                continue
            if path.name in {".creating", ".locks"}:
                if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                    raise StorageCorruptionError("workspace 私有目录类型无效")
                continue
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode) or not path.name.startswith("ws_"):
                raise StorageCorruptionError("workspace 根目录包含非法条目")
            lease = self.workspace_lease_lock(path.name)
            lease_acquired = lease.try_acquire()
            try:
                if not path.exists():
                    continue
                try:
                    snapshots.append(self.get(path.name))
                except WorkspaceNotFoundError as exc:
                    if path.exists():
                        raise StorageCorruptionError(
                            f"workspace manifest 缺失: {path.name}"
                        ) from exc
            finally:
                if lease_acquired:
                    lease.release()
        return tuple(snapshots)

    def get(self, workspace_id: str) -> WorkspaceSnapshot:
        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        lock = self._lock_for(workspace_id)
        with lock:
            manifest = self._read_workspace_manifest(workspace_id)
            return self._workspace_snapshot(manifest)

    def discard_uninitialized(self, workspace_id: str) -> None:
        """删除尚未发布任何 revision 的失败 workspace。"""

        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        lock = self._lock_for(workspace_id)
        with lock:
            manifest = self._read_workspace_manifest(workspace_id)
            if manifest.current_revision is not None or manifest.revision_ids:
                raise StorageCorruptionError("不得删除已发布 revision 的 workspace")
            workspace_path = self._workspace_path(workspace_id)
            with self._locks_guard:
                if any(
                    path == workspace_path or workspace_path in path.parents
                    for path in (*self._active_staging, *self._active_checkouts)
                ):
                    raise StorageCorruptionError("不得删除仍有活动 worker 的 workspace")
            _safe_remove_tree(workspace_path, parent=self.root)
            with self._locks_guard:
                self._sample_identities.pop(workspace_id, None)

    def record_analysis_outcome(
        self,
        workspace_id: str,
        *,
        state: Literal["failed", "cancelled"],
        reason: str,
    ) -> None:
        """把首次分析的持久化终态写入共享 workspace manifest。

        已发布 revision 的 workspace 视为成功, 不接受失败/取消标记。
        """

        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        clean_reason = reason.strip()[:2_048] or state
        lock = self._lock_for(workspace_id)
        with lock:
            manifest = self._read_workspace_manifest(workspace_id)
            if manifest.current_revision is not None:
                return
            outcome = AnalysisOutcome(
                state=state,
                reason=clean_reason,
                recorded_at=time.time(),
            )
            next_manifest = manifest.model_copy(update={"analysis_outcome": outcome})
            self._commit_manifest(workspace_id, next_manifest)

    def prepare_analysis_retry(
        self,
        workspace_id: str,
        *,
        expected_outcome: AnalysisOutcome,
    ) -> WorkspaceSnapshot:
        """校验失败终态未变化，清除它并返回可重新分析的样本快照。"""

        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        lock = self._lock_for(workspace_id)
        with lock:
            manifest = self._read_workspace_manifest(workspace_id)
            if manifest.current_revision is not None or manifest.revision_ids:
                raise AnalysisRetryUnavailableError("已有 revision 的 workspace 不能重试首次分析")
            if manifest.analysis_outcome is None:
                raise AnalysisRetryUnavailableError("workspace 没有可重试的首次分析失败终态")
            if manifest.analysis_outcome != expected_outcome:
                raise AnalysisRetryUnavailableError("workspace 的首次分析状态已经变化")
            next_manifest = manifest.model_copy(update={"analysis_outcome": None})
            self._commit_manifest(workspace_id, next_manifest)
            return self._workspace_snapshot(next_manifest)

    def get_revision(self, workspace_id: str, revision: str) -> RevisionSnapshot:
        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        revision = validate_identifier(revision, field="revision")
        lock = self._lock_for(workspace_id)
        with lock:
            manifest = self._read_workspace_manifest(workspace_id)
            if revision not in manifest.revision_ids:
                raise RevisionNotFoundError(f"revision 不存在: {revision}")
            return self._revision_snapshot(
                workspace_id,
                revision,
                pinned=revision in manifest.pinned_revisions,
            )

    def committed_operation_result(
        self,
        workspace_id: str,
        operation_id: str,
    ) -> dict[str, JsonValue] | None:
        """从已发布 revision 的提交凭据恢复长操作成功结果。"""

        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        operation_id = validate_identifier(operation_id, field="operation_id")
        lock = self._lock_for(workspace_id)
        with lock:
            manifest = self._read_workspace_manifest(workspace_id)
            matched_result: dict[str, JsonValue] | None = None
            for revision in reversed(manifest.revision_ids):
                revision_manifest = self._read_revision_manifest(
                    workspace_id,
                    revision,
                )
                if revision_manifest.operation_id == operation_id:
                    result = revision_manifest.operation_result
                    if result is None:
                        raise StorageCorruptionError("revision operation 提交凭据缺少结果")
                    if matched_result is not None:
                        raise StorageCorruptionError("operation_id 被多个 revision 提交凭据引用")
                    matched_result = dict(result)
            return matched_result

    @contextmanager
    def workspace_lock(self, workspace_id: str) -> Generator[None]:
        """为跨 worker 编排提供同一 workspace 的串行临界区。"""

        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        lock = self._lock_for(workspace_id)
        with lock:
            self._read_workspace_manifest(workspace_id)
            yield

    def workspace_lease_lock(self, workspace_id: str) -> InterprocessFileLock:
        """返回覆盖完整 worker 生命周期的 workspace 独占锁。"""

        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        return interprocess_file_lock(
            self._lock_root / f"{workspace_id}.lease.lock",
        )

    def begin_staging(
        self,
        workspace_id: str,
        *,
        expected_revision: str | None,
        source_revision: str | None = None,
    ) -> RevisionStaging:
        """以 expected revision 做 CAS, 并从指定冷 revision 建立同卷 staging。"""

        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        if expected_revision is not None:
            validate_identifier(expected_revision, field="expected_revision")
        if source_revision is not None:
            validate_identifier(source_revision, field="source_revision")
        elif expected_revision is not None:
            source_revision = expected_revision
        if expected_revision is None and source_revision is not None:
            raise ValueError("初始化 staging 不得指定 source_revision")
        lock = self._lock_for(workspace_id)
        with lock:
            manifest = self._read_workspace_manifest(workspace_id)
            self._check_revision_cas(manifest, expected_revision)
            if source_revision is not None and source_revision not in manifest.revision_ids:
                raise RevisionNotFoundError(f"revision 不存在: {source_revision}")
            staging_id = f"stg_{uuid.uuid4().hex}"
            candidate_revision = f"rev_{uuid.uuid4().hex}"
            staging_root = self._workspace_path(workspace_id) / ".staging"
            staging_root.mkdir(exist_ok=True)
            path = staging_root / staging_id
            if source_revision is None:
                path.mkdir()
            else:
                self._revision_snapshot(
                    workspace_id,
                    source_revision,
                    pinned=source_revision in manifest.pinned_revisions,
                    verify_payload=True,
                )
                source = self._revision_path(workspace_id, source_revision)
                if not source.is_dir():
                    raise RevisionNotFoundError(f"revision 内容缺失: {source_revision}")
                shutil.copytree(source, path, copy_function=shutil.copyfile)
                (path / _REVISION_MANIFEST_NAME).unlink(missing_ok=True)

            stage_manifest = _StagingManifest(
                schema_version=STORAGE_SCHEMA_VERSION,
                workspace_id=workspace_id,
                staging_id=staging_id,
                candidate_revision=candidate_revision,
                expected_revision=expected_revision,
                source_revision=source_revision,
            )
            atomic_write_json(path / _STAGING_MANIFEST_NAME, _staging_dict(stage_manifest))
            staging = RevisionStaging(
                workspace_id=workspace_id,
                staging_id=staging_id,
                candidate_revision=candidate_revision,
                expected_revision=expected_revision,
                source_revision=source_revision,
                path=path,
            )
            with self._locks_guard:
                self._active_staging.add(path)
            return staging

    def publish_staging(
        self,
        staging: RevisionStaging,
        *,
        receipt: ColdValidationReceipt,
        change_id: str | None = None,
        operation_id: str | None = None,
        operation_result: Mapping[str, JsonValue] | None = None,
    ) -> RevisionSnapshot:
        """复核冷验证摘要并 CAS 发布；失败清理以已写入的 manifest 为准。"""

        try:
            return self._publish_staging_once(
                staging,
                receipt=receipt,
                change_id=change_id,
                operation_id=operation_id,
                operation_result=operation_result,
            )
        except BaseException:
            self._discard_failed_staging(staging)
            raise

    def _publish_staging_once(
        self,
        staging: RevisionStaging,
        *,
        receipt: ColdValidationReceipt,
        change_id: str | None,
        operation_id: str | None,
        operation_result: Mapping[str, JsonValue] | None,
    ) -> RevisionSnapshot:
        image_identity = _strict_image_identity(receipt.image_identity)
        if change_id is not None:
            validate_identifier(change_id, field="change_id")
        if operation_id is not None:
            validate_identifier(operation_id, field="operation_id")
        workspace_id = validate_identifier(staging.workspace_id, field="workspace_id")
        expected_staging_path = self._workspace_path(workspace_id) / ".staging" / staging.staging_id
        if (
            staging.path != expected_staging_path
            or staging.path.is_symlink()
            or not staging.path.is_dir()
        ):
            raise StagingIntegrityError("staging 路径与 workspace 身份不一致")
        lock = self._lock_for(workspace_id)
        with lock:
            manifest = self._read_workspace_manifest(workspace_id)
            self._check_revision_cas(manifest, staging.expected_revision)
            stage_manifest = self._read_staging_manifest(staging.path)
            _verify_staging_handle(staging, stage_manifest)
            if not staging.database_path.is_file():
                raise StagingIntegrityError(f"staging 缺少 {_DATABASE_NAME}")

            expected_hashes = _validate_component_hashes(receipt.component_hashes)
            validate_identifier(receipt.validator, field="validator")
            actual_hashes = _hash_payload(staging.path)
            if actual_hashes != expected_hashes:
                raise StagingIntegrityError("staging 内容与冷验证摘要不一致")
            database_sha256 = actual_hashes[_DATABASE_NAME]

            revision_manifest = _RevisionManifest(
                schema_version=STORAGE_SCHEMA_VERSION,
                workspace_id=workspace_id,
                revision=staging.candidate_revision,
                parent_revision=staging.expected_revision,
                created_at=time.time(),
                database_sha256=database_sha256,
                component_hashes=actual_hashes,
                validator=receipt.validator,
                change_id=change_id,
                operation_id=operation_id,
                operation_result=(dict(operation_result) if operation_result is not None else None),
                image_identity=image_identity,
            )
            for revision in manifest.revision_ids:
                existing_revision = self._read_revision_manifest(workspace_id, revision)
                if operation_id is not None and existing_revision.operation_id == operation_id:
                    raise StagingIntegrityError("operation_id 已被其他 revision 提交")
            atomic_write_json(
                staging.path / _REVISION_MANIFEST_NAME,
                _revision_dict(revision_manifest),
            )
            (staging.path / _STAGING_MANIFEST_NAME).unlink(missing_ok=False)
            target = self._revision_path(workspace_id, staging.candidate_revision)
            target.parent.mkdir(exist_ok=True)
            try:
                os.replace(staging.path, target)
                if _hash_payload(target) != expected_hashes:
                    raise StagingIntegrityError("revision 移动后内容摘要发生变化")

                revision_ids = [*manifest.revision_ids, staging.candidate_revision]
                keep = _retained_revision_ids(
                    revision_ids=revision_ids,
                    current_revision=staging.candidate_revision,
                    pinned_revisions=set(manifest.pinned_revisions),
                    historical_limit=self._retained_revisions,
                )
                next_manifest = manifest.model_copy(
                    update={
                        "current_revision": staging.candidate_revision,
                        "revision_ids": [revision for revision in revision_ids if revision in keep],
                        "analysis_outcome": None,
                    }
                )
                published = RevisionSnapshot(
                    workspace_id=workspace_id,
                    revision=revision_manifest.revision,
                    parent_revision=revision_manifest.parent_revision,
                    created_at=revision_manifest.created_at,
                    database_sha256=revision_manifest.database_sha256,
                    component_hashes=MappingProxyType(dict(revision_manifest.component_hashes)),
                    validator=revision_manifest.validator,
                    change_id=revision_manifest.change_id,
                    operation_id=revision_manifest.operation_id,
                    operation_result=(
                        MappingProxyType(dict(revision_manifest.operation_result))
                        if revision_manifest.operation_result is not None
                        else None
                    ),
                    pinned=False,
                    path=target,
                    image_identity=image_identity,
                )
                self._commit_manifest(workspace_id, next_manifest)
            finally:
                with self._locks_guard:
                    self._active_staging.discard(staging.path)

            # manifest CAS 是发布的唯一提交点。提交后不再执行可能失败的删除;
            # 已不可达 revision 由显式 GC 在相同 workspace lease 下回收。
            return published

    def _discard_failed_staging(self, staging: RevisionStaging) -> None:
        """依据持久化 manifest 清理未提交的候选，保留已被引用的 revision。"""

        workspace_id = validate_identifier(staging.workspace_id, field="workspace_id")
        lock = self._lock_for(workspace_id)
        with lock:
            manifest = self._read_workspace_manifest(workspace_id)
            if staging.path.exists():
                _safe_remove_tree(
                    staging.path,
                    parent=self._workspace_path(workspace_id) / ".staging",
                )
            target = self._revision_path(workspace_id, staging.candidate_revision)
            if target.exists() and staging.candidate_revision not in manifest.revision_ids:
                _safe_remove_tree(
                    target,
                    parent=self._workspace_path(workspace_id) / "revisions",
                )
            with self._locks_guard:
                self._active_staging.discard(staging.path)

    def abort_staging(self, staging: RevisionStaging) -> None:
        workspace_id = validate_identifier(staging.workspace_id, field="workspace_id")
        lock = self._lock_for(workspace_id)
        with lock:
            if staging.path.exists():
                stage_manifest = self._read_staging_manifest(staging.path)
                _verify_staging_handle(staging, stage_manifest)
                _safe_remove_tree(
                    staging.path,
                    parent=self._workspace_path(workspace_id) / ".staging",
                )
            with self._locks_guard:
                self._active_staging.discard(staging.path)

    def create_checkout(
        self,
        workspace_id: str,
        revision: str,
        *,
        purpose: str,
    ) -> RevisionCheckout:
        """创建 worker 私有、可写、永不回写冷 revision 的 checkout。"""

        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        revision = validate_identifier(revision, field="revision")
        purpose = validate_identifier(purpose, field="purpose")
        lock = self._lock_for(workspace_id)
        with lock:
            self.get_revision(workspace_id, revision)
            checkout_id = f"chk_{uuid.uuid4().hex}"
            parent = self.checkout_root / workspace_id
            parent.mkdir(parents=True, exist_ok=True)
            path = parent / checkout_id
            shutil.copytree(
                self._revision_path(workspace_id, revision),
                path,
                copy_function=shutil.copyfile,
            )
            (path / _REVISION_MANIFEST_NAME).unlink(missing_ok=True)
            checkout = RevisionCheckout(
                workspace_id=workspace_id,
                revision=revision,
                checkout_id=checkout_id,
                purpose=purpose,
                path=path,
            )
            with self._locks_guard:
                self._active_checkouts.add(path)
            return checkout

    def discard_checkout(self, checkout: RevisionCheckout) -> None:
        validate_identifier(checkout.workspace_id, field="workspace_id")
        validate_identifier(checkout.checkout_id, field="checkout_id")
        parent = self.checkout_root / checkout.workspace_id
        if checkout.path.exists():
            _safe_remove_tree(checkout.path, parent=parent)
        with self._locks_guard:
            self._active_checkouts.discard(checkout.path)

    def pin_revision(
        self,
        workspace_id: str,
        revision: str,
        *,
        pinned: bool = True,
    ) -> WorkspaceSnapshot:
        workspace_id = validate_identifier(workspace_id, field="workspace_id")
        revision = validate_identifier(revision, field="revision")
        lock = self._lock_for(workspace_id)
        with lock:
            manifest = self._read_workspace_manifest(workspace_id)
            if revision not in manifest.revision_ids:
                raise RevisionNotFoundError(f"revision 不存在: {revision}")
            pins = set(manifest.pinned_revisions)
            if pinned:
                pins.add(revision)
            else:
                pins.discard(revision)
            if manifest.current_revision is None:
                raise StorageCorruptionError("包含 revision 的 workspace 缺少 HEAD")
            keep = _retained_revision_ids(
                revision_ids=manifest.revision_ids,
                current_revision=manifest.current_revision,
                pinned_revisions=pins,
                historical_limit=self._retained_revisions,
            )
            retained_ids = [candidate for candidate in manifest.revision_ids if candidate in keep]
            next_manifest = manifest.model_copy(
                update={
                    "revision_ids": retained_ids,
                    "pinned_revisions": sorted(pins),
                }
            )
            snapshot = self._workspace_snapshot(next_manifest)
            self._commit_manifest(workspace_id, next_manifest)
            # pin 的 manifest 更新同样是唯一提交点, 物理清理由显式 GC 完成。
            return snapshot

    def collect_garbage(
        self,
        *,
        workspace_id: str | None = None,
        dry_run: bool = True,
    ) -> GarbageCollectionResult:
        """回收未被 manifest 引用且当前进程未使用的 staging/revision/checkout。"""

        if workspace_id is None:
            workspace_ids: list[str] = []
            for path in sorted(self.root.iterdir(), key=lambda item: item.name):
                try:
                    mode = path.lstat().st_mode
                except FileNotFoundError:
                    continue
                if path.name in {".creating", ".locks"}:
                    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                        raise StorageCorruptionError("workspace 私有目录类型无效")
                    continue
                if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode) or not path.name.startswith("ws_"):
                    raise StorageCorruptionError("workspace 根目录包含非法条目")
                workspace_ids.append(validate_identifier(path.name, field="workspace_id"))
        else:
            workspace_ids = [validate_identifier(workspace_id, field="workspace_id")]
        candidates: list[Path] = []
        skipped: list[str] = []
        reclaimed = 0

        if workspace_id is None:
            creating_root = self.root / ".creating"
            with self._locks_guard:
                active_creating = set(self._active_creating)
            for path in sorted(creating_root.iterdir(), key=lambda item: item.name):
                try:
                    mode = path.lstat().st_mode
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode) or not path.name.startswith("ws_"):
                    raise StorageCorruptionError("workspace creating 根目录包含非法条目")
                if path in active_creating:
                    skipped.append(path.name)
                    continue
                creation_lease = self.workspace_lease_lock(path.name)
                if not creation_lease.try_acquire():
                    skipped.append(path.name)
                    continue
                try:
                    try:
                        mode = path.lstat().st_mode
                    except FileNotFoundError:
                        continue
                    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                        raise StorageCorruptionError("workspace creating 根目录包含非法条目")
                    candidates.append(path)
                    reclaimed += _tree_size(path)
                    if not dry_run:
                        _safe_remove_tree(path, parent=creating_root)
                finally:
                    creation_lease.release()

        for current_workspace_id in workspace_ids:
            lease = self.workspace_lease_lock(current_workspace_id)
            if not lease.try_acquire():
                skipped.append(current_workspace_id)
                continue
            try:
                workspace_candidates: list[Path] = []
                lock = self._lock_for(current_workspace_id)
                with lock:
                    try:
                        manifest = self._read_workspace_manifest(current_workspace_id)
                    except WorkspaceNotFoundError:
                        # 另一进程可能已在本轮预扫描后完成同一 workspace 的 GC。
                        continue
                    workspace_path = self._workspace_path(current_workspace_id)
                    orphan_uninitialized = (
                        manifest.current_revision is None
                        and not manifest.revision_ids
                        and time.time() - manifest.created_at >= OPERATION_RETENTION_SECONDS
                    )
                    if orphan_uninitialized:
                        workspace_candidates.append(workspace_path)
                    else:
                        referenced = set(manifest.revision_ids)
                        revision_root = workspace_path / "revisions"
                        if revision_root.exists():
                            if revision_root.is_symlink() or not revision_root.is_dir():
                                raise StorageCorruptionError("revision 根目录类型无效")
                            for path in revision_root.iterdir():
                                if (
                                    path.is_symlink()
                                    or not path.is_dir()
                                    or not path.name.startswith("rev_")
                                ):
                                    raise StorageCorruptionError("revision 根目录包含非法条目")
                                validate_identifier(path.name, field="revision")
                                if path.name not in referenced:
                                    workspace_candidates.append(path)
                        staging_root = workspace_path / ".staging"
                        if staging_root.exists():
                            if staging_root.is_symlink() or not staging_root.is_dir():
                                raise StorageCorruptionError("staging 根目录类型无效")
                            with self._locks_guard:
                                active_staging = set(self._active_staging)
                            for path in staging_root.iterdir():
                                if (
                                    path.is_symlink()
                                    or not path.is_dir()
                                    or not path.name.startswith("stg_")
                                ):
                                    raise StorageCorruptionError("staging 根目录包含非法条目")
                                validate_identifier(path.name, field="staging_id")
                                if path not in active_staging:
                                    workspace_candidates.append(path)
                        checkout_parent = self.checkout_root / current_workspace_id
                        if checkout_parent.exists():
                            if checkout_parent.is_symlink() or not checkout_parent.is_dir():
                                raise StorageCorruptionError("checkout workspace 目录类型无效")
                            with self._locks_guard:
                                active_checkouts = set(self._active_checkouts)
                            for path in checkout_parent.iterdir():
                                if (
                                    path.is_symlink()
                                    or not path.is_dir()
                                    or not path.name.startswith("chk_")
                                ):
                                    raise StorageCorruptionError(
                                        "checkout workspace 目录包含非法条目"
                                    )
                                validate_identifier(path.name, field="checkout_id")
                                if path not in active_checkouts:
                                    workspace_candidates.append(path)
                workspace_candidates = sorted(set(workspace_candidates), key=str)
                candidates.extend(workspace_candidates)
                reclaimed += sum(_tree_size(path) for path in workspace_candidates)
                if not dry_run:
                    for candidate in workspace_candidates:
                        parent = (
                            self.root
                            if candidate == self._workspace_path(current_workspace_id)
                            else _allowed_gc_parent(
                                candidate,
                                workspace_root=self.root,
                                checkout_root=self.checkout_root,
                            )
                        )
                        _safe_remove_tree(candidate, parent=parent)
                    if orphan_uninitialized:
                        with self._locks_guard:
                            self._sample_identities.pop(current_workspace_id, None)
            finally:
                lease.release()

        unique_candidates = tuple(sorted(set(candidates), key=str))
        return GarbageCollectionResult(
            dry_run=dry_run,
            removed_paths=unique_candidates,
            reclaimed_bytes=reclaimed,
            skipped_workspace_ids=tuple(skipped),
        )

    def _read_workspace_manifest(self, workspace_id: str) -> _WorkspaceManifest:
        workspace_path = self._workspace_path(workspace_id)
        if (
            workspace_path.is_symlink()
            or not workspace_path.is_dir()
            or workspace_path.resolve(strict=True).parent != self.root
        ):
            raise WorkspaceNotFoundError(f"workspace 不存在: {workspace_id}")
        path = workspace_path / _WORKSPACE_MANIFEST_NAME
        if not path.is_file():
            raise WorkspaceNotFoundError(f"workspace 不存在: {workspace_id}")
        try:
            manifest = _WorkspaceManifest.model_validate_json(path.read_bytes(), strict=True)
            _validate_workspace_manifest(manifest, workspace_id)
            self._validate_workspace_sample(workspace_path, manifest)
        except StorageCorruptionError:
            raise
        except (InvalidIdentifierError, OSError, ValidationError, ValueError) as exc:
            raise StorageCorruptionError(f"workspace manifest 损坏: {workspace_id}") from exc
        return manifest

    def _validate_workspace_sample(
        self,
        workspace_path: Path,
        manifest: _WorkspaceManifest,
    ) -> None:
        sample_path = workspace_path / _SAMPLE_NAME
        if sample_path.is_symlink() or not sample_path.is_file():
            raise StorageCorruptionError("workspace 原样本缺失或路径类型无效")
        stat = sample_path.stat()
        identity = (
            stat.st_size,
            stat.st_mtime_ns,
            stat.st_ctime_ns,
            stat.st_ino,
        )
        with self._locks_guard:
            cached = self._sample_identities.get(manifest.workspace_id)
        if (
            cached is not None
            and cached[:4] == identity
            and cached[4] == manifest.sample_sha256
            and stat.st_size == manifest.sample_size
        ):
            return
        if (
            stat.st_size != manifest.sample_size
            or sha256_file(sample_path) != manifest.sample_sha256
        ):
            raise StorageCorruptionError("workspace 原样本摘要校验失败")
        with self._locks_guard:
            self._sample_identities[manifest.workspace_id] = (*identity, manifest.sample_sha256)

    def _workspace_snapshot(self, manifest: _WorkspaceManifest) -> WorkspaceSnapshot:
        sample_path = self._workspace_path(manifest.workspace_id) / _SAMPLE_NAME
        revisions = tuple(
            self._revision_snapshot(
                manifest.workspace_id,
                revision,
                pinned=revision in manifest.pinned_revisions,
                verify_payload=False,
            )
            for revision in manifest.revision_ids
        )
        return WorkspaceSnapshot(
            workspace_id=manifest.workspace_id,
            sample_name=manifest.sample_name,
            sample_sha256=manifest.sample_sha256,
            sample_size=manifest.sample_size,
            created_at=manifest.created_at,
            current_revision=manifest.current_revision,
            sample_path=sample_path,
            revisions=revisions,
            analysis_outcome=manifest.analysis_outcome,
        )

    def _read_staging_manifest(self, path: Path) -> _StagingManifest:
        manifest_path = path / _STAGING_MANIFEST_NAME
        if not manifest_path.is_file():
            raise StagingIntegrityError("staging manifest 缺失")
        try:
            return _StagingManifest.model_validate_json(
                manifest_path.read_bytes(),
                strict=True,
            )
        except (OSError, ValidationError) as exc:
            raise StagingIntegrityError("staging manifest 损坏") from exc

    def _revision_snapshot(
        self,
        workspace_id: str,
        revision: str,
        *,
        pinned: bool,
        verify_payload: bool = True,
    ) -> RevisionSnapshot:
        path = self._revision_path(workspace_id, revision)
        manifest = self._read_revision_manifest(workspace_id, revision)
        if verify_payload:
            actual_hashes = _hash_payload(path)
            if actual_hashes != manifest.component_hashes:
                raise StorageCorruptionError(f"revision 内容摘要校验失败: {revision}")
        image_identity = manifest.image_identity
        return RevisionSnapshot(
            workspace_id=workspace_id,
            revision=revision,
            parent_revision=manifest.parent_revision,
            created_at=manifest.created_at,
            database_sha256=manifest.database_sha256,
            component_hashes=MappingProxyType(dict(manifest.component_hashes)),
            validator=manifest.validator,
            change_id=manifest.change_id,
            operation_id=manifest.operation_id,
            operation_result=(
                MappingProxyType(dict(manifest.operation_result))
                if manifest.operation_result is not None
                else None
            ),
            pinned=pinned,
            path=path,
            image_identity=(image_identity if isinstance(image_identity, ImageIdentity) else None),
            legacy_image_identity=(
                image_identity if isinstance(image_identity, _LegacyImageIdentity) else None
            ),
        )

    def _read_revision_manifest(
        self,
        workspace_id: str,
        revision: str,
    ) -> _RevisionManifest:
        path = self._revision_path(workspace_id, revision)
        revisions_root = self._workspace_path(workspace_id) / "revisions"
        if (
            path.is_symlink()
            or not path.is_dir()
            or path.resolve(strict=True).parent != revisions_root.resolve(strict=True)
        ):
            raise RevisionNotFoundError(f"revision 内容不存在: {revision}")
        manifest_path = path / _REVISION_MANIFEST_NAME
        if not manifest_path.is_file():
            raise RevisionNotFoundError(f"revision 内容不存在: {revision}")
        try:
            manifest = _RevisionManifest.model_validate_json(
                manifest_path.read_bytes(),
                strict=True,
            )
            _validate_revision_manifest(manifest, workspace_id, revision)
        except StorageCorruptionError:
            raise
        except (InvalidIdentifierError, OSError, ValidationError, ValueError) as exc:
            raise StorageCorruptionError(f"revision manifest 损坏: {revision}") from exc
        return manifest

    def _commit_manifest(
        self,
        workspace_id: str,
        manifest: _WorkspaceManifest,
    ) -> None:
        atomic_write_json(
            self._workspace_path(workspace_id) / _WORKSPACE_MANIFEST_NAME,
            _workspace_dict(manifest),
        )

    @staticmethod
    def _check_revision_cas(
        manifest: _WorkspaceManifest,
        expected_revision: str | None,
    ) -> None:
        if manifest.current_revision != expected_revision:
            raise RevisionConflictError("expected_revision 与 workspace 当前 revision 不一致")

    def _lock_for(self, workspace_id: str) -> InterprocessFileLock:
        with self._locks_guard:
            return self._workspace_locks.setdefault(
                workspace_id,
                interprocess_file_lock(self._lock_root / f"{workspace_id}.lock"),
            )

    def _workspace_path(self, workspace_id: str) -> Path:
        return self.root / workspace_id

    def _revision_path(self, workspace_id: str, revision: str) -> Path:
        return self._workspace_path(workspace_id) / "revisions" / revision


def hash_staging_payload(staging: RevisionStaging) -> Mapping[str, str]:
    """供 worker 冷验证完成后生成提交摘要。"""

    return MappingProxyType(_hash_payload(staging.path))


def _copy_sample(source: Path, target: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                output_stream.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            output_stream.flush()
            os.fsync(output_stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return digest.hexdigest(), size


def _hash_payload(path: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for candidate in sorted(path.rglob("*"), key=lambda item: item.as_posix()):
        if candidate.name in {_STAGING_MANIFEST_NAME, _REVISION_MANIFEST_NAME}:
            continue
        if candidate.is_symlink():
            raise StagingIntegrityError("revision payload 不得包含符号链接")
        if candidate.is_dir():
            continue
        if not candidate.is_file():
            raise StagingIntegrityError("revision payload 只能包含普通文件")
        relative = candidate.relative_to(path).as_posix()
        hashes[relative] = sha256_file(candidate)
    if _DATABASE_NAME not in hashes:
        raise StagingIntegrityError(f"revision payload 缺少 {_DATABASE_NAME}")
    return hashes


def _validate_component_hashes(values: Mapping[str, str]) -> dict[str, str]:
    checked: dict[str, str] = {}
    for relative, digest in values.items():
        candidate = Path(relative)
        if (
            not relative
            or candidate.is_absolute()
            or ".." in candidate.parts
            or "\\" in relative
            or relative in {_STAGING_MANIFEST_NAME, _REVISION_MANIFEST_NAME}
        ):
            raise StagingIntegrityError("component_hashes 包含非法相对路径")
        checked[relative] = validate_sha256(digest, field=f"component_hashes[{relative}]")
    if _DATABASE_NAME not in checked:
        raise StagingIntegrityError(f"component_hashes 缺少 {_DATABASE_NAME}")
    return checked


def _strict_image_identity(value: object) -> ImageIdentity:
    """从普通字段重新严格构造身份, 拒绝 model_construct 等绕过路径。"""

    ordinary = value.model_dump(mode="python") if isinstance(value, ImageIdentity) else value
    return ImageIdentity.model_validate(ordinary, strict=True)


def _validate_workspace_manifest(
    manifest: _WorkspaceManifest,
    workspace_id: str,
) -> None:
    if manifest.workspace_id != workspace_id:
        raise StorageCorruptionError("workspace manifest 与路径不一致")
    validate_identifier(manifest.workspace_id, field="workspace_id")
    validate_sha256(manifest.sample_sha256, field="sample_sha256")
    _validate_sample_name(manifest.sample_name)
    if (
        isinstance(manifest.sample_size, bool)
        or manifest.sample_size < 0
        or not math.isfinite(manifest.created_at)
        or manifest.created_at < 0
    ):
        raise StorageCorruptionError("workspace 数值字段无效")
    if len(manifest.revision_ids) != len(set(manifest.revision_ids)):
        raise StorageCorruptionError("revision_ids 包含重复项")
    if len(manifest.pinned_revisions) != len(set(manifest.pinned_revisions)):
        raise StorageCorruptionError("pinned_revisions 包含重复项")
    for revision in manifest.revision_ids:
        validate_identifier(revision, field="revision")
    if manifest.current_revision is not None:
        validate_identifier(manifest.current_revision, field="current_revision")
        if manifest.current_revision not in manifest.revision_ids:
            raise StorageCorruptionError("current_revision 未被 manifest 引用")
        if manifest.analysis_outcome is not None:
            raise StorageCorruptionError("已发布 revision 的 workspace 不得携带分析失败终态")
    elif manifest.revision_ids:
        raise StorageCorruptionError("包含 revision 的 workspace 缺少 HEAD")
    if not set(manifest.pinned_revisions).issubset(manifest.revision_ids):
        raise StorageCorruptionError("pinned revision 未被 manifest 引用")


def _validate_revision_manifest(
    manifest: _RevisionManifest,
    workspace_id: str,
    revision: str,
) -> None:
    if manifest.workspace_id != workspace_id or manifest.revision != revision:
        raise StorageCorruptionError("revision manifest 与路径不一致")
    if not math.isfinite(manifest.created_at) or manifest.created_at < 0:
        raise StorageCorruptionError("revision created_at 无效")
    validate_identifier(manifest.workspace_id, field="workspace_id")
    validate_identifier(manifest.revision, field="revision")
    if manifest.parent_revision is not None:
        validate_identifier(manifest.parent_revision, field="parent_revision")
    validate_identifier(manifest.validator, field="validator")
    if manifest.change_id is not None:
        validate_identifier(manifest.change_id, field="change_id")
    if manifest.operation_id is not None:
        validate_identifier(manifest.operation_id, field="operation_id")
        if manifest.operation_result is None:
            raise StorageCorruptionError("revision operation 提交凭据不完整")
    elif manifest.operation_result is not None:
        raise StorageCorruptionError("revision operation 结果缺少 operation_id")
    hashes = _validate_component_hashes(manifest.component_hashes)
    validate_sha256(manifest.database_sha256, field="database_sha256")
    if hashes[_DATABASE_NAME] != manifest.database_sha256:
        raise StorageCorruptionError("database SHA-256 与组件摘要不一致")


def _verify_staging_handle(
    staging: RevisionStaging,
    manifest: _StagingManifest,
) -> None:
    if (
        staging.workspace_id != manifest.workspace_id
        or staging.staging_id != manifest.staging_id
        or staging.candidate_revision != manifest.candidate_revision
        or staging.expected_revision != manifest.expected_revision
        or staging.source_revision != manifest.source_revision
    ):
        raise StagingIntegrityError("staging handle 与 manifest 不一致")


def _retained_revision_ids(
    *,
    revision_ids: list[str],
    current_revision: str,
    pinned_revisions: set[str],
    historical_limit: int,
) -> set[str]:
    historical = [revision for revision in revision_ids if revision != current_revision]
    return {
        current_revision,
        *(historical[-historical_limit:] if historical_limit else ()),
        *pinned_revisions,
    }


def _workspace_dict(manifest: _WorkspaceManifest) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "workspace_id": manifest.workspace_id,
        "sample_name": manifest.sample_name,
        "sample_sha256": manifest.sample_sha256,
        "sample_size": manifest.sample_size,
        "created_at": manifest.created_at,
        "current_revision": manifest.current_revision,
        "revision_ids": manifest.revision_ids,
        "pinned_revisions": manifest.pinned_revisions,
        "analysis_outcome": (
            manifest.analysis_outcome.model_dump(mode="json")
            if manifest.analysis_outcome is not None
            else None
        ),
    }


def _revision_dict(manifest: _RevisionManifest) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "workspace_id": manifest.workspace_id,
        "revision": manifest.revision,
        "parent_revision": manifest.parent_revision,
        "created_at": manifest.created_at,
        "database_sha256": manifest.database_sha256,
        "component_hashes": manifest.component_hashes,
        "validator": manifest.validator,
        "change_id": manifest.change_id,
        "operation_id": manifest.operation_id,
        "operation_result": manifest.operation_result,
        "image_identity": (
            manifest.image_identity.model_dump(mode="json")
            if manifest.image_identity is not None
            else None
        ),
    }


def _staging_dict(manifest: _StagingManifest) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "workspace_id": manifest.workspace_id,
        "staging_id": manifest.staging_id,
        "candidate_revision": manifest.candidate_revision,
        "expected_revision": manifest.expected_revision,
        "source_revision": manifest.source_revision,
    }


def _validate_sample_name(name: str) -> str:
    if not name or len(name) > 255 or any(character in name for character in "\r\n\0"):
        raise ValueError("样本文件名无效")
    return name


def _safe_remove_tree(path: Path, *, parent: Path) -> None:
    if not path.exists():
        return
    resolved = path.resolve()
    parent_resolved = parent.resolve()
    try:
        relative = resolved.relative_to(parent_resolved)
    except ValueError as exc:
        raise StorageCorruptionError(f"拒绝删除存储边界外路径: {resolved}") from exc
    if not relative.parts:
        raise StorageCorruptionError(f"拒绝删除存储根目录: {resolved}")
    shutil.rmtree(resolved)


def _tree_size(path: Path) -> int:
    total = 0
    for candidate in path.rglob("*"):
        if candidate.is_symlink():
            raise StorageCorruptionError("拒绝计算包含 symlink 的 GC 路径")
        if candidate.is_file():
            total += candidate.stat().st_size
        elif not candidate.is_dir():
            raise StorageCorruptionError("GC 路径包含非法文件类型")
    return total


def _allowed_gc_parent(
    candidate: Path,
    *,
    workspace_root: Path,
    checkout_root: Path,
) -> Path:
    resolved = candidate.resolve()
    checkout_resolved = checkout_root.resolve()
    try:
        relative = resolved.relative_to(checkout_resolved)
    except ValueError:
        relative = None
    if relative is not None and len(relative.parts) >= 2:
        return checkout_resolved / relative.parts[0]

    workspace_resolved = workspace_root.resolve()
    try:
        relative = resolved.relative_to(workspace_resolved)
    except ValueError as exc:
        raise StorageCorruptionError(f"GC 候选路径越界: {resolved}") from exc
    if len(relative.parts) < 3:
        raise StorageCorruptionError(f"GC 候选路径层级无效: {resolved}")
    return workspace_resolved / relative.parts[0] / relative.parts[1]
