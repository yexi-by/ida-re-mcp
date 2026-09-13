"""不可变 artifact 内容寻址存储。"""

from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import stat
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import quote, unquote, urlsplit

from pydantic import BaseModel, ConfigDict, ValidationError

from ida_re_mcp.constants import (
    CHUNKED_ARTIFACT_SCHEMA_VERSION,
    RESOURCE_CHUNK_BYTES,
    STORAGE_SCHEMA_VERSION,
)
from ida_re_mcp.supervisor._fs import (
    atomic_write_json,
    canonical_json_bytes,
    sha256_bytes,
    sha256_file,
    validate_identifier,
    validate_sha256,
)
from ida_re_mcp.supervisor._process_lock import InterprocessFileLock, interprocess_file_lock
from ida_re_mcp.supervisor.errors import ArtifactIntegrityError, ArtifactNotFoundError

_BLOB_NAME = "artifact.blob"
_MANIFEST_NAME = "artifact.json"
_STAGING_NAME = ".staging"
_ARTIFACT_DIRECTORY_PATTERN = re.compile(r"^art_[0-9a-f]{64}$")
_STAGING_DIRECTORY_PATTERN = re.compile(r"^\.artifact-[a-z0-9_]{8}$")


@dataclass(frozen=True, slots=True)
class ArtifactMetadata:
    """不可变 artifact 的公开元数据。"""

    workspace_id: str
    revision: str
    artifact_id: str
    content_sha256: str
    size: int
    media_type: str
    name: str | None
    listed: bool
    created_at: float

    @property
    def uri(self) -> str:
        return artifact_uri(self.workspace_id, self.revision, self.artifact_id)


@dataclass(frozen=True, slots=True)
class ArtifactChunk:
    """resource 分块读取结果。"""

    metadata: ArtifactMetadata
    offset: int
    data: bytes
    next_offset: int | None
    eof: bool


@dataclass(frozen=True, slots=True)
class ArtifactFileInput:
    """一次原子文件固化中的一个不可变输入。"""

    workspace_id: str
    revision: str
    source: Path
    media_type: str
    name: str | None = None
    expected_sha256: str | None = None
    expected_size: int | None = None
    listed: bool = True


@dataclass(frozen=True, slots=True)
class ChunkedArtifact:
    """由索引 resource 与独立不可变分块组成的大文件导出。"""

    index: ArtifactMetadata
    chunks: tuple[ArtifactMetadata, ...]
    content_sha256: str
    size: int
    media_type: str
    name: str


@dataclass(frozen=True, slots=True)
class ArtifactGarbageCollectionResult:
    """不可达 artifact revision scope 的回收结果。"""

    dry_run: bool
    removed_paths: tuple[Path, ...]
    reclaimed_bytes: int
    skipped_workspace_ids: tuple[str, ...]


class _ArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["1"]
    workspace_id: str
    revision: str
    artifact_id: str
    content_sha256: str
    size: int
    media_type: str
    name: str | None
    listed: bool
    created_at: float


class ArtifactStore:
    """按 workspace/revision 隔离的不可变 artifact store。"""

    def __init__(
        self,
        root: Path,
        *,
        workspace_lease_root: Path | None = None,
    ) -> None:
        self.root = root.resolve()
        self.workspace_lease_root = (
            workspace_lease_root.resolve() if workspace_lease_root is not None else None
        )
        self.root.mkdir(parents=True, exist_ok=True)
        self._gc_lease_root = self.root / ".gc-locks"
        self._gc_lease_root.mkdir(exist_ok=True)
        self._lock = threading.RLock()

    def resource_read_lock(self, workspace_id: str) -> InterprocessFileLock:
        """返回与 GC 共享的进程锁；完整读取生成文件期间须在同一线程持有。"""

        validate_identifier(workspace_id, field="workspace_id")
        return interprocess_file_lock(self._gc_lease_root / f"{workspace_id}.lease.lock")

    def put_bytes(
        self,
        *,
        workspace_id: str,
        revision: str,
        data: bytes,
        media_type: str,
        name: str | None = None,
        listed: bool = True,
    ) -> ArtifactMetadata:
        workspace_id, revision = _validate_scope(workspace_id, revision)
        _validate_media_type(media_type)
        _validate_name(name)
        content_sha256 = sha256_bytes(data)
        metadata = self._new_metadata(
            workspace_id=workspace_id,
            revision=revision,
            content_sha256=content_sha256,
            size=len(data),
            media_type=media_type,
            name=name,
            listed=listed,
        )
        with self._lock:
            return self._publish_new(
                metadata,
                lambda blob_path: _write_new_blob(blob_path, data),
            )

    def put_file(
        self,
        *,
        workspace_id: str,
        revision: str,
        source: Path,
        media_type: str,
        name: str | None = None,
        listed: bool = True,
    ) -> ArtifactMetadata:
        """流式复制普通文件, 并检测复制期间的源文件变化。"""

        workspace_id, revision = _validate_scope(workspace_id, revision)
        _validate_media_type(media_type)
        _validate_name(name)
        source = source.resolve(strict=True)
        if not source.is_file():
            raise ValueError(f"artifact 源不是普通文件: {source}")
        before = source.stat()
        content_sha256 = sha256_file(source)
        metadata = self._new_metadata(
            workspace_id=workspace_id,
            revision=revision,
            content_sha256=content_sha256,
            size=before.st_size,
            media_type=media_type,
            name=name,
            listed=listed,
        )

        with self._lock:

            def copy_source(blob_path: Path) -> None:
                copied_sha256, copied_size = _copy_new_blob(source, blob_path)
                after = source.stat()
                if (
                    copied_sha256 != content_sha256
                    or copied_size != before.st_size
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                ):
                    raise ArtifactIntegrityError("artifact 源在复制期间发生变化")

            return self._publish_new(metadata, copy_source)

    def put_files_atomic(
        self,
        inputs: tuple[ArtifactFileInput, ...],
    ) -> tuple[ArtifactMetadata, ...]:
        """将一组文件全部固化, 任一失败时撤销本组新建的 artifact。"""

        if not inputs:
            raise ValueError("inputs 不得为空")
        checked_inputs: list[ArtifactFileInput] = []
        for item in inputs:
            workspace_id, revision = _validate_scope(
                item.workspace_id,
                item.revision,
            )
            _validate_media_type(item.media_type)
            _validate_name(item.name)
            expected_sha256 = (
                validate_sha256(item.expected_sha256, field="expected_sha256")
                if item.expected_sha256 is not None
                else None
            )
            if item.expected_size is not None and (
                isinstance(item.expected_size, bool) or item.expected_size < 0
            ):
                raise ValueError("expected_size 必须为非负整数")
            source = item.source.resolve(strict=True)
            if not source.is_file():
                raise ValueError(f"artifact 源不是普通文件: {source}")
            checked_inputs.append(
                ArtifactFileInput(
                    workspace_id=workspace_id,
                    revision=revision,
                    source=source,
                    media_type=item.media_type,
                    name=item.name,
                    expected_sha256=expected_sha256,
                    expected_size=item.expected_size,
                    listed=item.listed,
                )
            )
        results: list[ArtifactMetadata] = []
        created: dict[str, ArtifactMetadata] = {}
        existing_ids: dict[tuple[str, str], set[str]] = {}
        with self._lock:
            try:
                for item in checked_inputs:
                    scope_key = (item.workspace_id, item.revision)
                    scope = self._ensure_scope(*scope_key)
                    known = existing_ids.setdefault(
                        scope_key,
                        {
                            path.name
                            for path in scope.glob("art_*")
                            if path.is_dir() and not path.is_symlink()
                        },
                    )
                    if item.listed:
                        metadata = self.put_file(
                            workspace_id=item.workspace_id,
                            revision=item.revision,
                            source=item.source,
                            media_type=item.media_type,
                            name=item.name,
                        )
                    else:
                        metadata = self.put_file(
                            workspace_id=item.workspace_id,
                            revision=item.revision,
                            source=item.source,
                            media_type=item.media_type,
                            name=item.name,
                            listed=False,
                        )
                    if metadata.artifact_id not in known:
                        created[metadata.uri] = metadata
                        known.add(metadata.artifact_id)
                    if (
                        item.expected_sha256 is not None
                        and metadata.content_sha256 != item.expected_sha256
                    ) or (item.expected_size is not None and metadata.size != item.expected_size):
                        raise ArtifactIntegrityError("artifact 源与预检身份不一致")
                    results.append(metadata)
            except BaseException:
                for metadata in created.values():
                    _remove_artifact_directory(
                        self._artifact_directory(metadata),
                        parent=self._scope(metadata.workspace_id, metadata.revision),
                    )
                raise
        return tuple(results)

    def put_chunked_file(
        self,
        *,
        workspace_id: str,
        revision: str,
        source: Path,
        media_type: str,
        name: str,
    ) -> ChunkedArtifact:
        """把任意大小文件固化为可逐个 ``resources/read`` 的 1 MiB 分块。"""

        workspace_id, revision = _validate_scope(workspace_id, revision)
        _validate_media_type(media_type)
        _validate_name(name)
        source = source.resolve(strict=True)
        if not source.is_file():
            raise ValueError(f"artifact 源不是普通文件: {source}")
        before = source.stat()
        if before.st_size < 1:
            raise ValueError("chunked artifact 源文件不得为空")

        scope = self._ensure_scope(workspace_id, revision)
        chunks: list[ArtifactMetadata] = []
        created: dict[str, ArtifactMetadata] = {}
        existing_ids = {
            path.name for path in scope.glob("art_*") if path.is_dir() and not path.is_symlink()
        }
        digest = hashlib.sha256()
        copied_size = 0
        with self._lock:
            try:
                with source.open("rb") as stream:
                    index = 0
                    while data := stream.read(RESOURCE_CHUNK_BYTES):
                        digest.update(data)
                        copied_size += len(data)
                        chunk = self.put_bytes(
                            workspace_id=workspace_id,
                            revision=revision,
                            data=data,
                            media_type="application/octet-stream",
                            name=f"{name}.part-{index:08d}",
                            listed=False,
                        )
                        if chunk.artifact_id not in existing_ids:
                            created[chunk.uri] = chunk
                            existing_ids.add(chunk.artifact_id)
                        chunks.append(chunk)
                        index += 1
                after = source.stat()
                if (
                    copied_size != before.st_size
                    or before.st_size != after.st_size
                    or before.st_mtime_ns != after.st_mtime_ns
                ):
                    raise ArtifactIntegrityError("chunked artifact 源在读取期间发生变化")
                content_sha256 = digest.hexdigest()
                index_payload = canonical_json_bytes(
                    {
                        "schema_version": CHUNKED_ARTIFACT_SCHEMA_VERSION,
                        "kind": "chunked_artifact",
                        "content": {
                            "media_type": media_type,
                            "name": name,
                            "sha256": content_sha256,
                            "size": copied_size,
                        },
                        "chunks": [
                            {
                                "offset": chunk_index * RESOURCE_CHUNK_BYTES,
                                "sha256": chunk.content_sha256,
                                "size": chunk.size,
                                "uri": chunk.uri,
                            }
                            for chunk_index, chunk in enumerate(chunks)
                        ],
                    }
                )
                index_artifact = self.put_bytes(
                    workspace_id=workspace_id,
                    revision=revision,
                    data=index_payload,
                    media_type="application/vnd.ida-re.chunked-artifact+json",
                    name=f"{name}.index.json",
                )
                if index_artifact.artifact_id not in existing_ids:
                    created[index_artifact.uri] = index_artifact
                    existing_ids.add(index_artifact.artifact_id)
            except BaseException:
                for metadata in created.values():
                    _remove_artifact_directory(
                        self._artifact_directory(metadata),
                        parent=scope,
                    )
                raise
        return ChunkedArtifact(
            index=index_artifact,
            chunks=tuple(chunks),
            content_sha256=content_sha256,
            size=copied_size,
            media_type=media_type,
            name=name,
        )

    def materialize_uri(self, uri: str, target: Path) -> ArtifactMetadata:
        """把已验证 artifact 独占复制到指定临时文件并再次校验摘要。"""

        workspace_id, revision, artifact_id = parse_artifact_uri(uri)
        with self._lock:
            metadata = self.get(workspace_id, revision, artifact_id, verify=True)
            target = target.resolve(strict=False)
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise FileExistsError(f"materialization 目标已存在: {target}")
            blob_path, _ = self._paths(metadata)
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, "wb") as output, blob_path.open("rb") as source:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
            except BaseException:
                target.unlink(missing_ok=True)
                raise
            if (
                target.stat().st_size != metadata.size
                or sha256_file(target) != metadata.content_sha256
            ):
                target.unlink(missing_ok=True)
                raise ArtifactIntegrityError("artifact materialization 摘要不一致")
            return metadata

    def discard_unpublished(self, metadata: ArtifactMetadata) -> None:
        """清理尚未发布 revision 作用域中的精确 artifact。"""

        workspace_id, revision = _validate_scope(
            metadata.workspace_id,
            metadata.revision,
        )
        validate_identifier(metadata.artifact_id, field="artifact_id")
        with self._lock:
            actual = self.get(
                workspace_id,
                revision,
                metadata.artifact_id,
                verify=True,
            )
            if _identity(actual) != _identity(metadata):
                raise ArtifactIntegrityError("拒绝清理身份不一致的 artifact")
            _remove_artifact_directory(
                self._artifact_directory(actual),
                parent=self._scope(workspace_id, revision),
            )

    def get(
        self,
        workspace_id: str,
        revision: str,
        artifact_id: str,
        *,
        verify: bool = True,
    ) -> ArtifactMetadata:
        workspace_id, revision = _validate_scope(workspace_id, revision)
        validate_identifier(artifact_id, field="artifact_id")
        with self._lock:
            metadata = self._read_manifest(workspace_id, revision, artifact_id)
            if verify:
                self._verify_blob(metadata)
            return metadata

    def list(self) -> tuple[ArtifactMetadata, ...]:
        """按稳定 URI 顺序列出顶层 artifact, 内容在读取时校验。"""

        with self._lock:
            directories = sorted(
                self.root.glob("*/*/art_*"),
                key=lambda path: path.as_posix(),
            )
        result: list[ArtifactMetadata] = []
        for directory in directories:
            relative = directory.relative_to(self.root)
            if len(relative.parts) != 3:
                continue
            workspace_id, revision, artifact_id = relative.parts
            gc_lease = self.resource_read_lock(workspace_id)
            gc_lease.acquire()
            try:
                with self._lock:
                    try:
                        mode = directory.lstat().st_mode
                    except FileNotFoundError:
                        continue
                    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                        raise ArtifactIntegrityError("artifact 根目录包含非法条目")
                    try:
                        metadata = self._read_manifest(
                            workspace_id,
                            revision,
                            artifact_id,
                        )
                    except ArtifactNotFoundError as exc:
                        if not directory.exists():
                            continue
                        raise ArtifactIntegrityError(
                            f"artifact manifest 缺失: {artifact_id}"
                        ) from exc
                    if metadata.listed:
                        result.append(metadata)
            finally:
                gc_lease.release()
        return tuple(result)

    def collect_garbage(
        self,
        *,
        retained_scopes: set[tuple[str, str]],
        retained_revision_provider: Callable[[str], set[str]] | None = None,
        dry_run: bool = True,
    ) -> ArtifactGarbageCollectionResult:
        """只回收已不属于任何保留 revision 的完整 artifact scope。

        多 Supervisor 共享 data root 时, 调用方可提供实时 revision 解析器。解析发生在
        对应 workspace lifecycle lease 内, 避免旧快照误删刚发布 revision 的 artifact。
        """

        checked_scopes = {
            _validate_scope(workspace_id, revision) for workspace_id, revision in retained_scopes
        }
        candidates: list[Path] = []
        skipped: list[str] = []
        reclaimed = 0
        with self._lock:
            workspace_roots = sorted(self.root.iterdir(), key=lambda item: item.name)
        for workspace_root in workspace_roots:
            try:
                mode = workspace_root.lstat().st_mode
            except FileNotFoundError:
                continue
            if workspace_root == self._gc_lease_root:
                if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                    raise ArtifactIntegrityError("artifact GC lease 根目录类型无效")
                continue
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise ArtifactIntegrityError("artifact 根目录包含非法条目")
            try:
                workspace_id = validate_identifier(
                    workspace_root.name,
                    field="workspace_id",
                )
            except ValueError as exc:
                raise ArtifactIntegrityError("artifact workspace 目录名无效") from exc
            if workspace_root.resolve(strict=True).parent != self.root:
                raise ArtifactIntegrityError("artifact workspace 路径越界")
            workspace_lease = (
                interprocess_file_lock(self.workspace_lease_root / f"{workspace_id}.lease.lock")
                if self.workspace_lease_root is not None
                else None
            )
            if workspace_lease is not None and not workspace_lease.try_acquire():
                skipped.append(workspace_id)
                continue
            try:
                workspace_retained_scopes = checked_scopes
                if retained_revision_provider is not None:
                    workspace_retained_scopes = {
                        (
                            workspace_id,
                            validate_identifier(revision, field="revision"),
                        )
                        for revision in retained_revision_provider(workspace_id)
                    }
                gc_lease = self.resource_read_lock(workspace_id)
                with gc_lease, self._lock:
                    if not workspace_root.exists():
                        continue
                    workspace_candidates: list[Path] = []
                    for revision_root in sorted(
                        workspace_root.iterdir(),
                        key=lambda item: item.name,
                    ):
                        if revision_root.is_symlink() or not revision_root.is_dir():
                            raise ArtifactIntegrityError(
                                "artifact workspace 包含非法 revision 条目"
                            )
                        try:
                            revision = validate_identifier(
                                revision_root.name,
                                field="revision",
                            )
                        except ValueError as exc:
                            raise ArtifactIntegrityError("artifact revision 目录名无效") from exc
                        if revision_root.resolve(strict=True).parent != workspace_root.resolve(
                            strict=True
                        ):
                            raise ArtifactIntegrityError("artifact revision 路径越界")
                        if (workspace_id, revision) not in workspace_retained_scopes:
                            _validate_artifact_scope(revision_root)
                            workspace_candidates.append(revision_root)
                        else:
                            workspace_candidates.extend(
                                _retained_scope_staging_candidates(revision_root)
                            )
                    candidates.extend(workspace_candidates)
                    reclaimed += sum(_tree_size(path) for path in workspace_candidates)
                    if not dry_run:
                        for candidate in workspace_candidates:
                            if candidate.parent.name == _STAGING_NAME:
                                _remove_artifact_directory(
                                    candidate,
                                    parent=candidate.parent,
                                )
                            else:
                                _remove_artifact_scope(candidate, self.root)
            finally:
                if workspace_lease is not None:
                    workspace_lease.release()
        unique = tuple(sorted(set(candidates), key=str))
        return ArtifactGarbageCollectionResult(
            dry_run=dry_run,
            removed_paths=unique,
            reclaimed_bytes=reclaimed,
            skipped_workspace_ids=tuple(skipped),
        )

    def read_chunk(
        self,
        workspace_id: str,
        revision: str,
        artifact_id: str,
        *,
        offset: int = 0,
        limit: int = RESOURCE_CHUNK_BYTES,
    ) -> ArtifactChunk:
        if isinstance(offset, bool) or offset < 0:
            raise ValueError("offset 必须为非负整数")
        if isinstance(limit, bool) or limit < 1 or limit > RESOURCE_CHUNK_BYTES:
            raise ValueError(f"limit 必须位于 1..{RESOURCE_CHUNK_BYTES}")

        metadata = self.get(workspace_id, revision, artifact_id, verify=True)
        if offset > metadata.size:
            raise ValueError("offset 超出 artifact 大小")
        blob_path, _ = self._paths(metadata)
        with blob_path.open("rb") as stream:
            stream.seek(offset)
            data = stream.read(limit)
        end = offset + len(data)
        eof = end >= metadata.size
        return ArtifactChunk(
            metadata=metadata,
            offset=offset,
            data=data,
            next_offset=None if eof else end,
            eof=eof,
        )

    def read_uri(
        self,
        uri: str,
        *,
        offset: int = 0,
        limit: int = RESOURCE_CHUNK_BYTES,
    ) -> ArtifactChunk:
        workspace_id, revision, artifact_id = parse_artifact_uri(uri)
        return self.read_chunk(
            workspace_id,
            revision,
            artifact_id,
            offset=offset,
            limit=limit,
        )

    def read_verified_chunk(
        self,
        metadata: ArtifactMetadata,
        *,
        offset: int = 0,
        limit: int = RESOURCE_CHUNK_BYTES,
    ) -> ArtifactChunk:
        """已完成一次全文件校验后读取后续块, 避免每块重复计算整文件摘要。"""

        if isinstance(offset, bool) or offset < 0:
            raise ValueError("offset 必须为非负整数")
        if isinstance(limit, bool) or limit < 1 or limit > RESOURCE_CHUNK_BYTES:
            raise ValueError(f"limit 必须位于 1..{RESOURCE_CHUNK_BYTES}")
        with self._lock:
            actual = self.get(
                metadata.workspace_id,
                metadata.revision,
                metadata.artifact_id,
                verify=False,
            )
            if _identity(actual) != _identity(metadata):
                raise ArtifactIntegrityError("artifact 身份在分块读取期间发生变化")
            blob_path, _ = self._paths(actual)
            if not blob_path.is_file() or blob_path.stat().st_size != actual.size:
                raise ArtifactIntegrityError("artifact 大小与 manifest 不一致")
            if offset > actual.size:
                raise ValueError("offset 超出 artifact 大小")
            with blob_path.open("rb") as stream:
                stream.seek(offset)
                data = stream.read(limit)
            end = offset + len(data)
            eof = end >= actual.size
            return ArtifactChunk(
                metadata=actual,
                offset=offset,
                data=data,
                next_offset=None if eof else end,
                eof=eof,
            )

    def read_all(self, workspace_id: str, revision: str, artifact_id: str) -> bytes:
        metadata = self.get(workspace_id, revision, artifact_id, verify=True)
        blob_path, _ = self._paths(metadata)
        return blob_path.read_bytes()

    def _new_metadata(
        self,
        *,
        workspace_id: str,
        revision: str,
        content_sha256: str,
        size: int,
        media_type: str,
        name: str | None,
        listed: bool,
    ) -> ArtifactMetadata:
        artifact_id = _artifact_id(
            workspace_id=workspace_id,
            revision=revision,
            content_sha256=content_sha256,
            media_type=media_type,
            name=name,
            listed=listed,
        )
        return ArtifactMetadata(
            workspace_id=workspace_id,
            revision=revision,
            artifact_id=artifact_id,
            content_sha256=content_sha256,
            size=size,
            media_type=media_type,
            name=name,
            listed=listed,
            created_at=time.time(),
        )

    def _existing_or_none(self, expected: ArtifactMetadata) -> ArtifactMetadata | None:
        directory = self._artifact_directory(expected)
        if not directory.exists():
            return None
        _validate_artifact_directory(directory)
        actual = self._read_manifest(
            expected.workspace_id,
            expected.revision,
            expected.artifact_id,
        )
        if _identity(actual) != _identity(expected):
            raise ArtifactIntegrityError("artifact_id 对应的不可变元数据冲突")
        self._verify_blob(actual)
        return actual

    def _read_manifest(
        self,
        workspace_id: str,
        revision: str,
        artifact_id: str,
    ) -> ArtifactMetadata:
        if _ARTIFACT_DIRECTORY_PATTERN.fullmatch(artifact_id) is None:
            raise ArtifactIntegrityError("artifact_id 不符合内容寻址身份")
        if not self._scope(workspace_id, revision).exists():
            raise ArtifactNotFoundError(f"artifact 不存在: {artifact_id}")
        scope = self._require_scope(workspace_id, revision)
        directory = scope / artifact_id
        if not directory.exists():
            raise ArtifactNotFoundError(f"artifact 不存在: {artifact_id}")
        _validate_artifact_directory(directory)
        path = directory / _MANIFEST_NAME
        if not path.is_file():
            raise ArtifactNotFoundError(f"artifact 不存在: {artifact_id}")
        try:
            model = _ArtifactManifest.model_validate_json(path.read_bytes(), strict=True)
        except (OSError, ValidationError) as exc:
            raise ArtifactIntegrityError(f"artifact manifest 损坏: {artifact_id}") from exc
        metadata = _from_manifest(model)
        if (
            metadata.workspace_id != workspace_id
            or metadata.revision != revision
            or metadata.artifact_id != artifact_id
        ):
            raise ArtifactIntegrityError("artifact manifest 与存储路径不一致")
        try:
            validate_sha256(metadata.content_sha256, field="content_sha256")
            _validate_media_type(metadata.media_type)
            _validate_name(metadata.name)
            if (
                isinstance(metadata.size, bool)
                or metadata.size < 0
                or not math.isfinite(metadata.created_at)
                or metadata.created_at < 0
            ):
                raise ValueError("artifact 数值字段无效")
            expected_id = _artifact_id(
                workspace_id=metadata.workspace_id,
                revision=metadata.revision,
                content_sha256=metadata.content_sha256,
                media_type=metadata.media_type,
                name=metadata.name,
                listed=metadata.listed,
            )
            if metadata.artifact_id != expected_id:
                raise ValueError("artifact_id 与不可变元数据不一致")
        except ValueError as exc:
            raise ArtifactIntegrityError("artifact manifest 字段无效") from exc
        return metadata

    def _verify_blob(self, metadata: ArtifactMetadata) -> None:
        blob_path, _ = self._paths(metadata)
        if not blob_path.is_file():
            raise ArtifactIntegrityError("artifact blob 缺失")
        stat = blob_path.stat()
        if stat.st_size != metadata.size:
            raise ArtifactIntegrityError("artifact 大小与 manifest 不一致")
        if sha256_file(blob_path) != metadata.content_sha256:
            raise ArtifactIntegrityError("artifact SHA-256 校验失败")

    def _paths(self, metadata: ArtifactMetadata) -> tuple[Path, Path]:
        directory = self._artifact_directory(metadata)
        return (
            directory / _BLOB_NAME,
            directory / _MANIFEST_NAME,
        )

    def _publish_new(
        self,
        metadata: ArtifactMetadata,
        write_blob: Callable[[Path], None],
    ) -> ArtifactMetadata:
        existing = self._existing_or_none(metadata)
        if existing is not None:
            return existing

        scope = self._ensure_scope(metadata.workspace_id, metadata.revision)
        staging_root = scope / _STAGING_NAME
        staging_root.mkdir(exist_ok=True, mode=0o700)
        staging = Path(tempfile.mkdtemp(prefix=".artifact-", dir=staging_root))
        final = self._artifact_directory(metadata)
        published = False
        try:
            write_blob(staging / _BLOB_NAME)
            atomic_write_json(staging / _MANIFEST_NAME, _manifest_dict(metadata))
            _validate_artifact_directory(staging, staging=True)
            os.rename(staging, final)
            published = True
            _fsync_directory(scope)
        except BaseException:
            if published and final.is_dir() and not final.is_symlink():
                _remove_artifact_directory(final, parent=scope)
            elif staging.exists():
                _remove_artifact_directory(staging, parent=staging_root)
            raise
        return metadata

    def _scope(self, workspace_id: str, revision: str) -> Path:
        return self.root / workspace_id / revision

    def _ensure_scope(self, workspace_id: str, revision: str) -> Path:
        workspace_root = self.root / workspace_id
        if workspace_root.exists():
            if (
                workspace_root.is_symlink()
                or not workspace_root.is_dir()
                or workspace_root.resolve(strict=True).parent != self.root
            ):
                raise ArtifactIntegrityError("artifact workspace 路径无效")
        else:
            workspace_root.mkdir(mode=0o700)
        scope = workspace_root / revision
        if scope.exists():
            return self._require_scope(workspace_id, revision)
        scope.mkdir(mode=0o700)
        return scope

    def _require_scope(self, workspace_id: str, revision: str) -> Path:
        workspace_root = self.root / workspace_id
        scope = workspace_root / revision
        if (
            workspace_root.is_symlink()
            or not workspace_root.is_dir()
            or workspace_root.resolve(strict=True).parent != self.root
            or scope.is_symlink()
            or not scope.is_dir()
            or scope.resolve(strict=True).parent != workspace_root.resolve(strict=True)
        ):
            raise ArtifactIntegrityError("artifact revision scope 路径无效")
        return scope

    def _artifact_directory(self, metadata: ArtifactMetadata) -> Path:
        return self._scope(metadata.workspace_id, metadata.revision) / metadata.artifact_id


def artifact_uri(workspace_id: str, revision: str, artifact_id: str) -> str:
    workspace_id, revision = _validate_scope(workspace_id, revision)
    validate_identifier(artifact_id, field="artifact_id")
    if _ARTIFACT_DIRECTORY_PATTERN.fullmatch(artifact_id) is None:
        raise ValueError("artifact_id 不符合内容寻址身份")
    return (
        "ida-re://workspaces/"
        f"{quote(workspace_id, safe='')}/revisions/{quote(revision, safe='')}"
        f"/artifacts/{quote(artifact_id, safe='')}"
    )


def parse_artifact_uri(uri: str) -> tuple[str, str, str]:
    parsed = urlsplit(uri)
    if (
        parsed.scheme != "ida-re"
        or parsed.netloc != "workspaces"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("不是当前 artifact URI")
    parts = [unquote(part) for part in parsed.path.split("/") if part]
    if len(parts) != 5 or parts[1] != "revisions" or parts[3] != "artifacts":
        raise ValueError("artifact URI 路径结构无效")
    workspace_id, revision, artifact_id = parts[0], parts[2], parts[4]
    _validate_scope(workspace_id, revision)
    validate_identifier(artifact_id, field="artifact_id")
    if _ARTIFACT_DIRECTORY_PATTERN.fullmatch(artifact_id) is None:
        raise ValueError("artifact_id 不符合内容寻址身份")
    return workspace_id, revision, artifact_id


def _validate_scope(workspace_id: str, revision: str) -> tuple[str, str]:
    validate_identifier(workspace_id, field="workspace_id")
    validate_identifier(revision, field="revision")
    return workspace_id, revision


def _validate_media_type(value: str) -> None:
    if (
        not value
        or len(value) > 255
        or "/" not in value
        or any(character in value for character in "\r\n\0")
    ):
        raise ValueError("media_type 无效")


def _validate_name(value: str | None) -> None:
    if value is not None and (
        not value or len(value) > 255 or any(character in value for character in "\r\n\0")
    ):
        raise ValueError("artifact name 无效")


def _artifact_id(
    *,
    workspace_id: str,
    revision: str,
    content_sha256: str,
    media_type: str,
    name: str | None,
    listed: bool,
) -> str:
    identity = canonical_json_bytes(
        {
            "content_sha256": content_sha256,
            "media_type": media_type,
            "name": name,
            "listed": listed,
            "revision": revision,
            "workspace_id": workspace_id,
        }
    )
    return f"art_{hashlib.sha256(identity).hexdigest()}"


def _manifest_dict(metadata: ArtifactMetadata) -> dict[str, object]:
    return {
        "schema_version": STORAGE_SCHEMA_VERSION,
        "workspace_id": metadata.workspace_id,
        "revision": metadata.revision,
        "artifact_id": metadata.artifact_id,
        "content_sha256": metadata.content_sha256,
        "size": metadata.size,
        "media_type": metadata.media_type,
        "name": metadata.name,
        "listed": metadata.listed,
        "created_at": metadata.created_at,
    }


def _from_manifest(model: _ArtifactManifest) -> ArtifactMetadata:
    return ArtifactMetadata(
        workspace_id=model.workspace_id,
        revision=model.revision,
        artifact_id=model.artifact_id,
        content_sha256=model.content_sha256,
        size=model.size,
        media_type=model.media_type,
        name=model.name,
        listed=model.listed,
        created_at=model.created_at,
    )


def _identity(
    metadata: ArtifactMetadata,
) -> tuple[str, str, str, str, int, str, str | None, bool]:
    return (
        metadata.workspace_id,
        metadata.revision,
        metadata.artifact_id,
        metadata.content_sha256,
        metadata.size,
        metadata.media_type,
        metadata.name,
        metadata.listed,
    )


def _tree_size(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ArtifactIntegrityError("拒绝计算包含 symlink 的 artifact 路径")
        if path.is_file():
            total += path.stat().st_size
        elif not path.is_dir():
            raise ArtifactIntegrityError("artifact 路径包含非法文件类型")
    return total


def _validate_artifact_directory(path: Path, *, staging: bool = False) -> None:
    pattern = _STAGING_DIRECTORY_PATTERN if staging else _ARTIFACT_DIRECTORY_PATTERN
    if pattern.fullmatch(path.name) is None or path.is_symlink() or not path.is_dir():
        raise ArtifactIntegrityError("artifact 发布目录无效")
    entries = {entry.name: entry for entry in path.iterdir()}
    if set(entries) != {_BLOB_NAME, _MANIFEST_NAME}:
        raise ArtifactIntegrityError("artifact 发布目录文件集合无效")
    if any(entry.is_symlink() or not entry.is_file() for entry in entries.values()):
        raise ArtifactIntegrityError("artifact 发布目录包含非法路径类型")


def _validate_artifact_scope(path: Path) -> None:
    _retained_scope_staging_candidates(path)


def _retained_scope_staging_candidates(path: Path) -> list[Path]:
    candidates: list[Path] = []
    for entry in sorted(path.iterdir(), key=lambda item: item.name):
        if entry.name == _STAGING_NAME:
            if entry.is_symlink() or not entry.is_dir():
                raise ArtifactIntegrityError("artifact staging 根目录无效")
            for staging in sorted(entry.iterdir(), key=lambda item: item.name):
                if (
                    _STAGING_DIRECTORY_PATTERN.fullmatch(staging.name) is None
                    or staging.is_symlink()
                    or not staging.is_dir()
                ):
                    raise ArtifactIntegrityError("artifact staging 包含非法条目")
                for partial in staging.rglob("*"):
                    if partial.is_symlink() or not partial.is_file():
                        raise ArtifactIntegrityError("artifact staging 包含非法路径类型")
                candidates.append(staging)
            continue
        _validate_artifact_directory(entry)
    return candidates


def _remove_artifact_directory(path: Path, *, parent: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ArtifactIntegrityError("拒绝清理非法 artifact 目录")
    resolved_parent = parent.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    if resolved_path.parent != resolved_parent:
        raise ArtifactIntegrityError("拒绝清理 artifact 边界外目录")
    shutil.rmtree(resolved_path)
    _fsync_directory(resolved_parent)


def _remove_artifact_scope(path: Path, root: Path) -> None:
    if path.is_symlink():
        raise ArtifactIntegrityError("拒绝递归清理 artifact symlink")
    resolved_root = root.resolve()
    resolved_path = path.resolve(strict=True)
    try:
        relative = resolved_path.relative_to(resolved_root)
    except ValueError as exc:
        raise ArtifactIntegrityError("拒绝清理 artifact 根目录外路径") from exc
    if len(relative.parts) != 2:
        raise ArtifactIntegrityError("artifact GC 只允许清理 revision scope")
    _validate_scope(relative.parts[0], relative.parts[1])
    shutil.rmtree(resolved_path)
    _fsync_directory(resolved_path.parent)


def _write_new_blob(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        raise
    finally:
        temporary.unlink(missing_ok=True)


def _copy_new_blob(source: Path, target: Path) -> tuple[str, int]:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.",
        suffix=".tmp",
        dir=target.parent,
    )
    temporary = Path(temporary_name)
    digest = hashlib.sha256()
    size = 0
    try:
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                output_stream.write(chunk)
                digest.update(chunk)
                size += len(chunk)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return digest.hexdigest(), size


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
