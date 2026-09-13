from __future__ import annotations

import json
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from pydantic import JsonValue

import ida_re_mcp.supervisor._fs as filesystem
from ida_re_mcp.supervisor import (
    ColdValidationReceipt,
    ImageIdentity,
    RevisionConflictError,
    RevisionSnapshot,
    StagingIntegrityError,
    StorageCorruptionError,
    WorkspaceRegistry,
    hash_staging_payload,
)
from ida_re_mcp.supervisor._fs import atomic_write_json


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


def _invalid_image_identity() -> ImageIdentity:
    return ImageIdentity.model_construct(
        container="macho",
        architecture="x86_64",
        bitness=64,
        endian="little",
        image_size=0x4000,
    )


@pytest.mark.parametrize(
    ("container", "architecture", "bitness"),
    [
        ("pe", "x86", 32),
        ("pe", "x86_64", 64),
        ("elf", "x86", 32),
        ("elf", "x86_64", 64),
        ("elf", "arm", 32),
        ("elf", "aarch64", 64),
    ],
)
def test_image_identity_accepts_supported_architecture_bitness_pairs(
    container: str,
    architecture: str,
    bitness: int,
) -> None:
    identity = ImageIdentity.model_validate(
        {
            "container": container,
            "architecture": architecture,
            "bitness": bitness,
            "endian": "little",
            "image_size": 0x4000,
        },
        strict=True,
    )

    assert identity.architecture == architecture
    assert identity.bitness == bitness


@pytest.mark.parametrize(
    ("container", "architecture", "bitness"),
    [
        ("pe", "arm", 32),
        ("pe", "aarch64", 64),
        ("elf", "x86", 64),
        ("elf", "x86_64", 32),
    ],
)
def test_image_identity_rejects_invalid_architecture_bitness_pairs(
    container: str,
    architecture: str,
    bitness: int,
) -> None:
    with pytest.raises(ValueError):
        ImageIdentity.model_validate(
            {
                "container": container,
                "architecture": architecture,
                "bitness": bitness,
                "endian": "little",
                "image_size": 0x4000,
            },
            strict=True,
        )


_LOCK_PROBE = """
from pathlib import Path
import sys
import time

from ida_re_mcp.supervisor import WorkspaceRegistry

root = Path(sys.argv[1])
workspace_id = sys.argv[2]
ready = Path(sys.argv[3])
acquired = Path(sys.argv[4])
release = Path(sys.argv[5])
registry = WorkspaceRegistry(root)
ready.write_text("ready", encoding="ascii")
with registry.workspace_lock(workspace_id):
    acquired.write_text("acquired", encoding="ascii")
    deadline = time.monotonic() + 30
    while not release.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("lock probe release timed out")
        time.sleep(0.01)
"""

_PUBLISH_PROBE = """
from pathlib import Path
import sys
import time

from ida_re_mcp.supervisor import (
    ColdValidationReceipt,
    ImageIdentity,
    RevisionConflictError,
    WorkspaceRegistry,
    hash_staging_payload,
)

root = Path(sys.argv[1])
checkout_root = Path(sys.argv[2])
workspace_id = sys.argv[3]
expected_revision = sys.argv[4]
label = sys.argv[5]
ready = Path(sys.argv[6])
start = Path(sys.argv[7])
result = Path(sys.argv[8])
registry = WorkspaceRegistry(root, checkout_root=checkout_root)
staging = registry.begin_staging(
    workspace_id,
    expected_revision=expected_revision,
)
unit = label.encode("ascii")
size = 4 * 1024 * 1024
staging.database_path.write_bytes((unit * (size // len(unit) + 1))[:size])
receipt = ColdValidationReceipt.create(
    validator="cold.worker",
    component_hashes=hash_staging_payload(staging),
    image_identity=ImageIdentity.model_validate(
        {
            "container": "pe",
            "architecture": "x86_64",
            "bitness": 64,
            "endian": "little",
            "image_size": 0x4000,
        },
        strict=True,
    ),
)
ready.write_text("ready", encoding="ascii")
deadline = time.monotonic() + 30
while not start.is_file():
    if time.monotonic() >= deadline:
        raise TimeoutError("publish probe start timed out")
    time.sleep(0.01)
try:
    revision = registry.publish_staging(staging, receipt=receipt)
except RevisionConflictError:
    result.write_text("conflict", encoding="ascii")
else:
    result.write_text(f"success:{revision.revision}", encoding="ascii")
"""

_LIFECYCLE_LEASE_PROBE = """
from pathlib import Path
import sys
import time

from ida_re_mcp.supervisor import WorkspaceRegistry

root = Path(sys.argv[1])
checkout_root = Path(sys.argv[2])
workspace_id = sys.argv[3]
revision = sys.argv[4]
ready = Path(sys.argv[5])
paths = Path(sys.argv[6])
release = Path(sys.argv[7])
registry = WorkspaceRegistry(root, checkout_root=checkout_root)
lease = registry.workspace_lease_lock(workspace_id)
with lease:
    staging = registry.begin_staging(
        workspace_id,
        expected_revision=revision,
    )
    staging.database_path.write_bytes(b"active staging")
    checkout = registry.create_checkout(
        workspace_id,
        revision,
        purpose="analysis",
    )
    paths.write_text(
        f"{staging.path}\\n{checkout.path}\\n",
        encoding="utf-8",
    )
    ready.write_text("ready", encoding="ascii")
    deadline = time.monotonic() + 30
    while not release.is_file():
        if time.monotonic() >= deadline:
            raise TimeoutError("lifecycle lease probe release timed out")
        time.sleep(0.01)
    registry.abort_staging(staging)
    registry.discard_checkout(checkout)
"""


def _publish(
    registry: WorkspaceRegistry,
    workspace_id: str,
    expected_revision: str | None,
    content: bytes,
) -> RevisionSnapshot:
    staging = registry.begin_staging(
        workspace_id,
        expected_revision=expected_revision,
    )
    staging.database_path.write_bytes(content)
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )
    return registry.publish_staging(staging, receipt=receipt)


def _new_registry(tmp_path: Path) -> tuple[WorkspaceRegistry, str, Path]:
    source = tmp_path / "sample.exe"
    source.write_bytes(b"sample bytes")
    registry = WorkspaceRegistry(
        tmp_path / "data" / "workspaces",
        checkout_root=tmp_path / "data" / "checkouts",
    )
    workspace = registry.create(source)
    return registry, workspace.workspace_id, source


def _start_probe(script: str, *arguments: str | Path) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-c", script, *(str(argument) for argument in arguments)],
        cwd=Path(__file__).resolve().parents[2],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )


def _wait_for_marker(
    marker: Path,
    process: subprocess.Popen[str],
    *,
    timeout: float = 10,
) -> None:
    deadline = time.monotonic() + timeout
    while not marker.is_file():
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                f"子进程在写入 {marker.name} 前退出: "
                f"code={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
            )
        if time.monotonic() >= deadline:
            pytest.fail(f"等待子进程标记超时: {marker}")
        time.sleep(0.01)


def _assert_process_succeeded(process: subprocess.Popen[str]) -> None:
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        pytest.fail(f"子进程未按时退出: stdout={stdout!r}, stderr={stderr!r}")
    assert process.returncode == 0, (
        f"子进程失败: code={process.returncode}, stdout={stdout!r}, stderr={stderr!r}"
    )


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=5)


def test_revision_commit_receipt_survives_cold_registry_reopen(tmp_path: Path) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    staging = registry.begin_staging(workspace_id, expected_revision=None)
    staging.database_path.write_bytes(b"cold idb with commit receipt")
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )
    operation_result: dict[str, JsonValue] = {
        "workspace_id": workspace_id,
        "revision": staging.candidate_revision,
        "sample_sha256": "f" * 64,
        "coverage": {
            "complete": True,
            "warnings": [],
        },
    }

    published = registry.publish_staging(
        staging,
        receipt=receipt,
        operation_id="op_workspace_create",
        operation_result=operation_result,
    )
    reopened = WorkspaceRegistry(
        registry.root,
        checkout_root=registry.checkout_root,
    )
    restored = reopened.get_revision(workspace_id, published.revision)

    assert restored.operation_id == "op_workspace_create"
    assert restored.operation_result == operation_result
    assert (
        reopened.committed_operation_result(
            workspace_id,
            "op_workspace_create",
        )
        == operation_result
    )
    assert reopened.committed_operation_result(workspace_id, "op_unknown") is None


@pytest.mark.parametrize(
    ("operation_id", "operation_result"),
    [
        pytest.param("op_workspace_create", None, id="missing-result"),
        pytest.param(None, {"revision": "rev_candidate"}, id="missing-id"),
    ],
)
def test_publish_rejects_unpaired_operation_commit_receipt(
    tmp_path: Path,
    operation_id: str | None,
    operation_result: dict[str, JsonValue] | None,
) -> None:
    registry, workspace_id, source = _new_registry(tmp_path)
    staging = registry.begin_staging(workspace_id, expected_revision=None)
    staging.database_path.write_bytes(b"candidate")
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )

    with pytest.raises(ValueError, match="operation_id 与 operation_result 必须同时存在"):
        registry.publish_staging(
            staging,
            receipt=receipt,
            operation_id=operation_id,
            operation_result=operation_result,
        )

    assert registry.get(workspace_id).current_revision is None
    assert source.read_bytes() == b"sample bytes"
    assert not staging.path.exists()


def test_publish_rejects_operation_result_bound_to_another_revision(
    tmp_path: Path,
) -> None:
    registry, workspace_id, source = _new_registry(tmp_path)
    staging = registry.begin_staging(workspace_id, expected_revision=None)
    staging.database_path.write_bytes(b"candidate")
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )

    with pytest.raises(ValueError, match="绑定当前 workspace/revision"):
        registry.publish_staging(
            staging,
            receipt=receipt,
            operation_id="op_workspace_create",
            operation_result={
                "workspace_id": workspace_id,
                "revision": "rev_another",
            },
        )

    assert registry.get(workspace_id).current_revision is None
    assert source.read_bytes() == b"sample bytes"
    assert not staging.path.exists()


@pytest.mark.parametrize("corruption", ["missing-result", "unexpected-field"])
def test_cold_reopen_rejects_corrupt_revision_commit_manifest(
    tmp_path: Path,
    corruption: str,
) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    staging = registry.begin_staging(workspace_id, expected_revision=None)
    staging.database_path.write_bytes(b"cold idb")
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )
    published = registry.publish_staging(
        staging,
        receipt=receipt,
        operation_id="op_workspace_create",
        operation_result={
            "workspace_id": workspace_id,
            "revision": staging.candidate_revision,
        },
    )
    manifest_path = published.path / "revision.json"
    manifest = cast(
        dict[str, object],
        json.loads(manifest_path.read_text(encoding="utf-8")),
    )
    assert manifest["schema_version"] == "1"
    if corruption == "missing-result":
        manifest["operation_result"] = None
    else:
        manifest["unexpected"] = True
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )

    reopened = WorkspaceRegistry(
        registry.root,
        checkout_root=registry.checkout_root,
    )
    with pytest.raises(StorageCorruptionError, match="revision manifest 损坏"):
        reopened.get_revision(workspace_id, published.revision)


def test_revision_publish_and_checkout_never_mutate_cold_database(tmp_path: Path) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    revision = _publish(registry, workspace_id, None, b"cold idb")

    checkout = registry.create_checkout(
        workspace_id,
        revision.revision,
        purpose="analysis",
    )
    checkout.database_path.write_bytes(b"worker-local mutation")

    assert registry.get_revision(workspace_id, revision.revision).database_path.read_bytes() == (
        b"cold idb"
    )
    registry.discard_checkout(checkout)
    assert not checkout.path.exists()


def test_publish_does_not_perform_fallible_readback_after_manifest_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    staging = registry.begin_staging(workspace_id, expected_revision=None)
    staging.database_path.write_bytes(b"candidate")
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )

    def reject_post_commit_readback(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("manifest CAS 后不得再次读盘构造返回值")

    monkeypatch.setattr(registry, "_revision_snapshot", reject_post_commit_readback)
    published = registry.publish_staging(staging, receipt=receipt)

    assert published.revision == staging.candidate_revision
    monkeypatch.undo()
    assert registry.get(workspace_id).current_revision == published.revision


def test_gc_never_lists_or_deletes_other_process_active_worker_paths(
    tmp_path: Path,
) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    revision = _publish(registry, workspace_id, None, b"cold idb")
    marker_root = tmp_path / "lease-gc-markers"
    marker_root.mkdir()
    ready = marker_root / "ready"
    paths_file = marker_root / "paths"
    release = marker_root / "release"
    process = _start_probe(
        _LIFECYCLE_LEASE_PROBE,
        registry.root,
        registry.checkout_root,
        workspace_id,
        revision.revision,
        ready,
        paths_file,
        release,
    )
    try:
        _wait_for_marker(ready, process)
        active_paths = tuple(
            Path(value) for value in paths_file.read_text(encoding="utf-8").splitlines()
        )
        assert len(active_paths) == 2
        assert all(path.is_dir() for path in active_paths)

        preview = registry.collect_garbage(dry_run=True)
        applied = registry.collect_garbage(dry_run=False)

        assert preview.removed_paths == ()
        assert applied.removed_paths == ()
        assert preview.skipped_workspace_ids == (workspace_id,)
        assert applied.skipped_workspace_ids == (workspace_id,)
        assert all(path.is_dir() for path in active_paths)
        release.write_text("release", encoding="ascii")
        _assert_process_succeeded(process)
    finally:
        release.touch(exist_ok=True)
        _terminate_process(process)


def test_revision_cas_allows_only_one_writer(tmp_path: Path) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    base = _publish(registry, workspace_id, None, b"base")
    first = registry.begin_staging(workspace_id, expected_revision=base.revision)
    second = registry.begin_staging(workspace_id, expected_revision=base.revision)
    first.database_path.write_bytes(b"first")
    second.database_path.write_bytes(b"second")
    first_receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(first),
        image_identity=_pe_image_identity(),
    )
    second_receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(second),
        image_identity=_pe_image_identity(),
    )

    winner = registry.publish_staging(first, receipt=first_receipt)
    with pytest.raises(RevisionConflictError):
        registry.publish_staging(second, receipt=second_receipt)

    assert registry.get(workspace_id).current_revision == winner.revision
    assert not second.path.exists()


def test_hash_mismatch_discards_staging_and_preserves_head(tmp_path: Path) -> None:
    registry, workspace_id, source = _new_registry(tmp_path)
    base = _publish(registry, workspace_id, None, b"base")
    staging = registry.begin_staging(workspace_id, expected_revision=base.revision)
    staging.database_path.write_bytes(b"before validation")
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )
    staging.database_path.write_bytes(b"after validation")

    with pytest.raises(StagingIntegrityError, match="摘要"):
        registry.publish_staging(staging, receipt=receipt)

    assert registry.get(workspace_id).current_revision == base.revision
    assert registry.get_revision(workspace_id, base.revision).database_path.read_bytes() == b"base"
    assert source.read_bytes() == b"sample bytes"
    assert not staging.path.exists()


def test_manifest_commit_failure_discards_candidate_and_preserves_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, workspace_id, source = _new_registry(tmp_path)
    base = _publish(registry, workspace_id, None, b"base")
    staging = registry.begin_staging(workspace_id, expected_revision=base.revision)
    staging.database_path.write_bytes(b"candidate")
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )

    def fail_commit(_workspace_id: str, _manifest: object) -> None:
        raise OSError("injected manifest failure")

    monkeypatch.setattr(registry, "_commit_manifest", fail_commit)

    with pytest.raises(OSError, match="injected"):
        registry.publish_staging(staging, receipt=receipt)

    assert registry.get(workspace_id).current_revision == base.revision
    assert registry.get_revision(workspace_id, base.revision).database_path.read_bytes() == b"base"
    assert source.read_bytes() == b"sample bytes"
    assert not staging.path.exists()


def test_manifest_sync_failure_preserves_already_referenced_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, workspace_id, _source = _new_registry(tmp_path)
    base = _publish(registry, workspace_id, None, b"base")
    staging = registry.begin_staging(workspace_id, expected_revision=base.revision)
    staging.database_path.write_bytes(b"candidate")
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )
    sync_directory = filesystem._fsync_directory  # pyright: ignore[reportPrivateUsage]

    def fail_workspace_sync(path: Path) -> None:
        if path == registry.root / workspace_id:
            raise OSError("injected post-replace sync failure")
        sync_directory(path)

    monkeypatch.setattr(filesystem, "_fsync_directory", fail_workspace_sync)

    with pytest.raises(OSError, match="post-replace"):
        registry.publish_staging(staging, receipt=receipt)

    reopened = WorkspaceRegistry(registry.root, checkout_root=registry.checkout_root)
    assert reopened.get(workspace_id).current_revision == staging.candidate_revision
    published = reopened.get_revision(workspace_id, staging.candidate_revision)
    assert published.database_path.read_bytes() == b"candidate"
    assert reopened.get_revision(workspace_id, base.revision).database_path.read_bytes() == b"base"


def test_retention_keeps_current_three_history_and_pinned(tmp_path: Path) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    revisions: list[RevisionSnapshot] = []
    expected: str | None = None
    for index in range(6):
        revision = _publish(
            registry,
            workspace_id,
            expected,
            f"revision-{index}".encode(),
        )
        revisions.append(revision)
        expected = revision.revision
        if index == 0:
            registry.pin_revision(workspace_id, revision.revision)

    workspace = registry.get(workspace_id)
    retained = {revision.revision for revision in workspace.revisions}

    assert workspace.current_revision == revisions[-1].revision
    assert revisions[0].revision in retained
    assert retained.issuperset(revision.revision for revision in revisions[-4:])
    assert len(retained) == 5

    registry.pin_revision(workspace_id, revisions[0].revision, pinned=False)
    after_unpin = {revision.revision for revision in registry.get(workspace_id).revisions}
    assert after_unpin == {revision.revision for revision in revisions[-4:]}


def test_manifest_commit_defers_unreachable_revision_cleanup_to_gc(tmp_path: Path) -> None:
    source = tmp_path / "sample.exe"
    source.write_bytes(b"sample bytes")
    registry = WorkspaceRegistry(
        tmp_path / "data" / "workspaces",
        checkout_root=tmp_path / "data" / "checkouts",
        retained_revisions=0,
    )
    workspace_id = registry.create(source).workspace_id
    base = _publish(registry, workspace_id, None, b"base")
    base_path = base.path

    current = _publish(registry, workspace_id, base.revision, b"current")

    assert registry.get(workspace_id).current_revision == current.revision
    assert base.revision not in {
        revision.revision for revision in registry.get(workspace_id).revisions
    }
    assert base_path.is_dir()
    preview = registry.collect_garbage(dry_run=True)
    assert base_path in preview.removed_paths
    applied = registry.collect_garbage(dry_run=False)
    assert base_path in applied.removed_paths
    assert not base_path.exists()


def test_restore_staging_uses_source_content_but_current_parent(tmp_path: Path) -> None:
    registry, workspace_id, source = _new_registry(tmp_path)
    parent = _publish(registry, workspace_id, None, b"parent")
    current = _publish(registry, workspace_id, parent.revision, b"current")

    staging = registry.begin_staging(
        workspace_id,
        expected_revision=current.revision,
        source_revision=parent.revision,
    )
    assert staging.database_path.read_bytes() == b"parent"
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=_pe_image_identity(),
    )
    restored = registry.publish_staging(
        staging,
        receipt=receipt,
        change_id="change_restore",
    )

    assert restored.parent_revision == current.revision
    assert restored.database_path.read_bytes() == b"parent"
    assert (
        registry.get_revision(
            workspace_id,
            parent.revision,
        ).database_path.read_bytes()
        == b"parent"
    )
    assert (
        registry.get_revision(
            workspace_id,
            current.revision,
        ).database_path.read_bytes()
        == b"current"
    )
    assert source.read_bytes() == b"sample bytes"


def test_workspace_lock_is_process_wide_but_not_global(tmp_path: Path) -> None:
    registry, first_workspace_id, _ = _new_registry(tmp_path)
    second_source = tmp_path / "second.exe"
    second_source.write_bytes(b"second sample")
    second_workspace_id = registry.create(second_source).workspace_id
    marker_root = tmp_path / "markers"
    marker_root.mkdir()

    first_ready = marker_root / "first.ready"
    first_acquired = marker_root / "first.acquired"
    first_release = marker_root / "first.release"
    same_ready = marker_root / "same.ready"
    same_acquired = marker_root / "same.acquired"
    same_release = marker_root / "same.release"
    other_ready = marker_root / "other.ready"
    other_acquired = marker_root / "other.acquired"
    other_release = marker_root / "other.release"
    processes: list[subprocess.Popen[str]] = []

    try:
        first = _start_probe(
            _LOCK_PROBE,
            registry.root,
            first_workspace_id,
            first_ready,
            first_acquired,
            first_release,
        )
        processes.append(first)
        _wait_for_marker(first_acquired, first)

        same = _start_probe(
            _LOCK_PROBE,
            registry.root,
            first_workspace_id,
            same_ready,
            same_acquired,
            same_release,
        )
        processes.append(same)
        _wait_for_marker(same_ready, same)
        time.sleep(0.2)
        assert not same_acquired.exists()

        other = _start_probe(
            _LOCK_PROBE,
            registry.root,
            second_workspace_id,
            other_ready,
            other_acquired,
            other_release,
        )
        processes.append(other)
        _wait_for_marker(other_acquired, other, timeout=3)
        assert not same_acquired.exists()

        other_release.write_text("release", encoding="ascii")
        _assert_process_succeeded(other)
        first_release.write_text("release", encoding="ascii")
        _assert_process_succeeded(first)
        _wait_for_marker(same_acquired, same)
        same_release.write_text("release", encoding="ascii")
        _assert_process_succeeded(same)
    finally:
        for release in (first_release, same_release, other_release):
            release.touch(exist_ok=True)
        for process in processes:
            _terminate_process(process)


def test_workspace_lock_recovers_after_owner_process_termination(tmp_path: Path) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    marker_root = tmp_path / "crash-markers"
    marker_root.mkdir()
    holder_acquired = marker_root / "holder.acquired"
    holder_release = marker_root / "holder.release"
    contender_ready = marker_root / "contender.ready"
    contender_acquired = marker_root / "contender.acquired"
    contender_release = marker_root / "contender.release"
    holder = _start_probe(
        _LOCK_PROBE,
        registry.root,
        workspace_id,
        marker_root / "holder.ready",
        holder_acquired,
        holder_release,
    )
    contender: subprocess.Popen[str] | None = None

    try:
        _wait_for_marker(holder_acquired, holder)
        contender = _start_probe(
            _LOCK_PROBE,
            registry.root,
            workspace_id,
            contender_ready,
            contender_acquired,
            contender_release,
        )
        _wait_for_marker(contender_ready, contender)
        time.sleep(0.2)
        assert not contender_acquired.exists()

        holder.terminate()
        holder.communicate(timeout=5)
        _wait_for_marker(contender_acquired, contender)
        contender_release.write_text("release", encoding="ascii")
        _assert_process_succeeded(contender)
    finally:
        holder_release.touch(exist_ok=True)
        contender_release.touch(exist_ok=True)
        _terminate_process(holder)
        if contender is not None:
            _terminate_process(contender)


def test_multiprocess_publish_has_one_cas_winner_and_preserves_storage(
    tmp_path: Path,
) -> None:
    registry, workspace_id, source = _new_registry(tmp_path)
    base = _publish(registry, workspace_id, None, b"base")
    before = registry.get(workspace_id)
    sample_bytes = before.sample_path.read_bytes()
    marker_root = tmp_path / "publish-markers"
    marker_root.mkdir()
    start = marker_root / "start"
    first_ready = marker_root / "first.ready"
    second_ready = marker_root / "second.ready"
    first_result = marker_root / "first.result"
    second_result = marker_root / "second.result"

    first = _start_probe(
        _PUBLISH_PROBE,
        registry.root,
        registry.checkout_root,
        workspace_id,
        base.revision,
        "first",
        first_ready,
        start,
        first_result,
    )
    second = _start_probe(
        _PUBLISH_PROBE,
        registry.root,
        registry.checkout_root,
        workspace_id,
        base.revision,
        "second",
        second_ready,
        start,
        second_result,
    )
    try:
        _wait_for_marker(first_ready, first)
        _wait_for_marker(second_ready, second)
        start.write_text("start", encoding="ascii")
        _assert_process_succeeded(first)
        _assert_process_succeeded(second)
    finally:
        start.touch(exist_ok=True)
        _terminate_process(first)
        _terminate_process(second)

    outcomes = (first_result.read_text(encoding="ascii"), second_result.read_text(encoding="ascii"))
    successes = [outcome for outcome in outcomes if outcome.startswith("success:")]
    assert len(successes) == 1
    assert outcomes.count("conflict") == 1
    winner_revision = successes[0].removeprefix("success:")

    current = registry.get(workspace_id)
    assert current.current_revision == winner_revision
    assert {revision.revision for revision in current.revisions} == {
        base.revision,
        winner_revision,
    }
    revision_root = registry.root / workspace_id / "revisions"
    assert {path.name for path in revision_root.iterdir() if path.is_dir()} == {
        base.revision,
        winner_revision,
    }
    for revision in current.revisions:
        registry.get_revision(workspace_id, revision.revision)
    staging_root = registry.root / workspace_id / ".staging"
    assert not staging_root.exists() or not any(staging_root.iterdir())
    assert current.sample_path.read_bytes() == sample_bytes
    assert current.sample_sha256 == before.sample_sha256
    assert source.read_bytes() == b"sample bytes"


def test_image_identity_persists_and_survives_cold_reopen(tmp_path: Path) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    staging = registry.begin_staging(workspace_id, expected_revision=None)
    staging.database_path.write_bytes(b"cold idb with image identity")
    identity = _pe_image_identity()
    receipt = ColdValidationReceipt.create(
        validator="cold.worker",
        component_hashes=hash_staging_payload(staging),
        image_identity=identity,
    )
    published = registry.publish_staging(staging, receipt=receipt)
    assert published.image_identity == identity

    reopened = WorkspaceRegistry(registry.root, checkout_root=registry.checkout_root)
    restored = reopened.get_revision(workspace_id, published.revision)
    assert restored.image_identity == identity
    snapshot = reopened.get(workspace_id)
    current = next(
        revision
        for revision in snapshot.revisions
        if revision.revision == snapshot.current_revision
    )
    assert current.image_identity == identity


def test_cold_validation_receipt_revalidates_constructed_image_identity() -> None:
    with pytest.raises(ValueError, match="container"):
        ColdValidationReceipt.create(
            validator="cold.worker",
            component_hashes={"database.i64": "0" * 64},
            image_identity=_invalid_image_identity(),
        )


def test_cold_validation_receipt_requires_image_identity() -> None:
    create = cast(
        Callable[..., ColdValidationReceipt],
        ColdValidationReceipt.create,
    )
    with pytest.raises(TypeError, match="image_identity"):
        create(
            validator="cold.worker",
            component_hashes={"database.i64": "0" * 64},
        )


@pytest.mark.parametrize("construction", ["direct", "tampered"])
def test_publish_revalidates_receipt_image_identity(
    tmp_path: Path,
    construction: str,
) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    staging = registry.begin_staging(workspace_id, expected_revision=None)
    staging.database_path.write_bytes(b"candidate")
    component_hashes = hash_staging_payload(staging)
    if construction == "direct":
        receipt = ColdValidationReceipt(
            validator="cold.worker",
            component_hashes=component_hashes,
            image_identity=_invalid_image_identity(),
        )
    else:
        receipt = ColdValidationReceipt.create(
            validator="cold.worker",
            component_hashes=component_hashes,
            image_identity=_pe_image_identity(),
        )
        object.__setattr__(receipt, "image_identity", _invalid_image_identity())

    with pytest.raises(ValueError, match="container"):
        registry.publish_staging(staging, receipt=receipt)

    assert registry.get(workspace_id).current_revision is None
    assert not staging.path.exists()


def test_legacy_revision_manifest_without_image_identity_reads_as_none(
    tmp_path: Path,
) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    published = _publish(registry, workspace_id, None, b"legacy cold idb")
    # 模拟旧版本发布的 revision manifest: 磁盘上缺少 image_identity 键.
    manifest_path = (
        registry.root / workspace_id / "revisions" / published.revision / "revision.json"
    )
    raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    raw.pop("image_identity", None)
    atomic_write_json(manifest_path, raw)

    reopened = WorkspaceRegistry(registry.root, checkout_root=registry.checkout_root)
    restored = reopened.get_revision(workspace_id, published.revision)
    assert restored.image_identity is None


def test_legacy_revision_manifest_identity_without_container_reads_as_none(
    tmp_path: Path,
) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    published = _publish(registry, workspace_id, None, b"legacy cold idb")
    manifest_path = (
        registry.root / workspace_id / "revisions" / published.revision / "revision.json"
    )
    raw = cast(
        dict[str, object],
        json.loads(manifest_path.read_text(encoding="utf-8")),
    )
    identity = cast(dict[str, object], raw["image_identity"])
    assert identity.pop("container") == "pe"
    atomic_write_json(manifest_path, raw)

    reopened = WorkspaceRegistry(registry.root, checkout_root=registry.checkout_root)
    restored = reopened.get_revision(workspace_id, published.revision)
    assert restored.image_identity is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("architecture", "mips64"),
        ("unexpected", "value"),
    ],
)
def test_legacy_revision_manifest_rejects_invalid_identity_evidence(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    published = _publish(registry, workspace_id, None, b"legacy cold idb")
    manifest_path = (
        registry.root / workspace_id / "revisions" / published.revision / "revision.json"
    )
    raw = cast(
        dict[str, object],
        json.loads(manifest_path.read_text(encoding="utf-8")),
    )
    identity = cast(dict[str, object], raw["image_identity"])
    identity.pop("container")
    identity[field] = value
    atomic_write_json(manifest_path, raw)

    reopened = WorkspaceRegistry(registry.root, checkout_root=registry.checkout_root)
    with pytest.raises(StorageCorruptionError, match="revision manifest"):
        reopened.get_revision(workspace_id, published.revision)


def test_record_analysis_outcome_persists_failure_across_reopen(tmp_path: Path) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    registry.record_analysis_outcome(
        workspace_id,
        state="failed",
        reason="bootstrap worker crashed",
    )
    reopened = WorkspaceRegistry(registry.root, checkout_root=registry.checkout_root)
    snapshot = reopened.get(workspace_id)
    assert snapshot.current_revision is None
    assert snapshot.analysis_outcome is not None
    assert snapshot.analysis_outcome.state == "failed"
    assert snapshot.analysis_outcome.reason == "bootstrap worker crashed"


def test_record_analysis_outcome_ignored_once_revision_published(tmp_path: Path) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    _publish(registry, workspace_id, None, b"published cold idb")
    registry.record_analysis_outcome(
        workspace_id,
        state="failed",
        reason="late failure must not overwrite success",
    )
    snapshot = registry.get(workspace_id)
    assert snapshot.current_revision is not None
    assert snapshot.analysis_outcome is None


def test_publish_clears_earlier_analysis_outcome(tmp_path: Path) -> None:
    registry, workspace_id, _ = _new_registry(tmp_path)
    registry.record_analysis_outcome(
        workspace_id,
        state="failed",
        reason="长操作失败",
    )

    _publish(registry, workspace_id, None, b"later successful cold idb")

    snapshot = registry.get(workspace_id)
    assert snapshot.current_revision is not None
    assert snapshot.analysis_outcome is None
