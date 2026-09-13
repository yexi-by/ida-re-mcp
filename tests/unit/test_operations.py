from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

import pytest

from ida_re_mcp.constants import MAX_OPERATION_WAIT_MS, OPERATION_RETENTION_SECONDS
from ida_re_mcp.supervisor import (
    OperationCoordinator,
    OperationNotFoundError,
    OperationSnapshot,
    OperationState,
    OperationStateError,
)
from ida_re_mcp.supervisor.operations import JsonValue, OperationRecovery


@dataclass
class ManualClock:
    value: float = 1_000.0

    def __call__(self) -> float:
        return self.value


def test_operation_happy_path_and_json_snapshot_isolation() -> None:
    coordinator = OperationCoordinator()
    queued = coordinator.create("workspace.analyze", workspace_id="ws_example")
    assert queued.state is OperationState.QUEUED

    running = coordinator.start(queued.operation_id)
    assert running.state is OperationState.RUNNING

    source = {"items": [{"value": 1}]}
    completed = coordinator.succeed(queued.operation_id, source)
    source["items"][0]["value"] = 99

    assert completed.state is OperationState.SUCCEEDED
    assert completed.terminal is True
    assert completed.result == {"items": [{"value": 1}]}
    assert coordinator.get(queued.operation_id).result == {"items": [{"value": 1}]}


def test_running_cancel_requires_executor_acknowledgement() -> None:
    coordinator = OperationCoordinator()
    operation = coordinator.create("debug.establish")
    coordinator.start(operation.operation_id)

    requested = coordinator.cancel(operation.operation_id)
    assert requested.state is OperationState.CANCEL_REQUESTED
    assert requested.terminal is False
    assert coordinator.is_cancel_requested(operation.operation_id)

    cancelled = coordinator.acknowledge_cancel(operation.operation_id)
    assert cancelled.state is OperationState.CANCELLED
    assert cancelled.terminal is True


def test_queued_cancel_is_immediately_terminal() -> None:
    coordinator = OperationCoordinator()
    operation = coordinator.create("report.build")

    cancelled = coordinator.cancel(operation.operation_id)

    assert cancelled.state is OperationState.CANCELLED
    with pytest.raises(OperationStateError):
        coordinator.start(operation.operation_id)


def test_wait_wakes_only_after_real_terminal_transition() -> None:
    coordinator = OperationCoordinator()
    operation = coordinator.create("analysis.refine")
    coordinator.start(operation.operation_id)
    waiter_started = threading.Event()
    result: list[OperationState] = []

    def wait_for_result() -> None:
        waiter_started.set()
        result.append(coordinator.wait(operation.operation_id, wait_ms=2_000).state)

    thread = threading.Thread(target=wait_for_result)
    thread.start()
    assert waiter_started.wait(timeout=1)
    coordinator.succeed(operation.operation_id, {"revision": "rev_next"})
    thread.join(timeout=2)

    assert not thread.is_alive()
    assert result == [OperationState.SUCCEEDED]


def test_wait_limit_is_strict() -> None:
    coordinator = OperationCoordinator()
    operation = coordinator.create("program.search")

    with pytest.raises(ValueError):
        coordinator.wait(operation.operation_id, wait_ms=MAX_OPERATION_WAIT_MS + 1)
    with pytest.raises(ValueError):
        coordinator.wait(operation.operation_id, wait_ms=True)


def test_terminal_operations_expire_after_retention() -> None:
    clock = ManualClock()
    coordinator = OperationCoordinator(clock=clock)
    operation = coordinator.create("workspace.export")
    coordinator.start(operation.operation_id)
    coordinator.succeed(operation.operation_id)

    clock.value += OPERATION_RETENTION_SECONDS + 1

    with pytest.raises(OperationNotFoundError):
        coordinator.get(operation.operation_id)


def test_failure_is_structured_and_does_not_expose_non_json_data() -> None:
    coordinator = OperationCoordinator()
    operation = coordinator.create("workspace.analyze")
    coordinator.start(operation.operation_id)

    failed = coordinator.fail(
        operation.operation_id,
        code="worker_crashed",
        message="worker 已退出",
        details={"exit_code": 7},
    )

    assert failed.state is OperationState.FAILED
    assert failed.failure is not None
    assert failed.failure.code == "worker_crashed"
    with pytest.raises(OperationStateError):
        coordinator.succeed(operation.operation_id)


def test_result_rejects_non_string_object_keys_without_changing_state() -> None:
    coordinator = OperationCoordinator()
    operation = coordinator.create("program.overview")
    coordinator.start(operation.operation_id)

    with pytest.raises(ValueError, match="键"):
        coordinator.succeed(operation.operation_id, {1: "invalid"})

    assert coordinator.get(operation.operation_id).state is OperationState.RUNNING


def test_terminal_operation_survives_coordinator_restart(tmp_path: Path) -> None:
    root = tmp_path / "operations"
    first = OperationCoordinator(storage_root=root)
    operation = first.create("workspace.export", workspace_id="workspace_example")
    first.start(operation.operation_id)
    first.succeed(operation.operation_id, {"artifact": "ida-re://example"})

    reopened = OperationCoordinator(storage_root=root)
    restored = reopened.get(operation.operation_id)

    assert restored.state is OperationState.SUCCEEDED
    assert restored.result == {"artifact": "ida-re://example"}
    latest = reopened.latest(
        workspace_id="workspace_example",
        kind="workspace.export",
    )
    assert latest is not None
    assert latest.operation_id == operation.operation_id


def test_clock_rollback_keeps_terminal_record_readable(tmp_path: Path) -> None:
    root = tmp_path / "operations"
    clock = ManualClock()
    coordinator = OperationCoordinator(storage_root=root, clock=clock)
    operation = coordinator.create("workspace.export")
    clock.value += 10
    running = coordinator.start(operation.operation_id)
    clock.value -= 20
    completed = coordinator.succeed(operation.operation_id, {"revision": "rev_ready"})

    restored = OperationCoordinator(storage_root=root, clock=clock).get(operation.operation_id)

    assert restored == completed
    assert restored.updated_at >= running.updated_at
    assert restored.finished_at == restored.updated_at


def test_clock_rollback_during_recovery_keeps_record_readable(tmp_path: Path) -> None:
    root = tmp_path / "operations"
    clock = ManualClock()
    coordinator = OperationCoordinator(storage_root=root, clock=clock)
    operation = coordinator.create("analysis.refine")
    clock.value += 10
    running = coordinator.start(operation.operation_id)
    clock.value -= 20

    recovered = OperationCoordinator(storage_root=root, clock=clock).get(operation.operation_id)
    reopened = OperationCoordinator(storage_root=root, clock=clock).get(operation.operation_id)

    assert recovered.state is OperationState.FAILED
    assert reopened == recovered
    assert reopened.updated_at >= running.updated_at
    assert reopened.finished_at == reopened.updated_at


@pytest.mark.parametrize(
    "state",
    [
        OperationState.QUEUED,
        OperationState.RUNNING,
        OperationState.CANCEL_REQUESTED,
    ],
)
def test_restart_recovers_every_nonterminal_state_from_commit_receipt(
    tmp_path: Path,
    state: OperationState,
) -> None:
    root = tmp_path / state.value
    first = OperationCoordinator(storage_root=root)
    operation = first.create("analysis.refine", workspace_id="workspace_example")
    if state in {OperationState.RUNNING, OperationState.CANCEL_REQUESTED}:
        first.start(operation.operation_id)
    if state is OperationState.CANCEL_REQUESTED:
        first.cancel(operation.operation_id)

    recovered_snapshots: list[OperationSnapshot] = []
    receipt_result: dict[str, JsonValue] = {
        "workspace_id": "workspace_example",
        "revision": "rev_committed",
        "actions": [
            {"kind": "rename_function", "entity_id": "function:entry"},
            {"kind": "set_comment", "repeatable": False},
        ],
    }

    def recover(snapshot: OperationSnapshot) -> OperationRecovery:
        recovered_snapshots.append(snapshot)
        return OperationRecovery(result=receipt_result)

    reopened = OperationCoordinator(
        storage_root=root,
        recover_incomplete=recover,
    )
    receipt_result["revision"] = "rev_mutated_after_recovery"
    restored = reopened.get(operation.operation_id)

    assert len(recovered_snapshots) == 1
    assert recovered_snapshots[0].operation_id == operation.operation_id
    assert recovered_snapshots[0].state is state
    assert restored.state is OperationState.SUCCEEDED
    assert restored.terminal is True
    assert restored.failure is None
    assert restored.result == {
        "workspace_id": "workspace_example",
        "revision": "rev_committed",
        "actions": [
            {"kind": "rename_function", "entity_id": "function:entry"},
            {"kind": "set_comment", "repeatable": False},
        ],
    }

    def reject_terminal_recovery(_snapshot: OperationSnapshot) -> OperationRecovery | None:
        pytest.fail("终态 operation 不应再次调用恢复器")

    persisted = OperationCoordinator(
        storage_root=root,
        recover_incomplete=reject_terminal_recovery,
    ).get(operation.operation_id)
    assert persisted.state is OperationState.SUCCEEDED
    assert persisted.result == restored.result


def test_restart_marks_incomplete_operation_failed(tmp_path: Path) -> None:
    root = tmp_path / "operations"
    first = OperationCoordinator(storage_root=root)
    operation = first.create("analysis.refine", workspace_id="workspace_example")
    first.start(operation.operation_id)

    unresolved: list[OperationSnapshot] = []

    def recover(snapshot: OperationSnapshot) -> None:
        unresolved.append(snapshot)
        return None

    reopened = OperationCoordinator(
        storage_root=root,
        recover_incomplete=recover,
    )
    restored = reopened.get(operation.operation_id)

    assert [snapshot.operation_id for snapshot in unresolved] == [operation.operation_id]
    assert restored.state is OperationState.FAILED
    assert restored.failure is not None
    assert restored.failure.code == "worker_crashed"
    assert restored.result is None


def test_persistent_operation_rejects_corrupt_current_record(tmp_path: Path) -> None:
    root = tmp_path / "operations"
    root.mkdir()
    (root / "op_corrupt.json").write_text('{"state":"succeeded"}', encoding="utf-8")

    with pytest.raises(OperationStateError, match="记录损坏"):
        OperationCoordinator(storage_root=root)
