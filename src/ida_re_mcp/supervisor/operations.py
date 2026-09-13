"""可持久恢复的长操作状态机。"""

from __future__ import annotations

import json
import math
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, cast

from ida_re_mcp.constants import MAX_OPERATION_WAIT_MS, OPERATION_RETENTION_SECONDS
from ida_re_mcp.supervisor._fs import atomic_write_json, validate_identifier
from ida_re_mcp.supervisor.errors import OperationNotFoundError, OperationStateError

type JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


class OperationState(StrEnum):
    """长操作的全部合法状态。"""

    QUEUED = "queued"
    RUNNING = "running"
    CANCEL_REQUESTED = "cancel_requested"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


_TERMINAL_STATES: Final = frozenset(
    {
        OperationState.SUCCEEDED,
        OperationState.FAILED,
        OperationState.CANCELLED,
    }
)
_RECORD_KEYS: Final = frozenset(
    {
        "operation_id",
        "kind",
        "workspace_id",
        "state",
        "created_at",
        "updated_at",
        "finished_at",
        "result",
        "failure",
    }
)


@dataclass(frozen=True, slots=True)
class OperationFailure:
    """可安全公开的业务失败。"""

    code: str
    message: str
    details: JsonValue = None


@dataclass(frozen=True, slots=True)
class OperationSnapshot:
    """operation 的不可变查询快照。"""

    operation_id: str
    kind: str
    workspace_id: str | None
    state: OperationState
    created_at: float
    updated_at: float
    finished_at: float | None
    result: JsonValue
    failure: OperationFailure | None

    @property
    def terminal(self) -> bool:
        return self.state in _TERMINAL_STATES


@dataclass(frozen=True, slots=True)
class OperationRecovery:
    """由更强持久化提交凭据证明的 operation 成功结果。"""

    result: JsonValue


@dataclass(slots=True)
class _OperationEntry:
    operation_id: str
    kind: str
    workspace_id: str | None
    state: OperationState
    created_at: float
    updated_at: float
    finished_at: float | None = None
    result: JsonValue = None
    failure: OperationFailure | None = None


class OperationCoordinator:
    """线程安全的 operation 状态机与最长 30 秒等待接口。"""

    def __init__(
        self,
        *,
        storage_root: Path | None = None,
        retention_seconds: int = OPERATION_RETENTION_SECONDS,
        clock: Callable[[], float] = time.time,
        recover_incomplete: Callable[[OperationSnapshot], OperationRecovery | None] | None = None,
    ) -> None:
        if isinstance(retention_seconds, bool) or retention_seconds < 1:
            raise ValueError("retention_seconds 必须为正整数")
        self._retention_seconds = retention_seconds
        self._clock = clock
        self._recover_incomplete = recover_incomplete
        self._condition = threading.Condition(threading.RLock())
        self._entries: dict[str, _OperationEntry] = {}
        self._storage_root = storage_root.resolve() if storage_root is not None else None
        if self._storage_root is not None:
            self._storage_root.mkdir(parents=True, exist_ok=True)
            self._load_current_records()

    def create(self, kind: str, *, workspace_id: str | None = None) -> OperationSnapshot:
        validate_identifier(kind, field="kind")
        if workspace_id is not None:
            validate_identifier(workspace_id, field="workspace_id")
        now = self._clock()
        entry = _OperationEntry(
            operation_id=f"op_{uuid.uuid4().hex}",
            kind=kind,
            workspace_id=workspace_id,
            state=OperationState.QUEUED,
            created_at=now,
            updated_at=now,
        )
        with self._condition:
            self._purge_locked(now)
            self._entries[entry.operation_id] = entry
            try:
                self._persist_locked(entry)
            except BaseException:
                del self._entries[entry.operation_id]
                raise
            self._condition.notify_all()
            return _snapshot(entry)

    def get(self, operation_id: str) -> OperationSnapshot:
        with self._condition:
            entry = self._require_locked(operation_id, now=self._clock())
            return _snapshot(entry)

    def start(self, operation_id: str) -> OperationSnapshot:
        with self._condition:
            entry = self._require_locked(operation_id, now=self._clock())
            self._require_state(entry, {OperationState.QUEUED})
            self._set_state(entry, OperationState.RUNNING)
            return _snapshot(entry)

    def wait(self, operation_id: str, *, wait_ms: int = 0) -> OperationSnapshot:
        """等待终态或超时; 非终态返回当前快照, 不伪造完成。"""

        if isinstance(wait_ms, bool) or wait_ms < 0 or wait_ms > MAX_OPERATION_WAIT_MS:
            raise ValueError(f"wait_ms 必须位于 0..{MAX_OPERATION_WAIT_MS}")

        deadline = time.monotonic() + (wait_ms / 1000)
        with self._condition:
            entry = self._require_locked(operation_id, now=self._clock())
            while entry.state not in _TERMINAL_STATES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=remaining)
                entry = self._require_locked(operation_id, now=self._clock())
            return _snapshot(entry)

    def cancel(self, operation_id: str) -> OperationSnapshot:
        """请求取消; 运行中的工作必须由执行者确认后才进入 cancelled。"""

        with self._condition:
            entry = self._require_locked(operation_id, now=self._clock())
            if entry.state is OperationState.QUEUED:
                self._set_state(entry, OperationState.CANCELLED, terminal=True)
            elif entry.state is OperationState.RUNNING:
                self._set_state(entry, OperationState.CANCEL_REQUESTED)
            elif entry.state is OperationState.CANCEL_REQUESTED:
                pass
            elif entry.state not in _TERMINAL_STATES:
                raise OperationStateError(f"无法从 {entry.state} 请求取消")
            return _snapshot(entry)

    def acknowledge_cancel(self, operation_id: str) -> OperationSnapshot:
        with self._condition:
            entry = self._require_locked(operation_id, now=self._clock())
            self._require_state(entry, {OperationState.CANCEL_REQUESTED})
            self._set_state(entry, OperationState.CANCELLED, terminal=True)
            return _snapshot(entry)

    def succeed(self, operation_id: str, result: object = None) -> OperationSnapshot:
        with self._condition:
            entry = self._require_locked(operation_id, now=self._clock())
            self._require_state(
                entry,
                {OperationState.RUNNING, OperationState.CANCEL_REQUESTED},
            )
            previous_result = entry.result
            previous_failure = entry.failure
            entry.result = _copy_json(result)
            entry.failure = None
            try:
                self._set_state(entry, OperationState.SUCCEEDED, terminal=True)
            except BaseException:
                entry.result = previous_result
                entry.failure = previous_failure
                raise
            return _snapshot(entry)

    def fail(
        self,
        operation_id: str,
        *,
        code: str,
        message: str,
        details: object = None,
    ) -> OperationSnapshot:
        validate_identifier(code, field="failure code")
        if not message:
            raise ValueError("failure message 不得为空")
        with self._condition:
            entry = self._require_locked(operation_id, now=self._clock())
            self._require_state(
                entry,
                {OperationState.RUNNING, OperationState.CANCEL_REQUESTED},
            )
            previous_result = entry.result
            previous_failure = entry.failure
            entry.failure = OperationFailure(
                code=code,
                message=message,
                details=_copy_json(details),
            )
            entry.result = None
            try:
                self._set_state(entry, OperationState.FAILED, terminal=True)
            except BaseException:
                entry.result = previous_result
                entry.failure = previous_failure
                raise
            return _snapshot(entry)

    def is_cancel_requested(self, operation_id: str) -> bool:
        return self.get(operation_id).state is OperationState.CANCEL_REQUESTED

    def latest(
        self,
        *,
        workspace_id: str,
        kind: str,
    ) -> OperationSnapshot | None:
        """返回指定 workspace 与 kind 的最新保留记录。"""

        validate_identifier(workspace_id, field="workspace_id")
        validate_identifier(kind, field="kind")
        with self._condition:
            self._purge_locked(self._clock())
            matches = [
                entry
                for entry in self._entries.values()
                if entry.workspace_id == workspace_id and entry.kind == kind
            ]
            if not matches:
                return None
            return _snapshot(
                max(
                    matches,
                    key=lambda entry: (entry.created_at, entry.operation_id),
                )
            )

    def purge_expired(self) -> int:
        with self._condition:
            return self._purge_locked(self._clock())

    def _require_locked(self, operation_id: str, *, now: float) -> _OperationEntry:
        validate_identifier(operation_id, field="operation_id")
        self._purge_locked(now)
        try:
            return self._entries[operation_id]
        except KeyError as exc:
            raise OperationNotFoundError(f"operation 不存在: {operation_id}") from exc

    @staticmethod
    def _require_state(
        entry: _OperationEntry,
        expected: set[OperationState],
    ) -> None:
        if entry.state not in expected:
            choices = ", ".join(sorted(state.value for state in expected))
            raise OperationStateError(
                f"operation {entry.operation_id} 当前为 {entry.state.value}, 要求 {choices}"
            )

    def _set_state(
        self,
        entry: _OperationEntry,
        state: OperationState,
        *,
        terminal: bool = False,
    ) -> None:
        # 系统时钟可能因校时回拨；同一记录的时间仍须符合持久化读取约束。
        now = max(self._clock(), entry.updated_at)
        previous = (entry.state, entry.updated_at, entry.finished_at)
        entry.state = state
        entry.updated_at = now
        entry.finished_at = now if terminal else None
        try:
            self._persist_locked(entry)
        except BaseException:
            entry.state, entry.updated_at, entry.finished_at = previous
            raise
        self._condition.notify_all()

    def _purge_locked(self, now: float) -> int:
        expired = [
            operation_id
            for operation_id, entry in self._entries.items()
            if entry.finished_at is not None and now - entry.finished_at >= self._retention_seconds
        ]
        for operation_id in expired:
            path = self._record_path(operation_id)
            if path is not None:
                path.unlink(missing_ok=True)
            del self._entries[operation_id]
        return len(expired)

    def _record_path(self, operation_id: str) -> Path | None:
        if self._storage_root is None:
            return None
        return self._storage_root / f"{operation_id}.json"

    def _persist_locked(self, entry: _OperationEntry) -> None:
        path = self._record_path(entry.operation_id)
        if path is None:
            return
        failure: dict[str, object] | None = None
        if entry.failure is not None:
            failure = {
                "code": entry.failure.code,
                "message": entry.failure.message,
                "details": entry.failure.details,
            }
        atomic_write_json(
            path,
            {
                "operation_id": entry.operation_id,
                "kind": entry.kind,
                "workspace_id": entry.workspace_id,
                "state": entry.state.value,
                "created_at": entry.created_at,
                "updated_at": entry.updated_at,
                "finished_at": entry.finished_at,
                "result": entry.result,
                "failure": failure,
            },
        )

    def _load_current_records(self) -> None:
        root = self._storage_root
        assert root is not None
        now = self._clock()
        for path in sorted(root.glob("op_*.json")):
            try:
                value: object = json.loads(
                    path.read_text(encoding="utf-8"),
                    object_pairs_hook=_unique_json_object,
                    parse_constant=_reject_json_constant,
                )
                entry = _entry_from_record(value)
            except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                raise OperationStateError(f"operation 记录损坏: {path.name}") from exc
            if path.name != f"{entry.operation_id}.json":
                raise OperationStateError(f"operation 记录文件名与身份不一致: {path.name}")
            if entry.operation_id in self._entries:
                raise OperationStateError(f"operation 记录身份重复: {entry.operation_id}")
            if entry.state not in _TERMINAL_STATES:
                recovered = (
                    self._recover_incomplete(_snapshot(entry))
                    if self._recover_incomplete is not None
                    else None
                )
                entry.state = (
                    OperationState.SUCCEEDED if recovered is not None else OperationState.FAILED
                )
                entry.updated_at = max(now, entry.updated_at)
                entry.finished_at = entry.updated_at
                entry.result = _copy_json(recovered.result) if recovered is not None else None
                entry.failure = (
                    None
                    if recovered is not None
                    else OperationFailure(
                        code="worker_crashed",
                        message="服务重启前的操作未完成",
                    )
                )
                self._persist_locked(entry)
            self._entries[entry.operation_id] = entry
        self._purge_locked(now)


def _snapshot(entry: _OperationEntry) -> OperationSnapshot:
    failure = entry.failure
    if failure is not None:
        failure = OperationFailure(
            code=failure.code,
            message=failure.message,
            details=_copy_json(failure.details),
        )
    return OperationSnapshot(
        operation_id=entry.operation_id,
        kind=entry.kind,
        workspace_id=entry.workspace_id,
        state=entry.state,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
        finished_at=entry.finished_at,
        result=_copy_json(entry.result),
        failure=failure,
    )


def _entry_from_record(value: object) -> _OperationEntry:
    if not isinstance(value, dict):
        raise ValueError("operation 记录必须是对象")
    record = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in record):
        raise ValueError("operation 记录字段不符合当前格式")
    record_keys = {cast(str, key) for key in record}
    if record_keys != set(_RECORD_KEYS):
        raise ValueError("operation 记录字段不符合当前格式")
    typed = cast(Mapping[str, object], record)

    operation_id = typed["operation_id"]
    kind = typed["kind"]
    workspace_id = typed["workspace_id"]
    if not isinstance(operation_id, str) or not operation_id.startswith("op_"):
        raise ValueError("operation_id 无效")
    validate_identifier(operation_id, field="operation_id")
    if not isinstance(kind, str):
        raise ValueError("operation kind 无效")
    validate_identifier(kind, field="kind")
    if workspace_id is not None:
        if not isinstance(workspace_id, str):
            raise ValueError("operation workspace_id 无效")
        validate_identifier(workspace_id, field="workspace_id")

    raw_state = typed["state"]
    if not isinstance(raw_state, str):
        raise ValueError("operation state 无效")
    try:
        state = OperationState(raw_state)
    except ValueError as exc:
        raise ValueError("operation state 无效") from exc

    created_at = _record_time(typed["created_at"], "created_at")
    updated_at = _record_time(typed["updated_at"], "updated_at")
    raw_finished_at = typed["finished_at"]
    finished_at = None if raw_finished_at is None else _record_time(raw_finished_at, "finished_at")
    if updated_at < created_at or (finished_at is not None and finished_at < updated_at):
        raise ValueError("operation 时间顺序无效")
    if (state in _TERMINAL_STATES) != (finished_at is not None):
        raise ValueError("operation 终态时间无效")

    result = _copy_json(typed["result"])
    raw_failure = typed["failure"]
    failure: OperationFailure | None = None
    if raw_failure is not None:
        if not isinstance(raw_failure, dict):
            raise ValueError("operation failure 无效")
        failure_record = cast(dict[object, object], raw_failure)
        if set(failure_record) != {"code", "message", "details"}:
            raise ValueError("operation failure 字段无效")
        code = failure_record["code"]
        message = failure_record["message"]
        if not isinstance(code, str) or not isinstance(message, str) or not message:
            raise ValueError("operation failure 内容无效")
        validate_identifier(code, field="failure code")
        failure = OperationFailure(
            code=code,
            message=message,
            details=_copy_json(failure_record["details"]),
        )
    if (state is OperationState.FAILED) != (failure is not None):
        raise ValueError("operation failure 与状态不一致")
    if state is not OperationState.SUCCEEDED and result is not None:
        raise ValueError("非成功 operation 不得持有 result")

    return _OperationEntry(
        operation_id=operation_id,
        kind=kind,
        workspace_id=workspace_id,
        state=state,
        created_at=created_at,
        updated_at=updated_at,
        finished_at=finished_at,
        result=result,
        failure=failure,
    )


def _record_time(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"operation {field} 无效")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"operation {field} 无效")
    return result


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"operation 记录包含重复字段: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"operation 记录包含非有限数值: {value}")


def _copy_json(value: object) -> JsonValue:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON 数字必须有限")
        return value
    if isinstance(value, list):
        return [_copy_json(item) for item in cast(list[object], value)]
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key, item in cast(dict[object, object], value).items():
            if not isinstance(key, str):
                raise ValueError("JSON 对象键必须是字符串")
            result[key] = _copy_json(item)
        return result
    raise ValueError("值必须是当前 JSON 数据")
