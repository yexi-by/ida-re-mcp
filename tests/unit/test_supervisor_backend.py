from __future__ import annotations

import asyncio
import os
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from ida_re_mcp.supervisor import backend as backend_module
from ida_re_mcp.supervisor._python_process import prepare_python_process_launch
from ida_re_mcp.supervisor.backend import (
    DebugRequestCancelled,
    SubprocessIdaBackend,
)
from ida_re_mcp.supervisor.workers import WorkerProcess, WorkerProcessError
from ida_re_mcp.worker.ipc import JsonObject, JsonValue


class _BlockingWorker:
    def __init__(self, *, debug_result: JsonObject | None = None) -> None:
        self.started = threading.Event()
        self.released = threading.Event()
        self.debug_result = debug_result
        self.request_id: str | None = None
        self.cancelled_request_id: str | None = None
        self.aborted = False
        self.close_calls = 0

    def execute(
        self,
        operation: str,
        input: Mapping[str, JsonValue],
        *,
        timeout_seconds: float,
        request_id: str | None = None,
    ) -> JsonObject:
        del operation, input, timeout_seconds
        self.request_id = request_id
        self.started.set()
        assert self.released.wait(3)
        if self.aborted:
            raise WorkerProcessError("worker_crashed", "worker 已由调用方取消")
        assert self.debug_result is not None
        return self.debug_result

    def cancel(self, request_id: str) -> None:
        self.cancelled_request_id = request_id
        self.released.set()

    def abort(self) -> None:
        self.aborted = True
        self.released.set()

    def close(self) -> None:
        self.close_calls += 1


class _BlockingCleanupWorker(_BlockingWorker):
    def __init__(self) -> None:
        super().__init__()
        self.abort_started = threading.Event()
        self.release_abort = threading.Event()
        self.abort_finished = threading.Event()
        self.close_started = threading.Event()
        self.release_close = threading.Event()
        self.close_finished = threading.Event()

    def abort(self) -> None:
        self.abort_started.set()
        assert self.release_abort.wait(3)
        super().abort()
        self.abort_finished.set()

    def close(self) -> None:
        self.close_started.set()
        assert self.release_close.wait(3)
        super().close()
        self.close_finished.set()


class _AbortRecordingWorker(WorkerProcess):
    def __init__(self) -> None:
        self.abort_calls = 0
        self.abort_started = threading.Event()
        self.release_abort = threading.Event()
        self.abort_finished = threading.Event()

    def abort(self) -> None:
        self.abort_started.set()
        assert self.release_abort.wait(3)
        self.abort_calls += 1
        self.abort_finished.set()


class _ProbeProcess:
    def __init__(self, *, exits_on_terminate: bool) -> None:
        self.returncode: int | None = None
        self.exits_on_terminate = exits_on_terminate
        self.communication_started = asyncio.Event()
        self.exited = asyncio.Event()
        self.actions: list[str] = []

    async def communicate(self) -> tuple[bytes, bytes]:
        self.actions.append("communicate")
        self.communication_started.set()
        await self.exited.wait()
        self.actions.append("communicate.done")
        return b"", b""

    def terminate(self) -> None:
        self.actions.append("terminate")
        if self.exits_on_terminate:
            self.returncode = -15
            self.exited.set()

    def kill(self) -> None:
        self.actions.append("kill")
        self.returncode = -9
        self.exited.set()

    async def wait(self) -> int:
        self.actions.append("wait")
        await self.exited.wait()
        assert self.returncode is not None
        self.actions.append("wait.done")
        return self.returncode


class _CompletedProbeProcess:
    def __init__(
        self,
        *,
        returncode: int,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ) -> None:
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr


def _replace_launch(
    monkeypatch: pytest.MonkeyPatch,
    worker: _BlockingWorker,
) -> None:
    def launch(*_args: object, **_kwargs: object) -> WorkerProcess:
        return cast(WorkerProcess, cast(object, worker))

    monkeypatch.setattr(WorkerProcess, "launch", launch)


def test_debug_cancellation_forwards_request_and_preserves_real_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        worker = _BlockingWorker(
            debug_result={
                "debug_session_id": "debug_123",
                "state": "suspended",
                "stop_id": "stop_456",
                "latest_sequence": 7,
                "cancelled": True,
            }
        )
        _replace_launch(monkeypatch, worker)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")
        debug = await backend.open_debug(
            checkout_path=tmp_path / "checkout.i64",
            sample_path=tmp_path / "sample.exe",
            revision="revision_123",
            allow_attach=False,
        )

        execution = asyncio.create_task(
            debug.execute("debug.control", {"action": "pause"}, timeout_seconds=5)
        )
        assert await asyncio.to_thread(worker.started.wait, 1)
        execution.cancel()

        with pytest.raises(DebugRequestCancelled) as cancelled:
            await execution
        assert cancelled.value.result == worker.debug_result
        assert worker.request_id
        assert worker.cancelled_request_id == worker.request_id
        assert not worker.aborted
        await debug.close()
        assert worker.close_calls == 1

    asyncio.run(scenario())


def test_analysis_cancellation_aborts_persistent_worker_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        worker = _BlockingWorker()
        _replace_launch(monkeypatch, worker)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")

        analysis = await backend.open_analysis(
            checkout_path=tmp_path / "checkout.i64",
            revision="revision_123",
        )
        execution = asyncio.create_task(
            analysis.execute(
                operation="program.overview",
                input={},
                timeout_seconds=5,
            )
        )
        assert await asyncio.to_thread(worker.started.wait, 1)
        execution.cancel()

        with pytest.raises(asyncio.CancelledError):
            await execution
        assert worker.aborted
        assert worker.cancelled_request_id is None
        await analysis.close()
        assert worker.close_calls == 1

    asyncio.run(scenario())


def test_debug_repeated_cancellation_waits_for_forwarding_and_real_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        cancel_started = threading.Event()
        release_cancel = threading.Event()

        class DelayedCancellationWorker(_BlockingWorker):
            def cancel(self, request_id: str) -> None:
                cancel_started.set()
                assert release_cancel.wait(3)
                super().cancel(request_id)

        worker = DelayedCancellationWorker(
            debug_result={
                "state": "suspended",
                "stop_id": "stop_after_cancellation",
                "latest_sequence": 7,
                "cancelled": True,
            }
        )
        _replace_launch(monkeypatch, worker)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")
        debug = await backend.open_debug(
            checkout_path=tmp_path / "checkout.i64",
            sample_path=tmp_path / "sample.exe",
            revision="revision_123",
            allow_attach=False,
        )
        execution = asyncio.create_task(
            debug.execute("debug.control", {"action": "pause"}, timeout_seconds=5)
        )
        try:
            assert await asyncio.to_thread(worker.started.wait, 1)
            execution.cancel()
            assert await asyncio.to_thread(cancel_started.wait, 1)
            execution.cancel()
            await asyncio.sleep(0)
            assert not execution.done()

            release_cancel.set()
            with pytest.raises(DebugRequestCancelled) as cancelled:
                await execution
            assert cancelled.value.result == worker.debug_result
            assert worker.cancelled_request_id == worker.request_id
            assert not worker.aborted
        finally:
            release_cancel.set()
            await asyncio.gather(execution, return_exceptions=True)
            await debug.close()

    asyncio.run(scenario())


def test_analysis_repeated_cancellation_waits_for_abort_to_finish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        worker = _BlockingCleanupWorker()
        _replace_launch(monkeypatch, worker)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")
        analysis = await backend.open_analysis(
            checkout_path=tmp_path / "checkout.i64",
            revision="revision_123",
        )
        execution = asyncio.create_task(analysis.execute("program.overview", {}, timeout_seconds=5))
        assert await asyncio.to_thread(worker.started.wait, 1)

        execution.cancel()
        assert await asyncio.to_thread(worker.abort_started.wait, 1)
        execution.cancel()
        await asyncio.sleep(0)
        assert not execution.done()

        worker.release_abort.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(execution), timeout=1)
        assert worker.abort_finished.is_set()
        assert worker.released.is_set()

        worker.release_close.set()
        await analysis.close()
        assert worker.close_finished.is_set()

    asyncio.run(scenario())


def test_analysis_close_cancellation_waits_for_process_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        worker = _BlockingCleanupWorker()
        _replace_launch(monkeypatch, worker)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")
        analysis = await backend.open_analysis(
            checkout_path=tmp_path / "checkout.i64",
            revision="revision_123",
        )

        closing = asyncio.create_task(analysis.close())
        assert await asyncio.to_thread(worker.close_started.wait, 1)
        closing.cancel()
        await asyncio.sleep(0)
        closing.cancel()
        await asyncio.sleep(0)
        assert not closing.done()

        worker.release_close.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(closing), timeout=1)
        assert worker.close_finished.is_set()
        assert worker.close_calls == 1

    asyncio.run(scenario())


def test_one_shot_repeated_cancellation_waits_for_abort_and_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        worker = _BlockingCleanupWorker()
        _replace_launch(monkeypatch, worker)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")
        execution = asyncio.create_task(
            backend.mutate(
                staging_path=tmp_path / "staging.i64",
                operations=[],
                timeout_seconds=5,
            )
        )
        assert await asyncio.to_thread(worker.started.wait, 1)

        execution.cancel()
        assert await asyncio.to_thread(worker.abort_started.wait, 1)
        execution.cancel()
        await asyncio.sleep(0)
        assert not execution.done()

        worker.release_abort.set()
        assert await asyncio.to_thread(worker.close_started.wait, 1)
        assert worker.abort_finished.is_set()
        execution.cancel()
        await asyncio.sleep(0)
        assert not execution.done()

        worker.release_close.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(asyncio.shield(execution), timeout=1)
        assert worker.close_finished.is_set()
        assert worker.close_calls == 1

    asyncio.run(scenario())


def test_launch_cancellation_aborts_worker_returned_by_launch_thread(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        launch_started = threading.Event()
        release_launch = threading.Event()
        worker = _AbortRecordingWorker()

        def launch(*_args: object, **_kwargs: object) -> WorkerProcess:
            launch_started.set()
            assert release_launch.wait(3)
            return worker

        monkeypatch.setattr(WorkerProcess, "launch", launch)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")
        opening = asyncio.create_task(
            backend.open_analysis(
                checkout_path=tmp_path / "checkout.i64",
                revision="revision_123",
            )
        )
        assert await asyncio.to_thread(launch_started.wait, 1)

        opening.cancel()
        await asyncio.sleep(0)
        release_launch.set()
        assert await asyncio.to_thread(worker.abort_started.wait, 1)
        opening.cancel()
        await asyncio.sleep(0)
        assert not opening.done()
        worker.release_abort.set()

        with pytest.raises(asyncio.CancelledError):
            await opening
        assert worker.abort_calls == 1
        assert worker.abort_finished.is_set()

    asyncio.run(scenario())


def test_doctor_cancellation_terminates_and_reaps_probe_before_propagating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        process = _ProbeProcess(exits_on_terminate=True)

        async def create_subprocess_exec(
            *_args: str,
            **_kwargs: object,
        ) -> asyncio.subprocess.Process:
            return cast(asyncio.subprocess.Process, cast(object, process))

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_subprocess_exec)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")
        execution = asyncio.create_task(backend.doctor())
        await asyncio.wait_for(process.communication_started.wait(), timeout=1)

        execution.cancel()

        with pytest.raises(asyncio.CancelledError):
            await execution
        assert process.returncode == -15
        assert process.actions.count("terminate") == 1
        assert process.actions.count("wait") == 1
        assert "kill" not in process.actions
        assert "communicate.done" in process.actions
        assert "wait.done" in process.actions
        assert process.actions.index("terminate") < process.actions.index("wait.done")

    asyncio.run(scenario())


def test_doctor_launches_the_real_venv_python_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        process = _CompletedProbeProcess(returncode=0, stdout=b'{"available":true}')
        captured_args: tuple[str, ...] | None = None
        captured_environment: dict[str, str] | None = None

        async def create_subprocess_exec(
            *args: str,
            **kwargs: object,
        ) -> asyncio.subprocess.Process:
            nonlocal captured_args, captured_environment
            captured_args = args
            environment = kwargs.get("env")
            assert isinstance(environment, dict)
            captured_environment = cast(dict[str, str], environment)
            return cast(asyncio.subprocess.Process, cast(object, process))

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_subprocess_exec)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")

        report = await backend.doctor()

        expected_executable, expected_environment = prepare_python_process_launch(os.environ)
        assert report["available"] is True
        assert captured_args == (
            expected_executable,
            "-m",
            "ida_re_mcp.worker",
            "probe",
        )
        assert captured_environment is not None
        assert captured_environment.get("__PYVENV_LAUNCHER__") == expected_environment.get(
            "__PYVENV_LAUNCHER__"
        )

    asyncio.run(scenario())


def test_doctor_cancellation_waits_for_inflight_probe_launch_then_reaps_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        process = _ProbeProcess(exits_on_terminate=True)
        launch_started = asyncio.Event()
        release_launch = asyncio.Event()

        async def create_subprocess_exec(
            *_args: str,
            **_kwargs: object,
        ) -> asyncio.subprocess.Process:
            launch_started.set()
            await release_launch.wait()
            return cast(asyncio.subprocess.Process, cast(object, process))

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_subprocess_exec)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")
        execution = asyncio.create_task(backend.doctor())
        await asyncio.wait_for(launch_started.wait(), timeout=1)

        execution.cancel()
        await asyncio.sleep(0)
        assert not execution.done()
        release_launch.set()

        with pytest.raises(asyncio.CancelledError):
            await execution
        assert process.returncode == -15
        assert process.actions.count("communicate") == 1
        assert process.actions.count("terminate") == 1
        assert process.actions.count("wait") == 1
        assert "kill" not in process.actions
        assert "communicate.done" in process.actions
        assert "wait.done" in process.actions

    asyncio.run(scenario())


def test_doctor_timeout_kills_and_reaps_probe_that_ignores_terminate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        process = _ProbeProcess(exits_on_terminate=False)

        async def create_subprocess_exec(
            *_args: str,
            **_kwargs: object,
        ) -> asyncio.subprocess.Process:
            return cast(asyncio.subprocess.Process, cast(object, process))

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_subprocess_exec)
        monkeypatch.setattr(backend_module, "_PROBE_TIMEOUT_SECONDS", 0.01)
        monkeypatch.setattr(backend_module, "_PROBE_TERMINATE_SECONDS", 0.01)
        backend = SubprocessIdaBackend(log_root=tmp_path / "logs")

        with pytest.raises(TimeoutError):
            await backend.doctor()
        assert process.returncode == -9
        assert process.actions[0:3] == ["communicate", "terminate", "wait"]
        assert process.actions.count("kill") == 1
        assert process.actions.count("wait") == 1
        assert "communicate.done" in process.actions
        assert "wait.done" in process.actions
        assert process.actions.index("terminate") < process.actions.index("kill")
        assert process.actions.index("kill") < process.actions.index("wait.done")

    asyncio.run(scenario())


def test_doctor_writes_raw_probe_error_to_log_without_exposing_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        sensitive = b"Traceback: C:\\Users\\private\\ida-probe.py"
        process = _CompletedProbeProcess(returncode=7, stderr=sensitive)

        async def create_subprocess_exec(
            *_args: str,
            **_kwargs: object,
        ) -> asyncio.subprocess.Process:
            return cast(asyncio.subprocess.Process, cast(object, process))

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_subprocess_exec)
        log_root = tmp_path / "logs"
        backend = SubprocessIdaBackend(log_root=log_root)

        report = await backend.doctor()

        assert report["available"] is False
        assert report["code"] == "worker_probe_failed"
        assert "stderr" not in report
        assert "C:\\Users\\private" not in str(report)
        assert sensitive in (log_root / "doctor-probe.log").read_bytes()

    asyncio.run(scenario())
