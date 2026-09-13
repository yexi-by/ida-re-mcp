# pyright: reportPrivateUsage=false
"""验证不依赖 IDA runtime 的保守 microcode 图算法。"""

from __future__ import annotations

from pathlib import Path

import pytest

from ida_re_mcp.worker.analysis import (
    AnalysisWorker,
    _BarrierReason,
    _MicroInstruction,
    _MicroProgram,
)


def _instruction(
    index: int,
    block: int,
    position: int,
    *,
    definitions: frozenset[str] = frozenset(),
    uses: frozenset[str] = frozenset(),
    barrier: _BarrierReason | None = None,
) -> _MicroInstruction:
    return _MicroInstruction(
        index=index,
        block=block,
        position=position,
        address=f"0x{0x401000 + index * 4:x}",
        opcode=index,
        text=f"micro_{index}",
        definitions=definitions,
        uses=uses,
        barrier=barrier,
    )


def _worker(tmp_path: Path) -> AnalysisWorker:
    checkout = tmp_path / "analysis.i64"
    checkout.write_bytes(b"private-checkout")
    return AnalysisWorker(checkout)


def test_may_backward_collects_every_cfg_reaching_definition(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    instructions = (
        _instruction(0, 0, 0, definitions=frozenset({"reg:0:8"})),
        _instruction(1, 1, 0, definitions=frozenset({"reg:0:4"})),
        _instruction(2, 2, 0, uses=frozenset({"reg:0:8"})),
    )
    program = _MicroProgram(
        instructions=instructions,
        block_instructions={0: (0,), 1: (1,), 2: (2,)},
        predecessors={0: (), 1: (), 2: (0, 1)},
        successors={0: (2,), 1: (2,), 2: ()},
    )

    selected, edges, barriers, limit_hit = worker._may_slice(
        program,
        [2],
        direction="backward",
        limit=10,
    )

    assert selected == {0, 1, 2}
    assert edges == {(0, 2), (1, 2)}
    assert barriers == {}
    assert limit_hit is False


@pytest.mark.parametrize("kind", ["reg", "stack", "global"])
def test_may_tracks_remaining_bytes_after_partial_writes(tmp_path: Path, kind: str) -> None:
    worker = _worker(tmp_path)
    full = f"{kind}:0:8"
    low = f"{kind}:0:4"
    high = f"{kind}:4:4"
    instructions = (
        _instruction(0, 0, 0, definitions=frozenset({full})),
        _instruction(1, 0, 1, definitions=frozenset({low})),
        _instruction(2, 1, 0, uses=frozenset({full})),
        _instruction(3, 1, 1, definitions=frozenset({high})),
        _instruction(4, 1, 2, uses=frozenset({full})),
    )
    program = _MicroProgram(
        instructions=instructions,
        block_instructions={0: (0, 1), 1: (2, 3, 4)},
        predecessors={0: (), 1: (0,)},
        successors={0: (1,), 1: ()},
    )

    partial = worker._may_slice(program, [2], direction="backward", limit=10)
    assert partial == ({0, 1, 2}, {(0, 2), (1, 2)}, {}, False)

    overwritten = worker._may_slice(program, [4], direction="backward", limit=10)
    assert overwritten == ({1, 3, 4}, {(1, 4), (3, 4)}, {}, False)

    forward = worker._may_slice(program, [0], direction="forward", limit=10)
    assert forward == ({0, 2}, {(0, 2)}, {}, False)


def test_may_stops_at_unknown_call_and_reports_the_barrier(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    instructions = (
        _instruction(0, 0, 0, definitions=frozenset({"reg:0:8"})),
        _instruction(1, 1, 0, barrier="unknown_call"),
        _instruction(2, 1, 1, uses=frozenset({"reg:0:8"})),
    )
    program = _MicroProgram(
        instructions=instructions,
        block_instructions={0: (0,), 1: (1, 2)},
        predecessors={0: (), 1: (0,)},
        successors={0: (1,), 1: ()},
    )

    selected, edges, barriers, limit_hit = worker._may_slice(
        program,
        [2],
        direction="backward",
        limit=10,
    )

    assert selected == {2}
    assert edges == set()
    assert barriers == {(1, "unknown_call"): None}
    assert limit_hit is False


def test_must_backward_proves_same_definition_across_cfg_merge(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    instructions = (
        _instruction(0, 0, 0, definitions=frozenset({"reg:0:8"})),
        _instruction(1, 3, 0, uses=frozenset({"reg:0:8"})),
    )
    program = _MicroProgram(
        instructions=instructions,
        block_instructions={0: (0,), 1: (), 2: (), 3: (1,)},
        predecessors={0: (), 1: (0,), 2: (0,), 3: (1, 2)},
        successors={0: (1, 2), 1: (3,), 2: (3,), 3: ()},
    )

    selected, edges, barriers, limit_hit = worker._must_slice(
        program,
        [1],
        direction="backward",
        limit=10,
    )

    assert selected == {0, 1}
    assert edges == {(0, 1)}
    assert barriers == {}
    assert limit_hit is False


def test_must_backward_omits_divergent_merge_definitions(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    instructions = (
        _instruction(0, 0, 0, definitions=frozenset({"reg:0:8"})),
        _instruction(1, 1, 0, definitions=frozenset({"reg:0:8"})),
        _instruction(2, 2, 0, uses=frozenset({"reg:0:8"})),
    )
    program = _MicroProgram(
        instructions=instructions,
        block_instructions={0: (0,), 1: (1,), 2: (2,)},
        predecessors={0: (), 1: (), 2: (0, 1)},
        successors={0: (2,), 1: (2,), 2: ()},
    )

    selected, edges, barriers, limit_hit = worker._must_slice(
        program,
        [2],
        direction="backward",
        limit=10,
    )

    assert selected == {2}
    assert edges == set()
    assert barriers == {}
    assert limit_hit is False


def test_must_backward_fixed_point_handles_loop_backedge(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    instructions = (
        _instruction(0, 0, 0, definitions=frozenset({"reg:0:8"})),
        _instruction(1, 1, 0, uses=frozenset({"reg:0:8"})),
        _instruction(2, 2, 0, uses=frozenset({"reg:8:8"})),
    )
    program = _MicroProgram(
        instructions=instructions,
        block_instructions={0: (0,), 1: (1,), 2: (2,)},
        predecessors={0: (), 1: (0, 2), 2: (1,)},
        successors={0: (1,), 1: (2,), 2: (1,)},
    )

    selected, edges, barriers, limit_hit = worker._must_slice(
        program,
        [1],
        direction="backward",
        limit=10,
    )

    assert selected == {0, 1}
    assert edges == {(0, 1)}
    assert barriers == {}
    assert limit_hit is False


def test_must_forward_returns_only_uses_with_one_all_path_definition(
    tmp_path: Path,
) -> None:
    worker = _worker(tmp_path)
    instructions = (
        _instruction(0, 0, 0, definitions=frozenset({"reg:0:8"})),
        _instruction(1, 1, 0, uses=frozenset({"reg:0:8"})),
        _instruction(2, 2, 0, uses=frozenset({"reg:0:8"})),
        _instruction(3, 3, 0, uses=frozenset({"reg:0:8"})),
    )
    program = _MicroProgram(
        instructions=instructions,
        block_instructions={0: (0,), 1: (1,), 2: (2,), 3: (3,)},
        predecessors={0: (), 1: (0,), 2: (0,), 3: (1, 2)},
        successors={0: (1, 2), 1: (3,), 2: (3,), 3: ()},
    )

    selected, edges, barriers, limit_hit = worker._must_slice(
        program,
        [0],
        direction="forward",
        limit=10,
    )

    assert selected == {0, 1, 2, 3}
    assert edges == {(0, 1), (0, 2), (0, 3)}
    assert barriers == {}
    assert limit_hit is False


def test_must_forward_rejects_use_with_an_alternative_definition(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    instructions = (
        _instruction(0, 0, 0, definitions=frozenset({"reg:0:8"})),
        _instruction(1, 1, 0, definitions=frozenset({"reg:0:8"})),
        _instruction(2, 2, 0, uses=frozenset({"reg:0:8"})),
    )
    program = _MicroProgram(
        instructions=instructions,
        block_instructions={0: (0,), 1: (1,), 2: (2,)},
        predecessors={0: (), 1: (), 2: (0, 1)},
        successors={0: (2,), 1: (2,), 2: ()},
    )

    selected, edges, barriers, limit_hit = worker._must_slice(
        program,
        [0],
        direction="forward",
        limit=10,
    )

    assert selected == {0}
    assert edges == set()
    assert barriers == {}
    assert limit_hit is False


@pytest.mark.parametrize(
    ("location", "reason"),
    [
        ("reg:0:8", "unknown_call"),
        ("stack:-8:8", "alias_ambiguity"),
    ],
)
def test_must_reports_unknown_side_effect_as_barrier(
    tmp_path: Path,
    location: str,
    reason: _BarrierReason,
) -> None:
    worker = _worker(tmp_path)
    instructions = (
        _instruction(0, 0, 0, definitions=frozenset({location})),
        _instruction(1, 1, 0, barrier=reason),
        _instruction(2, 1, 1, uses=frozenset({location})),
    )
    program = _MicroProgram(
        instructions=instructions,
        block_instructions={0: (0,), 1: (1, 2)},
        predecessors={0: (), 1: (0,)},
        successors={0: (1,), 1: ()},
    )

    selected, edges, barriers, limit_hit = worker._must_slice(
        program,
        [2],
        direction="backward",
        limit=10,
    )

    assert selected == {2}
    assert edges == set()
    assert barriers == {(1, reason): None}
    assert limit_hit is False


def test_must_limit_truncates_with_analysis_limit_instead_of_failing(
    tmp_path: Path,
) -> None:
    worker = _worker(tmp_path)
    instructions = (
        _instruction(0, 0, 0, definitions=frozenset({"reg:0:8"})),
        _instruction(
            1,
            0,
            1,
            definitions=frozenset({"reg:8:8"}),
            uses=frozenset({"reg:0:8"}),
        ),
        _instruction(
            2,
            0,
            2,
            definitions=frozenset({"reg:16:8"}),
            uses=frozenset({"reg:8:8"}),
        ),
        _instruction(3, 0, 3, uses=frozenset({"reg:16:8"})),
    )
    program = _MicroProgram(
        instructions=instructions,
        block_instructions={0: (0, 1, 2, 3)},
        predecessors={0: ()},
        successors={0: ()},
    )

    selected, edges, barriers, limit_hit = worker._must_slice(
        program,
        [3],
        direction="backward",
        limit=2,
    )

    assert selected == {2, 3}
    assert edges == {(2, 3)}
    assert barriers == {}
    assert limit_hit is True


def test_must_does_not_treat_a_partial_overlap_as_a_full_definition(
    tmp_path: Path,
) -> None:
    worker = _worker(tmp_path)
    program = _MicroProgram(
        instructions=(
            _instruction(0, 0, 0, definitions=frozenset({"reg:0:4"})),
            _instruction(1, 0, 1, uses=frozenset({"reg:0:8"})),
        ),
        block_instructions={0: (0, 1)},
        predecessors={0: ()},
        successors={0: ()},
    )

    selected, edges, barriers, limit_hit = worker._must_slice(
        program,
        [1],
        direction="backward",
        limit=10,
    )

    assert selected == {1}
    assert edges == set()
    assert barriers == {}
    assert limit_hit is False
