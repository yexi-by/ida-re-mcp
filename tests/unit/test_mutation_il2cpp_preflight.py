"""IL2CPP mutation 预检必须把 symbol 种类绑定到真实 IDA 地址语义。"""

from __future__ import annotations

from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Literal, cast

import pytest

from ida_re_mcp.il2cpp.bundle import Bundle
from ida_re_mcp.il2cpp.models import (
    FieldDefinition,
    ManagedImageRecord,
    ManagedSignature,
    ManifestRecord,
    MetadataBinding,
    MethodRecord,
    NamedTypeRef,
    NativeBinding,
    PrimitiveTypeRef,
    StructLayout,
    SymbolRecord,
    TypeRecord,
)
from ida_re_mcp.worker._ida import IdaModules
from ida_re_mcp.worker.errors import WorkerError
from ida_re_mcp.worker.mutation import MutationWorker

_IMAGE_ID = "image_" + "11" * 32
_SECOND_IMAGE_ID = "image_" + "55" * 32
_TYPE_ID = "type_" + "22" * 32
_SECOND_TYPE_ID = "type_" + "66" * 32
_METHOD_ID = "method_" + "33" * 32
_SYMBOL_ID = "symbol_" + "44" * 32


@dataclass(frozen=True, slots=True)
class _FakeFunction:
    start_ea: int


@dataclass(frozen=True, slots=True)
class _FakeSegmentInfo:
    end_ea: int


class _FakeName:
    @staticmethod
    def get_name(_ea: int) -> str:
        return "Actor_Data"

    @staticmethod
    def is_valid_typename(_name: str) -> bool:
        return True

    @staticmethod
    def is_uname(_name: str) -> bool:
        return True


class _FakeTinfo:
    def __init__(self, kept_size: int | None = None) -> None:
        self._kept_size = kept_size

    def get_named_type(self, _til: object, _name: str) -> bool:
        return self._kept_size is not None

    def get_size(self) -> int:
        assert self._kept_size is not None
        return self._kept_size


class _FakeTypeinf:
    def __init__(self, kept_size: int | None = None) -> None:
        self._kept_size = kept_size

    def tinfo_t(self) -> _FakeTinfo:
        return _FakeTinfo(self._kept_size)

    @staticmethod
    def get_idati() -> object:
        return object()


class _FakeNalt:
    @staticmethod
    def get_imagebase() -> int:
        return 0x140000000


class _FakeSegment:
    def __init__(self, end_ea: int) -> None:
        self._end_ea = end_ea

    def getseg(self, _ea: int) -> _FakeSegmentInfo:
        return _FakeSegmentInfo(end_ea=self._end_ea)


class _FakeFuncs:
    def __init__(self, function: _FakeFunction | None) -> None:
        self._function = function

    def get_func(self, _ea: int) -> _FakeFunction | None:
        return self._function


class _FakeBytes:
    def __init__(self, code_addresses: frozenset[int]) -> None:
        self._code_addresses = code_addresses

    @staticmethod
    def get_flags(ea: int) -> int:
        return ea

    @staticmethod
    def has_user_name(_flags: int) -> bool:
        return True

    def is_code(self, flags: int) -> bool:
        return flags in self._code_addresses

    def next_head(self, ea: int, max_ea: int) -> int:
        return min(
            (address for address in self._code_addresses if ea < address < max_ea),
            default=max_ea,
        )


class _TestMutationWorker(MutationWorker):
    def preflight_il2cpp(self, api: IdaModules, bundle: Bundle) -> None:
        self._preflight_il2cpp(api, bundle, {})

    def apply_kept_il2cpp(self, api: IdaModules, bundle: Bundle) -> dict[str, object]:
        resolutions = {_TYPE_ID: "keep"}
        self._preflight_il2cpp(api, bundle, resolutions)
        return self._apply_il2cpp(api, bundle, resolutions)


def _bundle(symbol_kind: Literal["function", "data"]) -> Bundle:
    native = NativeBinding(
        sha256="aa" * 32,
        size=4096,
        image_size=0x5000,
        architecture="x86_64",
        abi="msvc-x64",
        pointer_width=64,
        endianness="little",
    )
    manifest = ManifestRecord.model_validate(
        {
            "kind": "manifest",
            "schema": "1",
            "media_type": "application/vnd.ida-re.il2cpp-bundle+ndjson",
            "native": native,
            "metadata": MetadataBinding(sha256="bb" * 32, size=1024),
        },
        strict=True,
    )
    image = ManagedImageRecord(
        kind="managed_image",
        id=_IMAGE_ID,
        name="Assembly-CSharp",
        assembly_name="Assembly-CSharp.dll",
    )
    type_record = TypeRecord(
        kind="type",
        id=_TYPE_ID,
        image_id=_IMAGE_ID,
        namespace="Game",
        name="Actor",
        layout=StructLayout(
            kind="struct",
            size=8,
            alignment=8,
            fields=(
                FieldDefinition(
                    name="value",
                    offset=0,
                    type=PrimitiveTypeRef(kind="primitive", name="u64"),
                ),
            ),
        ),
    )
    method = MethodRecord(
        kind="method",
        id=_METHOD_ID,
        image_id=_IMAGE_ID,
        declaring_type_id=_TYPE_ID,
        name="Tick",
        rva="0x1000",
        managed_signature=ManagedSignature(return_type="System.Void", parameters=()),
        native_signature=None,
    )
    symbol = SymbolRecord(
        kind="symbol",
        id=_SYMBOL_ID,
        name="Actor_Tick" if symbol_kind == "function" else "Actor_Data",
        rva="0x1000",
        symbol_kind=symbol_kind,
        method_id=_METHOD_ID if symbol_kind == "function" else None,
        type=None if symbol_kind == "function" else PrimitiveTypeRef(kind="primitive", name="u64"),
    )
    return Bundle(
        manifest=manifest,
        images=(image,),
        types=(type_record,),
        methods=(method,),
        symbols=(symbol,),
        sha256="cc" * 32,
        record_count=5,
    )


def _api(
    *,
    function: _FakeFunction | None,
    code_addresses: frozenset[int] = frozenset(),
    segment_end: int = 0x140005000,
    kept_size: int | None = None,
) -> IdaModules:
    return cast(
        IdaModules,
        SimpleNamespace(
            ida_name=_FakeName(),
            ida_typeinf=_FakeTypeinf(kept_size),
            ida_nalt=_FakeNalt(),
            ida_segment=_FakeSegment(segment_end),
            ida_funcs=_FakeFuncs(function),
            ida_bytes=_FakeBytes(code_addresses),
        ),
    )


def test_function_symbol_requires_exact_ida_function_entry() -> None:
    worker = _TestMutationWorker()
    bundle = _bundle("function")
    entry = 0x140001000
    worker.preflight_il2cpp(_api(function=_FakeFunction(entry)), bundle)

    with pytest.raises(WorkerError, match="精确落在已分析函数入口"):
        worker.preflight_il2cpp(_api(function=None), bundle)
    with pytest.raises(WorkerError, match="精确落在已分析函数入口"):
        worker.preflight_il2cpp(_api(function=_FakeFunction(entry - 4)), bundle)


def test_data_symbol_rejects_function_membership_and_code() -> None:
    worker = _TestMutationWorker()
    bundle = _bundle("data")
    worker.preflight_il2cpp(_api(function=None), bundle)

    with pytest.raises(WorkerError, match="不得覆盖函数或已分析代码"):
        worker.preflight_il2cpp(
            _api(function=_FakeFunction(0x140000FF0)),
            bundle,
        )
    with pytest.raises(WorkerError, match="不得覆盖函数或已分析代码"):
        worker.preflight_il2cpp(
            _api(function=None, code_addresses=frozenset({0x140001004})),
            bundle,
        )
    with pytest.raises(WorkerError, match="范围超出所在 IDB segment"):
        worker.preflight_il2cpp(
            _api(function=None, segment_end=0x140001004),
            bundle,
        )


@pytest.mark.parametrize("crosses_segment", [False, True])
def test_kept_type_checks_its_actual_size_before_applying_data(crosses_segment: bool) -> None:
    worker = _TestMutationWorker()
    source = _bundle("data")
    symbol = source.symbols[0].model_copy(
        update={"type": NamedTypeRef(kind="named", type_id=_TYPE_ID)}
    )
    bundle = replace(source, symbols=(symbol,))
    api = _api(
        function=None,
        code_addresses=frozenset() if crosses_segment else frozenset({0x140001008}),
        segment_end=0x140001008 if crosses_segment else 0x140005000,
        kept_size=16,
    )

    with pytest.raises(WorkerError) as raised:
        worker.apply_kept_il2cpp(api, bundle)

    assert raised.value.code == ("address_unmapped" if crosses_segment else "address_kind_mismatch")


def test_different_type_ids_cannot_share_an_ida_type_name_across_images() -> None:
    worker = _TestMutationWorker()
    source = _bundle("function")
    second_image = ManagedImageRecord(
        kind="managed_image",
        id=_SECOND_IMAGE_ID,
        name="Second",
        assembly_name="Second.dll",
    )
    collision = source.types[0].model_copy(
        update={"id": _SECOND_TYPE_ID, "image_id": _SECOND_IMAGE_ID}
    )
    bundle = Bundle(
        manifest=source.manifest,
        images=(*source.images, second_image),
        types=(*source.types, collision),
        methods=source.methods,
        symbols=source.symbols,
        sha256=source.sha256,
        record_count=source.record_count + 2,
    )

    with pytest.raises(WorkerError) as raised:
        worker.preflight_il2cpp(_api(function=_FakeFunction(0x140001000)), bundle)

    assert raised.value.code == "type_name_collision"
    assert raised.value.details == {
        "name": "Game::Actor",
        "type_ids": [_TYPE_ID, _SECOND_TYPE_ID],
    }
