# pyright: reportAny=false, reportAttributeAccessIssue=false, reportUnnecessaryIsInstance=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
"""只在 staging IDB 上执行的事务化 mutation worker。"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ida_re_mcp.constants import MAX_MEMORY_READ_BYTES
from ida_re_mcp.il2cpp.bundle import Bundle, parse_il2cpp_bundle
from ida_re_mcp.il2cpp.models import (
    ArrayTypeRef,
    EnumLayout,
    NamedTypeRef,
    NativeSignature,
    PointerTypeRef,
    PrimitiveTypeRef,
    StructLayout,
    SymbolRecord,
    TypeRecord,
    TypeRef,
    UnionLayout,
)
from ida_re_mcp.worker._ida import IdaModules, OwnerThreadBound, require_ida
from ida_re_mcp.worker.errors import WorkerError, WorkerInputError

_CANONICAL_HEX = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_OPERATION_KEYS: dict[str, set[str]] = {
    "rename": {"kind", "address", "name", "expected_name"},
    "comment": {"kind", "address", "text", "repeatable", "expected_text"},
    "type": {"kind", "address", "declaration", "expected_declaration"},
    "patch": {"kind", "address", "bytes_hex", "expected_bytes_hex"},
    "import_il2cpp_bundle": {
        "kind",
        "path",
        "expected_native",
        "expected_metadata",
        "type_resolutions",
    },
}


@dataclass(slots=True)
class _PreparedOperation:
    kind: str
    raw: Mapping[str, object]
    target: int | None = None
    value: object = None


@dataclass(frozen=True, slots=True)
class _StorageField:
    name: str
    offset: int
    size: int


def _il2cpp_symbol_ea(imagebase: int, bundle: Bundle, symbol: SymbolRecord) -> int:
    rva = int(symbol.rva, 16)
    if bundle.manifest.native.abi == "aapcs32" and symbol.symbol_kind == "function":
        rva &= ~1
    return imagebase + rva


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _as_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise WorkerInputError(f"{label} 必须是字符串键对象")
    return cast(Mapping[str, object], value)


def _as_text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise WorkerInputError(f"{label} 必须是字符串")
    return value


def _canonical_address(value: object, label: str) -> int:
    text = _as_text(value, label)
    if _CANONICAL_HEX.fullmatch(text) is None:
        raise WorkerInputError(f"{label} 必须是规范小写十六进制")
    return int(text, 16)


class MutationWorker(OwnerThreadBound):
    """预检、应用、回读并保存单个 staging IDB。"""

    def __init__(self) -> None:
        super().__init__()
        self._api: IdaModules | None = None

    def apply(
        self,
        staging_path: Path,
        operations: Sequence[Mapping[str, object]],
    ) -> dict[str, object]:
        """对 staging 应用一批原子语义操作。

        失败时绝不保存; 调用方必须丢弃整个 staging。成功结果明确要求 Supervisor
        再使用全新 AnalysisWorker 做冷验证, 之后才能发布 revision。
        """

        self._assert_owner_thread()
        path = staging_path.resolve(strict=True)
        api = self._require_runtime(path)
        api.ida_auto.auto_wait()
        if not operations:
            raise WorkerInputError("operations 不能为空")
        prepared = [
            self._preflight(api, operation, index) for index, operation in enumerate(operations)
        ]
        applied: list[dict[str, object]] = []
        for index, operation in enumerate(prepared):
            try:
                applied.append(self._apply_one(api, operation))
            except Exception as exc:
                if isinstance(exc, WorkerError):
                    raise
                raise WorkerError(
                    "mutation_apply_failed",
                    "staging mutation 应用失败; staging 必须丢弃",
                    details={"operation_index": index, "kind": operation.kind},
                ) from exc
        for index, operation in enumerate(prepared):
            if not self._verify_one(api, operation):
                raise WorkerError(
                    "mutation_verify_failed",
                    "staging mutation 回读验证失败; staging 必须丢弃",
                    details={"operation_index": index, "kind": operation.kind},
                )
        api.ida_auto.auto_wait()
        if not api.ida_loader.save_database(str(path), api.ida_loader.DBFL_COMP):
            raise WorkerError(
                "mutation_save_failed",
                "IDA 无法保存 staging 数据库; staging 必须丢弃",
            )
        return {
            "staging_path": str(path),
            "staging_sha256": _file_sha256(path),
            "operations": applied,
            "cold_verification_required": True,
            "saved": True,
        }

    def _require_runtime(self, staging_path: Path) -> IdaModules:
        if self._api is None:
            self._api = require_ida(
                "ida_auto",
                "ida_bytes",
                "ida_funcs",
                "ida_idaapi",
                "ida_loader",
                "ida_name",
                "ida_nalt",
                "ida_segment",
                "ida_typeinf",
            )
        current = Path(self._api.ida_loader.get_path(self._api.ida_loader.PATH_TYPE_IDB)).resolve(
            strict=False
        )
        if current != staging_path:
            raise WorkerError(
                "staging_mismatch",
                "IDA 当前数据库不是指定 staging",
                details={"expected": str(staging_path), "actual": str(current)},
            )
        return self._api

    def _resolve_address(self, api: IdaModules, value: object) -> int:
        ref = _as_mapping(value, "address")
        keys = set(ref)
        space = _as_text(ref.get("space"), "address.space")
        if space == "database" and keys == {"space", "ea"}:
            ea = _canonical_address(ref.get("ea"), "address.ea")
        elif space == "image" and keys == {"space", "rva"}:
            ea = int(api.ida_nalt.get_imagebase()) + _canonical_address(
                ref.get("rva"), "address.rva"
            )
        elif space == "file" and keys == {"space", "offset"}:
            offset = _canonical_address(ref.get("offset"), "address.offset")
            ea = int(api.ida_loader.get_fileregion_ea(offset))
        else:
            raise WorkerInputError("address 必须是严格的 database、image 或 file 判别联合")
        if ea == int(api.ida_idaapi.BADADDR) or api.ida_segment.getseg(ea) is None:
            raise WorkerError("address_unmapped", "mutation 地址未映射到 IDB")
        return ea

    def _preflight(
        self,
        api: IdaModules,
        operation: Mapping[str, object],
        index: int,
    ) -> _PreparedOperation:
        raw = _as_mapping(operation, f"operations[{index}]")
        kind = _as_text(raw.get("kind"), f"operations[{index}].kind")
        allowed = _OPERATION_KEYS.get(kind)
        if allowed is None:
            raise WorkerInputError("未知 mutation kind", details={"kind": kind, "index": index})
        unknown = set(raw) - allowed
        required = allowed - {"expected_name", "expected_text", "expected_declaration"}
        missing = required - set(raw)
        if unknown or missing:
            raise WorkerInputError(
                "mutation 字段集合不匹配",
                details={"index": index, "unknown": sorted(unknown), "missing": sorted(missing)},
            )
        if kind == "import_il2cpp_bundle":
            bundle_path = Path(_as_text(raw.get("path"), "path"))
            expected_native = raw.get("expected_native")
            expected_metadata = raw.get("expected_metadata")
            if not isinstance(expected_native, (str, Mapping)) or not isinstance(
                expected_metadata, (str, Mapping)
            ):
                raise WorkerInputError("IL2CPP expected_native/expected_metadata 格式无效")
            bundle = parse_il2cpp_bundle(
                bundle_path,
                cast(str | Mapping[str, object], expected_native),
                cast(str | Mapping[str, object], expected_metadata),
            )
            resolutions = _as_mapping(raw.get("type_resolutions"), "type_resolutions")
            self._preflight_il2cpp(api, bundle, resolutions)
            return _PreparedOperation(kind, raw, value=bundle)

        target = self._resolve_address(api, raw.get("address"))
        if kind == "rename":
            name = _as_text(raw.get("name"), "name")
            if not api.ida_name.is_uname(name):
                raise WorkerInputError("name 不是合法 IDA 用户名称")
            current = str(api.ida_name.get_name(target) or "")
            expected = raw.get("expected_name")
            if expected is not None and current != _as_text(
                expected, "expected_name", allow_empty=True
            ):
                raise WorkerError(
                    "precondition_failed",
                    "rename 的 expected_name 与 staging 不一致",
                    details={"actual": current},
                )
            return _PreparedOperation(kind, raw, target, name)
        if kind == "comment":
            repeatable = raw.get("repeatable")
            if not isinstance(repeatable, bool):
                raise WorkerInputError("repeatable 必须是布尔值")
            text = _as_text(raw.get("text"), "text", allow_empty=True)
            current = str(api.ida_bytes.get_cmt(target, repeatable) or "")
            expected = raw.get("expected_text")
            if expected is not None and current != _as_text(
                expected, "expected_text", allow_empty=True
            ):
                raise WorkerError(
                    "precondition_failed",
                    "comment 的 expected_text 与 staging 不一致",
                    details={"actual": current},
                )
            return _PreparedOperation(kind, raw, target, text)
        if kind == "type":
            declaration = _as_text(raw.get("declaration"), "declaration")
            type_info = api.ida_typeinf.tinfo_t()
            if not api.ida_typeinf.parse_decl(
                type_info,
                api.ida_typeinf.get_idati(),
                declaration,
                api.ida_typeinf.PT_SIL,
            ):
                raise WorkerInputError("declaration 无法由 IDA 类型解析器解析")
            current_type = api.ida_typeinf.tinfo_t()
            current = str(current_type) if api.ida_nalt.get_tinfo(current_type, target) else ""
            expected = raw.get("expected_declaration")
            if expected is not None and current != _as_text(
                expected, "expected_declaration", allow_empty=True
            ):
                raise WorkerError(
                    "precondition_failed",
                    "type 的 expected_declaration 与 staging 不一致",
                    details={"actual": current},
                )
            return _PreparedOperation(kind, raw, target, type_info)
        if kind == "patch":
            replacement = _decode_hex_bytes(raw.get("bytes_hex"), "bytes_hex")
            expected = _decode_hex_bytes(raw.get("expected_bytes_hex"), "expected_bytes_hex")
            if not replacement or len(replacement) != len(expected):
                raise WorkerInputError("patch 新旧字节必须非空且等长")
            if len(replacement) > MAX_MEMORY_READ_BYTES:
                raise WorkerInputError("单个 IDB patch 超过 64 KiB")
            current = bytes(api.ida_bytes.get_bytes(target, len(expected)) or b"")
            if current != expected:
                raise WorkerError(
                    "precondition_failed",
                    "patch 的 expected_bytes_hex 与 staging 不一致",
                    details={"actual_bytes_hex": current.hex()},
                )
            return _PreparedOperation(kind, raw, target, replacement)
        raise AssertionError(kind)

    def _apply_one(self, api: IdaModules, operation: _PreparedOperation) -> dict[str, object]:
        if operation.kind == "rename":
            assert operation.target is not None and isinstance(operation.value, str)
            flags = int(api.ida_name.SN_CHECK | api.ida_name.SN_NOWARN | api.ida_name.SN_NON_AUTO)
            if not api.ida_name.set_name(operation.target, operation.value, flags):
                raise WorkerError("mutation_rejected", "IDA 拒绝设置名称")
            return {"kind": "rename", "address": _hex(operation.target)}
        if operation.kind == "comment":
            assert operation.target is not None and isinstance(operation.value, str)
            repeatable = cast(bool, operation.raw["repeatable"])
            if not api.ida_bytes.set_cmt(operation.target, operation.value, repeatable):
                raise WorkerError("mutation_rejected", "IDA 拒绝设置注释")
            return {"kind": "comment", "address": _hex(operation.target)}
        if operation.kind == "type":
            assert operation.target is not None
            if not api.ida_typeinf.apply_tinfo(
                operation.target, operation.value, api.ida_typeinf.TINFO_DEFINITE
            ):
                raise WorkerError("mutation_rejected", "IDA 拒绝应用类型")
            return {"kind": "type", "address": _hex(operation.target)}
        if operation.kind == "patch":
            assert operation.target is not None and isinstance(operation.value, bytes)
            api.ida_bytes.patch_bytes(operation.target, operation.value)
            return {
                "kind": "patch",
                "address": _hex(operation.target),
                "size": len(operation.value),
            }
        if operation.kind == "import_il2cpp_bundle":
            assert isinstance(operation.value, Bundle)
            resolutions = _as_mapping(operation.raw["type_resolutions"], "type_resolutions")
            return self._apply_il2cpp(api, operation.value, resolutions)
        raise AssertionError(operation.kind)

    def _verify_one(self, api: IdaModules, operation: _PreparedOperation) -> bool:
        if operation.kind == "rename":
            return str(api.ida_name.get_name(operation.target) or "") == operation.value
        if operation.kind == "comment":
            repeatable = cast(bool, operation.raw["repeatable"])
            return str(api.ida_bytes.get_cmt(operation.target, repeatable) or "") == operation.value
        if operation.kind == "type":
            current = api.ida_typeinf.tinfo_t()
            return bool(
                api.ida_nalt.get_tinfo(current, operation.target)
                and current.equals_to(operation.value)
            )
        if operation.kind == "patch":
            assert isinstance(operation.value, bytes)
            return (
                bytes(api.ida_bytes.get_bytes(operation.target, len(operation.value)) or b"")
                == operation.value
            )
        if operation.kind == "import_il2cpp_bundle":
            assert isinstance(operation.value, Bundle)
            resolutions = _as_mapping(operation.raw["type_resolutions"], "type_resolutions")
            return self._verify_il2cpp(api, operation.value, resolutions)
        return False

    def _preflight_il2cpp(
        self,
        api: IdaModules,
        bundle: Bundle,
        resolutions: Mapping[str, object],
    ) -> None:
        unknown_resolution = set(resolutions) - {record.id for record in bundle.types}
        if unknown_resolution:
            raise WorkerInputError(
                "type_resolutions 引用了 bundle 外类型",
                details={"type_ids": sorted(unknown_resolution)},
            )
        type_name_owners: dict[str, str] = {}
        for type_record in bundle.types:
            type_name = _ida_type_name(type_record)
            previous_type_id = type_name_owners.setdefault(type_name, type_record.id)
            if previous_type_id != type_record.id:
                raise WorkerError(
                    "type_name_collision",
                    "不同 IL2CPP type_id 不得映射到同一 IDA 类型名",
                    details={
                        "name": type_name,
                        "type_ids": [previous_type_id, type_record.id],
                    },
                )
            if not api.ida_name.is_valid_typename(type_name):
                raise WorkerInputError(
                    "IL2CPP 类型名不是合法 IDA 类型名",
                    details={"type_id": type_record.id, "name": type_name},
                )
            existing = api.ida_typeinf.tinfo_t()
            exists = bool(existing.get_named_type(api.ida_typeinf.get_idati(), type_name))
            resolution = resolutions.get(type_record.id)
            if exists and resolution not in {"replace", "keep"}:
                raise WorkerError(
                    "type_conflict",
                    "IL2CPP 类型冲突必须显式指定 replace 或 keep",
                    details={"type_id": type_record.id, "name": type_name},
                )
            if not exists and resolution is not None:
                raise WorkerInputError(
                    "不存在冲突的类型不得提供 resolution",
                    details={"type_id": type_record.id},
                )
        imagebase = int(api.ida_nalt.get_imagebase())
        for symbol in bundle.symbols:
            ea = _il2cpp_symbol_ea(imagebase, bundle, symbol)
            segment = api.ida_segment.getseg(ea)
            if segment is None:
                raise WorkerError(
                    "address_unmapped",
                    "IL2CPP symbol RVA 不在 IDB segment 内",
                    details={"symbol_id": symbol.id, "rva": symbol.rva},
                )
            if not api.ida_name.is_uname(symbol.name):
                raise WorkerInputError(
                    "IL2CPP symbol 名称不是合法 IDA 用户名称",
                    details={"symbol_id": symbol.id, "name": symbol.name},
                )
            function = api.ida_funcs.get_func(ea)
            if symbol.symbol_kind == "function":
                if function is None or int(function.start_ea) != ea:
                    raise WorkerError(
                        "address_kind_mismatch",
                        "IL2CPP function symbol 必须精确落在已分析函数入口",
                        details={"symbol_id": symbol.id, "rva": symbol.rva},
                    )
                continue
            assert symbol.type is not None
            self._validate_il2cpp_data_range(api, symbol, ea, bundle.type_ref_size(symbol.type))

    @staticmethod
    def _validate_il2cpp_data_range(
        api: IdaModules,
        symbol: SymbolRecord,
        ea: int,
        size: int,
    ) -> None:
        """按实际应用大小检查数据范围，避免保留类型扩展后覆盖已有代码。"""

        segment = api.ida_segment.getseg(ea)
        end_ea = ea + size
        if segment is None or size <= 0 or end_ea > int(segment.end_ea):
            raise WorkerError(
                "address_unmapped",
                "IL2CPP data symbol 范围超出所在 IDB segment",
                details={"symbol_id": symbol.id, "rva": symbol.rva},
            )
        cursor = ea
        while cursor < end_ea:
            if api.ida_funcs.get_func(cursor) is not None or api.ida_bytes.is_code(
                api.ida_bytes.get_flags(cursor)
            ):
                raise WorkerError(
                    "address_kind_mismatch",
                    "IL2CPP data symbol 不得覆盖函数或已分析代码",
                    details={"symbol_id": symbol.id, "rva": symbol.rva},
                )
            next_head = int(api.ida_bytes.next_head(cursor, end_ea))
            if next_head <= cursor or next_head >= end_ea:
                break
            cursor = next_head

    def _apply_il2cpp(
        self,
        api: IdaModules,
        bundle: Bundle,
        resolutions: Mapping[str, object],
    ) -> dict[str, object]:
        type_names = {record.id: _ida_type_name(record) for record in bundle.types}
        pointer_width = bundle.manifest.native.pointer_width
        kept: list[str] = []
        replaced: list[str] = []
        for record in bundle.types:
            existing = api.ida_typeinf.tinfo_t()
            exists = bool(
                existing.get_named_type(api.ida_typeinf.get_idati(), type_names[record.id])
            )
            if exists and resolutions.get(record.id) == "keep":
                kept.append(record.id)
                continue
            placeholder = self._build_placeholder_type(api, record)
            flags = int(api.ida_typeinf.NTF_REPLACE) if exists else 0
            if placeholder.set_named_type(
                api.ida_typeinf.get_idati(), type_names[record.id], flags
            ) != int(api.ida_typeinf.TERR_OK):
                raise WorkerError(
                    "mutation_rejected",
                    "IDA 拒绝创建 IL2CPP placeholder 类型",
                    details={"type_id": record.id},
                )
        for record in bundle.types:
            if record.id in kept:
                continue
            full_type = self._build_type(api, record, type_names, pointer_width)
            if full_type.set_named_type(
                api.ida_typeinf.get_idati(),
                type_names[record.id],
                api.ida_typeinf.NTF_REPLACE,
            ) != int(api.ida_typeinf.TERR_OK):
                raise WorkerError(
                    "mutation_rejected",
                    "IDA 拒绝发布 IL2CPP 完整类型",
                    details={"type_id": record.id},
                )
            replaced.append(record.id)

        imagebase = int(api.ida_nalt.get_imagebase())
        name_conflicts: list[dict[str, object]] = []
        named = 0
        typed = 0
        methods = bundle.method_by_id()
        for symbol in bundle.symbols:
            ea = _il2cpp_symbol_ea(imagebase, bundle, symbol)
            flags = int(api.ida_bytes.get_flags(ea))
            existing_name = str(api.ida_name.get_name(ea) or "")
            if api.ida_bytes.has_user_name(flags):
                if existing_name != symbol.name:
                    name_conflicts.append(
                        {
                            "symbol_id": symbol.id,
                            "address": _hex(ea),
                            "existing_name": existing_name,
                        }
                    )
            else:
                if not api.ida_name.set_name(
                    ea,
                    symbol.name,
                    api.ida_name.SN_CHECK | api.ida_name.SN_NOWARN | api.ida_name.SN_NON_AUTO,
                ):
                    raise WorkerError(
                        "mutation_rejected",
                        "IDA 拒绝应用 IL2CPP symbol 名称",
                        details={"symbol_id": symbol.id},
                    )
                named += 1
            if symbol.method_id is not None:
                method = methods[symbol.method_id]
                if method.native_signature is not None:
                    function_type = self._build_function_type(
                        api,
                        method.native_signature,
                        type_names,
                        pointer_width,
                    )
                    if not api.ida_typeinf.apply_tinfo(
                        ea, function_type, api.ida_typeinf.TINFO_DEFINITE
                    ):
                        raise WorkerError(
                            "mutation_rejected",
                            "IDA 拒绝应用 IL2CPP native signature",
                            details={"method_id": method.id},
                        )
                    typed += 1
            elif symbol.type is not None:
                symbol_type = self._type_ref(api, symbol.type, type_names, pointer_width)
                self._validate_il2cpp_data_range(api, symbol, ea, int(symbol_type.get_size()))
                if not api.ida_typeinf.apply_tinfo(ea, symbol_type, api.ida_typeinf.TINFO_DEFINITE):
                    raise WorkerError(
                        "mutation_rejected",
                        "IDA 拒绝应用 IL2CPP data 类型",
                        details={"symbol_id": symbol.id},
                    )
                typed += 1
        return {
            "kind": "import_il2cpp_bundle",
            "bundle_sha256": bundle.sha256,
            "types_applied": len(replaced),
            "types_kept": kept,
            "symbols_named": named,
            "symbols_typed": typed,
            "name_conflicts": name_conflicts,
        }

    def _build_placeholder_type(self, api: IdaModules, record: TypeRecord) -> object:
        if isinstance(record.layout, EnumLayout):
            return self._build_enum_type(api, record.layout)
        size = record.layout.size
        byte_type = api.ida_typeinf.tinfo_t(api.ida_typeinf.BTF_UINT8)
        array_type = api.ida_typeinf.tinfo_t()
        if not array_type.create_array(byte_type, size):
            raise WorkerError("type_build_failed", "无法构造 IL2CPP placeholder 数组")
        member = api.ida_typeinf.udm_t()
        member.name = "__opaque"
        member.offset = 0
        member.size = size * 8
        member.type = array_type
        members = api.ida_typeinf.udt_type_data_t()
        members.push_back(member)
        result = api.ida_typeinf.tinfo_t()
        kind = (
            api.ida_typeinf.BTF_UNION
            if isinstance(record.layout, UnionLayout)
            else api.ida_typeinf.BTF_STRUCT
        )
        if not result.create_udt(members, kind):
            raise WorkerError("type_build_failed", "无法构造 IL2CPP placeholder UDT")
        return result

    def _build_enum_type(self, api: IdaModules, layout: EnumLayout) -> object:
        enum_data = api.ida_typeinf.enum_type_data_t()
        _, signed = _enum_storage(layout.underlying)
        enum_data.set_enum_radix(10, signed)
        for item in layout.members:
            member = api.ida_typeinf.edm_t()
            member.name = item.name
            member.value = item.value & ((1 << 64) - 1)
            enum_data.push_back(member)
        result = api.ida_typeinf.tinfo_t()
        if not result.create_enum(enum_data):
            raise WorkerError("type_build_failed", "无法构造 IL2CPP enum")
        width, signed = _enum_storage(layout.underlying)
        if result.set_enum_width(width) != int(api.ida_typeinf.TERR_OK):
            raise WorkerError("type_build_failed", "无法设置 IL2CPP enum storage width")
        sign = api.ida_typeinf.type_signed if signed else api.ida_typeinf.type_unsigned
        if result.set_enum_sign(sign) != int(api.ida_typeinf.TERR_OK):
            raise WorkerError("type_build_failed", "无法设置 IL2CPP enum signedness")
        return result

    def _build_type(
        self,
        api: IdaModules,
        record: TypeRecord,
        type_names: Mapping[str, str],
        pointer_width: int,
    ) -> object:
        layout = record.layout
        if isinstance(layout, EnumLayout):
            return self._build_enum_type(api, layout)
        members = api.ida_typeinf.udt_type_data_t()
        occupied_end = 0
        for item in layout.fields:
            field_type = self._type_ref(api, item.type, type_names, pointer_width)
            field_size = int(field_type.get_size())
            member = api.ida_typeinf.udm_t()
            member.name = item.name
            member.offset = item.offset * 8
            member.size = field_size * 8
            member.type = field_type
            member.effalign = layout.alignment
            members.push_back(member)
            field_end = field_size if isinstance(layout, UnionLayout) else item.offset + field_size
            occupied_end = max(occupied_end, field_end)
        storage = _storage_field(record, occupied_end)
        if storage is not None:
            byte_type = api.ida_typeinf.tinfo_t(api.ida_typeinf.BTF_UINT8)
            storage_type = api.ida_typeinf.tinfo_t()
            if not storage_type.create_array(byte_type, storage.size):
                raise WorkerError("type_build_failed", "无法构造 IL2CPP UDT storage 字段")
            member = api.ida_typeinf.udm_t()
            member.name = storage.name
            member.offset = storage.offset * 8
            member.size = storage.size * 8
            member.type = storage_type
            member.effalign = 1
            members.push_back(member)
        members.total_size = layout.size
        members.unpadded_size = layout.size if storage is not None else occupied_end
        members.effalign = layout.alignment
        members.sda = layout.alignment.bit_length()
        members.is_union = isinstance(layout, UnionLayout)
        if isinstance(layout, StructLayout):
            members.taudt_bits |= api.ida_typeinf.TAUDT_FIXED
        result = api.ida_typeinf.tinfo_t()
        kind = (
            api.ida_typeinf.BTF_UNION
            if isinstance(layout, UnionLayout)
            else api.ida_typeinf.BTF_STRUCT
        )
        if not result.create_udt(members, kind):
            raise WorkerError("type_build_failed", "无法构造 IL2CPP UDT")
        if int(result.get_size()) != layout.size:
            raise WorkerError(
                "type_layout_mismatch",
                "IDA 构造后的 IL2CPP 类型大小与 bundle 不一致",
                details={
                    "type_id": record.id,
                    "expected_size": layout.size,
                    "actual_size": int(result.get_size()),
                },
            )
        return result

    def _type_ref(
        self,
        api: IdaModules,
        type_ref: TypeRef,
        type_names: Mapping[str, str],
        pointer_width: int,
    ) -> object:
        if isinstance(type_ref, PrimitiveTypeRef):
            return api.ida_typeinf.tinfo_t(_primitive_constant(api, type_ref.name, pointer_width))
        if isinstance(type_ref, NamedTypeRef):
            result = api.ida_typeinf.tinfo_t()
            if not result.get_named_type(api.ida_typeinf.get_idati(), type_names[type_ref.type_id]):
                raise WorkerError("type_build_failed", "无法解析已发布 IL2CPP named type")
            return result
        if isinstance(type_ref, PointerTypeRef):
            target = self._type_ref(api, type_ref.to, type_names, pointer_width)
            if type_ref.const:
                target.set_const()
            result = api.ida_typeinf.tinfo_t()
            if not result.create_ptr(target):
                raise WorkerError("type_build_failed", "无法构造 IL2CPP pointer type")
            return result
        if isinstance(type_ref, ArrayTypeRef):
            element = self._type_ref(api, type_ref.element, type_names, pointer_width)
            result = api.ida_typeinf.tinfo_t()
            if not result.create_array(element, type_ref.count):
                raise WorkerError("type_build_failed", "无法构造 IL2CPP array type")
            return result
        raise AssertionError(type(type_ref))

    def _build_function_type(
        self,
        api: IdaModules,
        signature: NativeSignature,
        type_names: Mapping[str, str],
        pointer_width: int,
    ) -> object:
        function_data = api.ida_typeinf.func_type_data_t()
        function_data.set_cc(_calling_convention_constant(api, signature.calling_convention))
        function_data.rettype = self._type_ref(
            api,
            signature.return_type,
            type_names,
            pointer_width,
        )
        for parameter in signature.parameters:
            argument = api.ida_typeinf.funcarg_t()
            argument.name = parameter.name
            argument.type = self._type_ref(
                api,
                parameter.type,
                type_names,
                pointer_width,
            )
            function_data.push_back(argument)
        result = api.ida_typeinf.tinfo_t()
        if not result.create_func(function_data):
            raise WorkerError("type_build_failed", "无法构造 IL2CPP native function type")
        return result

    def _verify_type_record(
        self,
        api: IdaModules,
        record: TypeRecord,
        type_names: Mapping[str, str],
        pointer_width: int,
    ) -> bool:
        actual = api.ida_typeinf.tinfo_t()
        if not actual.get_named_type(api.ida_typeinf.get_idati(), type_names[record.id]):
            return False
        expected = self._build_type(api, record, type_names, pointer_width)
        layout = record.layout
        if isinstance(layout, EnumLayout):
            width, signed = _enum_storage(layout.underlying)
            expected_sign = api.ida_typeinf.type_signed if signed else api.ida_typeinf.type_unsigned
            if (
                not actual.is_enum()
                or int(actual.get_size()) != width
                or actual.get_sign() != expected_sign
            ):
                return False
            actual_members = api.ida_typeinf.enum_type_data_t()
            expected_members = api.ida_typeinf.enum_type_data_t()
            if not actual.get_enum_details(actual_members) or not expected.get_enum_details(
                expected_members
            ):
                return False
            if actual_members.size() != expected_members.size():
                return False
            return all(
                actual_members[index].name == expected_members[index].name
                and int(actual_members[index].value) == int(expected_members[index].value)
                for index in range(actual_members.size())
            )
        if (
            int(actual.get_size()) != layout.size
            or bool(actual.is_union()) != isinstance(layout, UnionLayout)
            or bool(actual.is_struct()) != isinstance(layout, StructLayout)
        ):
            return False
        actual_members = api.ida_typeinf.udt_type_data_t()
        expected_members = api.ida_typeinf.udt_type_data_t()
        if not actual.get_udt_details(actual_members) or not expected.get_udt_details(
            expected_members
        ):
            return False
        if (
            int(actual_members.total_size) != layout.size
            or int(expected_members.total_size) != layout.size
            or actual_members.size() != expected_members.size()
        ):
            return False
        for index in range(actual_members.size()):
            actual_member = actual_members[index]
            expected_member = expected_members[index]
            if (
                actual_member.name != expected_member.name
                or int(actual_member.offset) != int(expected_member.offset)
                or int(actual_member.size) != int(expected_member.size)
                or not actual_member.type.equals_to(expected_member.type)
            ):
                return False
        return True

    def _verify_function_signature(
        self,
        api: IdaModules,
        actual: object,
        signature: NativeSignature,
        type_names: Mapping[str, str],
        pointer_width: int,
    ) -> bool:
        if not actual.is_func():
            return False
        expected = self._build_function_type(api, signature, type_names, pointer_width)
        actual_details = api.ida_typeinf.func_type_data_t()
        expected_details = api.ida_typeinf.func_type_data_t()
        if not actual.get_func_details(actual_details) or not expected.get_func_details(
            expected_details
        ):
            return False
        if (
            actual_details.get_explicit_cc() != expected_details.get_explicit_cc()
            or actual_details.is_vararg_cc()
            or not actual_details.rettype.equals_to(expected_details.rettype)
            or actual_details.size() != expected_details.size()
        ):
            return False
        return all(
            actual_details[index].name == expected_details[index].name
            and actual_details[index].type.equals_to(expected_details[index].type)
            for index in range(actual_details.size())
        )

    def _verify_il2cpp(
        self,
        api: IdaModules,
        bundle: Bundle,
        resolutions: Mapping[str, object],
    ) -> bool:
        imagebase = int(api.ida_nalt.get_imagebase())
        pointer_width = bundle.manifest.native.pointer_width
        methods = bundle.method_by_id()
        type_names = {record.id: _ida_type_name(record) for record in bundle.types}
        for record in bundle.types:
            if resolutions.get(record.id) == "keep":
                type_info = api.ida_typeinf.tinfo_t()
                if not type_info.get_named_type(api.ida_typeinf.get_idati(), type_names[record.id]):
                    return False
                continue
            if not self._verify_type_record(api, record, type_names, pointer_width):
                return False
        for symbol in bundle.symbols:
            ea = _il2cpp_symbol_ea(imagebase, bundle, symbol)
            flags = int(api.ida_bytes.get_flags(ea))
            if not api.ida_bytes.has_user_name(flags) and api.ida_name.get_name(ea) != symbol.name:
                return False
            if (
                symbol.method_id is not None
                and methods[symbol.method_id].native_signature is not None
            ):
                type_info = api.ida_typeinf.tinfo_t()
                signature = methods[symbol.method_id].native_signature
                assert signature is not None
                if not api.ida_nalt.get_tinfo(type_info, ea) or not self._verify_function_signature(
                    api,
                    type_info,
                    signature,
                    type_names,
                    pointer_width,
                ):
                    return False
            elif symbol.type is not None:
                type_info = api.ida_typeinf.tinfo_t()
                expected = self._type_ref(api, symbol.type, type_names, pointer_width)
                if not api.ida_nalt.get_tinfo(type_info, ea) or not type_info.equals_to(expected):
                    return False
        return True


def _enum_storage(underlying: str) -> tuple[int, bool]:
    return int(underlying[1:]) // 8, underlying.startswith("i")


def _storage_field(record: TypeRecord, occupied_end: int) -> _StorageField | None:
    layout = record.layout
    if not isinstance(layout, UnionLayout) or occupied_end >= layout.size:
        return None
    used_names = {field.name for field in layout.fields}
    base_name = f"__ida_re_storage_{record.id[-16:]}"
    name = base_name
    suffix = 0
    while name in used_names:
        suffix += 1
        name = f"{base_name}_{suffix}"
    return _StorageField(name=name, offset=0, size=layout.size)


def _primitive_constant(api: IdaModules, name: str, pointer_width: int) -> int:
    native_int = {
        32: api.ida_typeinf.BTF_INT32,
        64: api.ida_typeinf.BTF_INT64,
    }[pointer_width]
    native_uint = {
        32: api.ida_typeinf.BTF_UINT32,
        64: api.ida_typeinf.BTF_UINT64,
    }[pointer_width]
    constants = {
        "void": api.ida_typeinf.BTF_VOID,
        "bool": api.ida_typeinf.BTF_BOOL,
        "i8": api.ida_typeinf.BTF_INT8,
        "u8": api.ida_typeinf.BTF_UINT8,
        "i16": api.ida_typeinf.BTF_INT16,
        "u16": api.ida_typeinf.BTF_UINT16,
        "i32": api.ida_typeinf.BTF_INT32,
        "u32": api.ida_typeinf.BTF_UINT32,
        "i64": api.ida_typeinf.BTF_INT64,
        "u64": api.ida_typeinf.BTF_UINT64,
        "f32": api.ida_typeinf.BTF_FLOAT,
        "f64": api.ida_typeinf.BTF_DOUBLE,
        "native_int": native_int,
        "native_uint": native_uint,
    }
    return int(constants[name])


def _calling_convention_constant(api: IdaModules, name: str) -> int:
    constants = {
        "cdecl": api.ida_typeinf.CM_CC_CDECL,
        "win64": api.ida_typeinf.CM_CC_FASTCALL,
        "sysv": api.ida_typeinf.CM_CC_CDECL,
        "aapcs32": api.ida_typeinf.CM_CC_CDECL,
        "aapcs64": api.ida_typeinf.CM_CC_CDECL,
    }
    return int(constants[name])


def _ida_type_name(record: TypeRecord) -> str:
    qualified = f"{record.namespace}::{record.name}" if record.namespace else record.name
    return qualified


def _decode_hex_bytes(value: object, label: str) -> bytes:
    text = _as_text(value, label, allow_empty=True)
    if len(text) % 2:
        raise WorkerInputError(f"{label} 必须是偶数长度十六进制")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise WorkerInputError(f"{label} 包含非十六进制字符") from exc


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
