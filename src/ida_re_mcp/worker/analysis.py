# pyright: reportAny=false, reportAttributeAccessIssue=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
"""运行在 IDA owner 线程中的只读 Native 分析 worker。"""

from __future__ import annotations

import hashlib
import re
import sys
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from ida_re_mcp.constants import (
    DEFAULT_GRAPH_NODES,
    DEFAULT_PAGE_SIZE,
    MAX_GRAPH_NODES,
    MAX_PAGE_SIZE,
)
from ida_re_mcp.worker._ida import IdaModules, OwnerThreadBound, require_ida
from ida_re_mcp.worker.errors import CapabilityError, WorkerError, WorkerInputError

_CANONICAL_HEX = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
_MAX_PAGE_OFFSET = (1 << 63) - 1
_MAX_GRAPH_EDGES = 4 * MAX_GRAPH_NODES
_MAX_MICROCODE_INSTRUCTIONS = 100_000
_NONPAGED_CHUNK_LIMIT = 128
_SEARCH_PREVIEW_TEXT_LIMIT = 2_048
_INLINE_STRING_BYTES_LIMIT = 4 * 1_024
_INLINE_TYPE_TEXT_LIMIT = 16 * 1024
_MEMBER_TYPE_TEXT_LIMIT = 4 * 1024
_OVERVIEW_SECTIONS = frozenset(
    {
        "segments",
        "entry_points",
        "imports",
        "exports",
        "fixups",
        "unwind",
        "functions",
        "strings",
    }
)
_OPERATIONS = {
    "program.overview",
    "program.search",
    "address.inspect",
    "function.inspect",
    "graph.query",
    "dataflow.slice",
    "type.inspect",
}

type _BarrierReason = Literal["unknown_call", "alias_ambiguity", "analysis_limit"]
type _GraphNodeKind = Literal["function", "basic_block", "instruction", "data", "unknown"]
type _GraphEdgeKind = Literal["flow", "call", "jump", "xref_code", "xref_data", "unresolved"]


@dataclass(frozen=True, slots=True)
class _MicroInstruction:
    index: int
    block: int
    position: int
    address: str
    opcode: int
    text: str
    definitions: frozenset[str]
    uses: frozenset[str]
    barrier: _BarrierReason | None


@dataclass(frozen=True, slots=True)
class _MicroProgram:
    instructions: tuple[_MicroInstruction, ...]
    block_instructions: Mapping[int, tuple[int, ...]]
    predecessors: Mapping[int, tuple[int, ...]]
    successors: Mapping[int, tuple[int, ...]]
    input_locations: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class _MustDefinitionProof:
    definitions: frozenset[int]
    has_unbound_path: bool
    barriers: frozenset[tuple[int, _BarrierReason]]

    @property
    def unique_definition(self) -> int | None:
        """仅在每条进入路径都由同一条指令定义时返回证明结果。"""

        if self.has_unbound_path or self.barriers or len(self.definitions) != 1:
            return None
        return next(iter(self.definitions))


@dataclass(frozen=True, slots=True)
class _GraphNode:
    id: str
    kind: _GraphNodeKind
    address: int
    label: str
    function: int | None = None
    block_id: int | None = None

    def to_json(self) -> dict[str, object]:
        result: dict[str, object] = {
            "id": self.id,
            "kind": self.kind,
            "address": _hex(self.address),
            "label": self.label,
        }
        if self.function is not None:
            result["function"] = _hex(self.function)
        if self.block_id is not None:
            result["block_id"] = self.block_id
        return result


@dataclass(frozen=True, slots=True)
class _GraphEdge:
    source: str
    target: str
    kind: _GraphEdgeKind
    site: int | None = None

    def to_json(self) -> dict[str, object]:
        result: dict[str, object] = {
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
        }
        if self.site is not None:
            result["site"] = _hex(self.site)
        return result


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise WorkerInputError(f"{label} 必须是对象")
    if any(not isinstance(key, str) for key in value):
        raise WorkerInputError(f"{label} 只能包含字符串键")
    return cast(Mapping[str, object], value)


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise WorkerInputError(f"{label} 必须是非空字符串")
    return value


def _integer(value: object, label: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise WorkerInputError(f"{label} 必须是大于等于 {minimum} 的整数")
    if maximum is not None and value > maximum:
        raise WorkerInputError(f"{label} 超过上限 {maximum}")
    return value


def _canonical_hex(value: object, label: str) -> int:
    text = _text(value, label)
    if _CANONICAL_HEX.fullmatch(text) is None:
        raise WorkerInputError(f"{label} 必须是规范小写十六进制地址")
    return int(text, 16)


def _page_limit(input: Mapping[str, object], *, graph: bool = False) -> int:
    default = DEFAULT_GRAPH_NODES if graph else DEFAULT_PAGE_SIZE
    maximum = MAX_GRAPH_NODES if graph else MAX_PAGE_SIZE
    return _integer(input.get("limit", default), "limit", minimum=1, maximum=maximum)


def _inspect_limit(input: Mapping[str, object]) -> int:
    graph_bound = input.get("graph_bound", False)
    if not isinstance(graph_bound, bool):
        raise WorkerInputError("graph_bound 必须是布尔值")
    return _page_limit(input, graph=graph_bound)


def _page_offset(input: Mapping[str, object]) -> int:
    return _integer(
        input.get("offset", 0),
        "offset",
        minimum=0,
        maximum=_MAX_PAGE_OFFSET,
    )


def _page_fact(offset: int, limit: int, returned: int, has_more: bool) -> dict[str, object]:
    return {
        "offset": offset,
        "limit": limit,
        "returned": returned,
        "has_more": has_more,
        "next_offset": offset + limit if has_more else None,
    }


def _bounded_page[T](items: Iterable[T], offset: int, limit: int) -> tuple[list[T], bool]:
    page: list[T] = []
    matched = 0
    for item in items:
        if matched < offset:
            matched += 1
            continue
        if len(page) == limit:
            return page, True
        page.append(item)
        matched += 1
    return page, False


class AnalysisWorker(OwnerThreadBound):
    """一个私有 checkout 对应一个只读 IDA worker。"""

    def __init__(self, checkout_path: Path, *, revision: str | None = None) -> None:
        super().__init__()
        self.checkout_path = checkout_path.resolve(strict=True)
        self.revision = revision
        self._api: IdaModules | None = None
        self._analysis_ready = False
        self._closed = False

    def execute(self, operation: str, input: Mapping[str, object]) -> dict[str, object]:
        """执行一个有界只读查询。"""

        self._assert_owner_thread()
        if self._closed:
            raise WorkerError("worker_closed", "analysis worker 已关闭")
        if operation not in _OPERATIONS:
            raise WorkerInputError("analysis worker 不支持该操作", details={"operation": operation})
        api = self._require_runtime()
        self._ensure_analysis(api)
        handlers = {
            "program.overview": self._program_overview,
            "program.search": self._program_search,
            "address.inspect": self._address_inspect,
            "function.inspect": self._function_inspect,
            "graph.query": self._graph_query,
            "dataflow.slice": self._dataflow_slice,
            "type.inspect": self._type_inspect,
        }
        result = handlers[operation](api, input)
        result.setdefault("provenance", self._provenance(api))
        return result

    def close(self) -> None:
        """标记 checkout 不再使用; 调用方必须丢弃私有副本而非发布它。"""

        self._assert_owner_thread()
        self._closed = True

    def _require_runtime(self) -> IdaModules:
        if self._api is None:
            self._api = require_ida(
                "ida_auto",
                "ida_bytes",
                "ida_entry",
                "ida_fixup",
                "ida_frame",
                "ida_funcs",
                "ida_gdl",
                "ida_hexrays",
                "ida_ida",
                "ida_idaapi",
                "ida_idp",
                "ida_lines",
                "ida_loader",
                "ida_name",
                "ida_nalt",
                "ida_segment",
                "ida_typeinf",
                "ida_ua",
                "ida_xref",
                "idautils",
            )
            current_path = Path(
                self._api.ida_loader.get_path(self._api.ida_loader.PATH_TYPE_IDB)
            ).resolve(strict=False)
            if current_path != self.checkout_path:
                raise WorkerError(
                    "checkout_mismatch",
                    "IDA 当前数据库不是 worker 指定的私有 checkout",
                    details={
                        "expected": str(self.checkout_path),
                        "actual": str(current_path),
                    },
                )
        return self._api

    def _ensure_analysis(self, api: IdaModules) -> None:
        if not self._analysis_ready:
            api.ida_auto.auto_wait()
            self._analysis_ready = True

    def _provenance(self, api: IdaModules) -> dict[str, object]:
        change_count = api.ida_ida.inf_get_database_change_count()
        result: dict[str, object] = {
            "checkout_sha256": _file_sha256(self.checkout_path),
            "database_change_count": int(change_count),
            "backend": "ida-pro-9.3-headless",
            "processor": str(api.ida_ida.inf_get_procname()),
        }
        if self.revision is not None:
            result["revision"] = self.revision
        return result

    def _architecture(self, api: IdaModules) -> str:
        processor = str(api.ida_ida.inf_get_procname()).casefold()
        is_64_bit = bool(api.ida_ida.inf_is_64bit())
        is_32_bit = bool(api.ida_ida.inf_is_32bit_exactly())
        if processor == "metapc":
            if is_64_bit:
                return "x86_64"
            if is_32_bit:
                return "x86"
        if processor in {"arm", "armb"}:
            if is_64_bit:
                return "aarch64"
            if is_32_bit:
                return "arm"
        if processor == "aarch64" and is_64_bit:
            return "aarch64"
        raise CapabilityError(
            "当前静态产品边界不支持该处理器架构",
            capability="native_architecture",
            details={
                "processor": processor,
                "bitness": 64 if is_64_bit else 32 if is_32_bit else 16,
            },
        )

    def _container(self, api: IdaModules) -> str:
        """把 IDA 内部 filetype 枚举映射为稳定容器族; 非 ELF/PE 返回 other。"""

        file_type = int(api.ida_ida.inf_get_filetype())
        if file_type == int(api.ida_ida.f_ELF):
            return "elf"
        if file_type == int(api.ida_ida.f_PE):
            return "pe"
        return "other"

    def _resolve_address(self, api: IdaModules, raw: object) -> int:
        ref = _mapping(raw, "address")
        space = _text(ref.get("space"), "address.space")
        if space == "database":
            ea = _canonical_hex(ref.get("ea"), "address.ea")
        elif space == "image":
            rva = _canonical_hex(ref.get("rva"), "address.rva")
            ea = int(api.ida_nalt.get_imagebase()) + rva
        elif space == "file":
            offset = _canonical_hex(ref.get("offset"), "address.offset")
            ea = int(api.ida_loader.get_fileregion_ea(offset))
        else:
            raise WorkerInputError("静态查询只接受 database、image 或 file 地址空间")
        if ea == int(api.ida_idaapi.BADADDR):
            raise WorkerError("address_unmapped", "地址无法映射到 IDA 数据库")
        if api.ida_segment.getseg(ea) is None:
            raise WorkerError("address_unmapped", "地址不在任何 IDA segment 内")
        return ea

    def _program_overview(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        limit = _page_limit(input)
        raw_include = input.get("include", [])
        if not isinstance(raw_include, list) or any(
            not isinstance(item, str) for item in raw_include
        ):
            raise WorkerInputError("include 必须是字符串数组")
        include = cast(list[str], raw_include)
        if len(include) != len(set(include)) or set(include) - _OVERVIEW_SECTIONS:
            raise WorkerInputError("include 包含未知或重复 overview section")
        selected = set(include) if include else set(_OVERVIEW_SECTIONS)
        imagebase = int(api.ida_nalt.get_imagebase())
        maximum_address = int(api.ida_ida.inf_get_max_ea())
        if maximum_address <= imagebase:
            raise WorkerError(
                "invalid_image_layout",
                "IDA 镜像末地址必须严格大于 image base",
                details={
                    "imagebase": _hex(imagebase),
                    "maximum_address": _hex(maximum_address),
                },
            )
        segments: list[dict[str, object]] = []
        if "segments" in selected:
            segment = api.ida_segment.get_first_seg()
            while segment is not None and len(segments) < limit:
                permissions: list[str] = []
                if int(segment.perm) & int(api.ida_segment.SEGPERM_READ):
                    permissions.append("read")
                if int(segment.perm) & int(api.ida_segment.SEGPERM_WRITE):
                    permissions.append("write")
                if int(segment.perm) & int(api.ida_segment.SEGPERM_EXEC):
                    permissions.append("execute")
                segments.append(
                    {
                        "name": str(api.ida_segment.get_segm_name(segment)),
                        "class": str(api.ida_segment.get_segm_class(segment)),
                        "start": _hex(int(segment.start_ea)),
                        "end": _hex(int(segment.end_ea)),
                        "permissions": permissions,
                        "bitness": (16, 32, 64)[int(segment.bitness)],
                    }
                )
                segment = api.ida_segment.get_next_seg(int(segment.start_ea))

        badaddr = int(api.ida_idaapi.BADADDR)
        entry_points: list[dict[str, object]] = []
        start_ea = int(api.ida_ida.inf_get_start_ea())
        entry_point_count = int(
            start_ea != badaddr and api.ida_segment.getseg(start_ea) is not None
        )
        if entry_point_count and "entry_points" in selected:
            entry_points.append(
                {
                    "address": _hex(start_ea),
                    "name": str(api.ida_name.get_name(start_ea) or "entry_point"),
                }
            )

        exports: list[dict[str, object]] = []
        entry_qty = int(api.ida_entry.get_entry_qty())
        export_count = 0
        for index in range(entry_qty):
            ordinal = int(api.ida_entry.get_entry_ordinal(index))
            ea = int(api.ida_entry.get_entry(ordinal))
            if ea == start_ea:
                continue
            export_count += 1
            if "exports" in selected and len(exports) < limit:
                exports.append(
                    {
                        "ordinal": ordinal,
                        "address": _hex(ea),
                        "name": str(api.ida_entry.get_entry_name(ordinal) or ""),
                        "forwarder": str(api.ida_entry.get_entry_forwarder(ordinal) or ""),
                    }
                )

        imports: list[dict[str, object]] = []
        import_symbol_count = 0
        import_modules = int(api.ida_nalt.get_import_module_qty())
        for module_index in range(import_modules):
            module_name = str(api.ida_nalt.get_import_module_name(module_index) or "")

            def collect_import(
                ea: int,
                name: str | None,
                ordinal: int,
                bound_module_name: str = module_name,
            ) -> bool:
                nonlocal import_symbol_count
                import_symbol_count += 1
                if "imports" in selected and len(imports) < limit:
                    imports.append(
                        {
                            "module": bound_module_name,
                            "address": _hex(int(ea)),
                            "name": name or "",
                            "ordinal": int(ordinal),
                        }
                    )
                return True

            api.ida_nalt.enum_import_names(module_index, collect_import)

        fixups: list[dict[str, object]] = []
        fixup_count = 0
        fixup_ea = int(api.ida_fixup.get_first_fixup_ea())
        while fixup_ea != badaddr:
            fixup = api.ida_fixup.fixup_data_t()
            if api.ida_fixup.get_fixup(fixup, fixup_ea):
                fixup_count += 1
                if "fixups" in selected and len(fixups) < limit:
                    description = str(api.ida_fixup.get_fixup_desc(fixup_ea, fixup))
                    fixups.append(
                        {
                            "address": _hex(fixup_ea),
                            "type": int(fixup.get_type()),
                            "description": description[:_SEARCH_PREVIEW_TEXT_LIMIT],
                        }
                    )
            fixup_ea = int(api.ida_fixup.get_next_fixup_ea(fixup_ea))

        function_qty = int(api.ida_funcs.get_func_qty())
        unwind_count = 0
        catch_count = 0
        functions: list[dict[str, object]] = []
        unwind_regions: list[dict[str, object]] = []
        unwind_region_count = 0
        for index in range(function_qty):
            function = api.ida_funcs.getn_func(index)
            if function is None:
                continue
            flags = int(function.flags)
            is_unwind = bool(flags & int(api.ida_funcs.FUNC_UNWIND))
            is_catch = bool(flags & int(api.ida_funcs.FUNC_CATCH))
            unwind_count += int(is_unwind)
            catch_count += int(is_catch)
            unwind_region_count += int(is_unwind or is_catch)
            if "functions" in selected and len(functions) < limit:
                functions.append(
                    {
                        "address": _hex(int(function.start_ea)),
                        "name": str(api.ida_funcs.get_func_name(int(function.start_ea))),
                    }
                )
            if (is_unwind or is_catch) and "unwind" in selected and len(unwind_regions) < limit:
                kind = (
                    "unwind_and_catch"
                    if is_unwind and is_catch
                    else "unwind"
                    if is_unwind
                    else "catch"
                )
                unwind_regions.append(
                    {
                        "start": _hex(int(function.start_ea)),
                        "end": _hex(int(function.end_ea)),
                        "kind": kind,
                    }
                )

        ida_strings = api.idautils.Strings()
        ida_strings.setup(strtypes=[api.ida_nalt.STRTYPE_C])
        string_count = 0
        strings: list[dict[str, object]] = []
        string_preview_truncated = False
        for item in ida_strings:
            string_count += 1
            if "strings" in selected and len(strings) < limit:
                value = str(item)
                string_preview_truncated |= len(value) > _SEARCH_PREVIEW_TEXT_LIMIT
                strings.append(
                    {
                        "address": _hex(int(item.ea)),
                        "value": value[:_SEARCH_PREVIEW_TEXT_LIMIT],
                        "length": int(item.length),
                    }
                )
        raw_hash = api.ida_nalt.retrieve_input_file_sha256()
        input_hash = bytes(raw_hash).hex() if raw_hash is not None else ""
        container = self._container(api)
        return {
            "image": {
                "input_name": str(api.ida_nalt.get_root_filename()),
                "sha256": input_hash,
                "imagebase": _hex(imagebase),
                "minimum_address": _hex(int(api.ida_ida.inf_get_min_ea())),
                "maximum_address": _hex(maximum_address),
                "processor": str(api.ida_ida.inf_get_procname()),
                "architecture": self._architecture(api),
                "image_size": maximum_address - imagebase,
                "bitness": 64
                if api.ida_ida.inf_is_64bit()
                else 32
                if api.ida_ida.inf_is_32bit_exactly()
                else 16,
                "endianness": "big" if api.ida_ida.inf_is_be() else "little",
                "container": container,
            },
            "segments": segments,
            "entry_points": entry_points,
            "exports": exports,
            "imports": imports,
            "fixups": fixups,
            "unwind_regions": unwind_regions,
            "functions": functions,
            "strings": strings,
            "counts": {
                "segments": int(api.ida_segment.get_segm_qty()),
                "entry_points": entry_point_count,
                "exports": export_count,
                "import_modules": import_modules,
                "imports": import_symbol_count,
                "functions": function_qty,
                "strings": string_count,
                "fixups": fixup_count,
                "unwind_functions": unwind_count,
                "catch_functions": catch_count,
            },
            "coverage": self._overview_coverage(
                limit=limit,
                selected=selected,
                container=container,
                segment_count=int(api.ida_segment.get_segm_qty()),
                entry_point_count=entry_point_count,
                export_count=export_count,
                import_count=import_symbol_count,
                fixup_count=fixup_count,
                unwind_count=unwind_region_count,
                function_count=function_qty,
                string_count=string_count,
                string_preview_truncated=string_preview_truncated,
            ),
        }

    def _overview_coverage(
        self,
        *,
        limit: int,
        selected: set[str],
        container: str,
        segment_count: int,
        entry_point_count: int,
        export_count: int,
        import_count: int,
        fixup_count: int,
        unwind_count: int,
        function_count: int,
        string_count: int,
        string_preview_truncated: bool,
    ) -> dict[str, object]:
        truncated_sections = [
            name
            for name, count in (
                ("segments", segment_count),
                ("entry_points", entry_point_count),
                ("exports", export_count),
                ("imports", import_count),
                ("fixups", fixup_count),
                ("unwind", unwind_count),
                ("functions", function_count),
                ("strings", string_count),
            )
            if name in selected and count > limit
        ]
        truncation_reasons = [f"overview_{section}_limit_reached" for section in truncated_sections]
        if "strings" in selected and string_preview_truncated:
            truncation_reasons.append("overview_string_preview_text_hard_limit_reached")
        # unwind/exception 区域仅覆盖 PE/SEH 语义; ELF .eh_frame 不在当前契约内,
        # 因此请求 unwind 时对 ELF 显式降级而不是谎报 complete 的零结果.
        capability_reasons = (
            ["unwind_unsupported_for_elf_eh_frame"]
            if "unwind" in selected and container == "elf"
            else []
        )
        reasons = [*truncation_reasons, *capability_reasons]
        return {
            "complete": not reasons,
            "truncated": bool(truncation_reasons),
            "reasons": reasons,
            "limit": limit,
        }

    def _program_search(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        raw_domains = input.get("domains")
        if (
            not isinstance(raw_domains, list)
            or not raw_domains
            or any(not isinstance(item, str) for item in raw_domains)
        ):
            raise WorkerInputError("domains 必须是非空字符串数组")
        domains = cast(list[str], raw_domains)
        if len(domains) != len(set(domains)) or any(
            domain not in {"function", "name", "string", "bytes"} for domain in domains
        ):
            raise WorkerInputError("domains 只允许不重复的 function、name、string、bytes")
        text_domains = {"function", "name", "string"}.intersection(domains)
        raw_text_query = input.get("text_query")
        if text_domains:
            text_query = _text(raw_text_query, "text_query", allow_empty=True)
        elif raw_text_query is not None:
            raise WorkerInputError("未请求文本域时不得提供 text_query")
        else:
            text_query = None
        raw_bytes_query = input.get("bytes_query")
        if "bytes" in domains:
            bytes_query = _text(raw_bytes_query, "bytes_query")
            try:
                byte_pattern = bytes.fromhex(bytes_query)
            except ValueError as exc:
                raise WorkerInputError("bytes_query 必须是偶数长度小写十六进制") from exc
            if not byte_pattern or byte_pattern.hex() != bytes_query:
                raise WorkerInputError("bytes_query 必须是非空偶数长度小写十六进制")
        elif raw_bytes_query is not None:
            raise WorkerInputError("未请求 bytes 域时不得提供 bytes_query")
        else:
            bytes_query = None
            byte_pattern = None
        case_sensitive = input.get("case_sensitive", False)
        if not isinstance(case_sensitive, bool):
            raise WorkerInputError("case_sensitive 必须是布尔值")
        if case_sensitive and not text_domains:
            raise WorkerInputError("case_sensitive 只适用于文本域")
        limit = _page_limit(input)
        offset = _page_offset(input)
        results, has_more = _bounded_page(
            self._iter_program_search_matches(
                api,
                domains=domains,
                text_query=text_query,
                byte_pattern=byte_pattern,
                case_sensitive=case_sensitive,
            ),
            offset,
            limit,
        )
        preview_truncated = any(bool(item.pop("_preview_truncated", False)) for item in results)
        reasons = [
            *(["page_has_more"] if has_more else []),
            *(["search_preview_text_hard_limit_reached"] if preview_truncated else []),
        ]
        return {
            "domains": domains,
            "items": results,
            "page": _page_fact(offset, limit, len(results), has_more),
            "coverage": {
                "complete": not reasons,
                "truncated": bool(reasons),
                "reasons": reasons,
            },
        }

    def _iter_program_search_matches(
        self,
        api: IdaModules,
        *,
        domains: list[str],
        text_query: str | None,
        byte_pattern: bytes | None,
        case_sensitive: bool,
    ) -> Iterable[dict[str, object]]:
        for domain in domains:
            if domain == "function":
                assert text_query is not None
                yield from self._iter_function_matches(api, text_query, case_sensitive)
            elif domain == "string":
                assert text_query is not None
                yield from self._iter_string_matches(api, text_query, case_sensitive)
            elif domain == "name":
                assert text_query is not None
                yield from self._iter_name_matches(api, text_query, case_sensitive)
            else:
                assert byte_pattern is not None
                yield from self._iter_byte_matches(api, byte_pattern)

    def _iter_function_matches(
        self,
        api: IdaModules,
        query: str,
        case_sensitive: bool,
    ) -> Iterable[dict[str, object]]:
        needle = query if case_sensitive else query.casefold()
        for raw_entry in api.idautils.Functions():
            entry = int(raw_entry)
            name = str(api.ida_funcs.get_func_name(entry))
            haystack = name if case_sensitive else name.casefold()
            if needle in haystack:
                yield {
                    "domain": "function",
                    "address": _hex(entry),
                    "name": name or _hex(entry),
                }

    def _iter_string_matches(
        self,
        api: IdaModules,
        query: str,
        case_sensitive: bool,
    ) -> Iterable[dict[str, object]]:
        needle = query if case_sensitive else query.casefold()
        for item in api.idautils.Strings():
            value = str(item)
            haystack = value if case_sensitive else value.casefold()
            if needle in haystack:
                yield {
                    "domain": "string",
                    "address": _hex(int(item.ea)),
                    "value": value[:_SEARCH_PREVIEW_TEXT_LIMIT],
                    "length": int(item.length),
                    "type": int(item.strtype),
                    "_preview_truncated": len(value) > _SEARCH_PREVIEW_TEXT_LIMIT,
                }

    def _iter_name_matches(
        self,
        api: IdaModules,
        query: str,
        case_sensitive: bool,
    ) -> Iterable[dict[str, object]]:
        needle = query if case_sensitive else query.casefold()
        quantity = int(api.ida_name.get_nlist_size())
        for index in range(quantity):
            name = str(api.ida_name.get_nlist_name(index))
            address = int(api.ida_name.get_nlist_ea(index))
            haystack = name if case_sensitive else name.casefold()
            if needle in haystack:
                yield {
                    "domain": "name",
                    "address": _hex(address),
                    "name": name,
                }

    def _iter_byte_matches(
        self,
        api: IdaModules,
        pattern: bytes,
    ) -> Iterable[dict[str, object]]:
        minimum = int(api.ida_ida.inf_get_min_ea())
        maximum = int(api.ida_ida.inf_get_max_ea())
        flags = int(api.ida_bytes.BIN_SEARCH_FORWARD | api.ida_bytes.BIN_SEARCH_NOSHOW)
        current = minimum
        while current < maximum:
            found = int(api.ida_bytes.find_bytes(pattern, current, maximum, flags=flags))
            if found == int(api.ida_idaapi.BADADDR):
                return
            yield {
                "domain": "bytes",
                "address": _hex(found),
                "bytes": pattern.hex(),
            }
            current = found + 1

    def _address_inspect(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        ea = self._resolve_address(api, input.get("address"))
        limit = _inspect_limit(input)
        read_size = _integer(input.get("byte_count", 16), "byte_count", minimum=0, maximum=256)
        segment = api.ida_segment.getseg(ea)
        function = api.ida_funcs.get_func(ea)
        flags = int(api.ida_bytes.get_flags(ea))
        data = api.ida_bytes.get_bytes(ea, read_size) if read_size else b""
        instruction = api.ida_ua.insn_t()
        decoded = int(api.ida_ua.decode_insn(instruction, ea))
        text_truncated = False
        operands, operands_truncated = self._instruction_operands(
            api,
            instruction,
            ea,
        )
        text_truncated |= operands_truncated
        instruction_text = (
            str(api.ida_lines.tag_remove(api.ida_lines.generate_disasm_line(ea, 0) or ""))
            if decoded
            else ""
        )
        text_truncated |= len(instruction_text) > 4_096
        xrefs_from, from_has_more = _bounded_page(
            (
                {
                    "to": _hex(int(xref.to)),
                    "type": int(xref.type),
                    "is_code": bool(xref.iscode),
                }
                for xref in api.idautils.XrefsFrom(ea)
            ),
            0,
            limit,
        )
        xrefs_to, to_has_more = _bounded_page(
            (
                {
                    "from": _hex(int(xref.frm)),
                    "type": int(xref.type),
                    "is_code": bool(xref.iscode),
                }
                for xref in api.idautils.XrefsTo(ea)
            ),
            0,
            limit,
        )
        truncated = from_has_more or to_has_more
        return {
            "address": _hex(ea),
            "image_rva": _hex(ea - int(api.ida_nalt.get_imagebase())),
            "name": str(api.ida_name.get_name(ea) or ""),
            "segment": str(api.ida_segment.get_segm_name(segment)) if segment else None,
            "function": (
                {
                    "entry": _hex(int(function.start_ea)),
                    "name": str(api.ida_funcs.get_func_name(int(function.start_ea))),
                }
                if function is not None
                else None
            ),
            "item": {
                "is_code": bool(api.ida_bytes.is_code(flags)),
                "is_data": bool(api.ida_bytes.is_data(flags)),
                "size": int(api.ida_bytes.get_item_size(ea)),
                "bytes": bytes(data or b"").hex(),
            },
            "instruction": (
                {
                    "size": decoded,
                    "mnemonic": str(api.ida_ua.print_insn_mnem(ea)),
                    "text": instruction_text[:4_096],
                    "operands": operands,
                }
                if decoded
                else None
            ),
            "xrefs_from": xrefs_from,
            "xrefs_to": xrefs_to,
            "coverage": {
                "complete": not truncated and not text_truncated,
                "truncated": truncated or text_truncated,
                "reasons": [
                    *(["xref_hard_limit_reached"] if truncated else []),
                    *(["instruction_text_hard_limit_reached"] if text_truncated else []),
                ],
            },
        }

    @staticmethod
    def _instruction_operands(
        api: IdaModules,
        instruction: object,
        ea: int,
    ) -> tuple[list[dict[str, object]], bool]:
        """提取操作数。区分立即数值与可静态解析的直接地址引用。"""

        operands: list[dict[str, object]] = []
        text_truncated = False
        immediate_type = int(api.ida_ua.o_imm)
        reference_types = {
            int(api.ida_ua.o_mem),
            int(api.ida_ua.o_far),
            int(api.ida_ua.o_near),
        }
        for index in range(8):
            operand = instruction.ops[index]
            operand_type = int(operand.type)
            if operand_type == int(api.ida_ua.o_void):
                break
            operand_text = str(api.ida_lines.tag_remove(api.ida_ua.print_operand(ea, index) or ""))
            text_truncated |= len(operand_text) > 4_096
            operands.append(
                {
                    "index": index,
                    "type": operand_type,
                    "dtype": int(operand.dtype),
                    "text": operand_text[:4_096],
                    "value": (
                        _hex(int(operand.value) & 0xFFFF_FFFF_FFFF_FFFF)
                        if operand_type == immediate_type
                        else None
                    ),
                    "address": (
                        _hex(int(operand.addr) & 0xFFFF_FFFF_FFFF_FFFF)
                        if operand_type in reference_types
                        else None
                    ),
                }
            )
        return operands, text_truncated

    def _function_from_input(self, api: IdaModules, input: Mapping[str, object]) -> object:
        ea = self._resolve_address(api, input.get("address"))
        function = api.ida_funcs.get_func(ea)
        if function is None:
            raise WorkerError("function_not_found", "地址不属于 IDA 已识别函数")
        return function

    def _function_inspect(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        function = self._function_from_input(api, input)
        limit = _inspect_limit(input)
        offset = _page_offset(input)
        raw_views = input.get(
            "views",
            ["chunks", "disassembly", "blocks", "calls", "strings", "types"],
        )
        if not isinstance(raw_views, list) or any(not isinstance(item, str) for item in raw_views):
            raise WorkerInputError("views 必须是字符串数组")
        views = set(cast(list[str], raw_views))
        allowed = {
            "summary",
            "chunks",
            "disassembly",
            "pseudocode",
            "ctree",
            "blocks",
            "calls",
            "strings",
            "stack",
            "lvars",
            "types",
        }
        unknown = views - allowed
        if unknown:
            raise WorkerInputError("views 包含未知值", details={"views": sorted(unknown)})
        entry = int(function.start_ea)
        result: dict[str, object] = {
            "entry": _hex(entry),
            "name": str(api.ida_funcs.get_func_name(entry)),
            "size": int(api.ida_funcs.calc_func_size(function)),
            "flags": int(function.flags),
            "does_return": bool(function.does_return()),
        }
        page_lengths: list[int] = []
        page_has_more = False
        reasons: list[str] = []
        if "chunks" in views:
            chunks = [
                {"start": _hex(int(start)), "end": _hex(int(end))}
                for start, end in api.idautils.Chunks(entry)
            ]
            result["chunks"] = chunks[:_NONPAGED_CHUNK_LIMIT]
            if len(chunks) > _NONPAGED_CHUNK_LIMIT:
                reasons.append("function_chunk_hard_limit_reached")
        if "disassembly" in views:

            def iter_instructions() -> Iterable[dict[str, object]]:
                for ea in api.idautils.FuncItems(entry):
                    instruction = api.ida_ua.insn_t()
                    size = int(api.ida_ua.decode_insn(instruction, ea))
                    if not size:
                        continue
                    rendered = str(
                        api.ida_lines.tag_remove(api.ida_lines.generate_disasm_line(ea, 0) or "")
                    )
                    operands, operands_truncated = self._instruction_operands(
                        api,
                        instruction,
                        int(ea),
                    )
                    yield {
                        "address": _hex(int(ea)),
                        "size": size,
                        "mnemonic": str(api.ida_ua.print_insn_mnem(ea)),
                        "text": rendered[:4_096],
                        "operands": operands,
                        "_text_truncated": len(rendered) > 4_096 or operands_truncated,
                    }

            instructions, has_more = _bounded_page(iter_instructions(), offset, limit)
            if any(bool(instruction.pop("_text_truncated", False)) for instruction in instructions):
                reasons.append("disassembly_text_hard_limit_reached")
            result["instructions"] = instructions
            page_lengths.append(len(instructions))
            page_has_more |= has_more
        if "blocks" in views:

            def iter_blocks() -> Iterable[dict[str, object]]:
                for block in api.ida_gdl.FlowChart(function):
                    yield {
                        "id": int(block.id),
                        "start": _hex(int(block.start_ea)),
                        "end": _hex(int(block.end_ea)),
                        "successors": [int(item.id) for item in block.succs()],
                        "predecessors": [int(item.id) for item in block.preds()],
                    }

            blocks, has_more = _bounded_page(iter_blocks(), offset, limit)
            result["blocks"] = blocks
            page_lengths.append(len(blocks))
            page_has_more |= has_more
        if "calls" in views:
            calls, has_more = _bounded_page(
                self._iter_function_calls(api, entry),
                offset,
                limit,
            )
            result["calls"] = calls
            page_lengths.append(len(calls))
            page_has_more |= has_more
        if "strings" in views:
            strings, has_more = _bounded_page(
                self._iter_function_strings(api, entry),
                offset,
                limit,
            )
            if any(bool(string.pop("_value_truncated", False)) for string in strings):
                reasons.append("function_string_hard_limit_reached")
            result["strings"] = strings
            page_lengths.append(len(strings))
            page_has_more |= has_more
        cfunc = None
        if views & {"pseudocode", "ctree", "lvars"}:
            if not api.ida_hexrays.init_hexrays_plugin():
                raise CapabilityError(
                    "当前 IDA 许可证或架构没有可用 Hex-Rays decompiler",
                    capability="hexrays",
                )
            try:
                cfunc = api.ida_hexrays.decompile(entry)
            except Exception as exc:
                raise CapabilityError(
                    "Hex-Rays 无法反编译目标函数",
                    capability="hexrays_decompile",
                    details={"entry": _hex(entry), "reason": type(exc).__name__},
                ) from exc
            if cfunc is None:
                raise CapabilityError(
                    "Hex-Rays 无法反编译目标函数",
                    capability="hexrays_decompile",
                    details={"entry": _hex(entry)},
                )
        if "pseudocode" in views and cfunc is not None:
            lines, has_more = _bounded_page(
                (str(api.ida_lines.tag_remove(str(line.line))) for line in cfunc.get_pseudocode()),
                offset,
                limit,
            )
            if any(len(line) > 4_096 for line in lines):
                reasons.append("pseudocode_line_hard_limit_reached")
            result["pseudocode"] = [line[:4_096] for line in lines]
            page_lengths.append(len(lines))
            page_has_more |= has_more
        if "ctree" in views and cfunc is not None:
            ctree, has_more, text_truncated = self._ctree_items(
                api,
                cfunc,
                offset,
                limit,
            )
            if text_truncated:
                reasons.append("ctree_text_hard_limit_reached")
            result["ctree"] = ctree
            page_lengths.append(len(ctree))
            page_has_more |= has_more
        if "lvars" in views and cfunc is not None:

            def iter_variables() -> Iterable[dict[str, object]]:
                for index, variable in enumerate(cfunc.lvars):
                    type_text = str(variable.type())
                    yield {
                        "index": index,
                        "name": str(variable.name),
                        "type": type_text[:_MEMBER_TYPE_TEXT_LIMIT],
                        "_type_truncated": len(type_text) > _MEMBER_TYPE_TEXT_LIMIT,
                        "definition_address": _hex(int(variable.defea)),
                        "width": int(variable.width),
                        "location": "stack"
                        if variable.is_stk_var()
                        else "register"
                        if variable.is_reg_var()
                        else "other",
                    }

            variables, has_more = _bounded_page(iter_variables(), offset, limit)
            if any(bool(variable.pop("_type_truncated", False)) for variable in variables):
                reasons.append("local_type_text_hard_limit_reached")
            result["lvars"] = variables
            page_lengths.append(len(variables))
            page_has_more |= has_more
        if "stack" in views:
            result["stack"] = {
                "local_size": int(function.frsize),
                "saved_register_size": int(function.frregs),
                "argument_size": int(function.argsize),
                "frame_pointer_delta": int(function.fpd),
                "frame_size": int(api.ida_frame.get_frame_size(function)),
            }
        if "types" in views:
            type_info = api.ida_typeinf.tinfo_t()
            if api.ida_nalt.get_tinfo(type_info, entry):
                type_text = str(type_info)
                result["type"] = type_text[:_INLINE_TYPE_TEXT_LIMIT]
                if len(type_text) > _INLINE_TYPE_TEXT_LIMIT:
                    reasons.append("function_type_text_hard_limit_reached")
            else:
                result["type"] = None
        if page_has_more:
            reasons.append("page_has_more")
        result["page"] = _page_fact(
            offset,
            limit,
            max(page_lengths, default=0),
            page_has_more,
        )
        result["coverage"] = {
            "complete": not page_has_more and not reasons,
            "truncated": page_has_more or bool(reasons),
            "reasons": reasons,
        }
        return result

    def _iter_function_calls(
        self,
        api: IdaModules,
        entry: int,
    ) -> Iterable[dict[str, object]]:
        seen: set[tuple[int, int]] = set()
        for ea in api.idautils.FuncItems(entry):
            for xref in api.idautils.XrefsFrom(ea):
                if int(xref.type) not in {
                    int(api.ida_xref.fl_CF),
                    int(api.ida_xref.fl_CN),
                }:
                    continue
                target_function = api.ida_funcs.get_func(int(xref.to))
                if target_function is None:
                    continue
                target = int(target_function.start_ea)
                key = (int(ea), target)
                if key in seen:
                    continue
                seen.add(key)
                yield {
                    "site": _hex(int(ea)),
                    "target": _hex(target),
                    "name": str(api.ida_funcs.get_func_name(target)),
                    "xref_type": int(xref.type),
                }

    def _iter_function_strings(
        self,
        api: IdaModules,
        entry: int,
    ) -> Iterable[dict[str, object]]:
        seen: set[tuple[int, int]] = set()
        for ea in api.idautils.FuncItems(entry):
            for xref in api.idautils.XrefsFrom(ea):
                target = int(xref.to)
                target_flags = int(api.ida_bytes.get_flags(target))
                if not api.ida_bytes.is_strlit(target_flags):
                    continue
                key = (int(ea), target)
                if key in seen:
                    continue
                seen.add(key)
                raw = api.ida_bytes.get_strlit_contents(
                    target,
                    -1,
                    api.ida_nalt.get_str_type(target),
                )
                value = bytes(raw or b"")
                yield {
                    "site": _hex(int(ea)),
                    "address": _hex(target),
                    "value_hex": value[:_INLINE_STRING_BYTES_LIMIT].hex(),
                    "_value_truncated": len(value) > _INLINE_STRING_BYTES_LIMIT,
                }

    def _ctree_items(
        self,
        api: IdaModules,
        cfunc: object,
        offset: int,
        limit: int,
    ) -> tuple[list[dict[str, object]], bool, bool]:
        items: list[dict[str, object]] = []
        badaddr = int(api.ida_idaapi.BADADDR)

        class Visitor(api.ida_hexrays.ctree_visitor_t):
            def __init__(self) -> None:
                super().__init__(api.ida_hexrays.CV_FAST)
                self.matched = 0
                self.has_more = False

            def append(self, item: dict[str, object]) -> int:
                if self.matched < offset:
                    self.matched += 1
                    return 0
                if len(items) == limit:
                    self.has_more = True
                    return 1
                items.append(item)
                self.matched += 1
                return 0

            def visit_expr(self, expression: object) -> int:
                ea = int(expression.ea)
                if ea == badaddr:
                    return 0
                rendered = str(api.ida_lines.tag_remove(expression.print1(None)))
                return self.append(
                    {
                        "item": "expression",
                        "address": _hex(ea),
                        "opcode": int(expression.op),
                        "text": rendered[:4_096],
                        "_text_truncated": len(rendered) > 4_096,
                    }
                )

            def visit_insn(self, statement: object) -> int:
                ea = int(statement.ea)
                if ea == badaddr:
                    return 0
                return self.append(
                    {
                        "item": "statement",
                        "address": _hex(ea),
                        "opcode": int(statement.op),
                    }
                )

        visitor = Visitor()
        visitor.apply_to(cfunc.body, None)
        text_truncated = any(bool(item.pop("_text_truncated", False)) for item in items)
        return items, visitor.has_more, text_truncated

    def _graph_query(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        graph_kind = _text(input.get("kind"), "kind")
        if graph_kind not in {"cfg", "call", "xref"}:
            raise WorkerInputError("graph kind 只允许 cfg、call 或 xref")
        raw_roots = input.get("roots")
        if not isinstance(raw_roots, list) or not raw_roots or len(raw_roots) > 32:
            raise WorkerInputError("roots 必须是包含 1..32 个地址的数组")
        roots = [
            self._resolve_address(api, _mapping(root, f"roots[{index}]"))
            for index, root in enumerate(raw_roots)
        ]
        direction = _text(input.get("direction", "outgoing"), "direction")
        if direction not in {"outgoing", "incoming", "both"}:
            raise WorkerInputError("direction 只允许 outgoing、incoming 或 both")
        max_depth = _integer(input.get("max_depth", 1), "max_depth", minimum=0, maximum=32)
        limit = _page_limit(input, graph=True)
        edge_limit = min(_MAX_GRAPH_EDGES, limit * 4)
        if graph_kind == "cfg":
            root_nodes, load_neighbors = self._cfg_graph_source(api, roots, direction)
            incoming_indirect_unresolvable = False
        elif graph_kind == "call":
            root_nodes, load_neighbors = self._call_graph_source(api, roots, direction)
            incoming_indirect_unresolvable = max_depth > 0 and direction in {"incoming", "both"}
        else:
            root_nodes, load_neighbors = self._xref_graph_source(api, roots, direction)
            incoming_indirect_unresolvable = False

        (
            selected_nodes,
            selected_edges,
            unresolved_indirect_edges,
            node_limit_reached,
            edge_limit_reached,
        ) = self._bounded_graph_traversal(
            root_nodes,
            load_neighbors,
            max_depth=max_depth,
            limit=limit,
            edge_limit=edge_limit,
        )
        reasons = [
            *(["graph_node_limit_reached"] if node_limit_reached else []),
            *(["graph_edge_limit_reached"] if edge_limit_reached else []),
            *(["unresolved_indirect_calls"] if unresolved_indirect_edges else []),
            *(["indirect_incoming_edges_unresolvable"] if incoming_indirect_unresolvable else []),
        ]
        truncated = node_limit_reached or edge_limit_reached
        return {
            "kind": graph_kind,
            "direction": direction,
            "max_depth": max_depth,
            "nodes": [node.to_json() for node in selected_nodes],
            "edges": [edge.to_json() for edge in selected_edges],
            "unresolved_indirect_edges": unresolved_indirect_edges,
            "coverage": {
                "complete": not reasons,
                "truncated": truncated,
                "reasons": reasons,
                "node_limit": limit,
                "edge_limit": edge_limit,
            },
        }

    def _cfg_graph_source(
        self,
        api: IdaModules,
        roots: list[int],
        direction: str,
    ) -> tuple[
        list[_GraphNode],
        Callable[[str], tuple[list[tuple[_GraphNode, _GraphEdge]], int]],
    ]:
        nodes: dict[str, _GraphNode] = {}
        block_ends: dict[str, int] = {}
        outgoing: dict[str, list[_GraphEdge]] = {}
        incoming: dict[str, list[_GraphEdge]] = {}
        root_nodes: list[_GraphNode] = []
        loaded_functions: set[int] = set()
        for root in roots:
            function = api.ida_funcs.get_func(root)
            if function is None:
                raise WorkerError("function_not_found", "CFG root 地址不属于 IDA 已识别函数")
            entry = int(function.start_ea)
            if entry not in loaded_functions:
                blocks = sorted(
                    api.ida_gdl.FlowChart(function),
                    key=lambda block: (int(block.start_ea), int(block.id)),
                )
                if not blocks:
                    raise WorkerError("cfg_unavailable", "目标函数没有可用基本块")
                loaded_functions.add(entry)
                for block in blocks:
                    block_id = int(block.id)
                    key = self._cfg_node_id(entry, block_id)
                    node = _GraphNode(
                        id=key,
                        kind="basic_block",
                        address=int(block.start_ea),
                        label=(
                            f"{api.ida_funcs.get_func_name(entry) or _hex(entry)}: block {block_id}"
                        ),
                        function=entry,
                        block_id=block_id,
                    )
                    nodes[key] = node
                    block_ends[key] = int(block.end_ea)
                    outgoing.setdefault(key, [])
                    incoming.setdefault(key, [])
                for block in blocks:
                    source = self._cfg_node_id(entry, int(block.id))
                    for successor in sorted(
                        block.succs(),
                        key=lambda candidate: (int(candidate.start_ea), int(candidate.id)),
                    ):
                        target = self._cfg_node_id(entry, int(successor.id))
                        if target not in nodes:
                            continue
                        edge = _GraphEdge(source=source, target=target, kind="flow")
                        outgoing[source].append(edge)
                        incoming[target].append(edge)
            containing = [
                node
                for node in nodes.values()
                if node.function == entry and node.address <= root and root < block_ends[node.id]
            ]
            if containing:
                root_nodes.append(max(containing, key=lambda node: node.address))
            else:
                root_nodes.append(
                    min(
                        (node for node in nodes.values() if node.function == entry),
                        key=lambda node: node.address,
                    )
                )

        def load_neighbors(node_id: str) -> tuple[list[tuple[_GraphNode, _GraphEdge]], int]:
            pairs: list[tuple[_GraphNode, _GraphEdge]] = []
            if direction in {"outgoing", "both"}:
                pairs.extend((nodes[edge.target], edge) for edge in outgoing[node_id])
            if direction in {"incoming", "both"}:
                pairs.extend((nodes[edge.source], edge) for edge in incoming[node_id])
            return self._sorted_graph_pairs(pairs), 0

        return root_nodes, load_neighbors

    @staticmethod
    def _cfg_node_id(function: int, block_id: int) -> str:
        return f"cfg:{function:x}:{block_id}"

    def _call_graph_source(
        self,
        api: IdaModules,
        roots: list[int],
        direction: str,
    ) -> tuple[
        list[_GraphNode],
        Callable[[str], tuple[list[tuple[_GraphNode, _GraphEdge]], int]],
    ]:
        entries: dict[str, int] = {}

        def node_for_entry(entry: int) -> _GraphNode:
            node_id = f"fn:{entry:x}"
            entries[node_id] = entry
            name = str(api.ida_funcs.get_func_name(entry))
            return _GraphNode(
                id=node_id,
                kind="function",
                address=entry,
                label=name or _hex(entry),
            )

        root_nodes: list[_GraphNode] = []
        for root in roots:
            function = api.ida_funcs.get_func(root)
            if function is None:
                raise WorkerError("function_not_found", "call graph root 地址不属于 IDA 已识别函数")
            root_nodes.append(node_for_entry(int(function.start_ea)))

        def load_neighbors(node_id: str) -> tuple[list[tuple[_GraphNode, _GraphEdge]], int]:
            entry = entries[node_id]
            pairs: list[tuple[_GraphNode, _GraphEdge]] = []
            unresolved = 0
            if direction in {"outgoing", "both"}:
                outgoing, unresolved = self._function_call_edges(api, entry)
                for target, site, relation in outgoing:
                    target_node = node_for_entry(target)
                    pairs.append(
                        (
                            target_node,
                            _GraphEdge(
                                source=node_id,
                                target=target_node.id,
                                kind=relation,
                                site=site,
                            ),
                        )
                    )
            if direction in {"incoming", "both"}:
                for source, site, relation in self._function_caller_edges(api, entry):
                    source_node = node_for_entry(source)
                    pairs.append(
                        (
                            source_node,
                            _GraphEdge(
                                source=source_node.id,
                                target=node_id,
                                kind=relation,
                                site=site,
                            ),
                        )
                    )
            return self._sorted_graph_pairs(pairs), unresolved

        return root_nodes, load_neighbors

    def _function_call_edges(
        self,
        api: IdaModules,
        entry: int,
    ) -> tuple[list[tuple[int, int, Literal["call", "jump"]]], int]:
        edges: set[tuple[int, int, Literal["call", "jump"]]] = set()
        unresolved = 0
        call_xref_types = {
            int(api.ida_xref.fl_CF),
            int(api.ida_xref.fl_CN),
        }
        jump_xref_types = {
            int(api.ida_xref.fl_JF),
            int(api.ida_xref.fl_JN),
        }
        for ea in sorted(int(item) for item in api.idautils.FuncItems(entry)):
            instruction = api.ida_ua.insn_t()
            decoded = int(api.ida_ua.decode_insn(instruction, ea))
            is_call = bool(decoded and api.ida_idp.is_call_insn(instruction))
            is_indirect_jump = bool(decoded and api.ida_idp.is_indirect_jump_insn(instruction))
            resolved_at_site = False
            site_xrefs = list(api.idautils.XrefsFrom(ea))
            for xref in site_xrefs:
                xref_type = int(xref.type)
                if xref_type not in call_xref_types | jump_xref_types:
                    continue
                target_function = api.ida_funcs.get_func(int(xref.to))
                if target_function is None:
                    continue
                target = int(target_function.start_ea)
                if xref_type in call_xref_types:
                    resolved_at_site = True
                    edges.add((target, ea, "call"))
                elif target != entry:
                    edges.add((target, ea, "jump"))
            has_code_target = any(bool(xref.iscode) for xref in site_xrefs)
            if (is_call and not resolved_at_site) or (is_indirect_jump and not has_code_target):
                unresolved += 1
        return sorted(edges), unresolved

    def _function_caller_edges(
        self,
        api: IdaModules,
        entry: int,
    ) -> list[tuple[int, int, Literal["call", "jump"]]]:
        call_xref_types = {
            int(api.ida_xref.fl_CF),
            int(api.ida_xref.fl_CN),
        }
        jump_xref_types = {
            int(api.ida_xref.fl_JF),
            int(api.ida_xref.fl_JN),
        }
        edges: set[tuple[int, int, Literal["call", "jump"]]] = set()
        for xref in api.idautils.XrefsTo(entry):
            xref_type = int(xref.type)
            if xref_type not in call_xref_types | jump_xref_types:
                continue
            source_function = api.ida_funcs.get_func(int(xref.frm))
            if source_function is not None:
                source = int(source_function.start_ea)
                if source != entry or xref_type in call_xref_types:
                    edges.add(
                        (
                            source,
                            int(xref.frm),
                            "call" if xref_type in call_xref_types else "jump",
                        )
                    )
        return sorted(edges)

    def _xref_graph_source(
        self,
        api: IdaModules,
        roots: list[int],
        direction: str,
    ) -> tuple[
        list[_GraphNode],
        Callable[[str], tuple[list[tuple[_GraphNode, _GraphEdge]], int]],
    ]:
        addresses: dict[str, int] = {}

        def node_for_address(address: int) -> _GraphNode:
            node_id = f"ea:{address:x}"
            addresses[node_id] = address
            flags = int(api.ida_bytes.get_flags(address))
            if api.ida_bytes.is_code(flags):
                kind: _GraphNodeKind = "instruction"
            elif api.ida_bytes.is_data(flags):
                kind = "data"
            else:
                kind = "unknown"
            name = str(api.ida_name.get_name(address))
            return _GraphNode(
                id=node_id,
                kind=kind,
                address=address,
                label=name or _hex(address),
            )

        root_nodes = [node_for_address(root) for root in roots]

        def load_neighbors(node_id: str) -> tuple[list[tuple[_GraphNode, _GraphEdge]], int]:
            address = addresses[node_id]
            pairs: list[tuple[_GraphNode, _GraphEdge]] = []
            if direction in {"outgoing", "both"}:
                for xref in api.idautils.XrefsFrom(address):
                    target = int(xref.to)
                    target_node = node_for_address(target)
                    pairs.append(
                        (
                            target_node,
                            _GraphEdge(
                                source=node_id,
                                target=target_node.id,
                                kind="xref_code" if bool(xref.iscode) else "xref_data",
                                site=address,
                            ),
                        )
                    )
            if direction in {"incoming", "both"}:
                for xref in api.idautils.XrefsTo(address):
                    source = int(xref.frm)
                    source_node = node_for_address(source)
                    pairs.append(
                        (
                            source_node,
                            _GraphEdge(
                                source=source_node.id,
                                target=node_id,
                                kind="xref_code" if bool(xref.iscode) else "xref_data",
                                site=source,
                            ),
                        )
                    )
            return self._sorted_graph_pairs(pairs), 0

        return root_nodes, load_neighbors

    @staticmethod
    def _sorted_graph_pairs(
        pairs: Iterable[tuple[_GraphNode, _GraphEdge]],
    ) -> list[tuple[_GraphNode, _GraphEdge]]:
        unique: dict[tuple[str, str, str, int | None], tuple[_GraphNode, _GraphEdge]] = {}
        for node, edge in pairs:
            unique[(edge.source, edge.target, edge.kind, edge.site)] = (node, edge)
        return [
            pair
            for _, pair in sorted(
                unique.items(),
                key=lambda item: (
                    item[1][0].address,
                    item[0][0],
                    item[0][1],
                    item[0][2],
                    -1 if item[0][3] is None else item[0][3],
                ),
            )
        ]

    @staticmethod
    def _bounded_graph_traversal(
        roots: list[_GraphNode],
        load_neighbors: Callable[[str], tuple[list[tuple[_GraphNode, _GraphEdge]], int]],
        *,
        max_depth: int,
        limit: int,
        edge_limit: int,
    ) -> tuple[list[_GraphNode], list[_GraphEdge], int, bool, bool]:
        selected: dict[str, _GraphNode] = {}
        frontier: deque[tuple[str, int]] = deque()
        node_limit_reached = False
        for root in roots:
            if root.id in selected:
                continue
            if len(selected) == limit:
                node_limit_reached = True
                continue
            selected[root.id] = root
            frontier.append((root.id, 0))

        edges: dict[tuple[str, str, str, int | None], _GraphEdge] = {}
        edge_limit_reached = False
        unresolved_indirect_edges = 0
        while frontier:
            current, depth = frontier.popleft()
            if depth >= max_depth:
                continue
            neighbors, unresolved = load_neighbors(current)
            unresolved_indirect_edges += unresolved
            for neighbor, edge in neighbors:
                if neighbor.id not in selected:
                    if len(selected) == limit:
                        node_limit_reached = True
                        continue
                    selected[neighbor.id] = neighbor
                    frontier.append((neighbor.id, depth + 1))
                if edge.source not in selected or edge.target not in selected:
                    continue
                key = (edge.source, edge.target, edge.kind, edge.site)
                if key in edges:
                    continue
                if len(edges) == edge_limit:
                    edge_limit_reached = True
                    continue
                edges[key] = edge
        return (
            list(selected.values()),
            list(edges.values()),
            unresolved_indirect_edges,
            node_limit_reached,
            edge_limit_reached,
        )

    def _dataflow_slice(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        function = self._function_from_input(api, input)
        limit = _page_limit(input, graph=True)
        direction = _text(input.get("direction", "backward"), "direction")
        if direction not in {"backward", "forward"}:
            raise WorkerInputError("direction 只允许 backward 或 forward")
        semantics = _text(input.get("semantics", "may"), "semantics")
        if semantics not in {"may", "must"}:
            raise WorkerInputError("semantics 只允许 may 或 must")
        seed_ea = self._resolve_address(api, input.get("seed"))
        if not api.ida_hexrays.init_hexrays_plugin():
            raise CapabilityError(
                "函数内 dataflow slice 需要 Hex-Rays",
                capability="hexrays_microcode",
            )
        failure = api.ida_hexrays.hexrays_failure_t()
        try:
            mba = api.ida_hexrays.gen_microcode(
                api.ida_hexrays.mba_ranges_t(function),
                failure,
                api.ida_hexrays.mlist_t(),
                0,
                api.ida_hexrays.MMAT_GENERATED,
            )
        except Exception as exc:
            raise CapabilityError(
                "目标函数无法生成 Hex-Rays microcode",
                capability="hexrays_microcode",
                details={"reason": type(exc).__name__},
            ) from exc
        if mba is None:
            raise CapabilityError(
                "目标函数没有可用 Hex-Rays microcode",
                capability="hexrays_microcode",
                details={
                    "error_address": _hex(int(failure.errea)),
                    "error_code": int(failure.code),
                    "reason": str(failure.desc()),
                },
            )
        program = self._microcode_program(api, mba)
        seed_indexes = [
            instruction.index
            for instruction in program.instructions
            if instruction.address == _hex(seed_ea)
        ]
        if not seed_indexes:
            raise WorkerError("slice_seed_not_found", "seed 地址没有对应 microcode 指令")
        if semantics == "must":
            selected, edges, barriers, limit_hit = self._must_slice(
                program,
                seed_indexes,
                direction=direction,
                limit=limit,
            )
        else:
            selected, edges, barriers, limit_hit = self._may_slice(
                program,
                seed_indexes,
                direction=direction,
                limit=limit,
            )
        ordered_indexes = sorted(selected)
        retained = set(ordered_indexes)
        raw_barriers = [
            {
                "address": (program.instructions[index].address if index is not None else None),
                "reason": reason,
            }
            for index, reason in sorted(
                barriers,
                key=lambda item: (
                    -1 if item[0] is None else item[0],
                    item[1],
                ),
            )
        ]
        if limit_hit:
            raw_barriers.append({"address": None, "reason": "analysis_limit"})
        barrier_reasons = sorted({cast(str, item["reason"]) for item in raw_barriers})
        return {
            "function": _hex(int(function.start_ea)),
            "seed": _hex(seed_ea),
            "direction": direction,
            "mode": semantics,
            "instructions": [
                self._micro_instruction_json(program.instructions[index])
                for index in ordered_indexes
            ],
            "edges": [
                {
                    "source_index": source,
                    "target_index": target,
                    "relation": "defines",
                }
                for source, target in sorted(edges)
                if source in retained and target in retained
            ],
            "unknown_barriers": raw_barriers,
            "coverage": {
                "complete": not raw_barriers,
                "truncated": limit_hit,
                "reasons": barrier_reasons,
                "bounded_to_function": True,
                "microcode_maturity": int(mba.maturity),
            },
        }

    def _must_slice(
        self,
        program: _MicroProgram,
        seed_indexes: list[int],
        *,
        direction: str,
        limit: int,
    ) -> tuple[
        set[int],
        set[tuple[int, int]],
        dict[tuple[int | None, _BarrierReason], None],
        bool,
    ]:
        selected = set(seed_indexes[:limit])
        limit_hit = len(seed_indexes) > limit
        edges: set[tuple[int, int]] = set()
        barriers: dict[tuple[int | None, _BarrierReason], None] = {}
        frontier = list(sorted(selected, reverse=True))
        proof_cache: dict[tuple[int, str], _MustDefinitionProof] = {}
        while frontier:
            current_index = frontier.pop()
            current = program.instructions[current_index]
            sought = current.uses if direction == "backward" else current.definitions
            for location in sorted(sought):
                if self._barrier_blocks(current, location):
                    assert current.barrier is not None
                    barriers[(current_index, current.barrier)] = None
                    continue
                if direction == "backward":
                    proof = self._must_reaching_definition(
                        program,
                        current,
                        location,
                        proof_cache,
                    )
                    barriers.update({barrier: None for barrier in proof.barriers})
                    definition = proof.unique_definition
                    if definition is None:
                        continue
                    candidates = ((definition, current_index),)
                else:
                    uses, encountered = self._must_reachable_uses(
                        program,
                        current,
                        location,
                        proof_cache,
                    )
                    barriers.update(encountered)
                    candidates = tuple((current_index, use) for use in sorted(uses))
                for source, target in candidates:
                    candidate = source if direction == "backward" else target
                    if candidate not in selected:
                        if len(selected) == limit:
                            limit_hit = True
                            continue
                        selected.add(candidate)
                        frontier.append(candidate)
                    if source in selected and target in selected:
                        edges.add((source, target))
        return selected, edges, barriers, limit_hit

    def _must_reaching_definition(
        self,
        program: _MicroProgram,
        current: _MicroInstruction,
        location: str,
        cache: dict[tuple[int, str], _MustDefinitionProof],
    ) -> _MustDefinitionProof:
        cache_key = (current.index, location)
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        definitions: set[int] = set()
        barriers: set[tuple[int, _BarrierReason]] = set()
        has_unbound_path = False
        pending = [(current.block, current.position)]
        visited: set[tuple[int, int]] = set()
        while pending:
            block_id, before = pending.pop()
            state = (block_id, before)
            if state in visited:
                continue
            visited.add(state)
            stopped = False
            indexes = program.block_instructions[block_id]
            for candidate_index in reversed(indexes[:before]):
                candidate = program.instructions[candidate_index]
                if self._barrier_blocks(candidate, location):
                    assert candidate.barrier is not None
                    barriers.add((candidate_index, candidate.barrier))
                    stopped = True
                    break
                if self._definitions_overlap(candidate, location):
                    if self._definitions_cover(candidate, location):
                        definitions.add(candidate_index)
                    else:
                        has_unbound_path = True
                    stopped = True
                    break
            if stopped:
                continue
            predecessors = program.predecessors[block_id]
            if not predecessors:
                has_unbound_path = True
                continue
            for predecessor in predecessors:
                pending.append((predecessor, len(program.block_instructions[predecessor])))

        proof = _MustDefinitionProof(
            definitions=frozenset(definitions),
            has_unbound_path=has_unbound_path,
            barriers=frozenset(barriers),
        )
        cache[cache_key] = proof
        return proof

    def _must_reachable_uses(
        self,
        program: _MicroProgram,
        current: _MicroInstruction,
        location: str,
        proof_cache: dict[tuple[int, str], _MustDefinitionProof],
    ) -> tuple[set[int], dict[tuple[int | None, _BarrierReason], None]]:
        uses: set[int] = set()
        barriers: dict[tuple[int | None, _BarrierReason], None] = {}
        pending = [(current.block, current.position + 1)]
        visited: set[tuple[int, int]] = set()
        while pending:
            block_id, after = pending.pop()
            state = (block_id, after)
            if state in visited:
                continue
            visited.add(state)
            stopped = False
            indexes = program.block_instructions[block_id]
            for candidate_index in indexes[after:]:
                candidate = program.instructions[candidate_index]
                if self._barrier_blocks(candidate, location):
                    assert candidate.barrier is not None
                    barriers[(candidate_index, candidate.barrier)] = None
                    stopped = True
                    break
                if self._uses_overlap(candidate, location):
                    proof = self._must_reaching_definition(
                        program,
                        candidate,
                        location,
                        proof_cache,
                    )
                    barriers.update({barrier: None for barrier in proof.barriers})
                    if proof.unique_definition == current.index:
                        uses.add(candidate_index)
                if self._definitions_overlap(candidate, location):
                    stopped = True
                    break
            if stopped:
                continue
            for successor in program.successors[block_id]:
                pending.append((successor, 0))
        return uses, barriers

    def _may_slice(
        self,
        program: _MicroProgram,
        seed_indexes: list[int],
        *,
        direction: str,
        limit: int,
    ) -> tuple[
        set[int],
        set[tuple[int, int]],
        dict[tuple[int | None, _BarrierReason], None],
        bool,
    ]:
        selected = set(seed_indexes[:limit])
        limit_hit = len(seed_indexes) > limit
        frontier = list(sorted(selected, reverse=True))
        edges: set[tuple[int, int]] = set()
        barriers: dict[tuple[int | None, _BarrierReason], None] = {}
        while frontier:
            current_index = frontier.pop()
            current = program.instructions[current_index]
            sought = current.uses if direction == "backward" else current.definitions
            if current.barrier is not None and (
                current.barrier == "unknown_call"
                or any(self._is_memory_location(location) for location in sought)
            ):
                barriers[(current_index, current.barrier)] = None
            for location in sorted(sought):
                if direction == "backward":
                    related, encountered = self._reaching_definitions(
                        program,
                        current,
                        location,
                    )
                    candidate_edges = ((candidate, current_index) for candidate in related)
                else:
                    related, encountered = self._reachable_uses(
                        program,
                        current,
                        location,
                    )
                    candidate_edges = ((current_index, candidate) for candidate in related)
                barriers.update(encountered)
                for source, target in candidate_edges:
                    candidate = source if direction == "backward" else target
                    if candidate not in selected:
                        if len(selected) == limit:
                            limit_hit = True
                            continue
                        selected.add(candidate)
                        frontier.append(candidate)
                    if source in selected and target in selected:
                        edges.add((source, target))
        return selected, edges, barriers, limit_hit

    def _reaching_definitions(
        self,
        program: _MicroProgram,
        current: _MicroInstruction,
        location: str,
    ) -> tuple[set[int], dict[tuple[int | None, _BarrierReason], None]]:
        definitions: set[int] = set()
        barriers: dict[tuple[int | None, _BarrierReason], None] = {}
        pending = [(current.block, current.position, location)]
        visited: set[tuple[int, int, str]] = set()
        while pending:
            block_id, before, remaining = pending.pop()
            state = (block_id, before, remaining)
            if state in visited:
                continue
            visited.add(state)
            stopped = False
            indexes = program.block_instructions[block_id]
            for candidate_index in reversed(indexes[:before]):
                candidate = program.instructions[candidate_index]
                if self._barrier_blocks(candidate, remaining):
                    assert candidate.barrier is not None
                    barriers[(candidate_index, candidate.barrier)] = None
                    stopped = True
                    break
                if self._definitions_overlap(candidate, remaining):
                    definitions.add(candidate_index)
                    pending.extend(
                        (block_id, candidate.position, fragment)
                        for fragment in self._unwritten_locations(candidate, remaining)
                    )
                    stopped = True
                    break
            if not stopped:
                for predecessor in program.predecessors[block_id]:
                    pending.append(
                        (predecessor, len(program.block_instructions[predecessor]), remaining)
                    )
        return definitions, barriers

    def _reachable_uses(
        self,
        program: _MicroProgram,
        current: _MicroInstruction,
        location: str,
    ) -> tuple[set[int], dict[tuple[int | None, _BarrierReason], None]]:
        uses: set[int] = set()
        barriers: dict[tuple[int | None, _BarrierReason], None] = {}
        pending = [(current.block, current.position + 1, location)]
        visited: set[tuple[int, int, str]] = set()
        while pending:
            block_id, after, remaining = pending.pop()
            state = (block_id, after, remaining)
            if state in visited:
                continue
            visited.add(state)
            stopped = False
            indexes = program.block_instructions[block_id]
            for candidate_index in indexes[after:]:
                candidate = program.instructions[candidate_index]
                if self._barrier_blocks(candidate, remaining):
                    assert candidate.barrier is not None
                    barriers[(candidate_index, candidate.barrier)] = None
                    stopped = True
                    break
                if self._uses_overlap(candidate, remaining):
                    uses.add(candidate_index)
                if self._definitions_overlap(candidate, remaining):
                    pending.extend(
                        (block_id, candidate.position + 1, fragment)
                        for fragment in self._unwritten_locations(candidate, remaining)
                    )
                    stopped = True
                    break
            if not stopped:
                for successor in program.successors[block_id]:
                    pending.append((successor, 0, remaining))
        return uses, barriers

    @staticmethod
    def _unwritten_locations(instruction: _MicroInstruction, location: str) -> tuple[str, ...]:
        """部分写入只覆盖对应字节，继续追踪其余寄存器或内存范围。"""

        if location in instruction.definitions:
            return ()
        parts = location.split(":")
        if len(parts) != 3:
            return (location,)
        kind, start_text, size_text = parts
        start = int(start_text)
        fragments = [(start, start + int(size_text))]
        for definition in sorted(instruction.definitions):
            defined_parts = definition.split(":")
            if len(defined_parts) != 3 or defined_parts[0] != kind:
                continue
            defined_start = int(defined_parts[1])
            defined_end = defined_start + int(defined_parts[2])
            remaining: list[tuple[int, int]] = []
            for start, end in fragments:
                if defined_end <= start or defined_start >= end:
                    remaining.append((start, end))
                    continue
                if start < defined_start:
                    remaining.append((start, defined_start))
                if defined_end < end:
                    remaining.append((defined_end, end))
            fragments = remaining
        return tuple(f"{kind}:{start}:{end - start}" for start, end in fragments)

    def _microcode_program(self, api: IdaModules, mba: object) -> _MicroProgram:
        mba.build_graph()
        instructions: list[_MicroInstruction] = []
        block_instructions: dict[int, tuple[int, ...]] = {}
        predecessors: dict[int, tuple[int, ...]] = {}
        successors: dict[int, tuple[int, ...]] = {}
        for block_index in range(int(mba.qty)):
            block = mba.get_mblock(block_index)
            indexes: list[int] = []
            instruction = block.head
            position = 0
            while instruction is not None:
                if len(instructions) == _MAX_MICROCODE_INSTRUCTIONS:
                    raise CapabilityError(
                        "函数 microcode 超过有界分析上限",
                        capability="bounded_microcode_slice",
                        details={"limit": _MAX_MICROCODE_INSTRUCTIONS},
                    )
                definitions, uses, barrier = self._instruction_locations(
                    api,
                    instruction,
                )
                index = len(instructions)
                instructions.append(
                    _MicroInstruction(
                        index=index,
                        block=block_index,
                        position=position,
                        address=_hex(int(instruction.ea)),
                        opcode=int(instruction.opcode),
                        text=self._micro_instruction_text(instruction),
                        definitions=frozenset(definitions),
                        uses=frozenset(uses),
                        barrier=barrier,
                    )
                )
                indexes.append(index)
                position += 1
                if instruction is block.tail:
                    break
                instruction = instruction.next
            block_instructions[block_index] = tuple(indexes)
            predecessors[block_index] = tuple(
                int(block.pred(index)) for index in range(int(block.npred()))
            )
            successors[block_index] = tuple(
                int(block.succ(index)) for index in range(int(block.nsucc()))
            )
        return _MicroProgram(
            instructions=tuple(instructions),
            block_instructions=block_instructions,
            predecessors=predecessors,
            successors=successors,
            input_locations=self._microcode_input_locations(mba),
        )

    def _micro_instruction_text(self, instruction: object) -> str:
        try:
            rendered = instruction.dstr()
        except Exception:
            return f"opcode:{int(instruction.opcode)}"
        if not isinstance(rendered, str) or not rendered:
            return f"opcode:{int(instruction.opcode)}"
        return rendered[:4_096]

    def _microcode_input_locations(self, mba: object) -> frozenset[str]:
        variables = mba.vars
        inputs: set[str] = set()
        for index in range(int(variables.size())):
            marker = variables.at(index).is_arg_var
            if bool(marker() if callable(marker) else marker):
                inputs.add(f"lvar:{index}")
        return frozenset(inputs)

    def _instruction_locations(
        self,
        api: IdaModules,
        instruction: object,
    ) -> tuple[set[str], set[str], _BarrierReason | None]:
        definitions: set[str] = set()
        uses: set[str] = set()
        worker = self

        class Visitor(api.ida_hexrays.mop_visitor_t):
            def visit_mop(
                self,
                operand: object,
                _type: object,
                is_target: bool,
            ) -> int:
                key = worker._mop_key(api, operand)
                if key is not None:
                    (definitions if is_target else uses).add(key)
                return 0

        instruction.for_all_ops(Visitor())
        call = instruction.find_call(False)
        if call is not None:
            uses.add("memory:unknown")
            definitions.add("memory:unknown")
            return definitions, uses, "unknown_call"
        try:
            aliased_memory = bool(instruction.may_use_aliased_memory())
        except Exception:
            aliased_memory = True
        if aliased_memory:
            uses.add("memory:unknown")
            try:
                writes_aliased_memory = bool(instruction.has_side_effects(False))
            except Exception:
                writes_aliased_memory = True
            if writes_aliased_memory:
                definitions.add("memory:unknown")
            return definitions, uses, "alias_ambiguity"
        return definitions, uses, None

    def _mop_key(self, api: IdaModules, operand: object) -> str | None:
        operand_type = int(operand.t)
        size = max(int(operand.size), 1)
        if operand_type == int(api.ida_hexrays.mop_r):
            return f"reg:{int(operand.r)}:{size}"
        if operand_type == int(api.ida_hexrays.mop_S):
            return f"stack:{int(operand.s.off)}:{size}"
        if operand_type == int(api.ida_hexrays.mop_l):
            return f"lvar:{int(operand.l.idx)}"
        if operand_type == int(api.ida_hexrays.mop_v):
            return f"global:{int(operand.g)}:{size}"
        return None

    def _definitions_overlap(
        self,
        instruction: _MicroInstruction,
        location: str,
    ) -> bool:
        return any(
            self._locations_overlap(definition, location) for definition in instruction.definitions
        )

    def _definitions_cover(
        self,
        instruction: _MicroInstruction,
        location: str,
    ) -> bool:
        if location == "memory:unknown":
            return False
        parts = location.split(":")
        if parts[0] == "lvar":
            return location in instruction.definitions
        if len(parts) != 3:
            return location in instruction.definitions
        location_kind = parts[0]
        required_start = int(parts[1])
        required_end = required_start + int(parts[2])
        intervals: list[tuple[int, int]] = []
        for definition in instruction.definitions:
            definition_parts = definition.split(":")
            if len(definition_parts) != 3 or definition_parts[0] != location_kind:
                continue
            start = int(definition_parts[1])
            intervals.append((start, start + int(definition_parts[2])))
        cursor = required_start
        for start, end in sorted(intervals):
            if end <= cursor or start > cursor:
                continue
            cursor = max(cursor, end)
            if cursor >= required_end:
                return True
        return False

    def _uses_overlap(self, instruction: _MicroInstruction, location: str) -> bool:
        return any(self._locations_overlap(use, location) for use in instruction.uses)

    def _barrier_blocks(self, instruction: _MicroInstruction, location: str) -> bool:
        if instruction.barrier == "unknown_call":
            return True
        return instruction.barrier == "alias_ambiguity" and self._is_memory_location(location)

    def _is_memory_location(self, location: str) -> bool:
        return location == "memory:unknown" or location.startswith(("stack:", "global:"))

    def _locations_overlap(self, left: str, right: str) -> bool:
        if left == right:
            return True
        if left == "memory:unknown":
            return self._is_memory_location(right)
        if right == "memory:unknown":
            return self._is_memory_location(left)
        left_parts = left.split(":")
        right_parts = right.split(":")
        if left_parts[0] != right_parts[0]:
            return False
        if left_parts[0] == "lvar":
            return left_parts[1] == right_parts[1]
        if len(left_parts) != 3 or len(right_parts) != 3:
            return False
        left_start, left_size = int(left_parts[1]), int(left_parts[2])
        right_start, right_size = int(right_parts[1]), int(right_parts[2])
        return left_start < right_start + right_size and right_start < left_start + left_size

    def _micro_instruction_json(
        self,
        instruction: _MicroInstruction,
    ) -> dict[str, object]:
        return {
            "index": instruction.index,
            "block": instruction.block,
            "address": instruction.address,
            "opcode": instruction.opcode,
            "text": instruction.text,
            "defs": sorted(instruction.definitions),
            "uses": sorted(instruction.uses),
            "barrier": instruction.barrier,
        }

    def _type_inspect(self, api: IdaModules, input: Mapping[str, object]) -> dict[str, object]:
        offset = _page_offset(input)
        limit = _page_limit(input)
        type_info = api.ida_typeinf.tinfo_t()
        address = input.get("address")
        name = input.get("name")
        if (address is None) == (name is None):
            raise WorkerInputError("type.inspect 必须且只能提供 address 或 name")
        if address is not None:
            ea = self._resolve_address(api, address)
            if not api.ida_nalt.get_tinfo(type_info, ea):
                raise WorkerError("type_not_found", "目标地址没有类型信息")
            identity: dict[str, object] = {"address": _hex(ea)}
        else:
            type_name = _text(name, "name")
            if not type_info.get_named_type(api.ida_typeinf.get_idati(), type_name):
                raise WorkerError("type_not_found", "IDA 类型库中不存在精确名称")
            identity = {"name": type_name}
        declaration = str(type_info)
        text_reasons: list[str] = []
        if len(declaration) > _INLINE_TYPE_TEXT_LIMIT:
            text_reasons.append("type_declaration_text_hard_limit_reached")
        size = int(type_info.get_size())
        details: dict[str, object] = {
            **identity,
            "declaration": declaration[:_INLINE_TYPE_TEXT_LIMIT],
            "size": -1 if size == int(api.ida_typeinf.BADSIZE) else size,
            "is_pointer": bool(type_info.is_ptr()),
            "is_function": bool(type_info.is_func()),
            "is_struct": bool(type_info.is_struct()),
            "is_union": bool(type_info.is_union()),
            "is_enum": bool(type_info.is_enum()),
            "is_array": bool(type_info.is_array()),
        }
        returned = 0
        has_more = False
        if type_info.is_udt():
            members = api.ida_typeinf.udt_type_data_t()
            if type_info.get_udt_details(members):
                member_text_truncated = False

                def iter_members() -> Iterable[dict[str, object]]:
                    nonlocal member_text_truncated
                    for index, member in enumerate(members):
                        member_type = str(member.type)
                        member_text_truncated |= len(member_type) > _MEMBER_TYPE_TEXT_LIMIT
                        yield {
                            "index": index,
                            "name": str(member.name),
                            "offset_bits": int(member.offset),
                            "size_bits": int(member.size),
                            "type": member_type[:_MEMBER_TYPE_TEXT_LIMIT],
                        }

                page, has_more = _bounded_page(
                    iter_members(),
                    offset,
                    limit,
                )
                details["members"] = page
                returned = len(page)
                if member_text_truncated:
                    text_reasons.append("type_member_text_hard_limit_reached")
        reasons = [*(["page_has_more"] if has_more else []), *text_reasons]
        return {
            "type": details,
            "page": _page_fact(offset, limit, returned, has_more),
            "coverage": {
                "complete": not reasons,
                "truncated": bool(reasons),
                "reasons": reasons,
            },
        }


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_no_ida_imports_on_supervisor_thread() -> None:
    """供 doctor/测试确认 AnalysisWorker 模块本身不会加载 IDA。"""

    if any(
        name in {"idaapi", "idapro", "idautils"}
        or (name.startswith("ida_") and not name.startswith("ida_re_mcp"))
        for name in sys.modules
    ):
        raise WorkerError("ida_import_leak", "Supervisor 进程已经加载 IDAPython 模块")
