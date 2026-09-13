"""公开 MCP 工具的严格输入、输出与写事务模型。"""

from __future__ import annotations

from functools import cache
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    Field,
    JsonValue,
    StringConstraints,
    create_model,
    model_validator,
)

from ida_re_mcp.constants import (
    DEFAULT_GRAPH_NODES,
    DEFAULT_PAGE_SIZE,
    DEFAULT_WORKER_OPERATION_TIMEOUT_SECONDS,
    MAX_GRAPH_NODES,
    MAX_IL2CPP_TYPE_RESOLUTIONS,
    MAX_MEMORY_READ_BYTES,
    MAX_OPERATION_WAIT_MS,
    MAX_PAGE_SIZE,
    MAX_WORKER_OPERATION_TIMEOUT_SECONDS,
)
from ida_re_mcp.domain.address import (
    AddressRef,
    ImageAddress,
    RevisionAddress,
    RuntimeAddress,
    U64Hex,
)
from ida_re_mcp.domain.base import StrictModel
from ida_re_mcp.domain.common import Coverage, Provenance, StaticQuery
from ida_re_mcp.domain.identifiers import (
    ChangeId,
    ChangeSetId,
    Cursor,
    DebugSessionId,
    EntityId,
    ImageId,
    ModuleId,
    OperationId,
    RevisionId,
    StopId,
    WorkspaceId,
)

type Sha256 = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True),
]


class ArtifactReference(StrictModel):
    uri: str = Field(pattern=r"^ida-re://workspaces/[^/\s]+/revisions/[^/\s]+/artifacts/[^/\s]+$")
    sha256: Sha256
    size: int = Field(ge=1)
    media_type: str = Field(min_length=3, max_length=128)


class StaticOutput(StrictModel):
    result_artifact: ArtifactReference | None = None


def _validate_even_hex(value: str) -> str:
    if len(value) % 2:
        raise ValueError("十六进制字节串必须包含完整字节")
    return value


def _validate_type_name_bytes(value: str) -> str:
    if len(value.encode("utf-8")) > 96:
        raise ValueError("类型名称的 UTF-8 编码不得超过 96 字节")
    return value


type ByteHex = Annotated[
    str,
    StringConstraints(pattern=r"^(?:[0-9a-f]{2})*$", strict=True),
    AfterValidator(_validate_even_hex),
]


class OperationWaitInput(StrictModel):
    """查询后台任务，或等待它的状态发生变化。"""

    operation_id: OperationId = Field(description="要查询的后台任务编号。")
    wait_ms: int = Field(
        default=0,
        ge=0,
        le=MAX_OPERATION_WAIT_MS,
        description="最多等待多少毫秒；0 表示立即返回当前状态。",
    )


class OperationFailure(StrictModel):
    code: str = Field(min_length=1, max_length=96)
    message: str = Field(min_length=1, max_length=2_048)
    retryable: bool


class OperationWaitOutput(StrictModel):
    """后台任务当前可以确认的状态和结果。"""

    operation_id: OperationId = Field(description="本次查询对应的后台任务编号。")
    state: Literal[
        "queued",
        "running",
        "cancel_requested",
        "succeeded",
        "failed",
        "cancelled",
    ]
    progress: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="只有服务能确认真实进度时才返回；无法确认时为 null。",
    )
    result: JsonValue | None = Field(
        default=None,
        description="任务成功后的完整结果；任务未成功时为 null。",
    )
    failure: OperationFailure | None = Field(
        default=None,
        description="任务失败的原因和是否适合重试。",
    )


class OperationCancelInput(StrictModel):
    """请求停止一个尚未结束的后台任务。"""

    operation_id: OperationId = Field(description="要停止的后台任务编号。")
    reason: str | None = Field(
        default=None,
        max_length=1_024,
        description="可选的停止原因，供后续接手任务的 Agent 参考。",
    )


class OperationCancelOutput(StrictModel):
    operation_id: OperationId
    state: Literal[
        "queued",
        "running",
        "cancel_requested",
        "succeeded",
        "failed",
        "cancelled",
    ]
    cancellation_requested: bool


class WorkspaceCreateInput(StrictModel):
    """复制一个程序文件，并创建可以长期接手的分析项目。"""

    sample_path: str = Field(
        min_length=1,
        max_length=32_767,
        description="要分析的 PE 或 ELF 文件路径；原文件不会被修改。",
    )
    expected_sha256: Sha256 | None = Field(
        default=None,
        description="可选的文件校验值；不一致时拒绝创建，避免分析错文件。",
    )


class WorkspaceCreateOutput(StrictModel):
    workspace_id: WorkspaceId
    revision: RevisionId | None = None
    sample_sha256: Sha256
    analysis_operation_id: OperationId


class WorkspaceRetryInput(StrictModel):
    """重新分析尚未产生 revision 的失败项目。"""

    workspace_id: WorkspaceId = Field(description="要重试首次分析的项目编号。")


class WorkspaceRetryOutput(StrictModel):
    workspace_id: WorkspaceId
    sample_sha256: Sha256
    analysis_operation_id: OperationId


class WorkspaceListInput(StrictModel):
    """列出 data 目录中已经保存的分析项目。"""

    cursor: Cursor | None = Field(
        default=None,
        description="上一页返回的 next_cursor；首次查询不要填写。",
    )
    page_size: int = Field(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="本页最多返回多少个分析项目。",
    )


class WorkspaceAnalysisOutcome(StrictModel):
    """首次分析未成功时可安全公开的持久化终态。"""

    state: Literal["failed", "cancelled"]
    reason: str = Field(min_length=1, max_length=2_048)
    recorded_at: float = Field(ge=0, allow_inf_nan=False)


class WorkspaceSummary(StrictModel):
    workspace_id: WorkspaceId
    revision: RevisionId | None = None
    sample_name: str
    sample_sha256: Sha256
    architecture: str | None = None
    # unknown 表示当前会话无法证明 workspace 仍在分析(例如 Supervisor 曾被强杀,
    # 或该 workspace 属于另一条活动连接), 用以替代永久回落到 analyzing 的谎报.
    state: Literal["analyzing", "ready", "failed", "unknown"]
    analysis_outcome: WorkspaceAnalysisOutcome | None

    @model_validator(mode="after")
    def validate_analysis_outcome(self) -> Self:
        if (self.state == "failed") != (self.analysis_outcome is not None):
            raise ValueError("failed 状态必须且只能携带 analysis_outcome")
        return self


class WorkspaceListOutput(StrictModel):
    workspaces: list[WorkspaceSummary] = Field(max_length=MAX_PAGE_SIZE)
    next_cursor: Cursor | None = None


class WorkspaceGetInput(StrictModel):
    """读取一个分析项目的当前版本和历史版本。"""

    workspace_id: WorkspaceId = Field(description="要读取的分析项目编号。")
    cursor: Cursor | None = Field(
        default=None,
        description="上一页返回的 next_cursor；首次查询不要填写。",
    )
    page_size: int = Field(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="本页最多返回多少个历史版本。",
    )


class RevisionSummary(StrictModel):
    revision: RevisionId
    parent_revision: RevisionId | None = None
    idb_sha256: Sha256
    reason: str
    pinned: bool


class WorkspaceGetOutput(StrictModel):
    workspace_id: WorkspaceId
    current_revision: RevisionId
    sample_name: str
    sample_sha256: Sha256
    architecture: str
    bitness: Literal[32, 64]
    endian: Literal["little", "big"]
    revisions: list[RevisionSummary] = Field(max_length=MAX_PAGE_SIZE)
    next_cursor: Cursor | None = None
    # 早于 GC 保留窗口的 revision 被回收后, 最早一条 parent_revision 会悬挂;
    # 该标志让调用方区分“历史完整”与“更早历史已被回收”, 不把 next_cursor=None 误读为全量.
    history_truncated: bool


class WorkspaceExportInput(StrictModel):
    """把已经保存的分析版本导出为 IDA 数据库文件。"""

    workspace_id: WorkspaceId = Field(description="要导出的分析项目编号。")
    revision: RevisionId = Field(description="要导出的分析版本。")
    format: Literal["idb"] = Field(description="导出格式；当前只支持 IDA 数据库。")


class WorkspaceExportOutput(StrictModel):
    operation_id: OperationId
    workspace_id: WorkspaceId
    revision: RevisionId


class ProgramOverviewInput(StaticQuery):
    """读取程序的基本信息，并按需附带指定内容。"""

    include: list[
        Literal[
            "segments",
            "entry_points",
            "imports",
            "exports",
            "fixups",
            "unwind",
            "functions",
            "strings",
        ]
    ] = Field(
        default_factory=list,
        max_length=8,
        description=(
            "要附带的内容；留空时附带全部可选内容。"
            "可选段、入口点、导入、导出、重定位、异常处理、函数和字符串。"
        ),
    )


class ImageSummary(StrictModel):
    image_id: ImageId
    format: Literal["elf32", "elf64", "pe32", "pe32+", "unknown"]
    architecture: Literal["x86", "x86_64", "arm", "aarch64"]
    bitness: Literal[32, 64]
    endian: Literal["little", "big"]
    image_base: U64Hex
    image_size: int = Field(ge=1)
    sha256: Sha256


class SegmentSummary(StrictModel):
    entity_id: EntityId
    name: str
    start: AddressRef
    end: AddressRef
    permissions: str = Field(pattern=r"^[r-][w-][x-]$")


class NamedAddress(StrictModel):
    entity_id: EntityId | None = None
    name: str
    address: AddressRef


class FixupSummary(StrictModel):
    address: AddressRef
    fixup_type: int = Field(ge=0)
    description: str = Field(max_length=2_048)


class UnwindRegionSummary(StrictModel):
    entity_id: EntityId
    start: AddressRef
    end: AddressRef
    kind: Literal["unwind", "catch", "unwind_and_catch"]


class StringSummary(StrictModel):
    entity_id: EntityId
    address: AddressRef
    preview: str = Field(max_length=2_048)
    length: int = Field(ge=0)


class ProgramCounts(StrictModel):
    functions: int = Field(ge=0)
    strings: int = Field(ge=0)
    imports: int = Field(ge=0)
    exports: int = Field(ge=0)
    fixups: int = Field(ge=0)
    unwind_regions: int = Field(ge=0)
    exception_regions: int = Field(ge=0)


class ProgramOverviewOutput(StaticOutput):
    image: ImageSummary
    counts: ProgramCounts
    segments: list[SegmentSummary]
    entry_points: list[NamedAddress]
    imports: list[NamedAddress]
    exports: list[NamedAddress]
    fixups: list[FixupSummary]
    unwind_regions: list[UnwindRegionSummary]
    functions: list[NamedAddress]
    strings: list[StringSummary]
    coverage: Coverage
    provenance: Provenance


class ProgramSearchInput(StaticQuery):
    """按文本或十六进制字节搜索已经分析出的内容。"""

    domains: list[Literal["function", "name", "string", "bytes"]] = Field(
        min_length=1,
        max_length=4,
        description="搜索范围：函数、名称、字符串或原始字节。",
    )
    text_query: str | None = Field(
        default=None,
        max_length=1_024,
        description="文本搜索内容；搜索函数、名称或字符串时必须填写。",
    )
    bytes_query: ByteHex | None = Field(
        default=None,
        max_length=2_048,
        description="不带空格的十六进制字节；搜索 bytes 时必须填写。",
    )
    cursor: Cursor | None = Field(
        default=None,
        description="上一页返回的 next_cursor；首次查询不要填写。",
    )
    page_size: int = Field(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="本页最多返回多少条匹配结果。",
    )
    case_sensitive: bool = Field(default=False, description="文本搜索是否区分大小写。")

    @model_validator(mode="after")
    def validate_search_capabilities(self) -> Self:
        if len(self.domains) != len(set(self.domains)):
            raise ValueError("domains 不得重复")
        text_domains = {"function", "name", "string"}.intersection(self.domains)
        if text_domains and self.text_query is None:
            raise ValueError("function、name、string 域必须显式提供 text_query")
        if not text_domains and self.text_query is not None:
            raise ValueError("未请求文本域时不得提供 text_query")
        if "bytes" in self.domains and not self.bytes_query:
            raise ValueError("bytes 域必须提供非空 bytes_query")
        if "bytes" not in self.domains and self.bytes_query is not None:
            raise ValueError("未请求 bytes 域时不得提供 bytes_query")
        if self.case_sensitive and not text_domains:
            raise ValueError("case_sensitive 只适用于文本域")
        return self


class SearchMatch(StrictModel):
    domain: Literal["function", "name", "string", "bytes"]
    address: AddressRef | None = None
    entity_id: EntityId | None = None
    preview: str = Field(max_length=2_048)


class ProgramSearchOutput(StaticOutput):
    matches: list[SearchMatch] = Field(max_length=MAX_PAGE_SIZE)
    next_cursor: Cursor | None = None
    coverage: Coverage
    provenance: Provenance


class AddressInspectInput(StaticQuery):
    """读取一个地址处的指令、数据、名称、引用或所属函数。"""

    address: AddressRef = Field(description="要检查的地址及其地址种类。")
    include: list[Literal["bytes", "instruction", "data", "symbol", "xrefs", "function"]] = Field(
        default_factory=list,
        max_length=6,
        description="要返回的内容；留空时只确认地址。",
    )
    byte_count: int = Field(
        default=32,
        ge=0,
        le=256,
        description="请求 bytes 时，从该地址最多读取多少字节。",
    )


class CrossReference(StrictModel):
    kind: Literal["code_call", "code_jump", "code_flow", "data_read", "data_write", "data_offset"]
    source: AddressRef
    target: AddressRef
    resolved: bool


class OperandView(StrictModel):
    """IDA 解码后的单个结构化指令操作数。"""

    index: int = Field(ge=0, le=7)
    type: int = Field(ge=0, le=255)
    dtype: int = Field(ge=0, le=255)
    text: str = Field(max_length=4_096)
    value: U64Hex | None = None
    address: AddressRef | None = None


class InstructionView(StrictModel):
    address: AddressRef
    size: int = Field(ge=1)
    mnemonic: str
    text: str = Field(max_length=4_096)
    operands: list[OperandView] = Field(max_length=8)


class AddressInspectOutput(StaticOutput):
    address: AddressRef
    entity_id: EntityId | None = None
    bytes_hex: ByteHex | None = None
    instruction: InstructionView | None = None
    data_rendering: str | None = None
    symbol: str | None = None
    function_id: EntityId | None = None
    xrefs: list[CrossReference]
    coverage: Coverage
    provenance: Provenance


class FunctionByEntity(StrictModel):
    kind: Literal["entity"]
    entity_id: EntityId


class FunctionByAddress(StrictModel):
    kind: Literal["address"]
    address: AddressRef


type FunctionSelector = Annotated[
    FunctionByEntity | FunctionByAddress,
    Field(discriminator="kind"),
]


class FunctionInspectInput(StaticQuery):
    """按函数编号或地址读取函数详情。"""

    function: FunctionSelector = Field(description="要检查的函数编号或函数内地址。")
    views: list[
        Literal[
            "summary",
            "chunks",
            "instructions",
            "pseudocode",
            "ctree_map",
            "blocks",
            "calls",
            "strings",
            "stack",
            "locals",
            "types",
        ]
    ] = Field(
        default_factory=lambda: ["summary"],
        min_length=1,
        max_length=11,
        description="要读取的函数信息；默认只返回摘要。",
    )
    cursor: Cursor | None = Field(
        default=None,
        description="上一页返回的 next_cursor；首次查询不要填写。",
    )
    page_size: int = Field(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="本页最多返回多少条明细。",
    )


class FunctionChunk(StrictModel):
    start: AddressRef
    end: AddressRef


class BasicBlockView(StrictModel):
    entity_id: EntityId
    start: AddressRef
    end: AddressRef
    successors: list[EntityId]
    predecessors: list[EntityId]


class LocalVariableView(StrictModel):
    entity_id: EntityId
    name: str
    type_display: str
    storage: Literal["stack", "register", "other"]


class CtreeMapEntry(StrictModel):
    kind: Literal["expression", "statement"]
    address: AddressRef
    opcode: int = Field(ge=0)
    text: str | None = Field(default=None, max_length=4_096)


class FunctionStringView(StrictModel):
    reference: AddressRef
    address: AddressRef
    value_hex: ByteHex


class FunctionStackView(StrictModel):
    local_size: int = Field(ge=0)
    saved_register_size: int = Field(ge=0)
    argument_size: int = Field(ge=0)
    frame_pointer_delta: int
    frame_size: int = Field(ge=0)


class FunctionTypeView(StrictModel):
    display: str


class FunctionInspectOutput(StaticOutput):
    entity_id: EntityId
    name: str
    start: AddressRef
    end: AddressRef
    prototype: str | None = None
    chunks: list[FunctionChunk]
    instructions: list[InstructionView]
    pseudocode: list[str]
    ctree_map: list[CtreeMapEntry]
    blocks: list[BasicBlockView]
    calls: list[CrossReference]
    strings: list[FunctionStringView]
    stack: FunctionStackView | None = None
    locals: list[LocalVariableView]
    type_view: FunctionTypeView | None = None
    next_cursor: Cursor | None = None
    coverage: Coverage
    provenance: Provenance


class GraphQueryInput(StaticQuery):
    """从指定地址开始查询控制流、函数调用或引用关系。"""

    graph: Literal["cfg", "call", "xref"] = Field(
        description="关系种类：函数内控制流、函数调用或代码与数据引用。"
    )
    roots: list[AddressRef] = Field(
        min_length=1,
        max_length=32,
        description="开始查询的一个或多个地址。",
    )
    direction: Literal["outgoing", "incoming", "both"] = Field(
        default="outgoing",
        description="查询向外关系、向内关系或两个方向。",
    )
    max_depth: int = Field(default=1, ge=0, le=32, description="最多向外展开多少层。")
    max_nodes: int = Field(
        default=DEFAULT_GRAPH_NODES,
        ge=1,
        le=MAX_GRAPH_NODES,
        description="最多返回多少个节点。",
    )


class GraphNode(StrictModel):
    entity_id: EntityId
    kind: Literal["function", "basic_block", "instruction", "data", "unknown"]
    label: str
    address: AddressRef | None = None


class GraphEdge(StrictModel):
    source: EntityId
    target: EntityId
    kind: Literal["flow", "call", "jump", "xref_code", "xref_data", "unresolved"]
    evidence: AddressRef | None = None


class GraphQueryOutput(StaticOutput):
    nodes: list[GraphNode] = Field(max_length=MAX_GRAPH_NODES)
    edges: list[GraphEdge]
    unresolved_indirect_edges: int | None = Field(ge=0)
    coverage: Coverage
    provenance: Provenance


class SliceAddressSeed(StrictModel):
    kind: Literal["address"]
    address: AddressRef


class DataflowSliceInput(StaticQuery):
    """查询一条指令可能或必然依赖的数据来源和去向。"""

    function: FunctionSelector = Field(description="包含起点指令的函数。")
    seed: SliceAddressSeed = Field(description="开始追踪的数据流指令地址。")
    direction: Literal["backward", "forward"] = Field(
        description="向前查影响范围，或向后查数据来源。"
    )
    semantics: Literal["may", "must"] = Field(
        description="may 返回可能关系；must 只返回能够确认的必然关系。"
    )
    max_steps: int = Field(
        default=128,
        ge=1,
        le=MAX_GRAPH_NODES,
        description="最多追踪多少步。",
    )


class DataflowNode(StrictModel):
    entity_id: EntityId
    operation: str
    address: AddressRef | None = None


class DataflowEdge(StrictModel):
    source: EntityId
    target: EntityId
    relation: Literal["defines", "uses", "aliases", "control_dependency"]


class DataflowBarrier(StrictModel):
    reason: Literal[
        "unknown_call",
        "unknown_memory",
        "alias_ambiguity",
        "unknown_call_or_alias_memory",
        "analysis_limit",
    ]
    address: AddressRef | None = None
    detail: str


class DataflowSliceOutput(StaticOutput):
    semantics: Literal["may", "must"]
    nodes: list[DataflowNode]
    edges: list[DataflowEdge]
    barriers: list[DataflowBarrier]
    coverage: Coverage
    provenance: Provenance


class TypeByEntity(StrictModel):
    kind: Literal["entity"]
    entity_id: EntityId


class TypeByName(StrictModel):
    kind: Literal["name"]
    name: Annotated[
        str,
        StringConstraints(min_length=1, max_length=96, strict=True),
        AfterValidator(_validate_type_name_bytes),
    ]


class TypeAtAddress(StrictModel):
    kind: Literal["address"]
    address: AddressRef


type TypeSelector = Annotated[
    TypeByEntity | TypeByName | TypeAtAddress,
    Field(discriminator="kind"),
]


class TypeInspectInput(StaticQuery):
    """按类型编号、精确名称或地址读取 IDA 类型信息。"""

    type: TypeSelector = Field(description="要检查的类型编号、名称或所在地址。")
    cursor: Cursor | None = Field(
        default=None,
        description="上一页返回的 next_cursor；首次查询不要填写。",
    )
    page_size: int = Field(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="本页最多返回多少个类型字段。",
    )


class TypeFieldView(StrictModel):
    entity_id: EntityId
    name: str
    offset_bits: int = Field(ge=0)
    size_bits: int = Field(ge=0)
    type_display: str


class TypeInspectOutput(StaticOutput):
    entity_id: EntityId
    name: str
    kind: Literal["primitive", "pointer", "array", "struct", "union", "enum", "function"]
    size: int | None = Field(default=None, ge=0)
    display: str
    fields: list[TypeFieldView]
    next_cursor: Cursor | None = None
    coverage: Coverage
    provenance: Provenance


class ReportBuildInput(StaticQuery):
    """把指定分析版本整理成报告文件。"""

    format: Literal["markdown", "json"] = Field(description="报告使用 Markdown 或 JSON 格式。")
    sections: list[
        Literal[
            "overview",
            "entry_points",
            "imports_exports",
        ]
    ] = Field(
        min_length=1,
        max_length=3,
        description="报告中要包含的栏目。",
    )
    title: str | None = Field(
        default=None,
        max_length=256,
        description="可选的报告标题；不填时使用“逆向分析报告”。",
    )

    @model_validator(mode="after")
    def validate_sections(self) -> Self:
        if len(self.sections) != len(set(self.sections)):
            raise ValueError("sections 不得重复")
        return self


class ReportBuildOutput(StrictModel):
    operation_id: OperationId
    workspace_id: WorkspaceId
    revision: RevisionId


class AnalysisRefineInput(StaticQuery):
    """针对指定位置补充分析，并把结果保存为新版本。"""

    targets: list[RevisionAddress] = Field(
        default_factory=list,
        max_length=256,
        description="需要重新分析的位置；某些动作允许留空并处理整个程序。",
    )
    actions: list[Literal["autoanalysis", "reanalyze_function", "decompile", "rebuild_xrefs"]] = (
        Field(
            min_length=1,
            max_length=4,
            description="要执行的补充分析动作。",
        )
    )


class AnalysisRefineOutput(StrictModel):
    operation_id: OperationId
    workspace_id: WorkspaceId
    base_revision: RevisionId


class PrimitiveTypeRef(StrictModel):
    kind: Literal["primitive"]
    name: Literal[
        "void",
        "bool",
        "i8",
        "u8",
        "i16",
        "u16",
        "i32",
        "u32",
        "i64",
        "u64",
        "f32",
        "f64",
    ]


class NamedTypeRef(StrictModel):
    kind: Literal["named"]
    type_id: EntityId


class PointerTypeRef(StrictModel):
    kind: Literal["pointer"]
    to: CanonicalTypeRef
    pointee_const: bool = False

    @model_validator(mode="after")
    def validate_const_target(self) -> Self:
        if self.pointee_const and not isinstance(self.to, (PrimitiveTypeRef, NamedTypeRef)):
            raise ValueError("pointee_const 只允许修饰 primitive 或 named 类型")
        return self


class ArrayTypeRef(StrictModel):
    kind: Literal["array"]
    element: CanonicalTypeRef
    count: int = Field(ge=1, le=0xFFFF_FFFF)

    @model_validator(mode="after")
    def validate_element(self) -> Self:
        if isinstance(self.element, FunctionTypeRef) or (
            isinstance(self.element, PrimitiveTypeRef) and self.element.name == "void"
        ):
            raise ValueError("array element 必须是完整对象类型")
        return self


class FunctionParameterType(StrictModel):
    name: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$",
    )
    type: CanonicalTypeRef


class FunctionTypeRef(StrictModel):
    kind: Literal["function"]
    calling_convention: Literal["default", "cdecl", "stdcall", "fastcall"] = "default"
    return_type: CanonicalTypeRef
    parameters: list[FunctionParameterType] = Field(max_length=256)
    variadic: bool = False

    @model_validator(mode="after")
    def validate_signature(self) -> Self:
        if isinstance(self.return_type, (ArrayTypeRef, FunctionTypeRef)):
            raise ValueError("function return_type 不得是 array 或 function")
        for parameter in self.parameters:
            if isinstance(parameter.type, (ArrayTypeRef, FunctionTypeRef)) or (
                isinstance(parameter.type, PrimitiveTypeRef) and parameter.type.name == "void"
            ):
                raise ValueError("function parameter 必须是完整的非 void 对象类型")
        if self.variadic and not self.parameters:
            raise ValueError("variadic function 至少需要一个固定参数")
        return self


type CanonicalTypeRef = Annotated[
    PrimitiveTypeRef | NamedTypeRef | PointerTypeRef | ArrayTypeRef | FunctionTypeRef,
    Field(discriminator="kind"),
]


class RenameOperation(StrictModel):
    kind: Literal["rename"]
    target: RevisionAddress
    expected_name: str | None = None
    new_name: str = Field(min_length=1, max_length=1_024)


class CommentOperation(StrictModel):
    kind: Literal["comment"]
    target: RevisionAddress
    placement: Literal["regular", "repeatable"]
    expected_text: str | None = None
    text: str = Field(max_length=65_536)


class SetTypeOperation(StrictModel):
    kind: Literal["set_type"]
    target: RevisionAddress
    type_ref: CanonicalTypeRef


class PatchBytesOperation(StrictModel):
    kind: Literal["patch_bytes"]
    target: RevisionAddress
    expected_bytes: ByteHex
    replacement_bytes: ByteHex

    @model_validator(mode="after")
    def validate_equal_length(self) -> Self:
        if len(self.expected_bytes) != len(self.replacement_bytes):
            raise ValueError("expected_bytes 与 replacement_bytes 长度必须相同")
        if not self.expected_bytes:
            raise ValueError("patch_bytes 至少修改一个字节")
        return self


class Il2CppTypeResolution(StrictModel):
    type_id: Annotated[
        str,
        StringConstraints(pattern=r"^type_[0-9a-f]{64}$", strict=True),
    ]
    action: Literal["keep", "replace"]


class ImportIl2CppBundleOperation(StrictModel):
    kind: Literal["import_il2cpp_bundle"]
    bundle_path: str = Field(min_length=1, max_length=32_767)
    bundle_sha256: Sha256
    metadata_path: str = Field(min_length=1, max_length=32_767)
    metadata_sha256: Sha256
    type_resolutions: list[Il2CppTypeResolution] = Field(
        default_factory=list,
        max_length=MAX_IL2CPP_TYPE_RESOLUTIONS,
    )

    @model_validator(mode="after")
    def validate_type_resolutions(self) -> Self:
        type_ids = [resolution.type_id for resolution in self.type_resolutions]
        if len(type_ids) != len(set(type_ids)):
            raise ValueError("type_resolutions 不得重复引用同一 type_id")
        return self


type ChangeOperation = Annotated[
    RenameOperation
    | CommentOperation
    | SetTypeOperation
    | PatchBytesOperation
    | ImportIl2CppBundleOperation,
    Field(discriminator="kind"),
]


class ChangePrepareInput(StrictModel):
    """检查一组修改，并生成下一步保存时需要的编号和校验值。"""

    workspace_id: WorkspaceId = Field(description="要修改的分析项目编号。")
    base_revision: RevisionId = Field(description="修改所基于的当前分析版本。")
    operations: list[ChangeOperation] = Field(
        default_factory=list,
        max_length=1_000,
        description="要检查的修改；正常修改时填写。",
    )
    inverse_of_change_id: ChangeId | None = Field(
        default=None,
        description="要撤销的历史修改编号；撤销时填写，并且不要同时提供 operations。",
    )

    @model_validator(mode="after")
    def validate_prepare_mode(self) -> Self:
        if (self.inverse_of_change_id is None) == (len(self.operations) == 0):
            raise ValueError("operations 与 inverse_of_change_id 必须且只能提供一种")
        return self


class ChangeConflict(StrictModel):
    kind: Literal["user_name_preserved"]
    operation_index: int = Field(ge=0)
    source_id: str = Field(min_length=1, max_length=256)
    address: U64Hex
    existing_value: str = Field(max_length=1_024)


class ChangeImpact(StrictModel):
    renamed_entities: int = Field(ge=0)
    comments_changed: int = Field(ge=0)
    types_changed: int = Field(ge=0)
    patched_bytes: int = Field(ge=0)
    imported_symbols: int = Field(ge=0)
    conflicts: list[ChangeConflict]
    conflicts_artifact: ArtifactReference | None = None

    @model_validator(mode="after")
    def validate_conflict_output_mode(self) -> Self:
        if self.conflicts_artifact is not None and self.conflicts:
            raise ValueError("conflicts 与 conflicts_artifact 不得同时返回")
        return self


class ChangePrepareOutput(StrictModel):
    workspace_id: WorkspaceId
    base_revision: RevisionId
    change_set_id: ChangeSetId
    digest: Sha256
    operation_count: int = Field(ge=1)
    impact: ChangeImpact


class ChangeApplyInput(StrictModel):
    """保存已经通过 change.prepare 检查的修改。"""

    workspace_id: WorkspaceId = Field(description="要保存修改的分析项目编号。")
    expected_revision: RevisionId = Field(
        description="准备修改时使用的分析版本；版本已变化时会拒绝保存。"
    )
    change_set_id: ChangeSetId = Field(description="change.prepare 返回的修改集合编号。")
    digest: Sha256 = Field(description="change.prepare 返回的完整校验值。")


class ChangeApplyOutput(StrictModel):
    workspace_id: WorkspaceId
    previous_revision: RevisionId
    revision: RevisionId
    change_id: ChangeId


class DebugLaunchTarget(StrictModel):
    """由服务启动当前分析项目中的程序。"""

    kind: Literal["launch"] = Field(description="启动新进程。")
    arguments: list[str] = Field(
        default_factory=list,
        max_length=128,
        description="传给目标程序的命令行参数。",
    )
    stop_on_entry: bool = Field(default=True, description="启动后是否先停在程序入口。")


class DebugAttachTarget(StrictModel):
    """连接到已经运行的本机进程。"""

    kind: Literal["attach"] = Field(description="连接现有进程。")
    process_id: int = Field(
        ge=1,
        le=0xFFFF_FFFF,
        description="要连接的 Windows 进程编号。",
    )


type DebugTarget = Annotated[
    DebugLaunchTarget | DebugAttachTarget,
    Field(discriminator="kind"),
]


class DebugEstablishInput(StrictModel):
    """启动程序或连接现有进程，并建立调试会话。"""

    workspace_id: WorkspaceId = Field(description="调试所对应的分析项目编号。")
    revision: RevisionId = Field(description="调试所依据的分析版本。")
    target: DebugTarget = Field(description="启动新进程或连接现有进程。")
    timeout_ms: int = Field(
        default=30_000,
        ge=1,
        le=120_000,
        description="等待调试开始的最长时间，单位为毫秒。",
    )


class DebugEstablishOutput(StrictModel):
    debug_session_id: DebugSessionId
    workspace_id: WorkspaceId
    revision: RevisionId
    state: Literal["running", "suspended"]
    stop_id: StopId | None = None
    process_id: int = Field(ge=1)
    observed_event_sequence: int = Field(ge=1)
    completion_provenance: Literal["ida_event"]
    completion_kind: Literal["process_started", "process_attached"]

    @model_validator(mode="after")
    def validate_observed_state(self) -> Self:
        if (self.state == "suspended") != (self.stop_id is not None):
            raise ValueError("debug.establish 的 stop_id 必须与 suspended 状态一致")
        return self


class DebugControlInput(StrictModel):
    """暂停、继续、单步执行，或运行到指定位置。"""

    debug_session_id: DebugSessionId = Field(description="要控制的调试会话编号。")
    action: Literal["pause", "continue", "step_into", "step_over", "run_to"] = Field(
        description="要执行的调试动作。"
    )
    stop_id: StopId | None = Field(
        default=None,
        description="当前暂停编号；继续、单步和运行到指定位置时必须提供。",
    )
    target: ImageAddress | None = Field(
        default=None,
        description="run_to 的目标位置；其他动作不要填写。",
    )
    timeout_ms: int = Field(
        default=30_000,
        ge=1,
        le=120_000,
        description="等待动作完成的最长时间，单位为毫秒。",
    )

    @model_validator(mode="after")
    def validate_action_context(self) -> Self:
        if self.action == "run_to":
            if self.stop_id is None or self.target is None:
                raise ValueError("run_to 必须提供 stop_id 与 image target")
        elif self.target is not None:
            raise ValueError("只有 run_to 可以提供 target")
        if self.action in {"continue", "step_into", "step_over"} and self.stop_id is None:
            raise ValueError(f"{self.action} 必须提供 stop_id")
        if self.action == "pause" and self.stop_id is not None:
            raise ValueError("pause 在 running 状态执行, 不接受 stop_id")
        return self


class DebugControlOutput(StrictModel):
    debug_session_id: DebugSessionId
    state: Literal["running", "suspended", "exited"]
    stop_id: StopId | None = None
    observed_event_sequence: int = Field(ge=0)
    completion_provenance: Literal["ida_event", "state_observation"]
    completion_kind: Literal[
        "process_suspended",
        "breakpoint",
        "step",
        "exception",
        "process_exited",
        "execution_resumed",
    ]
    observed_debugger_state: Literal["DSTATE_RUN"] | None = None

    @model_validator(mode="after")
    def validate_completion_provenance(self) -> Self:
        if (self.state == "suspended") != (self.stop_id is not None):
            raise ValueError("debug.control 的 stop_id 必须与 suspended 状态一致")
        if self.completion_provenance == "state_observation":
            if (
                self.completion_kind != "execution_resumed"
                or self.observed_debugger_state != "DSTATE_RUN"
                or self.state != "running"
            ):
                raise ValueError("state_observation 完成证据必须明确为 DSTATE_RUN")
        elif self.observed_debugger_state is not None:
            raise ValueError("IDA event 完成证据不得携带 debugger 状态观察")
        if self.completion_kind in {"process_suspended", "breakpoint", "step", "exception"}:
            if self.state != "suspended":
                raise ValueError("停点完成事件必须产生 suspended 状态")
        elif self.completion_kind == "process_exited" and self.state != "exited":
            raise ValueError("process_exited 完成事件必须产生 exited 状态")
        return self


class DebugEventsInput(StrictModel):
    """读取调试会话中尚未处理的事件。"""

    debug_session_id: DebugSessionId = Field(description="要读取的调试会话编号。")
    after_sequence: int = Field(
        default=0,
        ge=0,
        description="只返回该事件序号之后的内容；首次读取使用 0。",
    )
    wait_ms: int = Field(
        default=0,
        ge=0,
        le=MAX_OPERATION_WAIT_MS,
        description="没有新事件时最多等待多少毫秒；0 表示立即返回。",
    )
    limit: int = Field(
        default=DEFAULT_PAGE_SIZE,
        ge=1,
        le=MAX_PAGE_SIZE,
        description="本次最多返回多少个事件。",
    )


class DebugEventModule(StrictModel):
    module_id: ModuleId
    name: str = Field(max_length=4_096)
    base: U64Hex
    size: int = Field(ge=0)


class DebugException(StrictModel):
    code: int = Field(ge=0, le=0xFFFF_FFFF)
    address: AddressRef | None = None
    can_continue: bool
    information: str = Field(max_length=4_096)


class DebugEvent(StrictModel):
    sequence: int = Field(ge=1)
    timestamp_ns: int = Field(ge=0)
    provenance: Literal["ida_event", "state_observation", "service_event"]
    kind: Literal[
        "process_started",
        "process_attached",
        "process_suspended",
        "execution_resumed",
        "library_loaded",
        "library_unloaded",
        "thread_started",
        "thread_exited",
        "breakpoint",
        "step",
        "exception",
        "process_exited",
        "process_detached",
        "information",
        "request_error",
        "worker_lost",
        "unknown",
    ]
    state: Literal["launching", "running", "suspended", "exited", "detached", "lost", "failed"]
    stop_id: StopId | None = None
    process_id: int | None = Field(default=None, ge=0)
    thread_id: int | None = Field(default=None, ge=0)
    address: AddressRef | None = None
    event_id: int | None = Field(default=None, ge=0)
    module: DebugEventModule | None = None
    exception: DebugException | None = None
    exit_code: int | None = None
    action: str | None = Field(default=None, max_length=128)
    reason: str | None = Field(default=None, max_length=2_048)
    observed_debugger_state: Literal["DSTATE_RUN"] | None = None

    @model_validator(mode="after")
    def validate_provenance(self) -> Self:
        if (self.state == "suspended") != (self.stop_id is not None):
            raise ValueError("debug event 的 stop_id 必须与 suspended 状态一致")
        if self.provenance == "state_observation":
            if (
                self.kind != "execution_resumed"
                or self.observed_debugger_state != "DSTATE_RUN"
                or self.event_id is not None
                or self.state != "running"
            ):
                raise ValueError("state_observation 必须是无 IDA event_id 的 DSTATE_RUN 恢复观察")
        elif self.observed_debugger_state is not None:
            raise ValueError("只有 state_observation 可以携带 observed_debugger_state")
        if self.provenance == "ida_event":
            if self.event_id is None or self.kind in {
                "execution_resumed",
                "request_error",
                "worker_lost",
            }:
                raise ValueError("ida_event 必须携带真实 event_id 且不得表示服务内部事件")
        if self.provenance == "service_event" and (
            self.kind not in {"request_error", "worker_lost"} or self.event_id is not None
        ):
            raise ValueError("service_event 只允许无 IDA event_id 的请求或 worker 事件")
        if (
            self.kind
            in {
                "process_suspended",
                "breakpoint",
                "step",
                "exception",
            }
            and self.state != "suspended"
        ):
            raise ValueError("真实停点事件必须产生 suspended 状态")
        terminal_states = {
            "process_exited": "exited",
            "process_detached": "detached",
            "request_error": "failed",
            "worker_lost": "lost",
        }
        expected_state = terminal_states.get(self.kind)
        if expected_state is not None and self.state != expected_state:
            raise ValueError("终止或失败事件与公开状态不一致")
        return self


class DebugEventsOutput(StrictModel):
    debug_session_id: DebugSessionId
    events: list[DebugEvent] = Field(max_length=MAX_PAGE_SIZE)
    last_sequence: int = Field(ge=0)
    observed_latest_sequence: int = Field(ge=0)
    has_more: bool

    @model_validator(mode="after")
    def validate_cursor(self) -> Self:
        if self.events and self.last_sequence != self.events[-1].sequence:
            raise ValueError("last_sequence 必须指向本页最后返回事件")
        if self.observed_latest_sequence < self.last_sequence:
            raise ValueError("observed_latest_sequence 不得早于分页游标")
        if self.has_more != (self.last_sequence < self.observed_latest_sequence):
            raise ValueError("has_more 必须反映 worker 已观察但尚未返回的事件")
        return self


class DebugInspectInput(StrictModel):
    """读取程序当前暂停位置的模块、线程、寄存器、调用栈或内存。"""

    debug_session_id: DebugSessionId = Field(description="要读取的调试会话编号。")
    stop_id: StopId = Field(description="当前暂停编号；状态变化后必须使用新的编号。")
    views: list[Literal["state", "modules", "threads", "registers", "stack", "memory", "maps"]] = (
        Field(
            min_length=1,
            max_length=7,
            description="要读取的调试信息。",
        )
    )
    memory_address: RuntimeAddress | None = Field(
        default=None,
        description="读取 memory 时的起始地址，必须绑定同一个 stop_id。",
    )
    memory_size: int | None = Field(
        default=None,
        ge=1,
        le=MAX_MEMORY_READ_BYTES,
        description="读取 memory 时的字节数。",
    )

    @model_validator(mode="after")
    def validate_memory_view(self) -> Self:
        if len(self.views) != len(set(self.views)):
            raise ValueError("views 不得重复")
        memory_requested = "memory" in self.views
        if memory_requested and (self.memory_address is None or self.memory_size is None):
            raise ValueError("memory 视图必须同时提供 memory_address 与 memory_size")
        if not memory_requested and (
            self.memory_address is not None or self.memory_size is not None
        ):
            raise ValueError("未请求 memory 视图时不得提供内存参数")
        if self.memory_address is not None and self.memory_address.stop_id != self.stop_id:
            raise ValueError("memory_address.stop_id 必须匹配请求 stop_id")
        return self


class DebugModule(StrictModel):
    module_id: ModuleId
    name: str
    base: RuntimeAddress
    size: int = Field(ge=0)


class DebugThread(StrictModel):
    thread_id: int = Field(ge=0)
    name: str | None = None
    current: bool


class RegisterValue(StrictModel):
    name: str
    value: U64Hex


class StackFrame(StrictModel):
    index: int = Field(ge=0)
    call_address: RuntimeAddress | None = None
    function_address: RuntimeAddress | None = None
    frame_pointer_value: U64Hex
    function_known: bool
    function_name: str | None = None


class IdaDebuggerMemoryMap(StrictModel):
    source: Literal["ida_debugger"]
    start: U64Hex
    end: U64Hex
    name: str
    segment_class: str
    segment_base: U64Hex
    bitness: Literal[16, 32, 64]
    permissions: int = Field(ge=0)


class WindowsVirtualQueryMemoryMap(StrictModel):
    source: Literal["windows_virtual_query_ex"]
    start: U64Hex
    end: U64Hex
    allocation_base: U64Hex
    allocation_protection: int = Field(ge=0)
    protection: int = Field(ge=0)
    state: int = Field(ge=0)
    memory_type: int = Field(ge=0)


type DebugMemoryMap = Annotated[
    IdaDebuggerMemoryMap | WindowsVirtualQueryMemoryMap,
    Field(discriminator="source"),
]


class DebugInspectOutput(StrictModel):
    debug_session_id: DebugSessionId
    stop_id: StopId
    state: Literal["suspended"]
    modules: list[DebugModule]
    threads: list[DebugThread]
    registers: list[RegisterValue]
    stack: list[StackFrame]
    memory_address: AddressRef | None = None
    memory_bytes: ByteHex | None = None
    memory_artifact: ArtifactReference | None = None
    memory_maps: list[DebugMemoryMap] = Field(default_factory=list)
    snapshot_artifact: ArtifactReference | None = None

    @model_validator(mode="after")
    def validate_memory_result(self) -> Self:
        if self.memory_bytes is not None and self.memory_artifact is not None:
            raise ValueError("memory_bytes 与 memory_artifact 不得同时返回")
        if self.memory_artifact is not None and self.memory_address is None:
            raise ValueError("memory_artifact 必须绑定 memory_address")
        if self.snapshot_artifact is not None and (
            self.modules
            or self.threads
            or self.registers
            or self.stack
            or self.memory_address is not None
            or self.memory_bytes is not None
            or self.memory_artifact is not None
            or self.memory_maps
        ):
            raise ValueError("snapshot_artifact 模式不得同时内联调试快照")
        return self


class ModuleBreakpointAddress(StrictModel):
    """相对于当前调试快照中已加载模块的断点位置。"""

    kind: Literal["module"]
    module_id: ModuleId
    rva: U64Hex


type BreakpointAddress = Annotated[
    ImageAddress | ModuleBreakpointAddress,
    Field(discriminator="kind"),
]


class BreakpointSpec(StrictModel):
    address: BreakpointAddress
    enabled: bool = True


class DebugBreakpointsInput(StrictModel):
    """用给定列表替换当前调试会话的全部断点。"""

    debug_session_id: DebugSessionId = Field(description="要设置断点的调试会话编号。")
    stop_id: StopId = Field(description="当前暂停编号。")
    replace: list[BreakpointSpec] = Field(
        max_length=1_024,
        description="替换后的完整断点列表；空列表表示清除全部断点。",
    )

    @model_validator(mode="after")
    def validate_unique_locations(self) -> Self:
        locations = [
            (
                item.address.kind,
                (
                    item.address.image_id
                    if isinstance(item.address, ImageAddress)
                    else item.address.module_id
                ),
                item.address.rva,
            )
            for item in self.replace
        ]
        if len(locations) != len(set(locations)):
            raise ValueError("replace 不得包含重复 image/module+rva")
        return self


class BreakpointState(StrictModel):
    entity_id: EntityId
    requested: BreakpointAddress
    runtime: AddressRef | None = None
    state: Literal["pending", "active", "disabled"]


class DebugBreakpointsOutput(StrictModel):
    debug_session_id: DebugSessionId
    stop_id: StopId
    breakpoints: list[BreakpointState]
    result_artifact: ArtifactReference | None = None

    @model_validator(mode="after")
    def validate_breakpoint_output_mode(self) -> Self:
        if self.result_artifact is not None and self.breakpoints:
            raise ValueError("breakpoints 与 result_artifact 不得同时返回")
        return self


class DebugFinishInput(StrictModel):
    """断开调试连接，或结束由服务启动的目标程序。"""

    debug_session_id: DebugSessionId = Field(description="要结束的调试会话编号。")
    action: Literal["detach", "terminate"] = Field(
        description="detach 只断开连接；terminate 结束服务启动的目标程序。"
    )
    timeout_ms: int = Field(
        default=30_000,
        ge=1,
        le=120_000,
        description="等待会话结束的最长时间，单位为毫秒。",
    )


class DebugFinishOutput(StrictModel):
    debug_session_id: DebugSessionId
    state: Literal["exited", "detached"]
    observed_event_sequence: int = Field(ge=1)
    completion_provenance: Literal["ida_event"]
    completion_kind: Literal["process_exited", "process_detached"]

    @model_validator(mode="after")
    def validate_terminal_observation(self) -> Self:
        expected = {
            "process_exited": "exited",
            "process_detached": "detached",
        }[self.completion_kind]
        if self.state != expected:
            raise ValueError("debug.finish 的真实终止事件与状态不一致")
        return self


class ExpertExecuteInput(StrictModel):
    """运行 IDAPython，并把数据库修改保存为新分析版本。"""

    workspace_id: WorkspaceId = Field(description="要处理的分析项目编号。")
    revision: RevisionId = Field(description="代码运行所基于的分析版本。")
    code: str = Field(
        min_length=1,
        max_length=262_144,
        description=("要运行的 IDAPython 代码。它可以访问本机文件、网络和子进程，不是隔离环境。"),
    )
    timeout_seconds: int = Field(
        default=DEFAULT_WORKER_OPERATION_TIMEOUT_SECONDS,
        ge=1,
        le=MAX_WORKER_OPERATION_TIMEOUT_SECONDS,
        description=("本次 Expert worker 操作最多运行多少秒；不能超过服务配置的普通操作时限。"),
    )


@cache
def configured_expert_execute_input(
    operation_timeout_seconds: int,
) -> type[ExpertExecuteInput]:
    """构造与当前 worker 配置一致的 Expert 公开输入模型。"""

    if not 1 <= operation_timeout_seconds <= MAX_WORKER_OPERATION_TIMEOUT_SECONDS:
        raise ValueError("operation_timeout_seconds 超出 Expert 允许范围")
    timeout_field = Field(
        default=operation_timeout_seconds,
        ge=1,
        le=operation_timeout_seconds,
        description=("本次 Expert worker 操作最多运行多少秒；不能超过服务配置的普通操作时限。"),
    )
    return create_model(
        ExpertExecuteInput.__name__,
        __base__=ExpertExecuteInput,
        timeout_seconds=(int, timeout_field),
    )


class ExpertExecuteOutput(StrictModel):
    workspace_id: WorkspaceId
    base_revision: RevisionId
    revision: RevisionId
    output_mode: Literal["inline", "artifact"]
    stdout: str | None = Field(default=None, max_length=65_536)
    stderr: str | None = Field(default=None, max_length=65_536)
    result_repr: str | None = Field(default=None, max_length=65_536)
    artifact: ArtifactReference | None = None

    @model_validator(mode="after")
    def validate_output_mode(self) -> Self:
        if self.output_mode == "inline":
            if self.stdout is None or self.stderr is None or self.artifact is not None:
                raise ValueError("inline expert 输出必须内联 stdout/stderr")
        elif (
            self.stdout is not None
            or self.stderr is not None
            or self.result_repr is not None
            or self.artifact is None
        ):
            raise ValueError("artifact expert 输出只能返回不可变 artifact 引用")
        return self
