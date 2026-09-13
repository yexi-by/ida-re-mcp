"""真实 stdio → MCP → Supervisor → IDA → revision 的产品链路门禁。"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import Literal, cast

import pytest
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

from ida_re_mcp.il2cpp import canonical_ndjson, compute_record_id
from ida_re_mcp.il2cpp.canonical import JsonObject as CanonicalJsonObject

JsonObject = dict[str, object]


@pytest.fixture
def stdio_runtime_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """为 IDALib 链路提供工作树外且不含测试长名的短运行根。"""

    root = tmp_path_factory.mktemp("s")
    assert not root.is_relative_to(Path(__file__).resolve().parents[2])
    return root


def _tree_identity(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _with_record_id(record: CanonicalJsonObject) -> CanonicalJsonObject:
    identified = dict(record)
    identified["id"] = compute_record_id(identified)
    return identified


def _write_il2cpp_bundle(
    path: Path,
    *,
    sample: Path,
    metadata: Path,
    image_size: int,
    architecture: Literal["x86", "x86_64", "arm", "aarch64"],
    abi: Literal["msvc-x86", "msvc-x64", "sysv-x86", "sysv-x64", "aapcs32", "aapcs64"],
    pointer_width: Literal[32, 64],
    calling_convention: Literal["cdecl", "win64", "sysv", "aapcs32", "aapcs64"],
    function_rva: str,
) -> None:
    pointer_size = pointer_width // 8
    manifest: CanonicalJsonObject = {
        "kind": "manifest",
        "schema": "1",
        "media_type": "application/vnd.ida-re.il2cpp-bundle+ndjson",
        "native": {
            "sha256": hashlib.sha256(sample.read_bytes()).hexdigest(),
            "size": sample.stat().st_size,
            "image_size": image_size,
            "architecture": architecture,
            "abi": abi,
            "pointer_width": pointer_width,
            "endianness": "little",
        },
        "metadata": {
            "sha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
            "size": metadata.stat().st_size,
        },
    }
    image = _with_record_id(
        {
            "kind": "managed_image",
            "name": "Assembly-CSharp",
            "assembly_name": "Assembly-CSharp.dll",
        }
    )
    vec3 = _with_record_id(
        {
            "kind": "type",
            "image_id": image["id"],
            "namespace": "Game",
            "name": "Vec3",
            "layout": {
                "kind": "struct",
                "size": 12,
                "alignment": 4,
                "fields": [
                    {"name": "x", "offset": 0, "type": {"kind": "primitive", "name": "f32"}},
                    {"name": "y", "offset": 4, "type": {"kind": "primitive", "name": "f32"}},
                    {"name": "z", "offset": 8, "type": {"kind": "primitive", "name": "f32"}},
                ],
            },
        }
    )
    metadata_type = _with_record_id(
        {
            "kind": "type",
            "image_id": image["id"],
            "namespace": "",
            "name": "MethodMetadata",
            "layout": {
                "kind": "struct",
                "size": pointer_size * 2,
                "alignment": pointer_size,
                "fields": [
                    {
                        "name": "name",
                        "offset": 0,
                        "type": {
                            "kind": "pointer",
                            "const": True,
                            "to": {"kind": "primitive", "name": "i8"},
                        },
                    },
                    {
                        "name": "token",
                        "offset": pointer_size,
                        "type": {"kind": "primitive", "name": "u32"},
                    },
                ],
            },
        }
    )
    actor_size = 24 if pointer_width == 32 else 32
    actor = _with_record_id(
        {
            "kind": "type",
            "image_id": image["id"],
            "namespace": "Game",
            "name": "Actor",
            "layout": {
                "kind": "struct",
                "size": actor_size,
                "alignment": pointer_size,
                "fields": [
                    {
                        "name": "klass",
                        "offset": 0,
                        "type": {
                            "kind": "pointer",
                            "const": False,
                            "to": {"kind": "primitive", "name": "void"},
                        },
                    },
                    {
                        "name": "monitor",
                        "offset": pointer_size,
                        "type": {
                            "kind": "pointer",
                            "const": False,
                            "to": {"kind": "primitive", "name": "void"},
                        },
                    },
                    {
                        "name": "instance_id",
                        "offset": pointer_size * 2,
                        "type": {"kind": "primitive", "name": "i32"},
                    },
                    {
                        "name": "position",
                        "offset": pointer_size * 2 + 4,
                        "type": {"kind": "named", "type_id": vec3["id"]},
                    },
                ],
            },
        }
    )
    native_probe = _with_record_id(
        {
            "kind": "type",
            "image_id": image["id"],
            "namespace": "Game",
            "name": "NativeProbe",
            "layout": {
                "kind": "struct",
                "size": pointer_size * 2,
                "alignment": pointer_size,
                "fields": [
                    {
                        "name": "signed_value",
                        "offset": 0,
                        "type": {"kind": "primitive", "name": "native_int"},
                    },
                    {
                        "name": "unsigned_value",
                        "offset": pointer_size,
                        "type": {"kind": "primitive", "name": "native_uint"},
                    },
                ],
            },
        }
    )
    wide_alignment = 4 if abi == "sysv-x86" else 8
    wide_offset = wide_alignment
    wide_probe = _with_record_id(
        {
            "kind": "type",
            "image_id": image["id"],
            "namespace": "Game",
            "name": "WideProbe",
            "layout": {
                "kind": "struct",
                "size": wide_offset + 8,
                "alignment": wide_alignment,
                "fields": [
                    {"name": "tag", "offset": 0, "type": {"kind": "primitive", "name": "u32"}},
                    {
                        "name": "wide",
                        "offset": wide_offset,
                        "type": {"kind": "primitive", "name": "u64"},
                    },
                ],
            },
        }
    )
    method = _with_record_id(
        {
            "kind": "method",
            "image_id": image["id"],
            "declaring_type_id": actor["id"],
            "name": "GetScore",
            "rva": function_rva,
            "managed_signature": {
                "return_type": "System.Int32",
                "parameters": [{"name": "bonus", "type": "System.Int32"}],
            },
            "native_signature": {
                "calling_convention": calling_convention,
                "return_type": {"kind": "primitive", "name": "i32"},
                "parameters": [
                    {
                        "name": "self",
                        "type": {
                            "kind": "pointer",
                            "const": False,
                            "to": {"kind": "named", "type_id": actor["id"]},
                        },
                    },
                    {
                        "name": "bonus",
                        "type": {"kind": "primitive", "name": "i32"},
                    },
                    {
                        "name": "method",
                        "type": {
                            "kind": "pointer",
                            "const": True,
                            "to": {"kind": "named", "type_id": metadata_type["id"]},
                        },
                    },
                ],
                "variadic": False,
            },
        }
    )
    symbol = _with_record_id(
        {
            "kind": "symbol",
            "name": "Actor_GetScore",
            "rva": function_rva,
            "symbol_kind": "function",
            "method_id": method["id"],
            "type": None,
        }
    )
    path.write_bytes(
        canonical_ndjson(
            [
                manifest,
                image,
                vec3,
                metadata_type,
                actor,
                native_probe,
                wide_probe,
                method,
                symbol,
            ]
        )
    )


def _environment(base: dict[str, str], runtime: Path) -> dict[str, str]:
    environment = base.copy()
    environment["APPDATA"] = str(runtime / "roaming")
    environment["LOCALAPPDATA"] = str(runtime / "local")
    environment["WIN_PD_OVERRIDE_APPDATA"] = environment["APPDATA"]
    environment["WIN_PD_OVERRIDE_LOCAL_APPDATA"] = environment["LOCALAPPDATA"]
    environment["PYTHONUTF8"] = "1"
    environment["XDG_CONFIG_HOME"] = str(runtime / "xdg-config")
    environment["XDG_DATA_HOME"] = str(runtime / "xdg-data")
    environment["XDG_STATE_HOME"] = str(runtime / "xdg-state")
    return environment


@asynccontextmanager
async def _official_session(
    *,
    environment: dict[str, str],
    stderr_path: Path,
) -> AsyncGenerator[ClientSession]:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ida_re_mcp", "serve"],
        env=environment,
        cwd=Path(__file__).resolve().parents[2],
    )
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    with stderr_path.open("w+", encoding="utf-8") as error_log:
        try:
            async with stdio_client(parameters, errlog=error_log) as streams:
                async with ClientSession(
                    *streams,
                    read_timeout_seconds=timedelta(seconds=180),
                    client_info=types.Implementation(
                        name="ida-re-mcp-ida-e2e",
                        version="1",
                    ),
                ) as client:
                    initialized = await client.initialize()
                    assert initialized.serverInfo.name == "ida-re-mcp"
                    assert initialized.capabilities.tools is not None
                    assert initialized.capabilities.resources is not None
                    yield client
        finally:
            error_log.flush()
            error_log.seek(0)
            stderr = error_log.read()
            assert stderr == "", stderr


async def _call_tool(
    client: ClientSession,
    *,
    name: str,
    arguments: JsonObject,
    timeout: float = 180,
) -> JsonObject:
    result = await client.call_tool(
        name,
        arguments,
        read_timeout_seconds=timedelta(seconds=timeout),
    )
    assert result.isError is False, result
    assert result.structuredContent is not None, result
    summaries = [item for item in result.content if isinstance(item, types.TextContent)]
    assert len(summaries) == 1, result
    assert any("\u4e00" <= character <= "\u9fff" for character in summaries[0].text)
    assert "structuredContent" in summaries[0].text
    return cast(JsonObject, result.structuredContent)


async def _wait_operation(
    client: ClientSession,
    *,
    operation_id: str,
) -> JsonObject:
    while True:
        output = await _call_tool(
            client,
            name="operation.wait",
            arguments={"operation_id": operation_id, "wait_ms": 30_000},
        )
        state = output["state"]
        if state == "succeeded":
            return cast(JsonObject, output["result"])
        if state in {"failed", "cancelled"}:
            pytest.fail(f"长操作未成功: {output}")


@pytest.mark.ida
@pytest.mark.parametrize(
    ("fixture_name", "architecture", "bitness", "image_format", "container"),
    [
        ("native_pe_x86.dll", "x86", 32, "pe32", "pe"),
        ("native_pe_x64.dll", "x86_64", 64, "pe32+", "pe"),
        ("native_elf_x86.so", "x86", 32, "elf32", "elf"),
        ("native_elf_armv7.so", "arm", 32, "elf32", "elf"),
    ],
)
def test_real_stdio_static_and_transaction_chain(
    stdio_runtime_root: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
    fixture_name: str,
    architecture: str,
    bitness: int,
    image_format: str,
    container: str,
) -> None:
    async def scenario() -> None:
        fixture_before = _tree_identity(fixture_directory)
        sample = stdio_runtime_root / fixture_name
        shutil.copyfile(fixture_directory / sample.name, sample)
        runtime = stdio_runtime_root / "runtime"
        async with _official_session(
            environment=_environment(ida_environment, runtime),
            stderr_path=stdio_runtime_root / "static-stdio-stderr.log",
        ) as client:
            created = await _call_tool(
                client,
                name="workspace.create",
                arguments={"sample_path": str(sample)},
            )
            workspace_id = cast(str, created["workspace_id"])
            operation_id = cast(str, created["analysis_operation_id"])
            initialized = await _wait_operation(
                client,
                operation_id=operation_id,
            )
            revision = cast(str, initialized["revision"])
            listed = await _call_tool(
                client,
                name="workspace.list",
                arguments={},
            )
            summaries = cast(list[JsonObject], listed["workspaces"])
            summary = next(item for item in summaries if item["workspace_id"] == workspace_id)
            assert summary["state"] == "ready"
            assert summary["architecture"] == architecture
            assert summary["analysis_outcome"] is None

            overview = await _call_tool(
                client,
                name="program.overview",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": revision,
                    "include": ["unwind"],
                },
            )
            image = cast(JsonObject, overview["image"])
            assert image["format"] == image_format
            assert image["architecture"] == architecture
            assert image["bitness"] == bitness
            expected_image_size = cast(int, image["image_size"])

            searched = await _call_tool(
                client,
                name="program.search",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": revision,
                    "domains": ["function"],
                    "text_query": "fixture_validate",
                    "page_size": 50,
                },
            )
            matches = cast(list[JsonObject], searched["matches"])
            assert matches
            target = cast(JsonObject, matches[0]["address"])
            assert target["kind"] == "database"

            prepared = await _call_tool(
                client,
                name="change.prepare",
                arguments={
                    "workspace_id": workspace_id,
                    "base_revision": revision,
                    "operations": [
                        {
                            "kind": "rename",
                            "target": target,
                            "new_name": "agent_verified_entry",
                        },
                        {
                            "kind": "set_type",
                            "target": target,
                            "type_ref": {
                                "kind": "function",
                                "return_type": {"kind": "primitive", "name": "i32"},
                                "parameters": [
                                    {
                                        "name": "input",
                                        "type": {
                                            "kind": "pointer",
                                            "to": {"kind": "primitive", "name": "i8"},
                                        },
                                    },
                                    {"name": "size", "type": {"kind": "primitive", "name": "u32"}},
                                ],
                            },
                        },
                    ],
                },
            )
            applied = await _call_tool(
                client,
                name="change.apply",
                arguments={
                    "workspace_id": workspace_id,
                    "expected_revision": revision,
                    "change_set_id": prepared["change_set_id"],
                    "digest": prepared["digest"],
                },
            )
            next_revision = cast(str, applied["revision"])
            assert next_revision != revision

            inspected_type = await _call_tool(
                client,
                name="type.inspect",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": next_revision,
                    "type": {"kind": "address", "address": target},
                },
            )
            assert inspected_type["kind"] == "function"
            assert inspected_type["size"] is None

            verified = await _call_tool(
                client,
                name="program.search",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": next_revision,
                    "domains": ["function"],
                    "text_query": "agent_verified_entry",
                    "page_size": 50,
                },
            )
            assert any(
                "agent_verified_entry" in cast(str, item["preview"])
                for item in cast(list[JsonObject], verified["matches"])
            )
        revision_manifests = [
            cast(JsonObject, json.loads(path.read_text(encoding="utf-8")))
            for path in runtime.rglob("revision.json")
        ]
        assert len(revision_manifests) == 2
        for manifest in revision_manifests:
            identity = cast(JsonObject, manifest["image_identity"])
            assert identity == {
                "architecture": architecture,
                "bitness": bitness,
                "container": container,
                "endian": "little",
                "image_size": expected_image_size,
            }
        assert _tree_identity(fixture_directory) == fixture_before

    asyncio.run(scenario())


@pytest.mark.ida
@pytest.mark.parametrize(
    (
        "fixture_name",
        "architecture",
        "abi",
        "pointer_width",
        "calling_convention",
        "function_rva",
        "container",
    ),
    [
        ("il2cpp_pe_x86.dll", "x86", "msvc-x86", 32, "cdecl", "0x1000", "pe"),
        ("il2cpp_pe_x64.dll", "x86_64", "msvc-x64", 64, "win64", "0x1000", "pe"),
        ("il2cpp_elf_x86.so", "x86", "sysv-x86", 32, "sysv", "0x13a0", "elf"),
        (
            "il2cpp_elf_armv7.so",
            "arm",
            "aapcs32",
            32,
            "aapcs32",
            "0x102d5",
            "elf",
        ),
    ],
)
def test_real_stdio_il2cpp_bundle_prepare_apply_and_publish(
    stdio_runtime_root: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
    fixture_name: str,
    architecture: Literal["x86", "x86_64", "arm", "aarch64"],
    abi: Literal["msvc-x86", "msvc-x64", "sysv-x86", "sysv-x64", "aapcs32", "aapcs64"],
    pointer_width: Literal[32, 64],
    calling_convention: Literal["cdecl", "win64", "sysv", "aapcs32", "aapcs64"],
    function_rva: str,
    container: str,
) -> None:
    async def scenario() -> None:
        sample = stdio_runtime_root / fixture_name
        shutil.copyfile(fixture_directory / sample.name, sample)
        metadata = fixture_directory / "il2cpp_metadata_fingerprint.bin"
        runtime = stdio_runtime_root / "runtime"
        async with _official_session(
            environment=_environment(ida_environment, runtime),
            stderr_path=stdio_runtime_root / "il2cpp-stdio-stderr.log",
        ) as client:
            created = await _call_tool(
                client,
                name="workspace.create",
                arguments={"sample_path": str(sample)},
            )
            workspace_id = cast(str, created["workspace_id"])
            initialized = await _wait_operation(
                client,
                operation_id=cast(str, created["analysis_operation_id"]),
            )
            revision = cast(str, initialized["revision"])
            overview = await _call_tool(
                client,
                name="program.overview",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": revision,
                    "include": [],
                },
            )
            overview_image = cast(JsonObject, overview["image"])
            image_size = cast(int, overview_image["image_size"])
            bundle = stdio_runtime_root / f"{sample.stem}.ndjson"
            _write_il2cpp_bundle(
                bundle,
                sample=sample,
                metadata=metadata,
                image_size=image_size,
                architecture=architecture,
                abi=abi,
                pointer_width=pointer_width,
                calling_convention=calling_convention,
                function_rva=function_rva,
            )

            prepared = await _call_tool(
                client,
                name="change.prepare",
                arguments={
                    "workspace_id": workspace_id,
                    "base_revision": revision,
                    "operations": [
                        {
                            "kind": "import_il2cpp_bundle",
                            "bundle_path": str(bundle),
                            "bundle_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
                            "metadata_path": str(metadata),
                            "metadata_sha256": hashlib.sha256(metadata.read_bytes()).hexdigest(),
                            "type_resolutions": [],
                        }
                    ],
                },
            )
            impact = cast(JsonObject, prepared["impact"])
            assert impact["conflicts"] == []
            applied = await _call_tool(
                client,
                name="change.apply",
                arguments={
                    "workspace_id": workspace_id,
                    "expected_revision": revision,
                    "change_set_id": prepared["change_set_id"],
                    "digest": prepared["digest"],
                },
            )
            next_revision = cast(str, applied["revision"])
            assert next_revision != revision

            actor = await _call_tool(
                client,
                name="type.inspect",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": next_revision,
                    "type": {"kind": "name", "name": "Game::Actor"},
                },
            )
            assert actor["kind"] == "struct"
            assert actor["size"] == (24 if pointer_width == 32 else 32)
            pointer_bits = pointer_width
            assert [
                (
                    field["name"],
                    field["offset_bits"],
                    field["size_bits"],
                )
                for field in cast(list[JsonObject], actor["fields"])
            ] == [
                ("klass", 0, pointer_bits),
                ("monitor", pointer_bits, pointer_bits),
                ("instance_id", pointer_bits * 2, 32),
                ("position", pointer_bits * 2 + 32, 96),
            ]

            native_probe = await _call_tool(
                client,
                name="type.inspect",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": next_revision,
                    "type": {"kind": "name", "name": "Game::NativeProbe"},
                },
            )
            assert native_probe["size"] == pointer_width // 4
            assert [
                field["size_bits"] for field in cast(list[JsonObject], native_probe["fields"])
            ] == [
                pointer_width,
                pointer_width,
            ]

            wide_probe = await _call_tool(
                client,
                name="type.inspect",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": next_revision,
                    "type": {"kind": "name", "name": "Game::WideProbe"},
                },
            )
            expected_wide_offset_bits = 32 if abi == "sysv-x86" else 64
            assert [
                (field["offset_bits"], field["size_bits"])
                for field in cast(list[JsonObject], wide_probe["fields"])
            ] == [(0, 32), (expected_wide_offset_bits, 64)]

            function = await _call_tool(
                client,
                name="function.inspect",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": next_revision,
                    "function": {
                        "kind": "address",
                        "address": {
                            "kind": "image",
                            "image_id": f"image~{created['sample_sha256']}",
                            "rva": function_rva,
                        },
                    },
                    "views": ["types"],
                },
            )
            prototype = cast(str, function["prototype"])
            assert "signed __int32 bonus" in prototype
            expected_calling_convention = (
                "__fastcall" if calling_convention == "win64" else "__cdecl"
            )
            assert expected_calling_convention in prototype

        manifests = [
            cast(JsonObject, json.loads(path.read_text(encoding="utf-8")))
            for path in runtime.rglob("revision.json")
        ]
        assert len(manifests) == 2
        mutation_manifest = next(
            manifest for manifest in manifests if manifest["parent_revision"] == revision
        )
        identity = cast(JsonObject, mutation_manifest["image_identity"])
        assert identity["container"] == container
        assert identity["architecture"] == architecture
        assert identity["bitness"] == pointer_width
        assert identity["endian"] == "little"
        assert isinstance(identity["image_size"], int)

    asyncio.run(scenario())


@pytest.mark.ida
def test_real_stdio_elf_overview_reports_container_capability_boundary(
    stdio_runtime_root: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
) -> None:
    async def scenario() -> None:
        sample = stdio_runtime_root / "native_elf_x64.so"
        shutil.copyfile(fixture_directory / sample.name, sample)
        async with _official_session(
            environment=_environment(ida_environment, stdio_runtime_root / "runtime"),
            stderr_path=stdio_runtime_root / "elf-stdio-stderr.log",
        ) as client:
            created = await _call_tool(
                client,
                name="workspace.create",
                arguments={"sample_path": str(sample)},
            )
            workspace_id = cast(str, created["workspace_id"])
            initialized = await _wait_operation(
                client,
                operation_id=cast(str, created["analysis_operation_id"]),
            )
            revision = cast(str, initialized["revision"])

            with_unwind = await _call_tool(
                client,
                name="program.overview",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": revision,
                    "include": ["unwind"],
                },
            )
            image = cast(JsonObject, with_unwind["image"])
            coverage = cast(JsonObject, with_unwind["coverage"])
            assert image["format"] == "elf64"
            assert coverage["status"] == "partial"
            assert coverage["truncated"] is False
            assert "unwind_unsupported_for_elf_eh_frame" in cast(
                list[str],
                coverage["reasons"],
            )

            without_unwind = await _call_tool(
                client,
                name="program.overview",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": revision,
                    "include": ["segments"],
                },
            )
            complete_coverage = cast(JsonObject, without_unwind["coverage"])
            assert complete_coverage["status"] == "complete"
            assert complete_coverage["truncated"] is False
            assert "unwind_unsupported_for_elf_eh_frame" not in cast(
                list[str],
                complete_coverage["reasons"],
            )

    asyncio.run(scenario())


@pytest.mark.ida
@pytest.mark.debugger
@pytest.mark.parametrize(
    ("fixture_name", "instruction_pointer", "stack_pointer"),
    [
        ("debug_target_x86.exe", "EIP", "ESP"),
        ("debug_target_x64.exe", "RIP", "RSP"),
    ],
)
def test_real_stdio_debug_chain(
    stdio_runtime_root: Path,
    ida_environment: dict[str, str],
    fixture_directory: Path,
    fixture_name: str,
    instruction_pointer: str,
    stack_pointer: str,
) -> None:
    async def scenario() -> None:
        fixture_before = _tree_identity(fixture_directory)
        sample = stdio_runtime_root / fixture_name
        shutil.copyfile(fixture_directory / sample.name, sample)
        async with _official_session(
            environment=_environment(ida_environment, stdio_runtime_root / "runtime"),
            stderr_path=stdio_runtime_root / "debug-stdio-stderr.log",
        ) as client:
            created = await _call_tool(
                client,
                name="workspace.create",
                arguments={"sample_path": str(sample)},
            )
            workspace_id = cast(str, created["workspace_id"])
            sample_sha256 = cast(str, created["sample_sha256"])
            initialized = await _wait_operation(
                client,
                operation_id=cast(str, created["analysis_operation_id"]),
            )
            revision = cast(str, initialized["revision"])
            established = await _call_tool(
                client,
                name="debug.establish",
                arguments={
                    "workspace_id": workspace_id,
                    "revision": revision,
                    "target": {
                        "kind": "launch",
                        "arguments": [],
                        "stop_on_entry": True,
                    },
                    "timeout_ms": 30_000,
                },
            )
            session_id = cast(str, established["debug_session_id"])
            stop_id = cast(str, established["stop_id"])
            assert established["state"] == "suspended"

            initial_events = await _call_tool(
                client,
                name="debug.events",
                arguments={
                    "debug_session_id": session_id,
                    "after_sequence": 0,
                    "wait_ms": 0,
                    "limit": 200,
                },
            )
            cursor = cast(int, initial_events["last_sequence"])
            breakpoint_result = await _call_tool(
                client,
                name="debug.breakpoints",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": stop_id,
                    "replace": [
                        {
                            "address": {
                                "kind": "image",
                                "image_id": f"image~{sample_sha256}",
                                "rva": "0x1000",
                            },
                            "enabled": True,
                        }
                    ],
                },
            )
            breakpoints = cast(list[JsonObject], breakpoint_result["breakpoints"])
            assert len(breakpoints) == 1
            assert breakpoints[0]["state"] == "active"

            controlled = await _call_tool(
                client,
                name="debug.control",
                arguments={
                    "debug_session_id": session_id,
                    "action": "continue",
                    "stop_id": stop_id,
                    "timeout_ms": 30_000,
                },
            )
            cursor = max(cursor, cast(int, controlled["observed_event_sequence"]))
            hit_stop_id: str | None = None
            for _attempt in range(6):
                events_output = await _call_tool(
                    client,
                    name="debug.events",
                    arguments={
                        "debug_session_id": session_id,
                        "after_sequence": cursor,
                        "wait_ms": 30_000,
                        "limit": 200,
                    },
                )
                events = cast(list[JsonObject], events_output["events"])
                for event in events:
                    if event["kind"] == "breakpoint":
                        hit_stop_id = cast(str, event["stop_id"])
                        break
                cursor = cast(int, events_output["last_sequence"])
                if hit_stop_id is not None:
                    break
            assert hit_stop_id is not None

            threads_snapshot = await _call_tool(
                client,
                name="debug.inspect",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": hit_stop_id,
                    "views": ["threads"],
                },
            )
            assert threads_snapshot["state"] == "suspended"
            assert cast(list[object], threads_snapshot["threads"])
            register_snapshot = await _call_tool(
                client,
                name="debug.inspect",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": hit_stop_id,
                    "views": ["registers"],
                },
            )
            register_names = {
                cast(str, register["name"])
                for register in cast(list[JsonObject], register_snapshot["registers"])
            }
            assert {instruction_pointer, stack_pointer}.issubset(register_names)
            stack_snapshot = await _call_tool(
                client,
                name="debug.inspect",
                arguments={
                    "debug_session_id": session_id,
                    "stop_id": hit_stop_id,
                    "views": ["stack"],
                },
            )
            assert cast(list[object], stack_snapshot["stack"])

            finished = await _call_tool(
                client,
                name="debug.finish",
                arguments={
                    "debug_session_id": session_id,
                    "action": "terminate",
                    "timeout_ms": 30_000,
                },
            )
            assert finished["state"] == "exited"
        assert _tree_identity(fixture_directory) == fixture_before

    asyncio.run(scenario())
