from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import cast

import pytest

from ida_re_mcp.domain.tools import ChangePrepareInput
from ida_re_mcp.il2cpp import canonical_ndjson, compute_record_id
from ida_re_mcp.il2cpp.canonical import JsonObject
from ida_re_mcp.il2cpp.models import NativeBinding
from ida_re_mcp.supervisor.change_adapter import (
    ArtifactMaterialization,
    ChangeAdapterInputError,
    ChangeAdapterResultError,
    ChangeContext,
    ChangeSourceError,
    InverseSource,
    SolidifiedSource,
    build_canonical_plan,
    build_mutation_execution,
    build_preflight_execution,
    parse_preflight_impact,
    parse_worker_impact,
    source_solidification_requests,
    validate_local_sources,
)
from ida_re_mcp.supervisor.changes import (
    StoredImportIl2CppBundleOperation,
    StoredRestoreRevisionOperation,
)

WORKSPACE_ID = "workspace_abcdef"
REVISION_ID = "revision_abcdef"
IMAGE_ID = "image_abcdef"
NATIVE_SHA256 = "11" * 32
DATABASE_SHA256 = "22" * 32


def _context() -> ChangeContext:
    return ChangeContext(
        workspace_id=WORKSPACE_ID,
        base_revision=REVISION_ID,
        image_id=IMAGE_ID,
        sample_sha256=NATIVE_SHA256,
        database_sha256=DATABASE_SHA256,
        component_hashes={
            "database.i64": DATABASE_SHA256,
            "database.i64.id0": "33" * 32,
        },
        native=NativeBinding(
            sha256=NATIVE_SHA256,
            size=4096,
            image_size=0x5000,
            architecture="x86_64",
            abi="msvc-x64",
            pointer_width=64,
            endianness="little",
        ),
    )


def _named_type_id(name: str) -> str:
    revision_tag = hashlib.sha256(REVISION_ID.encode()).hexdigest()[:16]
    encoded = base64.urlsafe_b64encode(name.encode()).decode().rstrip("=")
    return f"entity~tn~{revision_tag}~{encoded}"


def _normal_arguments() -> ChangePrepareInput:
    return ChangePrepareInput.model_validate(
        {
            "workspace_id": WORKSPACE_ID,
            "base_revision": REVISION_ID,
            "operations": [
                {
                    "kind": "rename",
                    "target": {"kind": "image", "image_id": IMAGE_ID, "rva": "0x1000"},
                    "expected_name": "sub_140001000",
                    "new_name": "parse_packet",
                },
                {
                    "kind": "comment",
                    "target": {"kind": "database", "ea": "0x140001000"},
                    "placement": "repeatable",
                    "expected_text": None,
                    "text": "network parser",
                },
                {
                    "kind": "set_type",
                    "target": {"kind": "image", "image_id": IMAGE_ID, "rva": "0x1000"},
                    "type_ref": {
                        "kind": "function",
                        "calling_convention": "fastcall",
                        "return_type": {"kind": "primitive", "name": "i32"},
                        "parameters": [
                            {
                                "name": "actor",
                                "type": {
                                    "kind": "pointer",
                                    "to": {
                                        "kind": "named",
                                        "type_id": _named_type_id("Game::Actor"),
                                    },
                                    "pointee_const": True,
                                },
                            }
                        ],
                        "variadic": False,
                    },
                },
                {
                    "kind": "patch_bytes",
                    "target": {"kind": "database", "ea": "0x140001020"},
                    "expected_bytes": "7505",
                    "replacement_bytes": "9090",
                },
            ],
        }
    )


def _write_bundle(bundle_path: Path, metadata_path: Path) -> str:
    metadata_path.write_bytes(b"metadata-fixture")
    metadata_sha256 = hashlib.sha256(metadata_path.read_bytes()).hexdigest()
    manifest: JsonObject = {
        "kind": "manifest",
        "schema": "1",
        "media_type": "application/vnd.ida-re.il2cpp-bundle+ndjson",
        "native": {
            "sha256": NATIVE_SHA256,
            "size": 4096,
            "image_size": 0x5000,
            "architecture": "x86_64",
            "abi": "msvc-x64",
            "pointer_width": 64,
            "endianness": "little",
        },
        "metadata": {
            "sha256": metadata_sha256,
            "size": metadata_path.stat().st_size,
        },
    }
    image: JsonObject = {
        "kind": "managed_image",
        "name": "Assembly-CSharp",
        "assembly_name": "Assembly-CSharp.dll",
    }
    image["id"] = compute_record_id(image)
    actor: JsonObject = {
        "kind": "type",
        "image_id": image["id"],
        "namespace": "Game",
        "name": "Actor",
        "layout": {
            "kind": "struct",
            "size": 8,
            "alignment": 8,
            "fields": [],
        },
    }
    actor["id"] = compute_record_id(actor)
    bundle_path.write_bytes(canonical_ndjson([manifest, image, actor]))
    return actor["id"]


def _il2cpp_arguments(bundle_path: Path, metadata_path: Path) -> ChangePrepareInput:
    type_id = _write_bundle(bundle_path, metadata_path)
    return ChangePrepareInput.model_validate(
        {
            "workspace_id": WORKSPACE_ID,
            "base_revision": REVISION_ID,
            "operations": [
                {
                    "kind": "import_il2cpp_bundle",
                    "bundle_path": str(bundle_path),
                    "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
                    "metadata_path": str(metadata_path),
                    "metadata_sha256": hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
                    "type_resolutions": [{"type_id": type_id, "action": "keep"}],
                }
            ],
        }
    )


def _artifact_uri(suffix: str) -> str:
    return f"ida-re://workspaces/{WORKSPACE_ID}/revisions/{REVISION_ID}/artifacts/art_{suffix * 64}"


def test_closed_operations_map_losslessly_to_worker_json() -> None:
    arguments = _normal_arguments()
    preflight = build_preflight_execution(arguments, _context())
    plan = build_canonical_plan(arguments, _context())
    execution = build_mutation_execution(plan.operations, _context())

    assert preflight.worker_operations == execution.worker_operations
    assert execution.mode == "worker"
    assert execution.restore_revision is None
    assert execution.worker_operations[0] == {
        "kind": "rename",
        "address": {"space": "image", "rva": "0x1000"},
        "name": "parse_packet",
        "expected_name": "sub_140001000",
    }
    assert execution.worker_operations[1]["repeatable"] is True
    assert execution.worker_operations[2]["declaration"] == (
        "__int32 __fastcall __ida_re_value(const Game::Actor *actor);"
    )
    assert execution.worker_operations[3]["bytes_hex"] == "9090"
    assert plan.preimage.component_hashes["database.i64.id0"] == "33" * 32


def test_il2cpp_paths_are_validated_then_removed_from_canonical_plan(tmp_path: Path) -> None:
    bundle_path = tmp_path / "annotations.ndjson"
    metadata_path = tmp_path / "global-metadata.dat"
    arguments = _il2cpp_arguments(bundle_path, metadata_path)

    validated = validate_local_sources(arguments, _context())
    preflight = build_preflight_execution(arguments, _context(), validated)
    assert preflight.worker_operations[0]["path"] == str(bundle_path)
    result: dict[str, object] = {
        "staging_path": r"C:\data\staging\database.i64",
        "staging_sha256": "44" * 32,
        "operations": [
            {
                "kind": "import_il2cpp_bundle",
                "bundle_sha256": validated[0].bundle_sha256,
                "types_applied": 0,
                "types_kept": sorted(validated[0].type_ids),
                "symbols_named": 0,
                "symbols_typed": 0,
                "name_conflicts": [],
            }
        ],
        "cold_verification_required": True,
        "saved": True,
    }
    assert parse_preflight_impact(arguments, validated, result).types_changed == 0
    applied = cast(list[dict[str, object]], result["operations"])
    applied[0]["bundle_sha256"] = "ff" * 32
    with pytest.raises(ChangeAdapterResultError, match="bundle SHA-256"):
        parse_preflight_impact(arguments, validated, result)
    requests = source_solidification_requests(validated)
    assert [(request.role, request.source) for request in requests] == [
        ("bundle", bundle_path),
        ("metadata", metadata_path),
    ]

    solidified = (
        SolidifiedSource(
            operation_index=0,
            role="bundle",
            artifact_uri=_artifact_uri("a"),
            content_sha256=validated[0].bundle_sha256,
            size=validated[0].bundle_size,
        ),
        SolidifiedSource(
            operation_index=0,
            role="metadata",
            artifact_uri=_artifact_uri("b"),
            content_sha256=validated[0].metadata_sha256,
            size=validated[0].metadata_size,
        ),
    )
    plan = build_canonical_plan(
        arguments,
        _context(),
        validated_sources=validated,
        solidified_sources=solidified,
    )
    stored = cast(StoredImportIl2CppBundleOperation, plan.operations[0])
    serialized = stored.model_dump_json()
    assert str(tmp_path) not in serialized
    assert stored.bundle_artifact_uri == _artifact_uri("a")
    assert stored.metadata_artifact_uri == _artifact_uri("b")

    execution = build_mutation_execution(
        plan.operations,
        _context(),
        artifacts=(
            ArtifactMaterialization(
                stored.bundle_artifact_uri,
                stored.bundle_sha256,
                stored.bundle_size,
                bundle_path,
            ),
            ArtifactMaterialization(
                stored.metadata_artifact_uri,
                stored.metadata_sha256,
                stored.metadata_size,
                metadata_path,
            ),
        ),
    )
    worker = execution.worker_operations[0]
    assert worker["path"] == str(bundle_path)
    assert worker["expected_metadata"] == {
        "sha256": stored.metadata_sha256,
        "size": stored.metadata_size,
    }
    assert cast(dict[str, str], worker["type_resolutions"]) != {}


def test_il2cpp_source_digest_and_artifact_scope_fail_closed(tmp_path: Path) -> None:
    bundle_path = tmp_path / "annotations.ndjson"
    metadata_path = tmp_path / "global-metadata.dat"
    arguments = _il2cpp_arguments(bundle_path, metadata_path)
    bundle_path.write_bytes(bundle_path.read_bytes() + b" ")
    with pytest.raises(ChangeSourceError, match="摘要"):
        validate_local_sources(arguments, _context())

    arguments = _il2cpp_arguments(bundle_path, metadata_path)
    validated = validate_local_sources(arguments, _context())
    metadata_path.write_bytes(metadata_path.read_bytes() + b"changed")
    with pytest.raises(ChangeSourceError, match="摘要"):
        build_preflight_execution(arguments, _context(), validated)
    arguments = _il2cpp_arguments(bundle_path, metadata_path)
    validated = validate_local_sources(arguments, _context())
    wrong_scope = SolidifiedSource(
        operation_index=0,
        role="bundle",
        artifact_uri=(
            f"ida-re://workspaces/workspace_other/revisions/{REVISION_ID}/artifacts/art_{'a' * 64}"
        ),
        content_sha256=validated[0].bundle_sha256,
        size=validated[0].bundle_size,
    )
    metadata = SolidifiedSource(
        operation_index=0,
        role="metadata",
        artifact_uri=_artifact_uri("b"),
        content_sha256=validated[0].metadata_sha256,
        size=validated[0].metadata_size,
    )
    with pytest.raises(ChangeAdapterInputError, match="workspace/revision"):
        build_canonical_plan(
            arguments,
            _context(),
            validated_sources=validated,
            solidified_sources=(wrong_scope, metadata),
        )


def test_inverse_plan_only_restores_applied_change_parent() -> None:
    arguments = ChangePrepareInput(
        workspace_id=WORKSPACE_ID,
        base_revision=REVISION_ID,
        inverse_of_change_id="change_abcdef",
    )
    source = InverseSource(
        workspace_id=WORKSPACE_ID,
        change_id="change_abcdef",
        applied_revision=REVISION_ID,
        parent_revision="revision_parent",
    )
    plan = build_canonical_plan(arguments, _context(), inverse_source=source)
    assert isinstance(plan.operations[0], StoredRestoreRevisionOperation)
    assert plan.inverse_of_change_id == "change_abcdef"
    execution = build_mutation_execution(plan.operations, _context())
    assert execution.mode == "restore_revision"
    assert execution.restore_revision == "revision_parent"

    later_source = source.model_copy(update={"applied_revision": "revision_later"})
    with pytest.raises(ChangeAdapterInputError, match="当前 base HEAD"):
        build_canonical_plan(arguments, _context(), inverse_source=later_source)


def test_worker_impact_is_strict_and_bound_to_operation_order() -> None:
    plan = build_canonical_plan(_normal_arguments(), _context())
    impact = parse_worker_impact(
        plan.operations,
        {
            "staging_path": r"C:\data\staging\database.i64",
            "staging_sha256": "44" * 32,
            "operations": [
                {"kind": "rename", "address": "0x140001000"},
                {"kind": "comment", "address": "0x140001000"},
                {"kind": "type", "address": "0x140001000"},
                {"kind": "patch", "address": "0x140001020", "size": 2},
            ],
            "cold_verification_required": True,
            "saved": True,
        },
    )
    assert impact.renamed_entities == 1
    assert impact.comments_changed == 1
    assert impact.types_changed == 1
    assert impact.patched_bytes == 2

    with pytest.raises(ChangeAdapterResultError, match="kind"):
        parse_worker_impact(
            plan.operations,
            {
                "staging_path": r"C:\data\staging\database.i64",
                "staging_sha256": "44" * 32,
                "operations": [
                    {"kind": "comment", "address": "0x140001000"},
                    {"kind": "rename", "address": "0x140001000"},
                    {"kind": "type", "address": "0x140001000"},
                    {"kind": "patch", "address": "0x140001020", "size": 2},
                ],
                "cold_verification_required": True,
                "saved": True,
            },
        )


def test_prepare_rejects_foreign_image_and_unresolvable_named_type() -> None:
    raw = _normal_arguments().model_dump(mode="json")
    operations = cast(list[dict[str, object]], raw["operations"])
    target = cast(dict[str, object], operations[0]["target"])
    target["image_id"] = "image_other"
    arguments = ChangePrepareInput.model_validate(raw)
    with pytest.raises(ChangeAdapterInputError, match="对应镜像"):
        build_canonical_plan(arguments, _context())

    raw = _normal_arguments().model_dump(mode="json")
    operations = cast(list[dict[str, object]], raw["operations"])
    set_type = operations[2]
    type_ref = cast(dict[str, object], set_type["type_ref"])
    parameters = cast(list[dict[str, object]], type_ref["parameters"])
    parameter_type = cast(dict[str, object], parameters[0]["type"])
    named = cast(dict[str, object], parameter_type["to"])
    named["type_id"] = "entity~tn~0000000000000000~Rm9v"
    arguments = ChangePrepareInput.model_validate(raw)
    with pytest.raises(ChangeAdapterInputError, match="base_revision"):
        build_canonical_plan(arguments, _context())
