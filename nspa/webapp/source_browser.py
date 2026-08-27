from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from nspa.vulnerability_verifier import (
    build_source_index,
    project_relative_path,
    resolve_source_file,
)


MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_LINES = 50_000


def read_finding_source(finding: dict[str, Any], requested_file: str | None = None) -> dict[str, Any]:
    source_root = Path(finding["source_path"]).resolve()
    if not source_root.is_dir():
        raise FileNotFoundError("项目源码目录不存在")
    index = build_source_index(source_root)
    locations = _locations(finding, source_root, index)
    available = list(dict.fromkeys(item["path"] for item in locations if item["available"]))

    target_name = requested_file or (available[0] if available else finding["file"])
    target = resolve_source_file(target_name, source_root, index)
    relative = project_relative_path(target, source_root) if target is not None else None
    if target is None or relative is None:
        raise FileNotFoundError(f"无法在项目源码中定位文件：{target_name}")
    if not target.is_file():
        raise FileNotFoundError(f"源码文件不存在：{target_name}")
    size = target.stat().st_size
    if size > MAX_SOURCE_BYTES:
        raise ValueError(f"源码文件超过在线查看上限（{MAX_SOURCE_BYTES // 1024 // 1024} MB）")
    raw = target.read_bytes()
    if b"\x00" in raw:
        raise ValueError("该文件不是可在线查看的文本源码")
    text_lines = raw.decode("utf-8", errors="replace").splitlines()
    truncated = len(text_lines) > MAX_SOURCE_LINES
    if truncated:
        text_lines = text_lines[:MAX_SOURCE_LINES]
    rel = relative.as_posix()
    annotations: dict[int, list[str]] = defaultdict(list)
    for location in locations:
        if location["path"] == rel and location["line"] > 0:
            annotations[location["line"]].append(location["role"])
    return {
        "path": rel,
        "language": _language(target.suffix.lower()),
        "total_lines": len(text_lines),
        "truncated": truncated,
        "available_files": available,
        "locations": locations,
        "lines": [
            {"number": number, "text": line, "roles": list(dict.fromkeys(annotations.get(number, [])))}
            for number, line in enumerate(text_lines, start=1)
        ],
    }


def _locations(
    finding: dict[str, Any], source_root: Path, index: dict[str, list[Path]]
) -> list[dict[str, Any]]:
    entries: list[tuple[dict[str, Any], str, str]] = [
        (
            {"file": finding["file"], "line": finding["line"], "column": finding["column"]},
            "access" if finding["vulnerability_type"] in {"use_after_free", "null_deref"} else "finding",
            "源码位置" if finding["vulnerability_type"] in {"use_after_free", "null_deref"} else "报告位置",
        )
    ]
    for location in finding.get("path", []):
        branch = str(location.get("branch", ""))
        role = "release" if branch.lower() == "free" else "call_path"
        entries.append((location, role, "释放位置" if role == "release" else "调用路径"))
    for location in finding.get("evidence", []):
        evidence_role = str(location.get("role", "")).lower()
        role = "release" if evidence_role in {"free", "release", "deallocation"} else "evidence"
        entries.append((location, role, "释放位置" if role == "release" else "复核结果"))

    result: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for raw, role, label in entries:
        file_name = str(raw.get("file", ""))
        source_path = resolve_source_file(file_name, source_root, index)
        relative = project_relative_path(source_path, source_root) if source_path else None
        path = relative.as_posix() if relative is not None else file_name
        key = (path, int(raw.get("line", 0) or 0), role)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "file": file_name,
                "path": path,
                "line": key[1],
                "column": int(raw.get("column", 0) or 0),
                "branch": raw.get("branch"),
                "role": role,
                "label": label,
                "available": relative is not None,
            }
        )
    return result


def _language(suffix: str) -> str:
    return {
        ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
        ".hh": "cpp", ".hpp": "cpp", ".hxx": "cpp", ".m": "objective-c", ".mm": "objective-cpp",
    }.get(suffix, "text")
