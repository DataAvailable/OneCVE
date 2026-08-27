from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Iterable


MAX_CONFIG_BYTES = 1024 * 1024
FUNCTION_NAME_RE = re.compile(r"^[A-Za-z_~][A-Za-z0-9_:$@.?~-]{0,254}$")
ALLOC_ALIASES = {"alloc", "allocator", "allocation", "malloc", "ck_alloc"}
FREE_ALIASES = {
    "free", "releaser", "release", "destroyer", "dealloc", "deallocator", "ck_free"
}


def normalize_function_names(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        name = str(value).strip()
        if not name:
            continue
        if not FUNCTION_NAME_RE.fullmatch(name):
            raise ValueError(f"无效的函数名：{name}")
        if name not in seen:
            seen.add(name)
            result.append(name)
    return sorted(result, key=str.casefold)


def parse_memory_function_config(content: bytes, filename: str = "") -> dict[str, list[str]]:
    if len(content) > MAX_CONFIG_BYTES:
        raise ValueError("配置文件不能超过 1 MB")
    if b"\x00" in content:
        raise ValueError("配置文件必须是文本文件")
    text = content.decode("utf-8-sig", errors="strict")
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if suffix == "json" or text.lstrip().startswith(("{", "[")):
        alloc, free = _parse_json(text)
    elif suffix == "csv":
        alloc, free = _parse_csv(text)
    else:
        alloc, free = _parse_text(text)
    return {
        "alloc_functions": normalize_function_names(alloc),
        "free_functions": normalize_function_names(free),
    }


def _parse_json(text: str) -> tuple[list[Any], list[Any]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON 配置格式错误：{exc.msg}") from exc
    alloc: list[Any] = []
    free: list[Any] = []
    if isinstance(data, dict):
        for key in ("alloc_functions", "alloc", "allocators"):
            if isinstance(data.get(key), list):
                alloc.extend(data[key])
        for key in ("free_functions", "free", "releasers", "destroyers"):
            if isinstance(data.get(key), list):
                free.extend(data[key])
        functions = data.get("functions", [])
    elif isinstance(data, list):
        functions = data
    else:
        raise ValueError("JSON 顶层必须是对象或数组")
    for item in functions:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("function")
        kind = str(item.get("kind") or item.get("category") or item.get("type") or "")
        target = _kind_target(kind)
        if name and target == "alloc":
            alloc.append(name)
        elif name and target == "free":
            free.append(name)
    return alloc, free


def _parse_csv(text: str) -> tuple[list[str], list[str]]:
    alloc: list[str] = []
    free: list[str] = []
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        raise ValueError("CSV 配置需要表头 kind,name")
    for row in rows:
        normalized = {str(key).strip().lower(): value for key, value in row.items()}
        kind = normalized.get("kind") or normalized.get("category") or normalized.get("type") or ""
        name = normalized.get("name") or normalized.get("function") or ""
        target = _kind_target(kind)
        if target == "alloc":
            alloc.append(name)
        elif target == "free":
            free.append(name)
    return alloc, free


def _parse_text(text: str) -> tuple[list[str], list[str]]:
    alloc: list[str] = []
    free: list[str] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].split("//", 1)[0].strip()
        if not line:
            continue
        match = re.match(r"^([^:=,\s]+)\s*[:=,\s]\s*(.+)$", line)
        if not match:
            raise ValueError(f"第 {line_number} 行格式错误，应为 alloc: 函数名 或 free: 函数名")
        target = _kind_target(match.group(1))
        if target is None:
            raise ValueError(f"第 {line_number} 行类型必须是 alloc 或 free")
        names = [value for value in re.split(r"[,\s]+", match.group(2)) if value]
        (alloc if target == "alloc" else free).extend(names)
    return alloc, free


def _kind_target(value: Any) -> str | None:
    normalized = str(value).strip().lower()
    if normalized in ALLOC_ALIASES:
        return "alloc"
    if normalized in FREE_ALIASES:
        return "free"
    return None


def render_saber_api_config(alloc_functions: Iterable[str], free_functions: Iterable[str]) -> str:
    lines = [*(f"alloc: {name}" for name in alloc_functions), *(f"free: {name}" for name in free_functions)]
    return "\n".join(lines) + ("\n" if lines else "")
