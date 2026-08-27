from __future__ import annotations

import os
from pathlib import Path


GIB = 1024**3
MAX_SABER_PARALLELISM = 8
MAX_LLM_PARALLELISM = 8
SABER_WORKER_MEMORY_BYTES = 3 * GIB
RESERVED_MEMORY_BYTES = 2 * GIB


def _read_positive_int(path: Path) -> int | None:
    try:
        value = path.read_text(encoding="utf-8").strip()
        if value == "max":
            return None
        parsed = int(value)
        return parsed if parsed > 0 else None
    except (OSError, ValueError):
        return None


def available_memory_bytes() -> int | None:
    """Return the effective memory limit, preferring the container cgroup limit."""
    candidates: list[int] = []
    for path in (
        Path("/sys/fs/cgroup/memory.max"),
        Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
    ):
        value = _read_positive_int(path)
        # Old cgroups use enormous sentinel values to mean "unlimited".
        if value is not None and value < 1 << 60:
            candidates.append(value)

    try:
        pages = int(os.sysconf("SC_PHYS_PAGES"))
        page_size = int(os.sysconf("SC_PAGE_SIZE"))
        if pages > 0 and page_size > 0:
            candidates.append(pages * page_size)
    except (AttributeError, OSError, TypeError, ValueError):
        pass
    return min(candidates) if candidates else None


def recommended_saber_parallelism() -> int:
    """Choose a conservative default for memory-heavy Saber child processes."""
    logical_cpus = max(1, os.cpu_count() or 1)
    cpu_budget = max(1, logical_cpus // 2)
    memory = available_memory_bytes()
    if memory is None:
        memory_budget = MAX_SABER_PARALLELISM
    else:
        usable = max(SABER_WORKER_MEMORY_BYTES, memory - RESERVED_MEMORY_BYTES)
        memory_budget = max(1, usable // SABER_WORKER_MEMORY_BYTES)
    return int(max(1, min(cpu_budget, memory_budget, MAX_SABER_PARALLELISM)))


def recommended_llm_parallelism() -> int:
    """Choose a modest default for I/O-bound LLM HTTP requests."""
    logical_cpus = max(1, os.cpu_count() or 1)
    return int(max(1, min(logical_cpus, 4, MAX_LLM_PARALLELISM)))


def hardware_summary() -> dict[str, int | None]:
    memory = available_memory_bytes()
    return {
        "logical_cpus": max(1, os.cpu_count() or 1),
        "memory_bytes": memory,
        "recommended_scan_parallelism": recommended_saber_parallelism(),
        "recommended_llm_parallelism": recommended_llm_parallelism(),
    }
