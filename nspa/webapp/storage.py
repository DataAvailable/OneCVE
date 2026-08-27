from __future__ import annotations

import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from .config import WebConfig
from .database import Database


BUILD_ARTIFACT_DIRECTORIES = ("build", "bitcode")


def directory_size(path: Path) -> int:
    """Return directory bytes without following links outside managed storage."""
    total = 0
    try:
        for root, directories, files in os.walk(path, followlinks=False):
            directories[:] = [
                name for name in directories if not (Path(root) / name).is_symlink()
            ]
            for name in files:
                candidate = Path(root) / name
                try:
                    if not candidate.is_symlink():
                        total += candidate.stat().st_size
                except OSError:
                    continue
    except OSError:
        return total
    return total


def managed_child(root: Path, identifier: str) -> Path:
    """Resolve a direct managed child and reject traversal or broad delete targets."""
    if not identifier or identifier in {".", ".."} or Path(identifier).name != identifier:
        raise ValueError("无效的存储目录标识")
    resolved_root = root.resolve()
    candidate = (resolved_root / identifier).resolve()
    if candidate.parent != resolved_root:
        raise ValueError("目标目录不在 OneCVE 管理范围内")
    return candidate


def remove_managed_child(root: Path, identifier: str) -> int:
    target = managed_child(root, identifier)
    size = directory_size(target) if target.exists() else 0
    if target.is_symlink():
        target.unlink(missing_ok=True)
    elif target.exists():
        shutil.rmtree(target)
    return size


def remove_managed_descendant(root: Path, identifier: str, *parts: str) -> int:
    """Remove one exact path below a managed child without widening the target."""
    base = managed_child(root, identifier)
    if not parts or any(not part or Path(part).name != part for part in parts):
        raise ValueError("无效的存储子路径")
    target = base.joinpath(*parts)
    resolved_parent = target.parent.resolve()
    resolved_base = base.resolve()
    if resolved_parent != resolved_base and resolved_base not in resolved_parent.parents:
        raise ValueError("目标路径不在 OneCVE 管理范围内")
    if target.is_symlink() or target.is_file():
        try:
            size = target.lstat().st_size
        except OSError:
            size = 0
        target.unlink(missing_ok=True)
        return size
    size = directory_size(target) if target.exists() else 0
    if target.exists():
        shutil.rmtree(target)
    return size


class StorageService:
    def __init__(self, database: Database, config: WebConfig) -> None:
        self.database = database
        self.config = config
        self._lock = threading.Lock()
        self._cache: tuple[float, dict[str, Any]] | None = None

    def invalidate(self) -> None:
        with self._lock:
            self._cache = None

    def usage(self, *, max_age: float = 5.0) -> dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            if self._cache is not None and now - self._cache[0] <= max_age:
                return self._cache[1]

        result = self._calculate_usage()
        with self._lock:
            self._cache = (now, result)
        return result

    def _calculate_usage(self) -> dict[str, Any]:
        self.config.ensure_directories()
        filesystem = shutil.disk_usage(self.config.data_root)
        projects = self.database.list_projects()
        scan_records = self.database.list_scan_records()

        project_rows: dict[str, dict[str, int]] = {
            project["id"]: {
                "managed_source_bytes": directory_size(
                    managed_child(self.config.projects_root, project["id"])
                ),
                "scan_bytes": 0,
                "build_bytes": 0,
            }
            for project in projects
        }

        scans_bytes = 0
        build_bytes = 0
        reports_bytes = 0
        for scan in scan_records:
            scan_root = managed_child(self.config.scans_root, scan["id"])
            scan_size = directory_size(scan_root)
            scan_build_size = sum(
                directory_size(scan_root / name) for name in BUILD_ARTIFACT_DIRECTORIES
            )
            scan_report_size = directory_size(scan_root / "reports")
            scans_bytes += scan_size
            build_bytes += scan_build_size
            reports_bytes += scan_report_size
            project_usage = project_rows.get(scan["project_id"])
            if project_usage is not None:
                project_usage["scan_bytes"] += scan_size
                project_usage["build_bytes"] += scan_build_size

        projects_bytes = directory_size(self.config.projects_root)
        database_bytes = sum(
            candidate.stat().st_size
            for candidate in self.config.database_path.parent.glob(
                f"{self.config.database_path.name}*"
            )
            if candidate.is_file()
        )
        data_bytes = directory_size(self.config.data_root)
        per_project = [
            {
                "project_id": project["id"],
                "managed_source_bytes": project_rows[project["id"]]["managed_source_bytes"],
                "scan_bytes": project_rows[project["id"]]["scan_bytes"],
                "build_bytes": project_rows[project["id"]]["build_bytes"],
                "total_bytes": (
                    project_rows[project["id"]]["managed_source_bytes"]
                    + project_rows[project["id"]]["scan_bytes"]
                ),
                "source_managed": project["source_kind"] in {"upload", "git"},
            }
            for project in projects
        ]
        return {
            "filesystem": {
                "total_bytes": filesystem.total,
                "used_bytes": filesystem.used,
                "free_bytes": filesystem.free,
            },
            "onecve": {
                "data_bytes": data_bytes,
                "projects_bytes": projects_bytes,
                "scans_bytes": scans_bytes,
                "database_bytes": database_bytes,
                "build_bytes": build_bytes,
                "reports_bytes": reports_bytes,
                "reclaimable_bytes": build_bytes,
            },
            "projects": per_project,
        }

    def clean_project_artifacts(self, project_id: str) -> dict[str, Any]:
        self.database.get_project(project_id)
        scans = self.database.list_scan_records(project_id=project_id)
        removed = 0
        cleaned_scans = 0
        for scan in scans:
            scan_root = managed_child(self.config.scans_root, scan["id"])
            scan_removed = 0
            for name in BUILD_ARTIFACT_DIRECTORIES:
                target = scan_root / name
                size = directory_size(target) if target.exists() else 0
                if target.is_symlink():
                    target.unlink(missing_ok=True)
                elif target.exists():
                    shutil.rmtree(target)
                scan_removed += size
            if scan_removed:
                cleaned_scans += 1
                removed += scan_removed
                self.database.update_scan(scan["id"], bitcode_count=0)
                self.database.add_event(
                    scan["id"], "cleanup", f"已清理构建产物 {scan_removed} 字节"
                )
        self.invalidate()
        return {
            "project_id": project_id,
            "cleaned_scans": cleaned_scans,
            "freed_bytes": removed,
        }
