from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_kind TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    build_system TEXT NOT NULL DEFAULT 'unknown',
                    status TEXT NOT NULL DEFAULT 'ready',
                    source_files INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    status TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    progress INTEGER NOT NULL DEFAULT 0,
                    checkers_json TEXT NOT NULL,
                    verify_enabled INTEGER NOT NULL DEFAULT 0,
                    scan_parallelism INTEGER NOT NULL DEFAULT 1,
                    llm_parallelism INTEGER NOT NULL DEFAULT 1,
                    build_strategy TEXT,
                    bitcode_count INTEGER NOT NULL DEFAULT 0,
                    source_unit_count INTEGER NOT NULL DEFAULT 0,
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    custom_alloc_json TEXT NOT NULL DEFAULT '[]',
                    custom_free_json TEXT NOT NULL DEFAULT '[]',
                    error TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    fingerprint TEXT NOT NULL,
                    checker TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    file TEXT NOT NULL,
                    line INTEGER NOT NULL,
                    column_no INTEGER NOT NULL,
                    verdict TEXT NOT NULL DEFAULT 'unreviewed',
                    confidence REAL NOT NULL DEFAULT 0,
                    rationale TEXT NOT NULL DEFAULT '',
                    fix_suggestion TEXT NOT NULL DEFAULT '',
                    path_json TEXT NOT NULL DEFAULT '[]',
                    evidence_json TEXT NOT NULL DEFAULT '[]',
                    snippets_json TEXT NOT NULL DEFAULT '[]',
                    raw_text TEXT NOT NULL DEFAULT '',
                    review_status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    UNIQUE(scan_id, fingerprint)
                );
                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    level TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS project_memory_functions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL CHECK(kind IN ('alloc', 'free')),
                    name TEXT NOT NULL,
                    source TEXT NOT NULL DEFAULT 'manual',
                    created_at TEXT NOT NULL,
                    UNIQUE(project_id, kind, name)
                );
                CREATE INDEX IF NOT EXISTS scans_project_idx ON scans(project_id, created_at DESC);
                CREATE INDEX IF NOT EXISTS findings_scan_idx ON findings(scan_id, vulnerability_type);
                CREATE INDEX IF NOT EXISTS events_scan_idx ON scan_events(scan_id, id);
                CREATE INDEX IF NOT EXISTS memory_functions_project_idx
                    ON project_memory_functions(project_id, kind, name);
                """
            )
            self._ensure_column(connection, "scans", "source_unit_count", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(connection, "scans", "custom_alloc_json", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(connection, "scans", "custom_free_json", "TEXT NOT NULL DEFAULT '[]'")
            self._ensure_column(connection, "scans", "scan_parallelism", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column(connection, "scans", "llm_parallelism", "INTEGER NOT NULL DEFAULT 1")

    @staticmethod
    def _ensure_column(
        connection: sqlite3.Connection, table: str, column: str, definition: str
    ) -> None:
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if column not in columns:
            connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def execute(self, sql: str, parameters: Sequence[Any] = ()) -> None:
        with self.connect() as connection:
            connection.execute(sql, parameters)

    def fetch_one(self, sql: str, parameters: Sequence[Any] = ()) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(sql, parameters).fetchone()
        return dict(row) if row is not None else None

    def fetch_all(self, sql: str, parameters: Sequence[Any] = ()) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(sql, parameters).fetchall()
        return [dict(row) for row in rows]

    def create_project(self, project: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        self.execute(
            """INSERT INTO projects
               (id, name, source_kind, source_path, build_system, status, source_files, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                project["id"], project["name"], project["source_kind"],
                project["source_path"], project.get("build_system", "unknown"),
                project.get("status", "ready"), project.get("source_files", 0), now, now,
            ),
        )
        return self.get_project(project["id"])

    def get_project(self, project_id: str) -> dict[str, Any]:
        project = self.fetch_one(
            """SELECT p.*,
                      (SELECT COUNT(*) FROM scans s WHERE s.project_id = p.id) AS scan_count,
                      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id
                       WHERE s.project_id = p.id) AS finding_count,
                      (SELECT s.status FROM scans s WHERE s.project_id = p.id
                       ORDER BY s.created_at DESC LIMIT 1) AS latest_scan_status
               FROM projects p WHERE p.id = ?""",
            (project_id,),
        )
        if project is None:
            raise KeyError(project_id)
        return project

    def list_projects(self) -> list[dict[str, Any]]:
        return self.fetch_all(
            """SELECT p.*,
                      (SELECT COUNT(*) FROM scans s WHERE s.project_id = p.id) AS scan_count,
                      (SELECT COUNT(*) FROM findings f JOIN scans s ON s.id = f.scan_id
                       WHERE s.project_id = p.id) AS finding_count,
                      (SELECT s.status FROM scans s WHERE s.project_id = p.id
                       ORDER BY s.created_at DESC LIMIT 1) AS latest_scan_status
               FROM projects p ORDER BY p.updated_at DESC"""
        )

    def update_project(self, project_id: str, **changes: Any) -> None:
        self._update("projects", project_id, changes)

    def delete_project(self, project_id: str) -> None:
        self.execute("DELETE FROM projects WHERE id = ?", (project_id,))

    def create_scan(self, scan: dict[str, Any]) -> dict[str, Any]:
        now = utc_now()
        self.execute(
            """INSERT INTO scans
               (id, project_id, status, stage, progress, checkers_json, verify_enabled,
                scan_parallelism, llm_parallelism, custom_alloc_json, custom_free_json,
                created_at, updated_at)
               VALUES (?, ?, 'queued', 'queued', 0, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan["id"], scan["project_id"], json.dumps(scan["checkers"]),
                int(scan.get("verify_enabled", False)),
                int(scan.get("scan_parallelism", 1)),
                int(scan.get("llm_parallelism", 1)),
                json.dumps(scan.get("custom_alloc", []), ensure_ascii=False),
                json.dumps(scan.get("custom_free", []), ensure_ascii=False), now, now,
            ),
        )
        return self.get_scan(scan["id"])

    def update_scan(self, scan_id: str, **changes: Any) -> None:
        self._update("scans", scan_id, changes)

    def delete_scan(self, scan_id: str) -> None:
        self.execute("DELETE FROM scans WHERE id = ?", (scan_id,))

    def delete_scans(self, scan_ids: Sequence[str]) -> None:
        identifiers = list(dict.fromkeys(scan_ids))
        if not identifiers:
            return
        placeholders = ", ".join("?" for _ in identifiers)
        with self.connect() as connection:
            connection.execute(
                f"DELETE FROM scans WHERE id IN ({placeholders})", identifiers
            )

    def list_scan_records(self, project_id: str | None = None) -> list[dict[str, Any]]:
        if project_id is None:
            return self.fetch_all("SELECT id, project_id, status FROM scans")
        return self.fetch_all(
            "SELECT id, project_id, status FROM scans WHERE project_id = ?",
            (project_id,),
        )

    def _update(self, table: str, row_id: str, changes: dict[str, Any]) -> None:
        if not changes:
            return
        changes["updated_at"] = utc_now()
        assignments = ", ".join(f"{key} = ?" for key in changes)
        self.execute(f"UPDATE {table} SET {assignments} WHERE id = ?", (*changes.values(), row_id))

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        scan = self.fetch_one(
            """SELECT s.*, p.name AS project_name, p.source_path, p.source_kind, p.build_system
               FROM scans s JOIN projects p ON p.id = s.project_id WHERE s.id = ?""",
            (scan_id,),
        )
        if scan is None:
            raise KeyError(scan_id)
        return self._decode_scan(scan)

    def list_scans(self, project_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        where = "WHERE s.project_id = ?" if project_id else ""
        parameters: tuple[Any, ...] = (project_id, limit) if project_id else (limit,)
        rows = self.fetch_all(
            f"""SELECT s.*, p.name AS project_name FROM scans s
                 JOIN projects p ON p.id = s.project_id {where}
                 ORDER BY s.created_at DESC LIMIT ?""",
            parameters,
        )
        return [self._decode_scan(row) for row in rows]

    @staticmethod
    def _decode_scan(row: dict[str, Any]) -> dict[str, Any]:
        row["checkers"] = json.loads(row.pop("checkers_json"))
        row["custom_alloc"] = json.loads(row.pop("custom_alloc_json", "[]"))
        row["custom_free"] = json.loads(row.pop("custom_free_json", "[]"))
        row["verify_enabled"] = bool(row["verify_enabled"])
        for legacy_field in (
            "llm_fallback_enabled", "generated_script", "script_status", "bitcode_coverage"
        ):
            row.pop(legacy_field, None)
        row["estimated_remaining_seconds"] = Database._estimate_remaining_seconds(row)
        return row

    @staticmethod
    def _estimate_remaining_seconds(scan: dict[str, Any]) -> int | None:
        if scan.get("status") not in {"running", "cancelling"}:
            return 0 if scan.get("status") == "completed" else None
        started_at = scan.get("started_at")
        try:
            progress = float(scan.get("progress") or 0)
            started = datetime.fromisoformat(str(started_at))
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        except (TypeError, ValueError):
            return None
        if progress < 1 or progress >= 100 or elapsed < 2:
            return None
        remaining = elapsed * (100.0 - progress) / progress
        return int(round(max(1.0, min(remaining, 7 * 24 * 60 * 60))))

    def add_event(self, scan_id: str, stage: str, message: str, level: str = "info") -> None:
        self.execute(
            "INSERT INTO scan_events(scan_id, level, stage, message, created_at) VALUES (?, ?, ?, ?, ?)",
            (scan_id, level, stage, message[:8000], utc_now()),
        )

    def list_events(self, scan_id: str, after: int = 0) -> list[dict[str, Any]]:
        return self.fetch_all(
            "SELECT * FROM scan_events WHERE scan_id = ? AND id > ? ORDER BY id", (scan_id, after)
        )

    def replace_findings(self, scan_id: str, findings: Sequence[dict[str, Any]]) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            connection.executemany(
                """INSERT INTO findings
                   (id, scan_id, fingerprint, checker, kind, vulnerability_type, file, line,
                    column_no, verdict, confidence, rationale, fix_suggestion, path_json,
                    evidence_json, snippets_json, raw_text, review_status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [(
                    item["id"], scan_id, item["fingerprint"], item["checker"], item["kind"],
                    item["vulnerability_type"], item["file"], item["line"], item["column"],
                    item.get("verdict", "unreviewed"), item.get("confidence", 0.0),
                    item.get("rationale", ""), item.get("fix_suggestion", ""),
                    json.dumps(item.get("path", []), ensure_ascii=False),
                    json.dumps(item.get("evidence", []), ensure_ascii=False),
                    json.dumps(item.get("snippets", []), ensure_ascii=False),
                    item.get("raw_text", ""), item.get("review_status", "pending"), now,
                ) for item in findings],
            )

    def clear_findings(self, scan_id: str) -> int:
        now = utc_now()
        with self.connect() as connection:
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
                ).fetchone()[0]
            )
            connection.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            connection.execute(
                "UPDATE scans SET finding_count = 0, updated_at = ? WHERE id = ?",
                (now, scan_id),
            )
        return count

    def delete_findings(self, scan_id: str, finding_ids: Sequence[str]) -> int:
        identifiers = list(dict.fromkeys(finding_ids))
        if not identifiers:
            return 0
        placeholders = ", ".join("?" for _ in identifiers)
        now = utc_now()
        with self.connect() as connection:
            count = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM findings WHERE scan_id = ? AND id IN ({placeholders})",
                    (scan_id, *identifiers),
                ).fetchone()[0]
            )
            connection.execute(
                f"DELETE FROM findings WHERE scan_id = ? AND id IN ({placeholders})",
                (scan_id, *identifiers),
            )
            remaining = int(
                connection.execute(
                    "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
                ).fetchone()[0]
            )
            connection.execute(
                "UPDATE scans SET finding_count = ?, updated_at = ? WHERE id = ?",
                (remaining, now, scan_id),
            )
        return count

    def list_findings(self, scan_id: str) -> list[dict[str, Any]]:
        rows = self.fetch_all(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY confidence DESC, file, line", (scan_id,)
        )
        return [self._decode_finding(row) for row in rows]

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        row = self.fetch_one("SELECT * FROM findings WHERE id = ?", (finding_id,))
        if row is None:
            raise KeyError(finding_id)
        return self._decode_finding(row)

    def get_finding_context(self, finding_id: str) -> dict[str, Any]:
        row = self.fetch_one(
            """SELECT f.*, s.project_id, p.source_path
               FROM findings f
               JOIN scans s ON s.id = f.scan_id
               JOIN projects p ON p.id = s.project_id
               WHERE f.id = ?""",
            (finding_id,),
        )
        if row is None:
            raise KeyError(finding_id)
        return self._decode_finding(row)

    def list_memory_functions(self, project_id: str) -> dict[str, list[str]]:
        self.get_project(project_id)
        rows = self.fetch_all(
            """SELECT kind, name FROM project_memory_functions
               WHERE project_id = ? ORDER BY kind, name COLLATE NOCASE""",
            (project_id,),
        )
        return {
            "alloc_functions": [row["name"] for row in rows if row["kind"] == "alloc"],
            "free_functions": [row["name"] for row in rows if row["kind"] == "free"],
        }

    def replace_memory_functions(
        self,
        project_id: str,
        alloc_functions: Sequence[str],
        free_functions: Sequence[str],
        *,
        source: str = "manual",
    ) -> dict[str, list[str]]:
        self.get_project(project_id)
        now = utc_now()
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM project_memory_functions WHERE project_id = ?", (project_id,)
            )
            connection.executemany(
                """INSERT INTO project_memory_functions
                   (project_id, kind, name, source, created_at) VALUES (?, ?, ?, ?, ?)""",
                [
                    (project_id, kind, name, source, now)
                    for kind, names in (("alloc", alloc_functions), ("free", free_functions))
                    for name in names
                ],
            )
        return self.list_memory_functions(project_id)

    def update_finding_review(self, finding_id: str, review_status: str) -> None:
        self.execute("UPDATE findings SET review_status = ? WHERE id = ?", (review_status, finding_id))

    def update_finding_verdict(
        self,
        finding_id: str,
        *,
        verdict: str,
        confidence: float,
        rationale: str,
        fix_suggestion: str,
        evidence: Sequence[dict[str, Any]],
    ) -> None:
        self.execute(
            """UPDATE findings
               SET verdict = ?, confidence = ?, rationale = ?, fix_suggestion = ?,
                   evidence_json = ? WHERE id = ?""",
            (
                verdict,
                confidence,
                rationale,
                fix_suggestion,
                json.dumps(list(evidence), ensure_ascii=False),
                finding_id,
            ),
        )

    @staticmethod
    def _decode_finding(row: dict[str, Any]) -> dict[str, Any]:
        row["column"] = row.pop("column_no")
        for field in ("path", "evidence", "snippets"):
            row[field] = json.loads(row.pop(f"{field}_json"))
        return row

    def get_settings(self) -> dict[str, str]:
        return {row["key"]: row["value"] for row in self.fetch_all("SELECT key, value FROM settings")}

    def set_settings(self, settings: dict[str, str]) -> None:
        now = utc_now()
        with self.connect() as connection:
            connection.executemany(
                """INSERT INTO settings(key, value, updated_at) VALUES (?, ?, ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
                [(key, value, now) for key, value in settings.items()],
            )
