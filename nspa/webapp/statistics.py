from __future__ import annotations

from datetime import datetime
from typing import Any

from .database import Database


def scan_statistics(database: Database, project_id: str | None = None, limit: int = 100) -> dict[str, Any]:
    where = "WHERE s.project_id = ?" if project_id else ""
    parameters: tuple[Any, ...] = (project_id, limit) if project_id else (limit,)
    rows = database.fetch_all(
        f"""SELECT s.id, s.project_id, p.name AS project_name, s.status, s.created_at,
                   s.started_at, s.finished_at, s.bitcode_count, s.source_unit_count,
                   p.source_files AS source_file_count, s.finding_count
            FROM scans s JOIN projects p ON p.id = s.project_id {where}
            ORDER BY s.created_at DESC LIMIT ?""",
        parameters,
    )
    if project_id:
        source_file_count = int(database.get_project(project_id)["source_files"] or 0)
    else:
        source_file_count = int(
            database.fetch_one("SELECT COALESCE(SUM(source_files), 0) AS value FROM projects")["value"]
        )
    scan_ids = [row["id"] for row in rows]
    type_rows: list[dict[str, Any]] = []
    llm_review: dict[str, int] = {}
    manual_review: dict[str, int] = {}
    if scan_ids:
        placeholders = ",".join("?" for _ in scan_ids)
        type_rows = database.fetch_all(
            f"""SELECT vulnerability_type AS type, COUNT(*) AS count
                FROM findings WHERE scan_id IN ({placeholders})
                GROUP BY vulnerability_type ORDER BY count DESC""",
            scan_ids,
        )
        llm_rows = database.fetch_all(
            f"""SELECT CASE
                       WHEN verdict = 'unknown' THEN 'false_positive'
                       WHEN verdict IS NULL OR verdict = '' THEN 'unreviewed'
                       ELSE verdict
                     END AS status,
                     COUNT(*) AS count
                FROM findings WHERE scan_id IN ({placeholders})
                GROUP BY CASE
                           WHEN verdict = 'unknown' THEN 'false_positive'
                           WHEN verdict IS NULL OR verdict = '' THEN 'unreviewed'
                           ELSE verdict
                         END""",
            scan_ids,
        )
        manual_rows = database.fetch_all(
            f"""SELECT review_status AS status, COUNT(*) AS count
                FROM findings WHERE scan_id IN ({placeholders})
                GROUP BY review_status""",
            scan_ids,
        )
        llm_review = {str(row["status"]): int(row["count"]) for row in llm_rows}
        manual_review = {
            str(row["status"]): int(row["count"]) for row in manual_rows
        }

    completed = [row for row in rows if row["status"] == "completed"]
    durations = [_duration(row) for row in completed]
    recent = []
    for row in rows:
        duration = _duration(row)
        recent.append({**row, "duration_seconds": duration})
    return {
        "summary": {
            "scans": len(rows),
            "completed_scans": len(completed),
            "findings": sum(int(row["finding_count"] or 0) for row in rows),
            "avg_duration_seconds": round(sum(durations) / max(len(durations), 1), 2),
            "bitcode_count": sum(int(row["bitcode_count"] or 0) for row in rows),
            "source_file_count": source_file_count,
        },
        "by_type": type_rows,
        "review_status": {
            "llm": llm_review,
            "manual": manual_review,
        },
        "recent_scans": recent[:20],
    }


def _duration(row: dict[str, Any]) -> float:
    if not row.get("started_at") or not row.get("finished_at"):
        return 0.0
    try:
        return max(0.0, (datetime.fromisoformat(row["finished_at"]) - datetime.fromisoformat(row["started_at"])).total_seconds())
    except (TypeError, ValueError):
        return 0.0
