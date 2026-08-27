from __future__ import annotations

import csv
import io
import json
from typing import Any, Sequence


CSV_COLUMNS = [
    "id",
    "project",
    "scan_id",
    "checker",
    "vulnerability_type",
    "kind",
    "file",
    "line",
    "column",
    "verdict",
    "confidence",
    "review_status",
    "rationale",
    "fix_suggestion",
    "path",
    "evidence",
    "snippets",
    "raw_text",
]


def render_findings_csv(scan: dict[str, Any], findings: Sequence[dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for finding in findings:
        writer.writerow(
            {
                **finding,
                "project": scan["project_name"],
                "scan_id": scan["id"],
                "path": json.dumps(finding["path"], ensure_ascii=False),
                "evidence": json.dumps(finding["evidence"], ensure_ascii=False),
                "snippets": json.dumps(finding["snippets"], ensure_ascii=False),
            }
        )
    return "\ufeff" + output.getvalue()
