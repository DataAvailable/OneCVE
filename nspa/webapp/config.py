from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class WebConfig:
    repository_root: Path
    data_root: Path
    database_path: Path
    projects_root: Path
    scans_root: Path
    max_upload_bytes: int
    max_workers: int

    @classmethod
    def from_environment(cls) -> "WebConfig":
        repository_root = Path(os.environ.get("NSPA_ROOT", REPOSITORY_ROOT)).resolve()
        data_root = Path(
            os.environ.get("NSPA_WEB_DATA_DIR", repository_root / ".nspa-web")
        ).resolve()
        return cls(
            repository_root=repository_root,
            data_root=data_root,
            database_path=data_root / "nspa.db",
            projects_root=data_root / "projects",
            scans_root=data_root / "scans",
            max_upload_bytes=int(os.environ.get("NSPA_MAX_UPLOAD_BYTES", 1024 * 1024 * 1024)),
            max_workers=max(1, int(os.environ.get("NSPA_WEB_WORKERS", "2"))),
        )

    def ensure_directories(self) -> None:
        for path in (self.data_root, self.projects_root, self.scans_root):
            path.mkdir(parents=True, exist_ok=True)


CONFIG = WebConfig.from_environment()

