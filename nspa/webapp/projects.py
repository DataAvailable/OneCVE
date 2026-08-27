from __future__ import annotations

import re
import shutil
import subprocess
import tarfile
import uuid
import zipfile
from pathlib import Path
from typing import BinaryIO, Callable
from urllib.parse import urlparse

from .config import WebConfig
from .database import Database


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm", ".h", ".hh", ".hpp", ".hxx"}
IGNORED_PARTS = {".git", ".svn", "node_modules", "CMakeFiles", "build", "dist"}
BUILD_MARKERS = (
    ("cmake", ("CMakeLists.txt",)),
    ("meson", ("meson.build",)),
    ("autotools", ("configure", "configure.ac", "configure.in", "autogen.sh", "buildconf")),
    ("make", ("GNUmakefile", "Makefile", "makefile")),
)


def candidate_build_directories(source: Path, max_depth: int = 3) -> list[Path]:
    source = source.resolve()
    result = [source]
    pending = [(source, 0)]
    while pending:
        current, depth = pending.pop(0)
        if depth >= max_depth:
            continue
        try:
            children = sorted(
                (path for path in current.iterdir() if path.is_dir()),
                key=lambda path: path.name.lower(),
            )
        except OSError:
            continue
        for child in children:
            if child.name in IGNORED_PARTS or child.name.startswith("."):
                continue
            result.append(child)
            pending.append((child, depth + 1))
    return result


def find_compile_database(source: Path) -> Path | None:
    source = source.resolve()
    direct = source / "compile_commands.json"
    if direct.is_file():
        return direct
    try:
        candidates = sorted(source.rglob("compile_commands.json"))
    except OSError:
        candidates = []
    for candidate in candidates:
        try:
            relative = candidate.relative_to(source)
        except ValueError:
            continue
        if len(relative.parts) > 5:
            continue
        if any(part in {".git", ".svn", "node_modules"} for part in relative.parts):
            continue
        if candidate.is_file():
            return candidate.resolve()
    return None


def discover_native_builds(source: Path) -> list[tuple[str, Path]]:
    source = source.resolve()
    for directory in candidate_build_directories(source):
        result: list[tuple[str, Path]] = []
        for system, markers in BUILD_MARKERS:
            if any((directory / marker).is_file() for marker in markers):
                result.append((system, directory))
        if result:
            return result
    return []


def discover_build(source: Path, *, include_compile_commands: bool = True) -> tuple[str, Path]:
    source = source.resolve()
    if include_compile_commands:
        compile_database = find_compile_database(source)
        if compile_database is not None:
            return "compile_commands", compile_database.parent
    native_builds = discover_native_builds(source)
    if native_builds:
        return native_builds[0]
    if any(source.rglob("*.bc")):
        return "bitcode", source
    return "unknown", source


def detect_build_system(source: Path) -> str:
    return discover_build(source)[0]


def count_sources(source: Path) -> int:
    count = 0
    for path in source.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        try:
            relative = path.relative_to(source)
        except ValueError:
            continue
        if not any(part in IGNORED_PARTS for part in relative.parts):
            count += 1
    return count


def safe_project_name(value: str) -> str:
    name = re.sub(r"[^\w.-]+", "-", value.strip(), flags=re.UNICODE).strip("-.")
    return name[:80] or "local-project"


class ProjectService:
    def __init__(self, database: Database, config: WebConfig) -> None:
        self.database = database
        self.config = config

    def add_local_project(self, name: str, source_path: str) -> dict[str, object]:
        source = Path(source_path).expanduser().resolve()
        if not source.is_dir():
            raise ValueError("源码目录不存在或不是目录")
        project_id = uuid.uuid4().hex
        return self.database.create_project(
            {
                "id": project_id,
                "name": safe_project_name(name or source.name),
                "source_kind": "local",
                "source_path": str(source),
                "build_system": detect_build_system(source),
                "source_files": count_sources(source),
            }
        )

    def add_uploaded_project(
        self,
        name: str,
        filename: str,
        stream: BinaryIO,
        *,
        on_chunk: Callable[[int], None] | None = None,
    ) -> dict[str, object]:
        project_id = uuid.uuid4().hex
        project_root = self.config.projects_root / project_id
        source_root = project_root / "source"
        archive_path = project_root / (Path(filename).name or "source.zip")
        project_root.mkdir(parents=True, exist_ok=False)
        total = 0
        try:
            with archive_path.open("wb") as target:
                while chunk := stream.read(1024 * 1024):
                    total += len(chunk)
                    if total > self.config.max_upload_bytes:
                        raise ValueError("上传文件超过本地配置的大小限制")
                    target.write(chunk)
                    if on_chunk:
                        on_chunk(total)
            source_root.mkdir()
            if archive_path.suffix.lower() == ".bc":
                shutil.move(str(archive_path), source_root / Path(filename).name)
            else:
                extract_archive_safely(archive_path, source_root)
            source = collapse_single_directory(source_root)
            project = self.database.create_project(
                {
                    "id": project_id,
                    "name": safe_project_name(name or Path(filename).stem),
                    "source_kind": "upload",
                    "source_path": str(source),
                    "build_system": detect_build_system(source),
                    "source_files": count_sources(source),
                }
            )
            archive_path.unlink(missing_ok=True)
            return project
        except Exception:
            shutil.rmtree(project_root, ignore_errors=True)
            raise

    def add_git_project(self, name: str, repository_url: str, ref: str = "") -> dict[str, object]:
        parsed = urlparse(repository_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("第一版仅支持公开的 HTTP/HTTPS Git 仓库")
        git = shutil.which("git")
        if not git:
            raise ValueError("本机未安装 Git")
        project_id = uuid.uuid4().hex
        project_root = self.config.projects_root / project_id
        source = project_root / "source"
        project_root.mkdir(parents=True, exist_ok=False)
        command = [
            git,
            "clone",
            "--depth",
            "1",
            "--recurse-submodules",
            "--shallow-submodules",
        ]
        if ref.strip():
            command.extend(["--branch", ref.strip()])
        command.extend([repository_url, str(source)])
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                timeout=600,
                check=False,
            )
            if completed.returncode != 0:
                raise ValueError(f"Git 获取失败：{completed.stdout[-2000:]}")
            return self.database.create_project(
                {
                    "id": project_id,
                    "name": safe_project_name(name or Path(parsed.path).stem),
                    "source_kind": "git",
                    "source_path": str(source),
                    "build_system": detect_build_system(source),
                    "source_files": count_sources(source),
                }
            )
        except Exception:
            shutil.rmtree(project_root, ignore_errors=True)
            raise


def collapse_single_directory(root: Path) -> Path:
    children = [path for path in root.iterdir() if path.name not in {"__MACOSX", ".DS_Store"}]
    if len(children) == 1 and children[0].is_dir():
        return children[0]
    return root


def extract_archive_safely(archive: Path, target: Path) -> None:
    lower_name = archive.name.lower()
    if lower_name.endswith(".zip"):
        with zipfile.ZipFile(archive) as handle:
            for member in handle.infolist():
                destination = checked_destination(target, member.filename)
                if member.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                with handle.open(member) as source, destination.open("wb") as output:
                    shutil.copyfileobj(source, output)
        return
    if any(lower_name.endswith(suffix) for suffix in (".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz")):
        with tarfile.open(archive, "r:*") as handle:
            for member in handle.getmembers():
                if member.issym() or member.islnk() or member.isdev():
                    raise ValueError(f"压缩包包含不允许的链接或设备文件：{member.name}")
                destination = checked_destination(target, member.name)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = handle.extractfile(member)
                if source is not None:
                    with source, destination.open("wb") as output:
                        shutil.copyfileobj(source, output)
        return
    raise ValueError("仅支持 ZIP、TAR、TAR.GZ、TGZ、TAR.XZ 源码包")


def checked_destination(root: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ValueError(f"压缩包包含绝对路径：{member_name}")
    destination = (root / normalized).resolve()
    try:
        destination.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"压缩包路径越界：{member_name}") from exc
    return destination
