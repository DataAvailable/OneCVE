from __future__ import annotations

import html
import json
import os
import shutil
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from .config import CONFIG
from .database import Database
from .exports import render_findings_csv
from .hardware import (
    hardware_summary,
    recommended_llm_parallelism,
    recommended_saber_parallelism,
)
from .llm_runtime import is_environment_variable_name, resolve_llm_runtime
from .memory_functions import normalize_function_names, parse_memory_function_config
from .projects import ProjectService
from .scanner import ScanManager
from .source_browser import read_finding_source
from .statistics import scan_statistics
from .storage import StorageService


database = Database(CONFIG.database_path)
projects = ProjectService(database, CONFIG)
scans = ScanManager(database, CONFIG)
storage = StorageService(database, CONFIG)


@asynccontextmanager
async def lifespan(_: FastAPI):
    CONFIG.ensure_directories()
    database.initialize()
    migrate_legacy_llm_key()
    scans.recover_interrupted_scans()
    yield
    scans.shutdown()


app = FastAPI(
    title="OneCVE Local Scanner API",
    version="0.1.0",
    description="Local-only orchestration API for OneCVE vulnerability scanning.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class LocalProjectRequest(BaseModel):
    name: str = ""
    source_path: str


class GitProjectRequest(BaseModel):
    name: str = ""
    repository_url: str
    ref: str = ""


class ScanRequest(BaseModel):
    checkers: list[Literal["leak", "dfree", "uaf", "fileck", "npd"]] = Field(
        default_factory=lambda: ["leak", "dfree", "uaf", "fileck", "npd"]
    )
    verify_enabled: bool = False
    parallelism: int | None = Field(default=None, ge=1, le=16)
    llm_parallelism: int | None = Field(default=None, ge=1, le=16)


class ScanBatchRequest(BaseModel):
    scan_ids: list[str] = Field(min_length=1, max_length=500)


class FindingBatchRequest(BaseModel):
    finding_ids: list[str] = Field(min_length=1, max_length=2000)


class ReviewRequest(BaseModel):
    status: Literal["pending", "confirmed", "false_positive", "ignored"]


class MemoryFunctionsRequest(BaseModel):
    alloc_functions: list[str] = Field(default_factory=list, max_length=1000)
    free_functions: list[str] = Field(default_factory=list, max_length=1000)


class SettingsRequest(BaseModel):
    svf_build_dir: str = ""
    saber_path: str = ""
    extapi_path: str = ""
    clang: str = "clang"
    clangxx: str = "clang++"
    build_timeout: int = Field(default=1800, ge=30, le=86400)
    saber_timeout: int = Field(default=300, ge=10, le=86400)
    scan_parallelism: int = Field(
        default_factory=recommended_saber_parallelism, ge=1, le=16
    )
    llm_parallelism: int = Field(
        default_factory=recommended_llm_parallelism, ge=1, le=16
    )
    llm_model: str = "gpt-4o-mini"
    llm_base_url: str = "https://api.openai.com/v1"
    llm_chat_path: str = "/chat/completions"
    llm_api_key_env: str = "OPENAI_API_KEY"
    llm_api_key: str = ""
    llm_timeout: int = Field(default=120, ge=10, le=1800)


class LLMConnectionTestRequest(BaseModel):
    llm_model: str = "gpt-4o-mini"
    llm_base_url: str = "https://api.openai.com/v1"
    llm_chat_path: str = "/chat/completions"
    llm_api_key_env: str = "OPENAI_API_KEY"
    llm_api_key: str = ""
    llm_timeout: int = Field(default=30, ge=5, le=120)


def migrate_legacy_llm_key() -> None:
    saved = database.get_settings()
    legacy = saved.get("llm_api_key_env", "").strip()
    if legacy and not is_environment_variable_name(legacy):
        database.set_settings(
            {
                "llm_api_key": saved.get("llm_api_key") or legacy,
                "llm_api_key_env": "OPENAI_API_KEY",
            }
        )


def not_found(kind: str, identifier: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"{kind}不存在：{identifier}")


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "mode": "local", "version": app.version}


@app.get("/api/dashboard")
def dashboard() -> dict[str, Any]:
    project_count = database.fetch_one("SELECT COUNT(*) AS value FROM projects")["value"]
    scan_count = database.fetch_one("SELECT COUNT(*) AS value FROM scans")["value"]
    finding_count = database.fetch_one("SELECT COUNT(*) AS value FROM findings")["value"]
    active_count = database.fetch_one(
        "SELECT COUNT(*) AS value FROM scans WHERE status IN ('queued', 'running', 'cancelling')"
    )["value"]
    by_type = database.fetch_all(
        "SELECT vulnerability_type AS type, COUNT(*) AS count FROM findings GROUP BY vulnerability_type"
    )
    return {
        "metrics": {
            "projects": project_count,
            "scans": scan_count,
            "findings": finding_count,
            "active_scans": active_count,
        },
        "by_type": by_type,
        "recent_scans": database.list_scans(limit=8),
    }


@app.get("/api/statistics")
def statistics(
    project_id: str | None = None,
    limit: int = Query(100, ge=1, le=500),
) -> dict[str, Any]:
    try:
        return scan_statistics(database, project_id=project_id, limit=limit)
    except KeyError:
        raise not_found("项目", project_id or "")


@app.get("/api/system")
def system_status() -> dict[str, Any]:
    settings = database.get_settings()
    llm = resolve_llm_runtime(settings)
    svf_build = settings.get("svf_build_dir") or os.environ.get("NSPA_SVF_BUILD_DIR", "")
    saber = settings.get("saber_path") or os.environ.get("NSPA_SABER", "")
    extapi = settings.get("extapi_path") or os.environ.get("SVF_EXTAPI", "")
    return {
        "tools": {
            name: shutil.which(name)
            for name in ("clang", "clang++", "cmake", "meson", "bear", "make", "bash", "git")
        },
        "paths": {"svf_build_dir": svf_build, "saber": saber, "extapi": extapi},
        "llm": {
            "api_key_env": llm.api_key_env,
            "configured": llm.configured,
            "authenticated": llm.authenticated,
            "local_endpoint": llm.local_endpoint,
            "endpoint": f"{llm.base_url}{llm.chat_path}",
        },
        "data_root": str(CONFIG.data_root),
        "hardware": hardware_summary(),
    }


@app.get("/api/storage")
def storage_status() -> dict[str, Any]:
    return storage.usage()


@app.get("/api/settings")
def get_settings() -> dict[str, Any]:
    defaults = SettingsRequest().model_dump()
    saved = database.get_settings()
    for key, default in defaults.items():
        if key in saved:
            defaults[key] = int(saved[key]) if isinstance(default, int) else saved[key]
    llm = resolve_llm_runtime(saved)
    defaults["llm_api_key"] = ""
    defaults["llm_api_key_configured"] = llm.authenticated
    return defaults


@app.put("/api/settings")
def update_settings(request: SettingsRequest) -> dict[str, Any]:
    existing = database.get_settings()
    values = {key: str(value) for key, value in request.model_dump().items()}
    submitted_key = values.pop("llm_api_key", "").strip()
    if submitted_key:
        values["llm_api_key"] = submitted_key
    elif existing.get("llm_api_key"):
        values["llm_api_key"] = existing["llm_api_key"]
    database.set_settings(values)
    return get_settings()


@app.post("/api/settings/llm/test")
def test_llm_connection(request: LLMConnectionTestRequest) -> dict[str, Any]:
    from nspa.llm_semantic_validator import OpenAICompatibleClient

    values = database.get_settings()
    submitted = {key: str(value) for key, value in request.model_dump().items()}
    submitted_key = submitted.pop("llm_api_key", "").strip()
    values.update(submitted)
    if submitted_key:
        values["llm_api_key"] = submitted_key
    llm = resolve_llm_runtime(values)
    if not llm.model or not llm.base_url or not llm.chat_path:
        raise HTTPException(status_code=400, detail="请完整填写模型、Base URL 和 Chat 路径")
    client = OpenAICompatibleClient(
        api_key=llm.api_key,
        base_url=llm.base_url,
        model=llm.model,
        chat_path=llm.chat_path,
        timeout=min(llm.timeout, 120.0),
        max_retries=0,
    )
    try:
        result = client.complete_json(
            [
                {
                    "role": "system",
                    "content": "Return only a valid JSON object. Do not use Markdown.",
                },
                {
                    "role": "user",
                    "content": 'Connection test. Reply with {"ok": true}.',
                },
            ]
        )
    except RuntimeError as exc:
        detail = str(exc)
        if "localhost" in llm.base_url or "127.0.0.1" in llm.base_url:
            detail += "；如果模型运行在 Windows 宿主机，请将地址改为 host.docker.internal"
        raise HTTPException(status_code=502, detail=detail[-1200:]) from exc
    return {
        "ok": True,
        "message": "LLM API 连接及 JSON 响应测试通过",
        "model": llm.model,
        "endpoint": client.chat_url,
        "authenticated": llm.authenticated,
        "response": result,
    }


@app.get("/api/projects")
def list_projects() -> list[dict[str, Any]]:
    return database.list_projects()


@app.get("/api/projects/{project_id}")
def get_project(project_id: str) -> dict[str, Any]:
    try:
        project = database.get_project(project_id)
    except KeyError:
        raise not_found("项目", project_id)
    project["scans"] = database.list_scans(project_id=project_id)
    return project


@app.delete("/api/projects/{project_id}")
def delete_project(project_id: str) -> dict[str, Any]:
    try:
        result = scans.delete_project(project_id)
    except KeyError:
        raise not_found("项目", project_id)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    storage.invalidate()
    return result


@app.post("/api/projects/{project_id}/artifacts/cleanup")
def cleanup_project_artifacts(project_id: str) -> dict[str, Any]:
    try:
        if scans.has_active_project_scan(project_id):
            raise ValueError("项目存在运行中的任务，请先终止任务再清理构建产物")
        result = storage.clean_project_artifacts(project_id)
    except KeyError:
        raise not_found("项目", project_id)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return result


@app.get("/api/projects/{project_id}/memory-functions")
def get_project_memory_functions(project_id: str) -> dict[str, Any]:
    try:
        functions = database.list_memory_functions(project_id)
    except KeyError:
        raise not_found("项目", project_id)
    return {"project_id": project_id, **functions}


@app.put("/api/projects/{project_id}/memory-functions")
def update_project_memory_functions(
    project_id: str, request: MemoryFunctionsRequest
) -> dict[str, Any]:
    try:
        alloc = normalize_function_names(request.alloc_functions)
        free = normalize_function_names(request.free_functions)
        functions = database.replace_memory_functions(project_id, alloc, free)
    except KeyError:
        raise not_found("项目", project_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"project_id": project_id, **functions}


@app.post("/api/projects/{project_id}/memory-functions/import")
def import_project_memory_functions(
    project_id: str, config: UploadFile = File(...)
) -> dict[str, Any]:
    try:
        database.get_project(project_id)
        content = config.file.read(1024 * 1024 + 1)
        functions = parse_memory_function_config(content, config.filename or "")
        saved = database.replace_memory_functions(
            project_id,
            functions["alloc_functions"],
            functions["free_functions"],
            source="file",
        )
    except KeyError:
        raise not_found("项目", project_id)
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        config.file.close()
    return {"project_id": project_id, **saved}


@app.post("/api/projects/local", status_code=201)
def add_local_project(request: LocalProjectRequest) -> dict[str, object]:
    try:
        return projects.add_local_project(request.name, request.source_path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/projects/git", status_code=201)
def add_git_project(request: GitProjectRequest) -> dict[str, object]:
    try:
        return projects.add_git_project(request.name, request.repository_url, request.ref)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/projects/upload", status_code=201)
def upload_project(
    archive: UploadFile = File(...),
    name: str = Form(""),
) -> dict[str, object]:
    try:
        return projects.add_uploaded_project(name, archive.filename or "source.zip", archive.file)
    except (ValueError, OSError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        archive.file.close()


@app.get("/api/scans")
def list_scans(project_id: str | None = None) -> list[dict[str, Any]]:
    return database.list_scans(project_id=project_id)


@app.post("/api/scans/bulk-cancel", status_code=202)
def cancel_scans(request: ScanBatchRequest) -> dict[str, Any]:
    try:
        cancelled = scans.cancel_many(request.scan_ids)
    except KeyError as exc:
        raise not_found("扫描", str(exc.args[0]))
    return {"scan_ids": [scan["id"] for scan in cancelled], "count": len(cancelled)}


@app.post("/api/scans/bulk-delete")
def delete_scans(request: ScanBatchRequest) -> dict[str, Any]:
    try:
        result = scans.delete_many(request.scan_ids)
    except KeyError as exc:
        raise not_found("扫描", str(exc.args[0]))
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    storage.invalidate()
    return result


@app.post("/api/projects/{project_id}/scans", status_code=202)
def create_scan(project_id: str, request: ScanRequest) -> dict[str, Any]:
    try:
        return scans.create_scan(
            project_id,
            request.checkers,
            verify_enabled=request.verify_enabled,
            parallelism=request.parallelism,
            llm_parallelism=request.llm_parallelism,
        )
    except KeyError:
        raise not_found("项目", project_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    try:
        scan = database.get_scan(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)
    scan["finding_summary"] = database.fetch_all(
        """SELECT vulnerability_type AS type, COUNT(*) AS count
           FROM findings WHERE scan_id = ? GROUP BY vulnerability_type""",
        (scan_id,),
    )
    return scan


@app.get("/api/scans/{scan_id}/events")
def get_scan_events(scan_id: str, after: int = Query(0, ge=0)) -> list[dict[str, Any]]:
    try:
        database.get_scan(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)
    return database.list_events(scan_id, after=after)


@app.post("/api/scans/{scan_id}/cancel", status_code=202)
def cancel_scan(scan_id: str) -> dict[str, Any]:
    try:
        return scans.cancel(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)


@app.delete("/api/scans/{scan_id}")
def delete_scan(scan_id: str) -> dict[str, Any]:
    try:
        result = scans.delete(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    storage.invalidate()
    return result


@app.get("/api/scans/{scan_id}/findings")
def list_findings(scan_id: str) -> list[dict[str, Any]]:
    try:
        database.get_scan(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)
    return database.list_findings(scan_id)


@app.delete("/api/scans/{scan_id}/findings")
def clear_scan_findings(scan_id: str) -> dict[str, Any]:
    try:
        result = scans.clear_findings(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    storage.invalidate()
    return result


@app.post("/api/scans/{scan_id}/findings/bulk-delete")
def delete_selected_findings(
    scan_id: str, request: FindingBatchRequest
) -> dict[str, Any]:
    try:
        result = scans.delete_findings(scan_id, request.finding_ids)
    except KeyError:
        raise not_found("扫描", scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    storage.invalidate()
    return result


@app.post("/api/scans/{scan_id}/findings/llm-review")
def review_selected_findings(
    scan_id: str, request: FindingBatchRequest
) -> dict[str, Any]:
    try:
        return scans.review_findings(scan_id, request.finding_ids)
    except KeyError as exc:
        raise not_found("漏洞", str(exc.args[0]))
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/scans/{scan_id}/findings/llm-review/progress")
def get_selected_findings_review_progress(scan_id: str) -> dict[str, Any]:
    try:
        return scans.get_llm_review_progress(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str) -> dict[str, Any]:
    try:
        return database.get_finding(finding_id)
    except KeyError:
        raise not_found("漏洞", finding_id)


@app.get("/api/findings/{finding_id}/source")
def get_finding_source(finding_id: str, file: str | None = None) -> dict[str, Any]:
    try:
        finding = database.get_finding_context(finding_id)
        return read_finding_source(finding, file)
    except KeyError:
        raise not_found("漏洞", finding_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.patch("/api/findings/{finding_id}/review")
def review_finding(finding_id: str, request: ReviewRequest) -> dict[str, Any]:
    try:
        database.get_finding(finding_id)
    except KeyError:
        raise not_found("漏洞", finding_id)
    database.update_finding_review(finding_id, request.status)
    return database.get_finding(finding_id)


@app.get("/api/scans/{scan_id}/export.json")
def export_json(scan_id: str) -> JSONResponse:
    try:
        scan = database.get_scan(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)
    return JSONResponse(
        {"scan": scan, "findings": database.list_findings(scan_id)},
        headers={
            "Content-Disposition": f'attachment; filename="onecve-{scan_id[:8]}.json"'
        },
    )


@app.get("/api/scans/{scan_id}/export.csv")
def export_csv(scan_id: str) -> Response:
    try:
        scan = database.get_scan(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)
    findings = database.list_findings(scan_id)
    return Response(
        content=render_findings_csv(scan, findings),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="onecve-{scan_id[:8]}.csv"'
        },
    )


@app.get("/api/scans/{scan_id}/export.sarif")
def export_sarif(scan_id: str) -> JSONResponse:
    try:
        findings = database.list_findings(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)
    results = [
        {
            "ruleId": item["vulnerability_type"],
            "level": "warning",
            "message": {"text": f"{item['kind']} ({item['checker']})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": item["file"]},
                    "region": {"startLine": item["line"], "startColumn": max(1, item["column"])},
                }
            }],
            "fingerprints": {"nspa/v1": item["fingerprint"]},
        }
        for item in findings
    ]
    return JSONResponse({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "OneCVE", "version": app.version}}, "results": results}],
    })


@app.get("/api/scans/{scan_id}/export.html", response_class=HTMLResponse)
def export_html(scan_id: str) -> str:
    try:
        scan = database.get_scan(scan_id)
    except KeyError:
        raise not_found("扫描", scan_id)
    findings = database.list_findings(scan_id)
    rows = "".join(
        "<tr>"
        f"<td>{html.escape(item['vulnerability_type'])}</td>"
        f"<td>{html.escape(item['kind'])}</td>"
        f"<td>{html.escape(item['file'])}:{item['line']}:{item['column']}</td>"
        f"<td>{html.escape(item['verdict'])}</td>"
        "</tr>"
        for item in findings
    )
    return f"""<!doctype html><html lang='zh-CN'><meta charset='utf-8'>
    <title>OneCVE 扫描报告</title><style>body{{font:14px system-ui;margin:40px;color:#17201c}}
    table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccd5cf;padding:10px;text-align:left}}
    th{{background:#edf4ef}}</style><h1>OneCVE 扫描报告</h1>
    <p>项目：{html.escape(scan['project_name'])}　状态：{html.escape(scan['status'])}　结果：{len(findings)}</p>
    <table><thead><tr><th>类型</th><th>检测结果</th><th>位置</th><th>复核</th></tr></thead>
    <tbody>{rows}</tbody></table></html>"""
