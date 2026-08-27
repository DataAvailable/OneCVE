from __future__ import annotations

import hashlib
import os
import threading
import time
import traceback
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Sequence

from nspa.fine_grained_reachability import (
    collect_bc_files,
    find_extapi_bc,
    find_saber_binary,
    run_saber_on_bitcode,
    write_saber_manifest,
)
from nspa.vulnerability_verifier_multi import (
    SaberWarning,
    SourceLocation,
    VerifierConfig,
    build_program_slice,
    build_source_index,
    is_api_error_verdict,
    load_saber_warnings,
    verify_slices,
    write_output,
)

from .building import BuildManager, BuildResult
from .config import WebConfig
from .database import Database, utc_now
from .hardware import recommended_llm_parallelism, recommended_saber_parallelism
from .llm_runtime import resolve_llm_runtime
from .memory_functions import render_saber_api_config
from .projects import IGNORED_PARTS
from .storage import remove_managed_child, remove_managed_descendant


TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
COMPILE_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}


class ScanManager:
    def __init__(self, database: Database, config: WebConfig) -> None:
        self.database = database
        self.config = config
        self.executor = ThreadPoolExecutor(max_workers=config.max_workers, thread_name_prefix="nspa-scan")
        self._futures: dict[str, Future[None]] = {}
        self._cancel: dict[str, threading.Event] = {}
        self._llm_review_progress: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def get_llm_review_progress(self, scan_id: str) -> dict[str, Any]:
        self.database.get_scan(scan_id)
        with self._lock:
            progress = dict(self._llm_review_progress.get(scan_id, {}))
        if not progress:
            return {
                "scan_id": scan_id,
                "active": False,
                "total": 0,
                "completed": 0,
                "percent": 0.0,
                "current_index": 0,
                "current_finding_id": "",
                "current_sample": "",
                "elapsed_seconds": 0.0,
                "estimated_remaining_seconds": None,
                "error": None,
            }
        started = float(progress.pop("_started_monotonic", time.monotonic()))
        elapsed = max(0.0, time.monotonic() - started)
        completed = int(progress.get("completed", 0))
        total = int(progress.get("total", 0))
        remaining = None
        if completed > 0 and total > completed:
            remaining = elapsed / completed * (total - completed)
        elif total > 0 and completed >= total:
            remaining = 0.0
        progress["elapsed_seconds"] = round(elapsed, 1)
        progress["estimated_remaining_seconds"] = (
            round(remaining, 1) if remaining is not None else None
        )
        return progress

    def _begin_llm_review_progress(
        self, scan_id: str, findings: Sequence[dict[str, Any]]
    ) -> None:
        with self._lock:
            current = self._llm_review_progress.get(scan_id)
            if current and current.get("active"):
                raise ValueError("该扫描已有 LLM 复核任务正在运行")
            first = findings[0] if findings else None
            self._llm_review_progress[scan_id] = {
                "scan_id": scan_id,
                "active": True,
                "total": len(findings),
                "completed": 0,
                "percent": 0.0,
                "current_index": 1 if first else 0,
                "current_finding_id": first["id"] if first else "",
                "current_sample": (
                    f'{first["file"]}:{first["line"]}:{first["column"]}'
                    if first
                    else ""
                ),
                "error": None,
                "_started_monotonic": time.monotonic(),
            }

    def _update_llm_review_progress(
        self, scan_id: str, completed: int, total: int, verdict: Any
    ) -> None:
        with self._lock:
            progress = self._llm_review_progress.get(scan_id)
            if not progress:
                return
            finding = self.database.get_finding(verdict.id)
            progress.update(
                completed=completed,
                total=total,
                percent=round(100 * completed / max(total, 1), 1),
                current_index=completed,
                current_finding_id=verdict.id,
                current_sample=(
                    f'{finding["file"]}:{finding["line"]}:{finding["column"]}'
                ),
            )

    def _finish_llm_review_progress(
        self, scan_id: str, *, error: str | None = None
    ) -> None:
        with self._lock:
            progress = self._llm_review_progress.get(scan_id)
            if not progress:
                return
            progress["active"] = False
            progress["error"] = error
            if error is None:
                progress["completed"] = progress["total"]
                progress["percent"] = 100.0
                progress["current_index"] = progress["total"]

    def recover_interrupted_scans(self) -> None:
        for scan in self.database.list_scans(limit=1000):
            if scan["status"] in {"queued", "running", "cancelling", "awaiting_approval"}:
                self.database.update_scan(
                    scan["id"],
                    status="failed",
                    stage="interrupted",
                    error="本地服务在任务执行期间退出，请重新运行扫描",
                    finished_at=utc_now(),
                )

    def create_scan(
        self,
        project_id: str,
        checkers: Sequence[str],
        *,
        verify_enabled: bool,
        parallelism: int | None = None,
        llm_parallelism: int | None = None,
    ) -> dict[str, Any]:
        self.database.get_project(project_id)
        memory_functions = self.database.list_memory_functions(project_id)
        valid = {"leak", "dfree", "uaf", "fileck", "npd"}
        normalized = list(dict.fromkeys(checker for checker in checkers if checker in valid))
        if not normalized:
            raise ValueError("至少选择一个检测器")
        settings = self.database.get_settings()
        configured_parallelism = int(
            parallelism
            if parallelism is not None
            else settings.get("scan_parallelism", recommended_saber_parallelism())
        )
        if not 1 <= configured_parallelism <= 16:
            raise ValueError("并行检测进程数必须在 1 到 16 之间")
        configured_llm_parallelism = int(
            llm_parallelism
            if llm_parallelism is not None
            else settings.get("llm_parallelism", recommended_llm_parallelism())
        )
        if not 1 <= configured_llm_parallelism <= 16:
            raise ValueError("LLM 复核线程数必须在 1 到 16 之间")
        scan = self.database.create_scan(
            {
                "id": uuid.uuid4().hex,
                "project_id": project_id,
                "checkers": normalized,
                "verify_enabled": verify_enabled,
                "scan_parallelism": configured_parallelism,
                "llm_parallelism": configured_llm_parallelism,
                "custom_alloc": memory_functions["alloc_functions"],
                "custom_free": memory_functions["free_functions"],
            }
        )
        self._submit(scan["id"])
        return scan

    def delete_findings(
        self, scan_id: str, finding_ids: Sequence[str]
    ) -> dict[str, Any]:
        scan = self.database.get_scan(scan_id)
        if self._is_active(scan):
            raise ValueError("运行中的扫描会继续写入结果，请先终止任务再删除")
        deleted_count = self.database.delete_findings(scan_id, finding_ids)
        self.database.add_event(
            scan_id,
            "cleanup",
            f"已删除 {deleted_count} 条选定漏洞结果",
        )
        return {"scan_id": scan_id, "deleted_count": deleted_count}

    def review_findings(
        self, scan_id: str, finding_ids: Sequence[str]
    ) -> dict[str, Any]:
        scan = self.database.get_scan(scan_id)
        if self._is_active(scan):
            raise ValueError("请等待扫描完成或先终止任务，再复核选定结果")
        identifiers = list(dict.fromkeys(finding_ids))
        if not identifiers:
            raise ValueError("请至少选择一条漏洞结果")
        available = {
            finding["id"]: finding
            for finding in self.database.list_findings(scan_id)
        }
        missing = [identifier for identifier in identifiers if identifier not in available]
        if missing:
            raise KeyError(missing[0])
        settings = self.database.get_settings()
        llm = resolve_llm_runtime(settings)
        if not llm.configured:
            raise ValueError("LLM 尚未配置，请先在本地设置中完成配置并测试连接")

        source = Path(scan["source_path"])
        source_index = build_source_index(source)
        slices = []
        for identifier in identifiers:
            finding = available[identifier]
            path = [
                SourceLocation(
                    file=str(location.get("file", "")),
                    line=int(location.get("line", 0) or 0),
                    column=int(location.get("column", 0) or 0),
                    branch=location.get("branch"),
                )
                for location in finding.get("path", [])
                if location.get("file") and location.get("line")
            ]
            warning = SaberWarning(
                id=identifier,
                checker=finding["checker"],
                kind=finding["kind"],
                site_label={
                    "memory_leak": "memory allocation",
                    "double_free": "memory release",
                    "use_after_free": "memory access",
                    "file_leak": "file open",
                    "null_deref": "dereference",
                }.get(finding["vulnerability_type"], "reported site"),
                report_file="web-selected-review",
                bc_file="",
                primary=SourceLocation(
                    file=finding["file"],
                    line=int(finding["line"]),
                    column=int(finding["column"]),
                ),
                path=path,
                raw_text=finding.get("raw_text", ""),
            )
            slices.append(
                build_program_slice(
                    warning, source_root=source, source_index=source_index
                )
            )

        workers = max(
            1,
            min(
                int(
                    settings.get("llm_parallelism")
                    or scan.get("llm_parallelism")
                    or recommended_llm_parallelism()
                ),
                len(slices),
                16,
            ),
        )
        client_config = VerifierConfig(
            dry_run=False,
            api_key=llm.api_key,
            base_url=llm.base_url,
            model=llm.model,
            temperature=0.0,
            timeout=llm.timeout,
            max_retries=3,
            json_mode=True,
            chat_path=llm.chat_path,
        )
        self.database.add_event(
            scan_id,
            "verifying",
            f"开始复核 {len(slices)} 条选定结果；并发线程 {workers}",
        )
        selected_findings = [available[identifier] for identifier in identifiers]
        self._begin_llm_review_progress(scan_id, selected_findings)
        try:
            verified = verify_slices(
                slices,
                client_config=client_config,
                checkpoint=None,
                progress=False,
                api_error_policy="unknown",
                workers=workers,
                parallel_backend="thread",
                progress_callback=lambda completed, total, verdict: (
                    self._update_llm_review_progress(
                        scan_id, completed, total, verdict
                    )
                ),
            )
        except Exception as exc:
            self._finish_llm_review_progress(scan_id, error=str(exc))
            raise
        try:
            for verdict in verified:
                self.database.update_finding_verdict(
                    verdict.id,
                    verdict=verdict.verdict,
                    confidence=verdict.confidence,
                    rationale=verdict.rationale,
                    fix_suggestion=verdict.fix_suggestion,
                    evidence=verdict.evidence_lines,
                )
            output = (
                self.config.scans_root
                / scan_id
                / "selected_verified_vulnerabilities.json"
            )
            write_output(verified, output, model=llm.model, dry_run=False)
            passed = sum(item.verdict == "true_positive" for item in verified)
            rejected = sum(item.verdict == "false_positive" for item in verified)
            unknown = sum(item.verdict == "unknown" for item in verified)
            api_errors = sum(is_api_error_verdict(item) for item in verified)
            self.database.add_event(
                scan_id,
                "verifying",
                f"选定结果复核完成：已通过 {passed}，未通过 {rejected + unknown}，"
                f"其中 API 错误 {api_errors}",
                "warning" if api_errors else "info",
            )
        except Exception as exc:
            self._finish_llm_review_progress(scan_id, error=str(exc))
            raise
        self._finish_llm_review_progress(scan_id)
        return {
            "scan_id": scan_id,
            "reviewed_count": len(verified),
            "passed": passed,
            "rejected": rejected,
            "unknown": unknown,
            "api_errors": api_errors,
        }

    def clear_findings(self, scan_id: str) -> dict[str, Any]:
        scan = self.database.get_scan(scan_id)
        if self._is_active(scan):
            raise ValueError("运行中的扫描会继续写入结果，请先终止任务再清空")
        cleared_count = self.database.clear_findings(scan_id)
        removed_bytes = 0
        for name in (
            "reports",
            "verification.jsonl",
            "verified_vulnerabilities.json",
            "verified_vulnerabilities_TP.json",
            "selected_verified_vulnerabilities.json",
            "selected_verified_vulnerabilities_TP.json",
        ):
            removed_bytes += remove_managed_descendant(
                self.config.scans_root, scan_id, name
            )
        self.database.add_event(
            scan_id,
            "cleanup",
            f"已清空 {cleared_count} 条漏洞结果及对应报告",
        )
        return {
            "scan_id": scan_id,
            "cleared_count": cleared_count,
            "freed_bytes": removed_bytes,
        }

    def cancel(self, scan_id: str) -> dict[str, Any]:
        scan = self.database.get_scan(scan_id)
        with self._lock:
            token = self._cancel.get(scan_id)
            future = self._futures.get(scan_id)
        if token is not None:
            token.set()
            if future is not None and future.cancel():
                with self._lock:
                    self._cancel.pop(scan_id, None)
                    self._futures.pop(scan_id, None)
                self.database.update_scan(
                    scan_id, status="cancelled", stage="cancelled", finished_at=utc_now()
                )
                self.database.add_event(scan_id, "cancelled", "等待中的任务已取消", "warning")
            else:
                self.database.update_scan(scan_id, status="cancelling", stage="cancelling")
                self.database.add_event(scan_id, "cancelling", "正在停止任务", "warning")
        elif scan["status"] not in TERMINAL_STATUSES:
            self.database.update_scan(
                scan_id, status="cancelled", stage="cancelled", finished_at=utc_now()
            )
        return self.database.get_scan(scan_id)

    def cancel_many(self, scan_ids: Sequence[str]) -> list[dict[str, Any]]:
        identifiers = list(dict.fromkeys(scan_ids))
        if not identifiers:
            raise ValueError("至少选择一个扫描任务")
        for scan_id in identifiers:
            self.database.get_scan(scan_id)
        return [self.cancel(scan_id) for scan_id in identifiers]

    def delete(self, scan_id: str) -> dict[str, Any]:
        return self.delete_many([scan_id])

    def delete_many(self, scan_ids: Sequence[str]) -> dict[str, Any]:
        identifiers = list(dict.fromkeys(scan_ids))
        if not identifiers:
            raise ValueError("至少选择一个扫描任务")
        records = [self.database.get_scan(scan_id) for scan_id in identifiers]
        active = [scan["id"] for scan in records if self._is_active(scan)]
        if active:
            raise ValueError(f"请先终止运行中的扫描任务：{', '.join(active[:5])}")

        removed_bytes = 0
        for scan_id in identifiers:
            removed_bytes += remove_managed_child(self.config.scans_root, scan_id)
        self.database.delete_scans(identifiers)
        return {
            "deleted_scan_ids": identifiers,
            "deleted_count": len(identifiers),
            "freed_bytes": removed_bytes,
        }

    def delete_project(self, project_id: str) -> dict[str, Any]:
        project = self.database.get_project(project_id)
        project_scans = self.database.list_scan_records(project_id=project_id)
        active = [scan["id"] for scan in project_scans if self._is_active(scan)]
        if active:
            raise ValueError(f"项目仍有运行中的任务，请先终止：{', '.join(active[:5])}")

        removed_bytes = 0
        for scan in project_scans:
            removed_bytes += remove_managed_child(self.config.scans_root, scan["id"])
        removed_bytes += remove_managed_child(self.config.projects_root, project_id)
        self.database.delete_project(project_id)
        return {
            "project_id": project_id,
            "project_name": project["name"],
            "deleted_scans": len(project_scans),
            "freed_bytes": removed_bytes,
            "external_source_preserved": project["source_kind"] == "local",
        }

    def has_active_project_scan(self, project_id: str) -> bool:
        return any(
            self._is_active(scan)
            for scan in self.database.list_scan_records(project_id=project_id)
        )

    def _is_active(self, scan: dict[str, Any]) -> bool:
        with self._lock:
            future = self._futures.get(scan["id"])
        return scan["status"] in {"queued", "running", "cancelling"} or (
            future is not None and not future.done()
        )

    def shutdown(self) -> None:
        with self._lock:
            for token in self._cancel.values():
                token.set()
        self.executor.shutdown(wait=False, cancel_futures=True)

    def _submit(self, scan_id: str) -> None:
        cancel = threading.Event()
        with self._lock:
            active = self._futures.get(scan_id)
            if active is not None and not active.done():
                raise ValueError("任务已在运行")
            self._cancel[scan_id] = cancel
            self._futures[scan_id] = self.executor.submit(
                self._run_scan, scan_id, cancel
            )

    def _run_scan(self, scan_id: str, cancel: threading.Event) -> None:
        try:
            scan = self.database.get_scan(scan_id)
            source = Path(scan["source_path"]).resolve()
            work_root = self.config.scans_root / scan_id
            report_dir = work_root / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            settings = self.database.get_settings()
            self._status(scan_id, "running", "preparing", 3, "准备项目与扫描目录")
            if not source.is_dir():
                raise RuntimeError(f"源码目录不存在：{source}")
            build_activity = {"events": 0}

            def build_log(level: str, message: str) -> None:
                self._event(scan_id, "building", message, level)
                if level in {"command", "info", "output"}:
                    build_activity["events"] += 1
                    if build_activity["events"] == 1 or build_activity["events"] % 8 == 0:
                        self._advance_progress(scan_id, 0.5, cap=18)

            builder = BuildManager(
                settings,
                build_log,
                lambda phase, completed, total: self._build_progress(
                    scan_id, phase, completed, total
                ),
            )
            self._status(scan_id, "running", "building", 6, "开始生成 LLVM Bitcode")
            build = builder.build(source, work_root, cancel)
            if cancel.is_set():
                self._cancelled(scan_id)
                return
            if not build.success:
                raise RuntimeError("\n".join(build.errors) or "Bitcode 构建失败")
            self.database.update_scan(
                scan_id,
                build_strategy=build.strategy,
                bitcode_count=len(build.bitcode_files),
                source_unit_count=count_compile_source_units(source),
            )
            self._status(
                scan_id, "running", "analyzing", 50,
                f"已生成 {len(build.bitcode_files)} 个 Bitcode，开始运行 Saber",
            )
            results = self._run_saber(scan, build, report_dir, settings, cancel)
            write_saber_manifest(results, report_dir)
            if cancel.is_set():
                self._cancelled(scan_id)
                return
            self._status(scan_id, "running", "parsing", 90, "解析并去重检测结果")
            warnings = load_saber_warnings(report_dir)
            findings = self._build_findings(source, warnings, scan["verify_enabled"], settings, scan_id)
            self._set_progress(scan_id, 99)
            self.database.replace_findings(scan_id, findings)
            self.database.update_scan(
                scan_id,
                status="completed",
                stage="completed",
                progress=100,
                finding_count=len(findings),
                finished_at=utc_now(),
                error=None,
            )
            self._event(scan_id, "completed", f"扫描完成，共发现 {len(findings)} 条结果")
        except Exception as exc:
            if cancel.is_set():
                self._cancelled(scan_id)
            else:
                self.database.update_scan(
                    scan_id,
                    status="failed",
                    stage="failed",
                    error=str(exc),
                    finished_at=utc_now(),
                )
                self._event(scan_id, "failed", str(exc), "error")
                debug_path = self.config.scans_root / scan_id / "traceback.txt"
                debug_path.parent.mkdir(parents=True, exist_ok=True)
                debug_path.write_text(traceback.format_exc(), encoding="utf-8")
        finally:
            with self._lock:
                self._cancel.pop(scan_id, None)
                self._futures.pop(scan_id, None)

    def _run_saber(
        self,
        scan: dict[str, Any],
        build: BuildResult,
        report_dir: Path,
        settings: dict[str, str],
        cancel: threading.Event,
    ) -> list[Any]:
        svf_build = Path(
            settings.get("svf_build_dir")
            or os.environ.get("NSPA_SVF_BUILD_DIR", self.config.repository_root / "SVF" / "Release-build")
        )
        saber_override = settings.get("saber_path") or os.environ.get("NSPA_SABER")
        extapi_override = settings.get("extapi_path") or os.environ.get("SVF_EXTAPI")
        saber = find_saber_binary(svf_build, Path(saber_override) if saber_override else None)
        extapi = find_extapi_bc(svf_build, Path(extapi_override) if extapi_override else None)
        if not saber.is_file():
            raise RuntimeError(f"未找到 Saber：{saber}，请在本地设置中配置路径")
        if not extapi.is_file():
            raise RuntimeError(f"未找到 extapi.bc：{extapi}，请在本地设置中配置路径")
        extra_options: list[str] = []
        if scan.get("custom_alloc") or scan.get("custom_free"):
            api_config = report_dir.parent / "custom-memory-api.conf"
            api_config.write_text(
                render_saber_api_config(scan.get("custom_alloc", []), scan.get("custom_free", [])),
                encoding="utf-8",
            )
            extra_options.append(f"-api-config={api_config}")
            self._event(
                scan["id"],
                "analyzing",
                f"已加载 {len(scan.get('custom_alloc', []))} 个分配函数和 "
                f"{len(scan.get('custom_free', []))} 个释放函数",
            )
        total = len(build.bitcode_files) * len(scan["checkers"])
        if total == 0:
            return []
        jobs = [
            (index, bitcode, checker)
            for index, (bitcode, checker) in enumerate(
                (
                    (bitcode, checker)
                    for bitcode in build.bitcode_files
                    for checker in scan["checkers"]
                ),
                start=1,
            )
        ]
        parallelism = max(1, min(int(scan.get("scan_parallelism") or 1), total))
        self._event(
            scan["id"],
            "analyzing",
            f"使用 {parallelism} 路并行 Saber 子进程执行 {total} 个检测单元",
        )

        def run_job(index: int, bitcode: Path, checker: str) -> tuple[int, list[Any]]:
            if cancel.is_set():
                return index, []
            self._event(
                scan["id"], "analyzing", f"[{index}/{total}] saber -{checker} {bitcode.name}"
            )
            return index, list(
                run_saber_on_bitcode(
                    saber=saber,
                    extapi=extapi,
                    bc_files=[bitcode],
                    checkers=[checker],
                    output_dir=report_dir,
                    timeout=float(settings.get("saber_timeout", "300")),
                    continue_on_error=True,
                    save_stdout=False,
                    progress=False,
                    cancel=cancel,
                    extra_options=extra_options,
                )
            )

        ordered_results: dict[int, list[Any]] = {}
        completed = 0
        with ThreadPoolExecutor(
            max_workers=parallelism, thread_name_prefix=f"saber-{scan['id'][:8]}"
        ) as executor:
            futures = {
                executor.submit(run_job, index, bitcode, checker): index
                for index, bitcode, checker in jobs
            }
            for future in as_completed(futures):
                index, job_results = future.result()
                ordered_results[index] = job_results
                completed += 1
                self._set_progress(
                    scan["id"], 50 + round(38 * completed / max(total, 1), 1)
                )
                if cancel.is_set():
                    for pending in futures:
                        pending.cancel()

        return [
            result
            for index in sorted(ordered_results)
            for result in ordered_results[index]
        ]

    def _build_findings(
        self,
        source: Path,
        warnings: Sequence[Any],
        verify_enabled: bool,
        settings: dict[str, str],
        scan_id: str,
    ) -> list[dict[str, Any]]:
        source_index = build_source_index(source)
        slices = []
        total_warnings = len(warnings)
        for index, warning in enumerate(warnings, start=1):
            slices.append(
                build_program_slice(warning, source_root=source, source_index=source_index)
            )
            self._set_progress(
                scan_id,
                90 + round(4 * index / max(total_warnings, 1), 1),
            )
        if not slices:
            self._set_progress(scan_id, 94)
        verdicts: dict[str, Any] = {}
        if verify_enabled and slices:
            self._status(scan_id, "running", "verifying", 94, "使用 LLM 复核 Saber 检测结果")
            llm = resolve_llm_runtime(settings)
            if llm.configured:
                llm_workers = max(
                    1,
                    min(
                        int(
                            self.database.get_scan(scan_id).get("llm_parallelism")
                            or recommended_llm_parallelism()
                        ),
                        16,
                    ),
                )
                client_config = VerifierConfig(
                    dry_run=False,
                    api_key=llm.api_key,
                    base_url=llm.base_url,
                    model=llm.model,
                    temperature=0.0,
                    timeout=llm.timeout,
                    max_retries=3,
                    json_mode=True,
                    chat_path=llm.chat_path,
                )
                auth_label = "API Key" if llm.authenticated else "无 Key"
                self._event(
                    scan_id,
                    "verifying",
                    f"使用 {auth_label} LLM API：{llm.base_url}{llm.chat_path}；"
                    f"并发线程 {llm_workers}",
                    "info",
                )
                checkpoint = (
                    self.config.scans_root
                    / scan_id
                    / "verified_vulnerabilities.json.checkpoint.jsonl"
                )

                def report_verification_progress(
                    completed: int, total: int, verdict: Any
                ) -> None:
                    self._set_progress(
                        scan_id, 94 + round(5 * completed / max(total, 1), 1)
                    )
                    label = {
                        "true_positive": "已通过",
                        "false_positive": "未通过",
                        "unknown": "未通过",
                    }.get(verdict.verdict, "未通过")
                    self._event(
                        scan_id,
                        "verifying",
                        f"[{completed}/{total}] LLM 复核{label}：{verdict.id}",
                        "warning" if is_api_error_verdict(verdict) else "info",
                    )

                verified = verify_slices(
                    slices,
                    client_config=client_config,
                    checkpoint=checkpoint,
                    progress=True,
                    api_error_policy="unknown",
                    workers=llm_workers,
                    parallel_backend="thread",
                    progress_callback=report_verification_progress,
                )
                verification_output = (
                    self.config.scans_root / scan_id / "verified_vulnerabilities.json"
                )
                tp_output = write_output(
                    verified,
                    verification_output,
                    model=llm.model,
                    dry_run=False,
                )
                passed = sum(item.verdict == "true_positive" for item in verified)
                rejected = sum(item.verdict == "false_positive" for item in verified)
                unknown = sum(item.verdict == "unknown" for item in verified)
                api_errors = sum(is_api_error_verdict(item) for item in verified)
                self._event(
                    scan_id,
                    "verifying",
                    f"LLM 复核完成：已通过 {passed}，未通过 {rejected + unknown}；"
                    f"其中 API 错误 {api_errors}；"
                    f"完整结果 {verification_output.name}，通过结果 {tp_output.name}",
                    "warning" if api_errors else "info",
                )
                verdicts = {item.id: item for item in verified}
            else:
                self._event(
                    scan_id,
                    "verifying",
                    f"LLM 未配置，跳过复核；默认远程接口需要设置 {llm.api_key_env}",
                    "warning",
                )
        deduplicated: dict[str, dict[str, Any]] = {}
        for program_slice in slices:
            warning = program_slice.warning
            fingerprint = hashlib.sha256(
                f"{warning.vulnerability_type}|{warning.primary.file}|{warning.primary.line}|{warning.kind}".encode()
            ).hexdigest()[:24]
            verdict = verdicts.get(warning.id)
            item = {
                "id": uuid.uuid5(uuid.NAMESPACE_URL, f"{scan_id}:{fingerprint}").hex,
                "fingerprint": fingerprint,
                "checker": warning.checker,
                "kind": warning.kind,
                "vulnerability_type": warning.vulnerability_type,
                "file": warning.primary.file,
                "line": warning.primary.line,
                "column": warning.primary.column,
                "path": [location.to_dict() for location in warning.path],
                "snippets": [snippet.to_dict() for snippet in program_slice.snippets],
                "raw_text": warning.raw_text,
            }
            if verdict:
                item.update(
                    verdict=verdict.verdict,
                    confidence=verdict.confidence,
                    rationale=verdict.rationale,
                    fix_suggestion=verdict.fix_suggestion,
                    evidence=verdict.evidence_lines,
                )
            deduplicated.setdefault(fingerprint, item)
        return list(deduplicated.values())

    def _status(self, scan_id: str, status: str, stage: str, progress: float, message: str) -> None:
        current = float(self.database.get_scan(scan_id).get("progress") or 0)
        self.database.update_scan(
            scan_id,
            status=status,
            stage=stage,
            progress=max(current, max(0, min(100, progress))),
            started_at=utc_now() if stage == "preparing" else self.database.get_scan(scan_id).get("started_at"),
        )
        self._event(scan_id, stage, message)

    def _build_progress(self, scan_id: str, phase: str, completed: int, total: int) -> None:
        if total <= 0:
            return
        fraction = max(0.0, min(1.0, completed / total))
        if phase == "native-build":
            target = 8 + 14 * fraction
        else:
            target = 8 + 40 * fraction
        self._set_progress(scan_id, round(target, 1))

    def _set_progress(self, scan_id: str, progress: float) -> None:
        current = float(self.database.get_scan(scan_id).get("progress") or 0)
        target = max(current, max(0.0, min(100.0, progress)))
        if target > current:
            self.database.update_scan(scan_id, progress=round(target, 1))

    def _advance_progress(self, scan_id: str, amount: float, *, cap: float) -> None:
        current = float(self.database.get_scan(scan_id).get("progress") or 0)
        self._set_progress(scan_id, min(cap, current + amount))

    def _event(self, scan_id: str, stage: str, message: str, level: str = "info") -> None:
        if message.strip():
            self.database.add_event(scan_id, stage, message, level)

    def _cancelled(self, scan_id: str) -> None:
        self.database.update_scan(
            scan_id, status="cancelled", stage="cancelled", finished_at=utc_now()
        )
        self._event(scan_id, "cancelled", "任务已取消", "warning")


def count_compile_source_units(source: Path) -> int:
    count = 0
    for path in source.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in COMPILE_SOURCE_SUFFIXES:
            continue
        try:
            relative = path.relative_to(source)
        except ValueError:
            continue
        if not any(part in IGNORED_PARTS for part in relative.parts):
            count += 1
    return count
