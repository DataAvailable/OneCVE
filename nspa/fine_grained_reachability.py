"""Run NSPA's fine-grained reachability stage with SVF/Saber.

This stage consumes LLM-validated custom memory functions, injects them into
SaberCheckerAPI's static external-interface table, optionally rebuilds Saber,
and runs Saber checkers over a directory of LLVM bitcode files.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


MEMORY_CATEGORIES = {"allocator", "releaser", "destroyer"}
DEFAULT_CHECKERS = ("leak", "dfree", "uaf", "fileck", "npd")
OLD_BLOCK_RE = re.compile(
    r"^[ \t]*/\* NSPA_AUTO_[A-Z0-9_]*EI_PAIRS_BEGIN \*/.*?^[ \t]*/\* NSPA_AUTO_[A-Z0-9_]*EI_PAIRS_END \*/[ \t]*\n?",
    re.DOTALL | re.MULTILINE,
)
NSPA_BLOCK_RE = re.compile(
    r"^[ \t]*/\* NSPA_AUTO_[A-Z0-9_]+_CK_(?:ALLOC|FREE)_BEGIN \*/.*?^[ \t]*/\* NSPA_AUTO_[A-Z0-9_]+_CK_(?:ALLOC|FREE)_END \*/[ \t]*\n?",
    re.DOTALL | re.MULTILINE,
)
EI_PAIR_RE = re.compile(
    r'\{\s*"((?:\\.|[^"\\])*)"\s*,\s*SaberCheckerAPI::(CK_[A-Z_]+)\s*\}'
)


@dataclass(slots=True, frozen=True)
class SaberMemoryFunction:
    name: str
    category: str
    checker_type: str
    confidence: float
    file: str
    signature: str


@dataclass(slots=True)
class SaberRunResult:
    bc_file: str
    checker: str
    command: list[str]
    returncode: int
    stdout_file: str | None
    stderr_file: str | None
    elapsed_seconds: float

    def to_dict(self) -> dict[str, object]:
        return {
            "bc_file": self.bc_file,
            "checker": self.checker,
            "command": self.command,
            "returncode": self.returncode,
            "stdout_file": self.stdout_file,
            "stderr_file": self.stderr_file,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }


def load_validated_memory_functions(
    path: Path,
    *,
    min_confidence: float = 0.5,
    skip_macros: bool = True,
    skip_file_prefixes: Sequence[str] = ("docs/examples/", "tests/"),
    skip_names: Sequence[str] = ("main",),
) -> list[SaberMemoryFunction]:
    data = json.loads(path.read_text(encoding="utf-8"))
    skip_name_set = set(skip_names)
    functions: list[SaberMemoryFunction] = []
    seen: set[tuple[str, str]] = set()

    for item in data.get("functions", []):
        name = str(item.get("name", "")).strip()
        category = str(item.get("category", "")).strip()
        confidence = float(item.get("confidence", 0.0) or 0.0)
        cfr = item.get("cfr", {}) if isinstance(item.get("cfr", {}), dict) else {}
        entity_kind = str(cfr.get("entity_kind", ""))
        file_path = str(item.get("file", "") or cfr.get("file", ""))
        signature = str(item.get("signature", "") or cfr.get("signature", ""))

        if not name or name in skip_name_set:
            continue
        if category not in MEMORY_CATEGORIES:
            continue
        if confidence < min_confidence:
            continue
        if skip_macros and entity_kind == "function_like_macro":
            continue
        if any(file_path.startswith(prefix) for prefix in skip_file_prefixes):
            continue

        checker_type = category_to_checker_type(category)
        dedupe_key = (name, checker_type)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        functions.append(
            SaberMemoryFunction(
                name=name,
                category=category,
                checker_type=checker_type,
                confidence=confidence,
                file=file_path,
                signature=signature,
            )
        )

    return sorted(functions, key=lambda fn: (fn.checker_type, fn.name))


def category_to_checker_type(category: str) -> str:
    if category == "allocator":
        return "CK_ALLOC"
    if category in {"releaser", "destroyer"}:
        return "CK_FREE"
    raise ValueError(f"Unsupported memory category for Saber: {category}")


def patch_saber_checker_api(
    cpp_path: Path,
    functions: Sequence[SaberMemoryFunction],
    *,
    project_tag: str,
    create_backup: bool = True,
) -> tuple[int, int]:
    original = cpp_path.read_text(encoding="utf-8", errors="replace")
    cleaned = remove_existing_nspa_blocks(original)
    existing_names = parse_existing_ei_pair_names(cleaned)

    alloc_fns = [
        fn for fn in functions
        if fn.checker_type == "CK_ALLOC" and fn.name not in existing_names
    ]
    free_fns = [
        fn for fn in functions
        if fn.checker_type == "CK_FREE" and fn.name not in existing_names
    ]

    patched = insert_block_before_type(
        cleaned,
        "CK_FREE",
        render_block(project_tag, "CK_ALLOC", alloc_fns),
    )
    patched = insert_block_before_type(
        patched,
        "CK_FOPEN",
        render_block(project_tag, "CK_FREE", free_fns),
    )
    patched = re.sub(
        r"(?m)^\s*\{0,\s*SaberCheckerAPI::CK_DUMMY\}",
        "    {0, SaberCheckerAPI::CK_DUMMY}",
        patched,
    )

    if patched != original:
        if create_backup:
            backup = cpp_path.with_suffix(cpp_path.suffix + ".bak")
            backup.write_text(original, encoding="utf-8")
        cpp_path.write_text(patched, encoding="utf-8")

    return len(alloc_fns), len(free_fns)


def remove_existing_nspa_blocks(text: str) -> str:
    text = OLD_BLOCK_RE.sub("\n", text)
    text = NSPA_BLOCK_RE.sub("\n", text)
    return text


def parse_existing_ei_pair_names(text: str) -> set[str]:
    return {c_unescape(match.group(1)) for match in EI_PAIR_RE.finditer(text)}


def c_unescape(text: str) -> str:
    return bytes(text, "utf-8").decode("unicode_escape")


def c_string(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def render_block(
    project_tag: str,
    checker_type: str,
    functions: Sequence[SaberMemoryFunction],
) -> str:
    tag = sanitize_tag(project_tag)
    lines = [
        f"    /* NSPA_AUTO_{tag}_{checker_type}_BEGIN */",
        f"    /* NSPA: {project_tag} project-specific {checker_type} entries */",
    ]
    for fn in functions:
        lines.append(
            f'    {{"{c_string(fn.name)}", SaberCheckerAPI::{checker_type}}},'
            f"  // {fn.category}, conf={fn.confidence:.3g}, {fn.file}"
        )
    lines.append(f"    /* NSPA_AUTO_{tag}_{checker_type}_END */")
    return "\n".join(lines)


def sanitize_tag(project_tag: str) -> str:
    tag = re.sub(r"[^A-Za-z0-9]+", "_", project_tag.upper()).strip("_")
    return tag or "PROJECT"


def insert_block_before_type(text: str, checker_type: str, block: str) -> str:
    pattern = re.compile(rf"^(\s*\{{\s*\".*?\",\s*SaberCheckerAPI::{checker_type}\}}\s*,.*)$", re.MULTILINE)
    match = pattern.search(text)
    if match is None:
        raise ValueError(f"Cannot find first {checker_type} entry in SaberCheckerAPI.cpp")
    return text[: match.start()] + block + "\n" + text[match.start():]


def run_rebuild_script(
    script: Path,
    *,
    nspa_root: Path,
    svf_build_dir: Path,
    bc_dir: Path,
    validated_json: Path,
) -> None:
    command = [
        "bash",
        str(script),
        str(nspa_root),
        str(svf_build_dir),
        str(bc_dir),
        str(validated_json),
    ]
    subprocess.run(command, check=True)


def find_saber_binary(svf_build_dir: Path, override: Path | None = None) -> Path:
    if override is not None:
        return override
    from_path = shutil.which("saber")
    if from_path:
        return Path(from_path)
    return svf_build_dir / "bin" / "saber"


def find_extapi_bc(svf_build_dir: Path, override: Path | None = None) -> Path:
    if override is not None:
        return override
    env_value = os.environ.get("SVF_EXTAPI")
    if env_value:
        return Path(env_value)
    return svf_build_dir / "lib" / "extapi.bc"


def collect_bc_files(bc_dir: Path, limit: int | None = None) -> list[Path]:
    files = sorted(path for path in bc_dir.rglob("*.bc") if path.is_file())
    return files[:limit] if limit is not None else files


def run_saber_on_bitcode(
    *,
    saber: Path,
    extapi: Path,
    bc_files: Sequence[Path],
    checkers: Sequence[str],
    output_dir: Path,
    timeout: float | None = None,
    continue_on_error: bool = True,
    save_stdout: bool = False,
    progress: bool = True,
    cancel: threading.Event | None = None,
    extra_options: Sequence[str] = (),
) -> list[SaberRunResult]:
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[SaberRunResult] = []
    total_runs = len(bc_files) * len(checkers)
    run_index = 0

    for bc_file in bc_files:
        rel_stem = safe_result_stem(bc_file)
        for checker in checkers:
            run_index += 1
            stdout_path = output_dir / f"{rel_stem}.{checker}.stdout.txt"
            stderr_path = output_dir / f"{rel_stem}.{checker}.stderr.txt"
            command = [
                str(saber),
                f"-{checker}",
                f"-extapi={extapi}",
                *extra_options,
                str(bc_file),
            ]
            if progress:
                print(
                    f"[{run_index}/{total_runs}] saber -{checker} {bc_file}",
                    file=sys.stderr,
                    flush=True,
                )
            start = time.monotonic()
            stdout_tmp = temp_output_path(output_dir, f"{rel_stem}.{checker}.stdout")
            stderr_tmp = temp_output_path(output_dir, f"{rel_stem}.{checker}.stderr")
            with stdout_tmp.open("w", encoding="utf-8", errors="replace") as stdout, stderr_tmp.open(
                "w", encoding="utf-8", errors="replace"
            ) as stderr:
                process_options: dict[str, object] = {}
                if os.name == "nt":
                    process_options["creationflags"] = getattr(
                        subprocess, "CREATE_NEW_PROCESS_GROUP", 0
                    )
                else:
                    process_options["start_new_session"] = True
                process = subprocess.Popen(
                    command,
                    stdout=stdout,
                    stderr=stderr,
                    **process_options,
                )
                deadline = start + timeout if timeout is not None else None
                while process.poll() is None:
                    if cancel is not None and cancel.is_set():
                        _stop_subprocess_tree(process)
                        returncode = 130
                        stderr.write("\nOneCVE scan cancelled\n")
                        break
                    if deadline is not None and time.monotonic() >= deadline:
                        _stop_subprocess_tree(process, force=True)
                        returncode = 124
                        stderr.write(f"\nNSPA timeout after {timeout} seconds\n")
                        break
                    time.sleep(0.1)
                else:
                    returncode = process.returncode
            elapsed = time.monotonic() - start

            stdout_file = finalize_stdout_file(stdout_tmp, stdout_path, save_stdout)
            stderr_file = finalize_stderr_file(stderr_tmp, stderr_path, returncode)
            if progress:
                status = "OK" if returncode == 0 else f"FAIL({returncode})"
                saved = []
                if stdout_file:
                    saved.append(f"stdout={stdout_file}")
                if stderr_file:
                    saved.append(f"stderr={stderr_file}")
                suffix = " | " + ", ".join(saved) if saved else ""
                print(
                    f"[{run_index}/{total_runs}] {status} {checker} {bc_file} ({elapsed:.2f}s){suffix}",
                    file=sys.stderr,
                    flush=True,
                )
            result = SaberRunResult(
                bc_file=str(bc_file),
                checker=checker,
                command=command,
                returncode=returncode,
                stdout_file=str(stdout_file) if stdout_file else None,
                stderr_file=str(stderr_file) if stderr_file else None,
                elapsed_seconds=elapsed,
            )
            results.append(result)
            if returncode != 0 and not continue_on_error:
                raise RuntimeError(f"Saber failed: {' '.join(shlex.quote(part) for part in command)}")

    return results


def _stop_subprocess_tree(process: subprocess.Popen[object], *, force: bool = False) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            command = ["taskkill", "/PID", str(process.pid), "/T"]
            if force:
                command.append("/F")
            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill() if force else process.terminate()
        except OSError:
            return
    try:
        process.wait(timeout=1 if force else 3)
    except subprocess.TimeoutExpired:
        if not force:
            _stop_subprocess_tree(process, force=True)


def temp_output_path(output_dir: Path, label: str) -> Path:
    handle = tempfile.NamedTemporaryFile(
        prefix=f".{label}.",
        suffix=".tmp",
        dir=output_dir,
        delete=False,
    )
    path = Path(handle.name)
    handle.close()
    return path


def finalize_stdout_file(tmp_path: Path, final_path: Path, save_stdout: bool) -> Path | None:
    has_content = tmp_path.exists() and tmp_path.stat().st_size > 0
    if save_stdout and has_content:
        tmp_path.replace(final_path)
        return final_path
    tmp_path.unlink(missing_ok=True)
    return None


def finalize_stderr_file(tmp_path: Path, final_path: Path, returncode: int) -> Path | None:
    has_content = tmp_path.exists() and tmp_path.stat().st_size > 0
    if has_content:
        tmp_path.replace(final_path)
        return final_path
    if returncode != 0:
        final_path.write_text(
            f"NSPA: saber exited with return code {returncode} but produced no stderr output.\n",
            encoding="utf-8",
        )
        tmp_path.unlink(missing_ok=True)
        return final_path
    tmp_path.unlink(missing_ok=True)
    return None


def safe_result_stem(path: Path) -> str:
    text = str(path)
    text = re.sub(r"^[./]+", "", text)
    return re.sub(r"[^A-Za-z0-9_.-]+", "__", text).removesuffix(".bc")


def format_elapsed_seconds(seconds: float) -> str:
    minutes, remainder = divmod(seconds, 60.0)
    hours, minutes = divmod(int(minutes), 60)
    if hours:
        return f"{hours}h {minutes}m {remainder:.3f}s"
    if minutes:
        return f"{minutes}m {remainder:.3f}s"
    return f"{remainder:.3f}s"


def write_saber_manifest(
    results: Sequence[SaberRunResult],
    output_dir: Path,
    *,
    stage_elapsed_seconds: float | None = None,
    saber_elapsed_seconds: float | None = None,
) -> Path:
    manifest = output_dir / "manifest.json"
    metadata = {
        "run_count": len(results),
        "failed_count": sum(1 for result in results if result.returncode != 0),
    }
    if stage_elapsed_seconds is not None:
        metadata["stage_elapsed_seconds"] = round(stage_elapsed_seconds, 3)
        metadata["stage_elapsed"] = format_elapsed_seconds(stage_elapsed_seconds)
    if saber_elapsed_seconds is not None:
        metadata["saber_elapsed_seconds"] = round(saber_elapsed_seconds, 3)
        metadata["saber_elapsed"] = format_elapsed_seconds(saber_elapsed_seconds)
    payload = {
        "metadata": metadata,
        "runs": [result.to_dict() for result in results],
    }
    manifest.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    tsv = output_dir / "manifest.tsv"
    with tsv.open("w", encoding="utf-8") as handle:
        handle.write("returncode\tchecker\tbc_file\tstdout_file\tstderr_file\telapsed_seconds\n")
        for result in results:
            handle.write(
                f"{result.returncode}\t{result.checker}\t{result.bc_file}\t"
                f"{result.stdout_file or '-'}\t{result.stderr_file or '-'}\t{result.elapsed_seconds:.3f}\n"
            )
    return manifest


def parse_checkers(value: str) -> list[str]:
    checkers = [item.strip().lstrip("-") for item in value.split(",") if item.strip()]
    valid = set(DEFAULT_CHECKERS)
    unknown = [checker for checker in checkers if checker not in valid]
    if unknown:
        raise argparse.ArgumentTypeError(f"Unknown Saber checker(s): {', '.join(unknown)}")
    return checkers


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inject NSPA memory APIs into Saber and run fine-grained checks.")
    parser.add_argument("--validated-json", type=Path, default=Path("outputs/nspa_curl_validated_memory_functions.json"))
    parser.add_argument("--project", default="curl")
    parser.add_argument("--saber-api-cpp", type=Path, default=Path("SVF/svf/lib/SABER/SaberCheckerAPI.cpp"))
    parser.add_argument("--nspa-root", type=Path, default=Path.cwd())
    parser.add_argument("--svf-build-dir", type=Path, default=Path("SVF/Release-build"))
    parser.add_argument("--bc-dir", type=Path, default=Path("workspace/curl-bc"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/saber/curl"))
    parser.add_argument("--rebuild-script", type=Path, default=Path("compile_script/rebuild_and_check_saber.sh"))
    parser.add_argument("--min-confidence", type=float, default=0.5)
    parser.add_argument("--keep-macros", action="store_true", help="Also inject function-like macro names")
    parser.add_argument("--no-backup", action="store_true")
    parser.add_argument("--skip-rebuild", action="store_true")
    parser.add_argument("--skip-saber", action="store_true")
    parser.add_argument("--saber", type=Path)
    parser.add_argument("--extapi", type=Path)
    parser.add_argument("--checkers", type=parse_checkers, default=list(DEFAULT_CHECKERS))
    parser.add_argument("--bc-limit", type=int, help="Run Saber on only the first N .bc files")
    parser.add_argument("--timeout", type=float, help="Per-Saber-run timeout in seconds")
    parser.add_argument(
        "--save-stdout",
        action="store_true",
        help="Save non-empty Saber stdout files. By default stdout is discarded.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Do not print per-Saber-run progress.",
    )
    parser.add_argument("--stop-on-error", action="store_true")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)

    if not 0.0 <= args.min_confidence <= 1.0:
        parser.error("--min-confidence must be between 0 and 1")
    if args.bc_limit is not None and args.bc_limit < 1:
        parser.error("--bc-limit must be >= 1")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    stage_start = time.perf_counter()
    functions = load_validated_memory_functions(
        args.validated_json,
        min_confidence=args.min_confidence,
        skip_macros=not args.keep_macros,
    )
    alloc_count, free_count = patch_saber_checker_api(
        args.saber_api_cpp,
        functions,
        project_tag=args.project,
        create_backup=not args.no_backup,
    )

    if not args.skip_rebuild:
        run_rebuild_script(
            args.rebuild_script,
            nspa_root=args.nspa_root.resolve(),
            svf_build_dir=args.svf_build_dir.resolve(),
            bc_dir=args.bc_dir.resolve(),
            validated_json=args.validated_json.resolve(),
        )

    results: list[SaberRunResult] = []
    saber_elapsed_seconds = 0.0
    if not args.skip_saber:
        saber = find_saber_binary(args.svf_build_dir, args.saber)
        extapi = find_extapi_bc(args.svf_build_dir, args.extapi)
        bc_files = collect_bc_files(args.bc_dir, args.bc_limit)
        saber_start = time.perf_counter()
        results = run_saber_on_bitcode(
            saber=saber,
            extapi=extapi,
            bc_files=bc_files,
            checkers=args.checkers,
            output_dir=args.output_dir,
            timeout=args.timeout,
            continue_on_error=not args.stop_on_error,
            save_stdout=args.save_stdout,
            progress=not args.quiet,
        )
        saber_elapsed_seconds = time.perf_counter() - saber_start

    stage_elapsed_seconds = time.perf_counter() - stage_start
    if not args.skip_saber:
        write_saber_manifest(
            results,
            args.output_dir,
            stage_elapsed_seconds=stage_elapsed_seconds,
            saber_elapsed_seconds=saber_elapsed_seconds,
        )

    print(
        "[+] 第二阶段：细粒度可达性分析运行时间: "
        f"{format_elapsed_seconds(stage_elapsed_seconds)} ({stage_elapsed_seconds:.3f}s)",
        file=sys.stderr,
        flush=True,
    )
    if not args.skip_saber:
        print(
            "[+] 步骤4：运行 Saber 检测 bitcode 时间: "
            f"{format_elapsed_seconds(saber_elapsed_seconds)} ({saber_elapsed_seconds:.3f}s)",
            file=sys.stderr,
            flush=True,
        )

    if args.summary:
        print(
            json.dumps(
                {
                    "validated_json": str(args.validated_json),
                    "saber_api_cpp": str(args.saber_api_cpp),
                    "loaded_memory_functions": len(functions),
                    "injected_allocators": alloc_count,
                    "injected_releasers": free_count,
                    "saber_run_count": len(results),
                    "saber_failed_count": sum(1 for result in results if result.returncode != 0),
                    "output_dir": str(args.output_dir),
                    "stage_elapsed_seconds": round(stage_elapsed_seconds, 3),
                    "stage_elapsed": format_elapsed_seconds(stage_elapsed_seconds),
                    "saber_elapsed_seconds": round(saber_elapsed_seconds, 3),
                    "saber_elapsed": format_elapsed_seconds(saber_elapsed_seconds),
                },
                ensure_ascii=False,
            )
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
