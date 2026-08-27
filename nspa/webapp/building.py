from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import signal
import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

from .projects import discover_build, discover_native_builds, find_compile_database


LogCallback = Callable[[str, str], None]
ProgressCallback = Callable[[str, int, int], None]


@dataclass(slots=True)
class BuildResult:
    success: bool
    strategy: str
    bitcode_files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class BuildError(RuntimeError):
    pass


class SkippedCompileCommand(RuntimeError):
    """A compile database record that is not a replayable driver invocation."""


class BuildManager:
    def __init__(
        self,
        settings: dict[str, str],
        log: LogCallback,
        progress: ProgressCallback | None = None,
    ) -> None:
        self.settings = settings
        self.log = log
        self.progress = progress
        self.clang = settings.get("clang") or os.environ.get("NSPA_CLANG") or "clang"
        self.clangxx = settings.get("clangxx") or os.environ.get("NSPA_CLANGXX") or "clang++"
        self.timeout = int(settings.get("build_timeout", "1800"))
        self.min_bitcode_coverage = min(
            1.0, max(0.0, float(settings.get("min_bitcode_coverage", "0.5")))
        )
        self.configure_retries = max(
            0, min(12, int(settings.get("configure_retries", "8")))
        )
        self.source_fallback_max_units = max(
            1, int(settings.get("source_fallback_max_units", "5000"))
        )
        self._autotools_recovery_cache: dict[Path, tuple[list[str], str, str]] = {}
        self._unsupported_clang_options: set[str] = set()

    def build(
        self,
        source: Path,
        work_root: Path,
        cancel: threading.Event,
    ) -> BuildResult:
        build_dir = work_root / "build"
        bc_dir = work_root / "bitcode"
        build_dir.mkdir(parents=True, exist_ok=True)
        bc_dir.mkdir(parents=True, exist_ok=True)
        native_builds = discover_native_builds(source)
        build_system, build_root = (
            native_builds[0]
            if native_builds
            else discover_build(source, include_compile_commands=False)
        )
        if native_builds:
            summary = "；".join(f"{system}@{root}" for system, root in native_builds)
            self.log("info", f"识别到 {len(native_builds)} 个候选构建入口：{summary}")
        else:
            self.log("info", f"识别构建系统：{build_system}（构建根目录：{build_root}）")

        direct_bc = sorted(source.rglob("*.bc")) if build_system == "bitcode" else []
        if direct_bc:
            self.log("info", f"项目已包含 {len(direct_bc)} 个 Bitcode 文件，跳过源码编译")
            return BuildResult(True, "existing-bitcode", direct_bc)

        errors: list[str] = []
        existing_compile_db = find_compile_database(source)
        if existing_compile_db is not None:
            try:
                self._prepare_existing_compile_database(
                    existing_compile_db, source, cancel
                )
                self.log("info", f"优先重放已有编译数据库：{existing_compile_db}")
                files = self._replay_compile_database(existing_compile_db, source, bc_dir, cancel)
                return BuildResult(True, "compile-commands", files)
            except (BuildError, OSError, subprocess.SubprocessError) as exc:
                errors.append(f"已有编译数据库不可用：{exc}")
                self.log("warning", errors[-1])

        for index, (candidate_system, candidate_root) in enumerate(native_builds, start=1):
            strategy_build_dir = build_dir / f"{index}-{candidate_system}"
            strategy_build_dir.mkdir(parents=True, exist_ok=True)
            try:
                compile_db, strategy = self._produce_compile_database(
                    source,
                    candidate_root,
                    strategy_build_dir,
                    candidate_system,
                    cancel,
                )
                files = self._replay_compile_database(compile_db, source, bc_dir, cancel)
                return BuildResult(True, strategy, files)
            except (BuildError, OSError, subprocess.SubprocessError) as exc:
                errors.append(
                    f"{candidate_system}@{candidate_root} 编译数据库策略失败：{exc}"
                )
                self.log("warning", errors[-1])
            if candidate_system in {"make", "autotools"}:
                try:
                    files = self._build_with_bitcode_wrappers(
                        source,
                        candidate_root,
                        strategy_build_dir,
                        bc_dir,
                        candidate_system,
                        cancel,
                    )
                    return BuildResult(
                        True, f"{candidate_system}-bitcode-wrapper", files
                    )
                except (BuildError, OSError, subprocess.SubprocessError) as exc:
                    errors.append(
                        f"{candidate_system}@{candidate_root} Bitcode 包装器策略失败：{exc}"
                    )
                    self.log("warning", errors[-1])

        try:
            self.log(
                "warning",
                "原生构建策略未得到可用 Bitcode，启用独立编译单元回退",
            )
            files = self._build_sources_independently(source, bc_dir, cancel)
            return BuildResult(True, "source-unit-fallback", files, errors=errors)
        except (BuildError, OSError, subprocess.SubprocessError) as exc:
            errors.append(f"独立编译单元回退失败：{exc}")
            self.log("warning", errors[-1])

        if not errors:
            errors.append("无法识别受支持的构建系统，也未找到可用的 compile_commands.json")
        self.log("error", f"自动构建失败：{errors[-1]}")
        return BuildResult(False, build_system, errors=errors)

    def _produce_compile_database(
        self,
        source: Path,
        build_root: Path,
        build_dir: Path,
        build_system: str,
        cancel: threading.Event,
    ) -> tuple[Path, str]:
        if build_system == "cmake":
            self._require_tool("cmake")
            cmake_build = build_dir / "cmake"
            self._run(
                [
                    "cmake", "-S", str(build_root), "-B", str(cmake_build), "-G", "Ninja",
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                    "-DCMAKE_BUILD_TYPE=Debug",
                    "-DBUILD_SHARED_LIBS=OFF",
                    "-DBUILD_TESTING=OFF",
                    f"-DCMAKE_C_COMPILER={self.clang}",
                    f"-DCMAKE_CXX_COMPILER={self.clangxx}",
                ],
                build_root,
                cancel,
                self._build_environment(),
            )
            self._run(
                ["cmake", "--build", str(cmake_build), "--parallel", "2"],
                build_root,
                cancel,
                self._build_environment(),
                check=False,
            )
            compile_db = cmake_build / "compile_commands.json"
            if not compile_db.is_file():
                raise BuildError("CMake 配置成功，但未生成 compile_commands.json")
            return compile_db, "cmake"
        if build_system == "meson":
            self._require_tool("meson")
            meson_build = build_dir / "meson"
            environment = self._build_environment()
            self._run(
                [
                    "meson", "setup", str(meson_build), str(build_root),
                    "--buildtype=debug", "-Ddefault_library=static",
                ],
                build_root,
                cancel,
                environment,
            )
            self._run(
                ["meson", "compile", "-C", str(meson_build), "-j", "2"],
                build_root,
                cancel,
                environment,
                check=False,
            )
            compile_db = meson_build / "compile_commands.json"
            if not compile_db.is_file():
                raise BuildError("Meson 未生成 compile_commands.json")
            return compile_db, "meson"
        if build_system in {"make", "autotools"}:
            self._require_tool("bear")
            self._clean_make_tree(build_root, cancel)
            build_environment = self._build_environment()
            if build_system == "autotools":
                build_environment = self._prepare_autotools(build_root, cancel)
            compile_db = build_dir / "compile_commands.json"
            compile_db.unlink(missing_ok=True)
            make_command = ["make", "-k", "-j2", *self._make_targets(build_root)]
            self._run(
                ["bear", "--output", str(compile_db), "--", *make_command],
                build_root,
                cancel,
                build_environment,
                check=False,
            )
            if not compile_db.is_file() or compile_db.stat().st_size == 0:
                raise BuildError("Bear 未捕获到编译命令")
            return compile_db, build_system
        raise BuildError("无法识别构建系统，也未找到 compile_commands.json")

    def _build_environment(self, **overrides: str) -> dict[str, str]:
        environment = {
            **os.environ,
            "CC": self.clang,
            "CXX": self.clangxx,
        }
        environment.setdefault(
            "CFLAGS", os.environ.get("ONECVE_CFLAGS", os.environ.get("NSPA_CFLAGS", "-O0 -g"))
        )
        environment.setdefault(
            "CXXFLAGS", os.environ.get("ONECVE_CXXFLAGS", os.environ.get("NSPA_CXXFLAGS", "-O0 -g"))
        )
        environment.update(overrides)
        return environment

    def _prepare_existing_compile_database(
        self,
        compile_db: Path,
        source_root: Path,
        cancel: threading.Event,
    ) -> None:
        """Materialize generated headers/sources required by compile commands."""
        try:
            entries = json.loads(compile_db.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            return
        candidates = [compile_db.parent.resolve(), source_root.resolve()]
        if isinstance(entries, list) and entries:
            directory = Path(str(entries[0].get("directory") or source_root)).resolve()
            candidates.insert(0, directory)
        seen: set[Path] = set()
        for candidate in candidates:
            if candidate in seen or not candidate.is_dir():
                continue
            seen.add(candidate)
            if (candidate / "build.ninja").is_file():
                self.log("info", f"重放前执行生成阶段：ninja -C {candidate}")
                self._run(
                    ["ninja", "-C", str(candidate), "-k", "0", "-j", "2"],
                    candidate,
                    cancel,
                    self._build_environment(),
                    check=False,
                )
                return
            if any(
                (candidate / name).is_file()
                for name in ("Makefile", "makefile", "GNUmakefile")
            ):
                self.log("info", f"重放前执行生成阶段：make -C {candidate}")
                self._run(
                    ["make", "-k", "-j2"],
                    candidate,
                    cancel,
                    self._build_environment(),
                    check=False,
                )
                return

    def _clean_make_tree(self, build_root: Path, cancel: threading.Event) -> None:
        if not any((build_root / name).is_file() for name in ("Makefile", "makefile", "GNUmakefile")):
            return
        result = self._run(
            ["make", "distclean"],
            build_root,
            cancel,
            check=False,
            warn_on_failure=False,
        )
        if result != 0:
            self._run(
                ["make", "clean"],
                build_root,
                cancel,
                check=False,
                warn_on_failure=False,
            )

    def _prepare_autotools(
        self, build_root: Path, cancel: threading.Event
    ) -> dict[str, str]:
        self._prepare_git_submodules(build_root, cancel)
        configure = build_root / "configure"
        generator = next(
            (
                build_root / name
                for name in ("buildconf", "autogen.sh", "bootstrap")
                if (build_root / name).is_file()
            ),
            None,
        )
        if not self._autotools_configure_complete(build_root, configure):
            self.log("info", "Autotools 配置文件或辅助文件不完整，重新执行引导")
            if generator is not None:
                self._run(
                    ["bash", str(generator)],
                    build_root,
                    cancel,
                    self._build_environment(NOCONFIGURE="1"),
                )
            else:
                self._require_tool("autoreconf")
                self._run(["autoreconf", "-fi"], build_root, cancel, self._build_environment())
        if not self._autotools_configure_complete(build_root, configure):
            raise BuildError(f"Autotools 未生成完整的 configure 与辅助文件：{build_root}")
        configure_options = self._autotools_configure_options(build_root)
        cache_key = build_root.resolve()
        cached = self._autotools_recovery_cache.get(cache_key)
        if cached is not None:
            configure_options, cc, cxx = cached
            configure_environment = self._build_environment(CC=cc, CXX=cxx)
        else:
            configure_options = list(configure_options)
            configure_environment = self._build_environment()
        if configure_options:
            self.log(
                "info",
                "根据源码特征启用构建适配参数：" + " ".join(configure_options),
            )
        attempts: list[str] = []
        for attempt in range(self.configure_retries + 1):
            try:
                self._run(
                    ["bash", str(configure), *configure_options],
                    build_root,
                    cancel,
                    configure_environment,
                )
                self._autotools_recovery_cache[cache_key] = (
                    list(configure_options),
                    configure_environment["CC"],
                    configure_environment["CXX"],
                )
                return configure_environment
            except BuildError as exc:
                attempts.append(str(exc))
                if attempt >= self.configure_retries:
                    break
                recovery = self._autotools_recovery_action(
                    configure,
                    str(exc),
                    configure_options,
                    configure_environment,
                )
                if recovery is None:
                    break
                kind, value = recovery
                if kind == "option":
                    configure_options.append(value)
                    self.log(
                        "warning",
                        f"Autotools 配置失败，验证到可用恢复选项，重试：{value}",
                    )
                else:
                    configure_environment = self._build_environment(CC="gcc", CXX="g++")
                    self.log(
                        "warning",
                        "Autotools 配置要求 GCC，改用 GCC 生成构建规则；最终 Bitcode 仍由 Clang 生成",
                    )
        detail = attempts[-1] if attempts else "未知配置错误"
        raise BuildError(detail)

    def _autotools_recovery_action(
        self,
        configure: Path,
        error: str,
        selected_options: Sequence[str],
        environment: dict[str, str],
    ) -> tuple[str, str] | None:
        try:
            configure_text = configure.read_text(encoding="utf-8", errors="replace")
        except OSError:
            configure_text = ""
        selected_keys = {option.split("=", 1)[0] for option in selected_options}

        suggested = re.findall(
            r"(?:use|try)(?:\s+the)?\s+(--[A-Za-z0-9][A-Za-z0-9_.-]*(?:=[^\s,.;]+)?)\s+option",
            error,
            flags=re.IGNORECASE,
        )
        for option in suggested:
            if self._configure_supports_option(configure_text, option, selected_keys):
                return "option", option

        lowered = error.lower()
        if "32-bit" in lowered or "32 bit" in lowered or "-m32" in lowered:
            for option in (
                "--enable-win64",
                "--enable-archs=x86_64",
                "--disable-32bit",
                "--disable-32-bit",
                "--enable-64bit",
            ):
                if self._configure_supports_option(configure_text, option, selected_keys):
                    return "option", option

        if (
            "gcc instead of clang" in lowered
            and Path(environment.get("CC", "")).name.startswith("clang")
            and shutil.which("gcc")
            and shutil.which("g++")
        ):
            return "compiler", "gcc"

        missing = re.findall(
            r"configure:\s*error:.*?\b([A-Za-z][A-Za-z0-9+_.-]*)\b[^\n]*?not found",
            error,
            flags=re.IGNORECASE,
        )
        for dependency in missing:
            names = [dependency.lower()]
            if names[0].startswith("lib") and len(names[0]) > 3:
                names.append(names[0][3:])
            for name in names:
                for option in (f"--without-{name}", f"--disable-{name}"):
                    if self._configure_supports_option(configure_text, option, selected_keys):
                        return "option", option

        # Some Autoconf projects enable an optional subsystem by default but
        # abort with an unhelpful boolean error when its development headers
        # are unavailable.  GNU Screen's PAM probe is one example:
        #
        #   checking for PAM support... configure: error: no
        #
        # Recover only when the failed check explicitly names a "support"
        # feature and configure advertises the matching enable/with option.
        # This keeps the fallback capability-driven instead of project-name
        # driven and avoids silently disabling mandatory dependencies.
        failed_support_checks = re.findall(
            r"checking\s+for\s+([A-Za-z][A-Za-z0-9+_.-]*)\s+support\s*\.\.\.\s*"
            r"configure:\s*error:\s*(?:no|failed)\b",
            error,
            flags=re.IGNORECASE,
        )
        for feature in failed_support_checks:
            name = feature.lower()
            for option in (f"--disable-{name}", f"--without-{name}"):
                if self._configure_supports_option(configure_text, option, selected_keys):
                    return "option", option
        return None

    @staticmethod
    def _configure_supports_option(
        configure_text: str, option: str, selected_keys: set[str]
    ) -> bool:
        key = option.split("=", 1)[0]
        if key in selected_keys:
            return False
        aliases = [key]
        if key.startswith("--disable-"):
            aliases.append("--enable-" + key.removeprefix("--disable-"))
        elif key.startswith("--without-"):
            aliases.append("--with-" + key.removeprefix("--without-"))
        return any(alias in configure_text for alias in aliases)

    def _prepare_git_submodules(self, build_root: Path, cancel: threading.Event) -> None:
        if not (build_root / ".gitmodules").is_file() or not (build_root / ".git").exists():
            return
        self._require_tool("git")
        self.log("info", "检测到 Git 子模块，确保递归子模块已初始化")
        self._run(
            ["git", "submodule", "update", "--init", "--recursive", "--depth", "1"],
            build_root,
            cancel,
        )

    @staticmethod
    def _autotools_configure_complete(build_root: Path, configure: Path) -> bool:
        if not configure.is_file():
            return False
        try:
            configure_text = configure.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        match = re.search(r"\bac_aux_files=(?:\"([^\"]*)\"|'([^']*)')", configure_text)
        if match is None:
            return True
        required = (match.group(1) or match.group(2) or "").split()
        if not required:
            return True
        aux_dir = build_root
        configure_ac = build_root / "configure.ac"
        if configure_ac.is_file():
            try:
                configure_ac_text = configure_ac.read_text(encoding="utf-8", errors="replace")
            except OSError:
                configure_ac_text = ""
            aux_match = re.search(
                r"AC_CONFIG_AUX_DIR\s*\(\s*(?:\[([^\]]+)\]|([^\)]+))\s*\)",
                configure_ac_text,
            )
            if aux_match is not None:
                relative = (aux_match.group(1) or aux_match.group(2) or "").strip()
                if relative:
                    aux_dir = build_root / relative
        return all((aux_dir / name).is_file() for name in required)

    @staticmethod
    def _source_profile(build_root: Path) -> str | None:
        """Recognize source layouts that need semantic build adaptation.

        Detection intentionally uses stable repository files rather than the
        uploaded project name, so renamed archives and local directories work.
        """
        if (
            (build_root / "src" / "sqliteInt.h").is_file()
            and (build_root / "tool" / "mksqlite3c.tcl").is_file()
            and (build_root / "ext" / "fts5").is_dir()
        ):
            return "sqlite"
        return None

    def _autotools_configure_options(self, build_root: Path) -> list[str]:
        if self._source_profile(build_root) == "sqlite":
            # SQLite defaults to one amalgamated sqlite3.c.  Saber needs the
            # original translation units for useful per-file analysis.
            return ["--disable-amalgamation", "--disable-shared", "--disable-readline"]
        return []

    def _make_targets(self, build_root: Path) -> list[str]:
        if self._source_profile(build_root) == "sqlite":
            # Build the core library only.  This avoids replaying the generated
            # amalgamation again as part of the command-line shell target.
            return ["libsqlite3.a"]
        return []

    def _build_with_bitcode_wrappers(
        self,
        source_root: Path,
        build_root: Path,
        build_dir: Path,
        bc_dir: Path,
        build_system: str,
        cancel: threading.Event,
    ) -> list[Path]:
        self._require_tool("make")
        wrapper_dir = build_dir / "wrappers"
        wrapper_dir.mkdir(parents=True, exist_ok=True)
        cc_wrapper = wrapper_dir / "clang-bitcode"
        cxx_wrapper = wrapper_dir / "clangxx-bitcode"
        cc_wrapper.write_text(self._wrapper_script(self.clang), encoding="utf-8", newline="\n")
        cxx_wrapper.write_text(self._wrapper_script(self.clangxx), encoding="utf-8", newline="\n")
        cc_wrapper.chmod(0o755)
        cxx_wrapper.chmod(0o755)

        self._clean_make_tree(build_root, cancel)
        if build_system == "autotools":
            self._prepare_autotools(build_root, cancel)
        environment = self._build_environment(
            CC=str(cc_wrapper),
            CXX=str(cxx_wrapper),
            AR=shutil.which("llvm-ar") or "llvm-ar",
            RANLIB=shutil.which("llvm-ranlib") or "llvm-ranlib",
        )
        self.log("info", "编译数据库策略未成功，改用 Clang Bitcode 包装器直接构建")
        self._run(
            [
                "make",
                "-k",
                "-j2",
                f"CC={cc_wrapper}",
                f"CXX={cxx_wrapper}",
                f"AR={environment['AR']}",
                f"RANLIB={environment['RANLIB']}",
                *self._make_targets(build_root),
            ],
            build_root,
            cancel,
            environment,
            check=False,
        )
        files = self._collect_bitcode_outputs(source_root, build_root, build_dir, bc_dir, cancel)
        if not files:
            raise BuildError("Bitcode 包装器构建完成，但未收集到 LLVM Bitcode 对象")
        self.log("info", f"Bitcode 包装器共收集 {len(files)} 个编译单元")
        return files

    @staticmethod
    def _wrapper_script(compiler: str) -> str:
        quoted_compiler = shlex.quote(compiler)
        return f"""#!/usr/bin/env bash
set -eu
compile=0
for argument in "$@"; do
    if [ "$argument" = "-c" ]; then
        compile=1
        break
    fi
done
if [ "$compile" = "1" ]; then
    exec {quoted_compiler} -emit-llvm -fno-discard-value-names "$@"
fi
exec {quoted_compiler} "$@"
"""

    def _collect_bitcode_outputs(
        self,
        source_root: Path,
        build_root: Path,
        build_dir: Path,
        bc_dir: Path,
        cancel: threading.Event,
    ) -> list[Path]:
        collected: list[Path] = []
        seen_content: set[tuple[int, str]] = set()
        for candidate in build_root.rglob("*"):
            if cancel.is_set():
                raise BuildError("任务已取消")
            if not candidate.is_file() or candidate.suffix.lower() not in {".o", ".obj", ".bc"}:
                continue
            if ".git" in candidate.parts or not self._is_llvm_bitcode(candidate):
                continue
            identity = self._bitcode_identity(candidate)
            if identity in seen_content:
                continue
            seen_content.add(identity)
            collected.append(self._copy_bitcode(candidate, candidate, source_root, bc_dir))

        llvm_ar = shutil.which("llvm-ar")
        if llvm_ar:
            archive_root = build_dir / "archive-extract"
            for archive in build_root.rglob("*.a"):
                if cancel.is_set():
                    raise BuildError("任务已取消")
                if ".git" in archive.parts:
                    continue
                digest = hashlib.sha1(str(archive).encode("utf-8")).hexdigest()[:10]
                extract_dir = archive_root / digest
                shutil.rmtree(extract_dir, ignore_errors=True)
                extract_dir.mkdir(parents=True, exist_ok=True)
                if self._run(
                    [llvm_ar, "x", str(archive)],
                    extract_dir,
                    cancel,
                    check=False,
                    warn_on_failure=False,
                ) != 0:
                    continue
                for member in extract_dir.rglob("*"):
                    if not member.is_file() or not self._is_llvm_bitcode(member):
                        continue
                    label = Path(f"{archive.name}.members") / member.name
                    identity = self._bitcode_identity(member)
                    if identity in seen_content:
                        continue
                    seen_content.add(identity)
                    collected.append(self._copy_bitcode(member, label, source_root, bc_dir))

        return sorted(set(collected))

    def _build_sources_independently(
        self,
        source_root: Path,
        bc_dir: Path,
        cancel: threading.Event,
    ) -> list[Path]:
        source_root = source_root.resolve()
        bc_dir = bc_dir.resolve()
        excluded_parts = {
            ".git",
            ".hg",
            ".svn",
            "autom4te.cache",
            "node_modules",
            "__pycache__",
        }
        suffixes = {".c", ".cc", ".cpp", ".cxx", ".m", ".mm"}
        units = [
            path.resolve()
            for path in source_root.rglob("*")
            if path.is_file()
            and path.suffix.lower() in suffixes
            and not excluded_parts.intersection(path.relative_to(source_root).parts)
        ]
        units = sorted(set(units))
        if not units:
            raise BuildError("项目中没有发现可独立编译的 C/C++ 源文件")

        selected = units[: self.source_fallback_max_units]
        if len(selected) < len(units):
            self.log(
                "warning",
                f"发现 {len(units)} 个编译单元，独立回退最多尝试前 "
                f"{len(selected)} 个；最终覆盖率仍按全部源文件计算",
            )
        else:
            self.log("info", f"独立编译单元回退将尝试 {len(selected)} 个源文件")

        common_includes: list[Path] = [source_root]
        for relative in ("include", "src"):
            candidate = source_root / relative
            if candidate.is_dir():
                common_includes.append(candidate.resolve())

        generated: list[Path] = []
        failures: list[str] = []
        started = time.monotonic()
        for index, source in enumerate(selected, start=1):
            if cancel.is_set():
                raise BuildError("任务已取消")
            if time.monotonic() - started > self.timeout:
                self.log(
                    "warning",
                    f"独立编译单元回退达到 {self.timeout} 秒时间上限，停止继续尝试",
                )
                break
            try:
                relative = source.relative_to(source_root).as_posix()
            except ValueError:
                continue
            digest = hashlib.sha1(str(source).encode("utf-8")).hexdigest()[:10]
            stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", relative).rsplit(".", 1)[0]
            output = bc_dir / f"fallback_{stem}-{digest}.bc"
            output.parent.mkdir(parents=True, exist_ok=True)
            compiler = (
                self.clangxx
                if source.suffix.lower() in {".cc", ".cpp", ".cxx", ".mm"}
                else self.clang
            )
            include_dirs = list(common_includes)
            parent = source.parent
            while parent != source_root and source_root in parent.parents:
                include_dirs.append(parent)
                parent = parent.parent
            include_args: list[str] = []
            seen_includes: set[Path] = set()
            for include_dir in include_dirs:
                if include_dir in seen_includes:
                    continue
                seen_includes.add(include_dir)
                include_args.extend(("-I", str(include_dir)))
            command = [
                compiler,
                "-O0",
                "-g",
                "-fno-discard-value-names",
                "-Wno-error",
                *include_args,
                "-emit-llvm",
                "-c",
                str(source),
                "-o",
                str(output),
            ]
            self.log("info", f"独立生成 Bitcode {index}/{len(selected)}：{relative}")
            try:
                self._run(command, source.parent, cancel)
                if output.is_file() and self._is_llvm_bitcode(output):
                    generated.append(output)
                else:
                    failures.append(f"{relative}: 未生成有效 LLVM Bitcode")
            except (BuildError, OSError, subprocess.SubprocessError) as exc:
                failures.append(f"{relative}: {exc}")
            self._report_progress("source-units", index, len(selected))

        coverage = len(generated) / len(units)
        self.log(
            "info",
            f"独立编译单元覆盖率：{len(generated)}/{len(units)}（{coverage:.1%}）",
        )
        if not generated or coverage < self.min_bitcode_coverage:
            detail = "; ".join(failures[:5])
            raise BuildError(
                f"独立编译单元覆盖率 {coverage:.1%} 低于最低要求 "
                f"{self.min_bitcode_coverage:.1%}。{detail}"
            )
        if failures:
            self.log(
                "warning",
                f"独立回退中 {len(failures)} 个编译单元失败，{len(generated)} 个成功",
            )
        return generated

    @staticmethod
    def _is_llvm_bitcode(path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                magic = handle.read(4)
        except OSError:
            return False
        return magic in {b"BC\xc0\xde", b"\xde\xc0\x17\x0b"}

    @staticmethod
    def _bitcode_identity(path: Path) -> tuple[int, str]:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return path.stat().st_size, digest.hexdigest()

    @staticmethod
    def _copy_bitcode(candidate: Path, label: Path, source_root: Path, bc_dir: Path) -> Path:
        try:
            display = label.relative_to(source_root).as_posix()
        except ValueError:
            display = label.as_posix()
        digest = hashlib.sha1(f"{candidate}:{display}".encode("utf-8")).hexdigest()[:10]
        stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", display).rsplit(".", 1)[0]
        output = bc_dir / f"{stem}-{digest}.bc"
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(candidate, output)
        return output

    def _replay_compile_database(
        self,
        compile_db: Path,
        source_root: Path,
        bc_dir: Path,
        cancel: threading.Event,
    ) -> list[Path]:
        try:
            entries = json.loads(compile_db.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BuildError(f"无法读取编译数据库：{exc}") from exc
        if not isinstance(entries, list):
            raise BuildError("compile_commands.json 顶层必须是数组")
        generated: list[Path] = []
        generated_set: set[Path] = set()
        seen_commands: set[tuple[str, ...]] = set()
        failures: list[str] = []
        for index, entry in enumerate(entries, start=1):
            if cancel.is_set():
                raise BuildError("任务已取消")
            try:
                command, cwd, output = self._bitcode_command(entry, source_root, bc_dir)
                command_key = tuple(command)
                if command_key in seen_commands:
                    self.log("info", f"跳过重复编译数据库记录 {index}/{len(entries)}")
                    self._report_progress("bitcode-replay", index, len(entries))
                    continue
                seen_commands.add(command_key)
                self.log("info", f"生成 Bitcode {index}/{len(entries)}：{Path(str(entry.get('file'))).name}")
                try:
                    self._run(command, cwd, cancel)
                except BuildError as exc:
                    command = self._retry_without_unsupported_options(
                        command, str(exc), cwd, cancel
                    )
                if output.is_file() and output not in generated_set:
                    generated.append(output)
                    generated_set.add(output)
            except SkippedCompileCommand as exc:
                self.log("info", f"跳过编译数据库记录 {index}/{len(entries)}：{exc}")
            except (BuildError, OSError, subprocess.SubprocessError) as exc:
                failures.append(f"{entry.get('file', '<unknown>')}: {exc}")
                self.log("error", failures[-1])
            self._report_progress("bitcode-replay", index, len(entries))
        if not generated:
            detail = "; ".join(failures[:5])
            raise BuildError(f"所有编译单元均未生成 Bitcode。{detail}")
        attempted = len(generated) + len(failures)
        coverage = len(generated) / attempted if attempted else 1.0
        self.log(
            "info",
            f"Bitcode 构建覆盖率：{len(generated)}/{attempted}（{coverage:.1%}）",
        )
        if failures:
            self.log("warning", f"{len(failures)} 个编译单元失败，{len(generated)} 个成功")
            if coverage < self.min_bitcode_coverage:
                detail = "; ".join(failures[:5])
                raise BuildError(
                    f"Bitcode 构建覆盖率 {coverage:.1%} 低于最低要求 "
                    f"{self.min_bitcode_coverage:.1%}。{detail}"
                )
        return generated

    def _retry_without_unsupported_options(
        self,
        command: list[str],
        error: str,
        cwd: Path,
        cancel: threading.Event,
    ) -> list[str]:
        protected = {"-c", "-o", "-emit-llvm"}
        current = list(command)
        current_error = error
        removed: list[str] = []
        for _ in range(4):
            unsupported = re.findall(
                r"(?:unknown argument|unsupported option)(?::)?\s+['\"](-[^'\"]+)['\"]",
                current_error,
                flags=re.IGNORECASE,
            )
            prefixes = [option for option in unsupported if option not in protected]
            if not prefixes:
                raise BuildError(current_error)
            self._unsupported_clang_options.update(prefixes)
            adjusted = [
                argument
                for argument in current
                if not any(
                    argument == option
                    or (option.endswith("=") and argument.startswith(option))
                    for option in prefixes
                )
            ]
            newly_removed = [argument for argument in current if argument not in adjusted]
            if not newly_removed:
                raise BuildError(current_error)
            removed.extend(newly_removed)
            current = adjusted
            self.log(
                "warning",
                "Clang 不支持原构建器参数，移除后重试：" + " ".join(newly_removed),
            )
            try:
                self._run(current, cwd, cancel)
                return current
            except BuildError as exc:
                current_error = str(exc)
        raise BuildError(
            f"移除不兼容参数后仍无法生成 Bitcode（已移除：{' '.join(removed)}）："
            f"{current_error}"
        )

    def _bitcode_command(
        self, entry: dict[str, object], source_root: Path, bc_dir: Path
    ) -> tuple[list[str], Path, Path]:
        cwd = Path(str(entry.get("directory") or source_root)).resolve()
        source = Path(str(entry.get("file") or ""))
        if not source.is_absolute():
            source = cwd / source
        source = source.resolve()
        if not source.is_file():
            raise BuildError(f"源文件不存在：{source}")
        raw_args = entry.get("arguments")
        if isinstance(raw_args, list):
            args = [str(item) for item in raw_args]
        else:
            command_text = str(entry.get("command") or "")
            args = shlex.split(command_text, posix=os.name != "nt")
        if not args:
            raise BuildError("编译命令为空")
        if "-cc1" in args:
            raise SkippedCompileCommand("Clang 内部 -cc1 命令由对应的驱动层记录覆盖")
        driver_arguments = self._driver_arguments(args)
        compiler = self.clangxx if source.suffix.lower() in {".cc", ".cpp", ".cxx", ".mm"} else self.clang
        cleaned: list[str] = []
        skip_next = False
        options_with_value = {"-o", "-MF", "-MT", "-MQ", "-MJ", "--serialize-diagnostics"}
        options_to_remove = {"-MD", "-MMD", "-MP", "-c", "-emit-llvm"}
        for argument in driver_arguments:
            if skip_next:
                skip_next = False
                continue
            if argument in options_with_value:
                skip_next = True
                continue
            if argument in options_to_remove or argument == "--":
                continue
            if argument.startswith("-o") and len(argument) > 2:
                continue
            if argument.startswith("--output="):
                continue
            if any(
                argument.startswith(prefix) and len(argument) > len(prefix)
                for prefix in ("-MF", "-MT", "-MQ", "-MJ")
            ):
                continue
            if argument == "-Werror" or argument.startswith("-Werror="):
                continue
            if any(
                argument == option
                or (option.endswith("=") and argument.startswith(option))
                for option in self._unsupported_clang_options
            ):
                continue
            if self._same_path_argument(argument, cwd, source):
                continue
            cleaned.append(argument)
        if "-mabi=ms" in cleaned:
            cleaned = [argument for argument in cleaned if argument != "-mabi=ms"]
            if not any(
                argument == "-target"
                or argument.startswith("--target=")
                or argument.startswith("-target=")
                for argument in cleaned
            ):
                architecture = "i686" if "-m32" in cleaned else "x86_64"
                cleaned.insert(0, f"--target={architecture}-w64-windows-gnu")
                self.log(
                    "info",
                    f"将 GCC -mabi=ms 转换为 Clang Windows 目标：{architecture}",
                )
        try:
            display = source.relative_to(source_root).as_posix()
        except ValueError:
            display = source.name
        command_identity = "\0".join([str(source), compiler, *cleaned])
        digest = hashlib.sha1(command_identity.encode("utf-8")).hexdigest()[:10]
        stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", display).rsplit(".", 1)[0]
        output = bc_dir / f"{stem}-{digest}.bc"
        output.parent.mkdir(parents=True, exist_ok=True)
        return [compiler, *cleaned, "-O0", "-g", "-emit-llvm", "-c", str(source), "-o", str(output)], cwd, output

    @staticmethod
    def _driver_arguments(args: list[str]) -> list[str]:
        wrappers = {"ccache", "sccache", "distcc", "icecc", "gomacc"}
        index = 0
        if Path(args[0]).name == "env":
            index = 1
            while index < len(args):
                value = args[index]
                if "=" in value and not value.startswith("-"):
                    index += 1
                    continue
                if value in {"-i", "--ignore-environment"}:
                    index += 1
                    continue
                break
        while index < len(args) and Path(args[index]).name in wrappers:
            index += 1
        if index >= len(args):
            raise BuildError("编译命令没有实际编译器")
        return args[index + 1 :]

    @staticmethod
    def _same_path_argument(argument: str, cwd: Path, expected: Path) -> bool:
        if not argument or argument.startswith("-"):
            return False
        candidate = Path(argument)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        try:
            return candidate.resolve() == expected
        except OSError:
            return False

    def _run(
        self,
        command: Sequence[str],
        cwd: Path,
        cancel: threading.Event,
        environment: dict[str, str] | None = None,
        *,
        check: bool = True,
        warn_on_failure: bool = True,
    ) -> int:
        self.log("command", shlex.join(str(part) for part in command))
        process_options: dict[str, object] = {}
        if os.name == "nt":
            process_options["creationflags"] = getattr(
                subprocess, "CREATE_NEW_PROCESS_GROUP", 0
            )
        else:
            process_options["start_new_session"] = True
        process = subprocess.Popen(
            [str(part) for part in command],
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            bufsize=1,
            **process_options,
        )
        output: list[str] = []
        assert process.stdout is not None
        line_queue: queue.Queue[str | None] = queue.Queue()

        def read_output() -> None:
            assert process.stdout is not None
            for raw_line in process.stdout:
                line_queue.put(raw_line.rstrip())
            line_queue.put(None)

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        started = time.monotonic()
        finished_reading = False
        while not finished_reading:
            if cancel.is_set():
                self._stop_process_tree(process)
                raise BuildError("任务已取消")
            if time.monotonic() - started > self.timeout:
                self._stop_process_tree(process, force=True)
                raise BuildError(f"命令执行超过 {self.timeout} 秒")
            try:
                line = line_queue.get(timeout=0.2)
            except queue.Empty:
                if process.poll() is not None and not reader.is_alive():
                    break
                continue
            if line is None:
                finished_reading = True
                continue
            output.append(line)
            line_no = len(output)
            if line_no <= 300:
                self.log("output", line)
                native_progress = re.match(r"^\[\s*(\d+)\s*/\s*(\d+)\]", line)
                if native_progress:
                    self._report_progress(
                        "native-build",
                        int(native_progress.group(1)),
                        int(native_progress.group(2)),
                    )
            elif line_no == 301:
                self.log("warning", "构建输出过长，界面日志已截断；完整错误仍用于任务诊断")
        returncode = process.wait()
        if returncode != 0 and check:
            detail = "\n".join(output[-40:])
            raise BuildError(f"命令退出码 {returncode}\n{detail}".strip())
        if returncode != 0 and warn_on_failure:
            detail = "\n".join(output[-10:])
            self.log(
                "warning",
                f"命令退出码 {returncode}，继续尝试收集可用构建产物"
                + (f"\n{detail}" if detail else ""),
            )
        return returncode

    def _report_progress(self, phase: str, completed: int, total: int) -> None:
        if self.progress is not None and total > 0:
            self.progress(phase, max(0, completed), total)

    @staticmethod
    def _stop_process_tree(process: subprocess.Popen[str], *, force: bool = False) -> None:
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
                BuildManager._stop_process_tree(process, force=True)

    @staticmethod
    def _require_tool(name: str) -> None:
        if shutil.which(name) is None:
            raise BuildError(f"未找到构建工具：{name}")

def first_existing(paths: Sequence[Path]) -> Path | None:
    return next((path for path in paths if path.is_file()), None)
