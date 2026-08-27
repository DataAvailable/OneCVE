"""Detect project-specific memory operation candidates.

This module implements the first NSPA stage described in
``LLM检索自定义内存操作函数.md``:

1. Build Candidate Function Records (CFRs) from C/C++ functions,
   declarations, and function-like macros.
2. Conservatively filter CFRs with structural, lexical, documentation, and
   call-graph evidence.
3. Emit compact records that can be handed to an LLM for semantic validation.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

try:
    from tree_sitter import Language, Node, Parser
    import tree_sitter_c
    import tree_sitter_cpp
except ImportError as exc:  # pragma: no cover - import failure is reported by CLI.
    Language = None
    Node = None
    Parser = None
    tree_sitter_c = None
    tree_sitter_cpp = None
    TREE_SITTER_IMPORT_ERROR = exc
else:
    TREE_SITTER_IMPORT_ERROR = None


SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".c++",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".ipp",
}

DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    "build",
    "cmake-build-debug",
    "cmake-build-release",
    "node_modules",
    "vendor",
    "third_party",
    "__pycache__",
}

CONTROL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "alignof",
    "_Alignof",
    "catch",
    "new",
    "delete",
}

STANDARD_ALLOC_PRIMITIVES = {
    "malloc",
    "calloc",
    "realloc",
    "reallocarray",
    "aligned_alloc",
    "memalign",
    "posix_memalign",
    "valloc",
    "pvalloc",
    "strdup",
    "strndup",
    "wcsdup",
    "asprintf",
    "vasprintf",
    "operator new",
    "operator new[]",
}

STANDARD_FREE_PRIMITIVES = {
    "free",
    "cfree",
    "delete",
    "delete[]",
    "operator delete",
    "operator delete[]",
}

STRONG_ALLOC_NAME_RE = re.compile(
    r"(^|_)(x?alloc|malloc|calloc|realloc|reallocarray|new|create|dup|clone)(_|$)",
    re.IGNORECASE,
)
WEAK_ALLOC_NAME_RE = re.compile(
    r"(^|_)(copy|make|reserve|grow)(_|$)",
    re.IGNORECASE,
)
STRONG_FREE_NAME_RE = re.compile(
    r"(^|_)(free|release|destroy|dispose|delete|dealloc)(_|$)",
    re.IGNORECASE,
)
WEAK_FREE_NAME_RE = re.compile(
    r"(^|_)(clear|cleanup|clean|close|unref|decref|discard|teardown)(_|$)",
    re.IGNORECASE,
)
MEM_DOC_RE = re.compile(
    r"\b(allocat(?:e|es|ed|ing|ion)|free(?:s|d|ing)?|release(?:s|d|ing)?|"
    r"destroy(?:s|ed|ing)?|dispose(?:s|d|ing)?|delete(?:s|d|ing)?|"
    r"memory|heap|ownership|owned|caller owns|deallocat(?:e|es|ed|ing|ion))\b",
    re.IGNORECASE,
)
NON_MEMORY_DOC_RE = re.compile(
    r"\b(log|logging|trace|debug|format|printf|print|compare|sort|hash|query|"
    r"getter|setter|status|statistics|counter|checksum)\b",
    re.IGNORECASE,
)
NON_MEMORY_NAME_RE = re.compile(
    r"^(get|set|is|has|log|trace|debug|print|format|compare|cmp|hash|sort|"
    r"find|lookup|parse|read|write|test|check)_",
    re.IGNORECASE,
)
CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
FUNCTION_NAME_RE = re.compile(r"([~A-Za-z_]\w*(?:::[~A-Za-z_]\w*)?)\s*$")
DECLARATION_RE = re.compile(
    r"(?P<signature>[A-Za-z_][\w\s:*&<>,.~\[\]\(\)]*?\([^;{}#]*\))\s*;",
    re.MULTILINE,
)
MACRO_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*(.*)$")


@dataclass(slots=True)
class CandidateFunctionRecord:
    project: str
    file: str
    name: str
    entity_kind: str
    signature: str
    return_type: str
    parameters: list[str]
    direct_calls: list[str]
    start_line: int
    end_line: int
    documentation: str = ""
    macro_value: str = ""
    evidence: list[str] = field(default_factory=list)
    score: float = 0.0
    confidence: float = 0.0
    llm_hint: str = "unknown"

    def llm_payload(self) -> dict[str, object]:
        """Return the compact CFR shape used by LLM semantic validation."""
        return {
            "project": self.project,
            "file": self.file,
            "name": self.name,
            "entity_kind": self.entity_kind,
            "signature": self.signature,
            "return_type": self.return_type,
            "parameters": self.parameters,
            "direct_calls": self.direct_calls,
            "documentation": self.documentation,
            "macro_value": self.macro_value,
            "filter_evidence": self.evidence,
            "filter_score": round(self.score, 2),
            "filter_confidence": self.confidence,
            "candidate_hint": self.llm_hint,
        }


class MemoryFunctionDetector:
    """Build and filter CFRs for C/C++ projects."""

    def __init__(
        self,
        project_root: Path,
        *,
        project_name: str | None = None,
        excludes: Iterable[str] = DEFAULT_EXCLUDES,
        min_score: float = 2.0,
        min_confidence: float | None = None,
    ) -> None:
        self.project_root = project_root.resolve()
        self.project_name = project_name or self.project_root.name
        self.excludes = set(excludes)
        self.min_score = min_score
        self.min_confidence = min_confidence
        self.parser_mode = "regex_fallback"
        self.parsers = {}
        if TREE_SITTER_IMPORT_ERROR is None:
            self.parser_mode = "tree_sitter"
            self.parsers = {
                "c": self._make_parser(tree_sitter_c.language()),
                "cpp": self._make_parser(tree_sitter_cpp.language()),
            }

    @staticmethod
    def _make_parser(language_capsule: object) -> Parser:
        parser = Parser()
        parser.language = Language(language_capsule)
        return parser

    def run(self) -> tuple[list[CandidateFunctionRecord], list[CandidateFunctionRecord]]:
        raw = list(self.build_records())
        filtered = self.filter_records(raw)
        return raw, filtered

    def build_records(self) -> Iterator[CandidateFunctionRecord]:
        for source_path in self.iter_source_files():
            yield from self.extract_file_records(source_path)

    def iter_source_files(self) -> Iterator[Path]:
        for path in sorted(self.project_root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in SOURCE_EXTENSIONS:
                continue
            if any(part in self.excludes for part in path.relative_to(self.project_root).parts):
                continue
            yield path

    def extract_file_records(self, path: Path) -> list[CandidateFunctionRecord]:
        if self.parser_mode != "tree_sitter":
            return self.extract_file_records_regex(path)

        source = path.read_bytes()
        parser = self.parsers["cpp" if path.suffix.lower() in {".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hxx", ".hh", ".ipp"} else "c"]
        tree = parser.parse(source)
        lines = source.decode("utf-8", errors="replace").splitlines()
        records: list[CandidateFunctionRecord] = []

        for node in walk_named(tree.root_node):
            if node.type == "function_definition":
                record = self._record_from_function_definition(path, source, lines, node)
            elif node.type == "declaration":
                record = self._record_from_declaration(path, source, lines, node)
            elif node.type == "preproc_function_def":
                record = self._record_from_macro(path, source, lines, node)
            else:
                continue

            if record is not None:
                records.append(record)

        return records

    def extract_file_records_regex(self, path: Path) -> list[CandidateFunctionRecord]:
        source_text = path.read_text(encoding="utf-8", errors="replace")
        masked = mask_comments_and_strings(source_text)
        lines = source_text.splitlines()
        records: list[CandidateFunctionRecord] = []

        records.extend(self._regex_macro_records(path, source_text, lines))
        function_ranges: list[tuple[int, int]] = []
        for signature, body, start, body_start, end in iter_regex_function_definitions(source_text, masked):
            parsed = parse_regex_signature(signature)
            if parsed is None:
                continue
            name, return_type, parameters = parsed
            if name in CONTROL_KEYWORDS:
                continue
            function_ranges.append((start, end))
            records.append(
                CandidateFunctionRecord(
                    project=self.project_name,
                    file=str(path.relative_to(self.project_root)),
                    name=name,
                    entity_kind="function_definition",
                    signature=normalize_space(signature),
                    return_type=return_type,
                    parameters=parameters,
                    direct_calls=extract_calls_from_text(mask_comments_and_strings(body)),
                    start_line=source_text.count("\n", 0, start) + 1,
                    end_line=source_text.count("\n", 0, end) + 1,
                    documentation=extract_leading_doc(lines, source_text.count("\n", 0, start)),
                )
            )

        for match in DECLARATION_RE.finditer(masked):
            if range_overlaps(match.start(), match.end(), function_ranges):
                continue
            signature = source_text[match.start("signature") : match.end("signature")]
            parsed = parse_regex_signature(signature)
            if parsed is None:
                continue
            name, return_type, parameters = parsed
            if name in CONTROL_KEYWORDS:
                continue
            records.append(
                CandidateFunctionRecord(
                    project=self.project_name,
                    file=str(path.relative_to(self.project_root)),
                    name=name,
                    entity_kind="function_declaration",
                    signature=normalize_space(signature),
                    return_type=return_type,
                    parameters=parameters,
                    direct_calls=[],
                    start_line=source_text.count("\n", 0, match.start()) + 1,
                    end_line=source_text.count("\n", 0, match.end()) + 1,
                    documentation=extract_leading_doc(lines, source_text.count("\n", 0, match.start())),
                )
            )

        return records

    def _regex_macro_records(
        self, path: Path, source_text: str, lines: Sequence[str]
    ) -> list[CandidateFunctionRecord]:
        records: list[CandidateFunctionRecord] = []
        for start_line, macro_text in iter_logical_macro_lines(lines):
            match = MACRO_RE.match(macro_text)
            if not match:
                continue
            name, params, value = match.groups()
            records.append(
                CandidateFunctionRecord(
                    project=self.project_name,
                    file=str(path.relative_to(self.project_root)),
                    name=name,
                    entity_kind="function_like_macro",
                    signature=f"#define {name}({params})",
                    return_type="macro",
                    parameters=split_parameters(f"({params})"),
                    direct_calls=extract_calls_from_text(mask_comments_and_strings(value)),
                    start_line=start_line + 1,
                    end_line=start_line + macro_text.count("\n") + 1,
                    documentation=extract_leading_doc(lines, start_line),
                    macro_value=normalize_space(value),
                )
            )
        return records

    def _record_from_function_definition(
        self, path: Path, source: bytes, lines: Sequence[str], node: Node
    ) -> CandidateFunctionRecord | None:
        declarator = node.child_by_field_name("declarator")
        body = node.child_by_field_name("body")
        if declarator is None or body is None:
            return None
        name = extract_declarator_name(source, declarator)
        if not name or name in CONTROL_KEYWORDS:
            return None
        parameter_node = find_first_descendant(declarator, {"parameter_list"})
        parameters = split_parameters(node_text(source, parameter_node)) if parameter_node else []
        signature = normalize_space(source[node.start_byte : body.start_byte].decode("utf-8", errors="replace"))
        return_type = extract_return_type(source, node, declarator)

        return CandidateFunctionRecord(
            project=self.project_name,
            file=str(path.relative_to(self.project_root)),
            name=name,
            entity_kind="function_definition",
            signature=signature,
            return_type=return_type,
            parameters=parameters,
            direct_calls=extract_direct_calls(source, body),
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            documentation=extract_leading_doc(lines, node.start_point[0]),
        )

    def _record_from_declaration(
        self, path: Path, source: bytes, lines: Sequence[str], node: Node
    ) -> CandidateFunctionRecord | None:
        if node.parent is not None and node.parent.type not in {
            "translation_unit",
            "declaration_list",
            "namespace_definition",
            "linkage_specification",
        }:
            return None
        if find_first_descendant(node, {"function_declarator"}) is None:
            return None
        if node_has_descendant(node, {"compound_statement"}):
            return None

        declarator = find_first_descendant(node, {"function_declarator", "pointer_declarator", "reference_declarator"})
        if declarator is None:
            return None
        name = extract_declarator_name(source, declarator)
        if not name or name in CONTROL_KEYWORDS:
            return None
        parameter_node = find_first_descendant(declarator, {"parameter_list"})
        parameters = split_parameters(node_text(source, parameter_node)) if parameter_node else []
        signature = normalize_space(node_text(source, node).rstrip(";"))
        return_type = extract_return_type(source, node, declarator)

        return CandidateFunctionRecord(
            project=self.project_name,
            file=str(path.relative_to(self.project_root)),
            name=name,
            entity_kind="function_declaration",
            signature=signature,
            return_type=return_type,
            parameters=parameters,
            direct_calls=[],
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            documentation=extract_leading_doc(lines, node.start_point[0]),
        )

    def _record_from_macro(
        self, path: Path, source: bytes, lines: Sequence[str], node: Node
    ) -> CandidateFunctionRecord | None:
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")
        value_node = node.child_by_field_name("value")
        if name_node is None or params_node is None:
            return None
        name = node_text(source, name_node)
        if not name:
            return None
        parameters = split_parameters(node_text(source, params_node))
        value = node_text(source, value_node) if value_node is not None else ""
        signature = f"#define {name}{node_text(source, params_node)}"

        return CandidateFunctionRecord(
            project=self.project_name,
            file=str(path.relative_to(self.project_root)),
            name=name,
            entity_kind="function_like_macro",
            signature=signature,
            return_type="macro",
            parameters=parameters,
            direct_calls=extract_calls_from_text(value),
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            documentation=extract_leading_doc(lines, node.start_point[0]),
            macro_value=normalize_space(value),
        )

    def filter_records(
        self, records: Sequence[CandidateFunctionRecord]
    ) -> list[CandidateFunctionRecord]:
        unique = deduplicate_records(records)
        by_name = build_name_index(unique)

        for record in unique:
            record.score, record.evidence, record.llm_hint = score_base_evidence(record)
            record.confidence = score_to_confidence(record.score)

        changed = True
        while changed:
            changed = False
            retained_names = {
                record.name
                for record in unique
                if is_retained(record, self.min_score, self.min_confidence)
                and is_propagatable_memory_candidate(record)
            }
            for record in unique:
                if "calls_project_memory_candidate" in record.evidence:
                    continue
                called = sorted({call for call in record.direct_calls if call in retained_names})
                if called and can_receive_project_call_evidence(record):
                    record.evidence.append("calls_project_memory_candidate")
                    record.evidence.append("project_memory_calls:" + ",".join(called[:8]))
                    record.score += 2.5
                    record.confidence = score_to_confidence(record.score)
                    if record.llm_hint == "unknown":
                        record.llm_hint = infer_hint_from_called_names(called, by_name)
                    changed = True

        return [
            record
            for record in unique
            if is_retained(record, self.min_score, self.min_confidence)
        ]


def walk_named(node: Node) -> Iterator[Node]:
    stack = [node]
    while stack:
        current = stack.pop()
        if current.is_named:
            yield current
        stack.extend(reversed(current.children))


def node_text(source: bytes, node: Node | None) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def find_first_descendant(node: Node, types: set[str]) -> Node | None:
    for child in walk_named(node):
        if child.type in types:
            return child
    return None


def node_has_descendant(node: Node, types: set[str]) -> bool:
    return find_first_descendant(node, types) is not None


def extract_declarator_name(source: bytes, node: Node) -> str:
    if node.type in {
        "identifier",
        "field_identifier",
        "qualified_identifier",
        "namespace_identifier",
        "type_identifier",
        "destructor_name",
        "operator_name",
    }:
        return normalize_cpp_name(node_text(source, node))

    field = node.child_by_field_name("declarator")
    if field is not None:
        name = extract_declarator_name(source, field)
        if name:
            return name

    for child in node.children:
        if child.is_named:
            name = extract_declarator_name(source, child)
            if name:
                return name
    return ""


def normalize_cpp_name(name: str) -> str:
    return normalize_space(name).replace(" :: ", "::").replace("::~", "::~")


def split_parameters(parameter_text: str) -> list[str]:
    text = parameter_text.strip()
    if text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    if not text.strip() or text.strip() == "void":
        return []

    params: list[str] = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        if char == "," and depth == 0:
            params.append(normalize_space("".join(current)))
            current = []
        else:
            current.append(char)
    if current:
        params.append(normalize_space("".join(current)))
    return [param for param in params if param]


def mask_comments_and_strings(text: str) -> str:
    chars = list(text)
    i = 0
    state = "code"
    while i < len(chars):
        char = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "line_comment"
                continue
            if char == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block_comment"
                continue
            if char == '"':
                chars[i] = " "
                i += 1
                state = "string"
                continue
            if char == "'":
                chars[i] = " "
                i += 1
                state = "char"
                continue
            i += 1
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                chars[i] = " "
            i += 1
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "code"
            else:
                if char != "\n":
                    chars[i] = " "
                i += 1
        elif state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if char == "\\" and i + 1 < len(chars):
                chars[i] = " "
                if chars[i + 1] != "\n":
                    chars[i + 1] = " "
                i += 2
                continue
            if char == quote:
                chars[i] = " "
                i += 1
                state = "code"
                continue
            if char != "\n":
                chars[i] = " "
            i += 1
    return "".join(chars)


def iter_logical_macro_lines(lines: Sequence[str]) -> Iterator[tuple[int, str]]:
    row = 0
    while row < len(lines):
        line = lines[row]
        if not line.lstrip().startswith("#"):
            row += 1
            continue
        start = row
        parts = [line.rstrip("\\")]
        while line.rstrip().endswith("\\") and row + 1 < len(lines):
            row += 1
            line = lines[row]
            parts.append(line.rstrip("\\"))
        yield start, "\n".join(parts)
        row += 1


def iter_regex_function_definitions(
    source_text: str, masked: str
) -> Iterator[tuple[str, str, int, int, int]]:
    pos = 0
    while pos < len(masked):
        brace = masked.find("{", pos)
        if brace == -1:
            break
        prefix = masked[:brace].rstrip()
        if not prefix.endswith(")"):
            pos = brace + 1
            continue
        end = find_matching_brace(masked, brace)
        if end == -1:
            pos = brace + 1
            continue
        start = signature_start(masked, brace)
        signature = source_text[start:brace].strip()
        if parse_regex_signature(signature) is not None:
            yield signature, source_text[brace + 1 : end], start, brace + 1, end + 1
            pos = end + 1
        else:
            pos = brace + 1


def signature_start(masked: str, brace: int) -> int:
    boundary = max(
        masked.rfind(";", 0, brace),
        masked.rfind("}", 0, brace),
        masked.rfind("{", 0, brace),
    )
    start = boundary + 1
    while start < brace and masked[start].isspace():
        start += 1
    return start


def find_matching_brace(masked: str, open_brace: int) -> int:
    depth = 0
    for index in range(open_brace, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def parse_regex_signature(signature: str) -> tuple[str, str, list[str]] | None:
    compact = normalize_space(signature)
    if not compact or compact.startswith("#"):
        return None
    if re.search(r"\b(typedef|return|if|for|while|switch|catch)\b", compact.split("(", 1)[0]):
        return None
    open_paren = compact.rfind("(")
    close_paren = compact.rfind(")")
    if open_paren == -1 or close_paren < open_paren:
        return None
    head = compact[:open_paren].strip()
    name_match = FUNCTION_NAME_RE.search(head)
    if name_match is None:
        return None
    name = normalize_cpp_name(name_match.group(1))
    if name in CONTROL_KEYWORDS:
        return None
    return_type = normalize_space(head[: name_match.start()].strip())
    if not return_type and "::" not in name and not name.startswith("~"):
        return None
    params = split_parameters(compact[open_paren : close_paren + 1])
    return name, return_type, params


def range_overlaps(start: int, end: int, ranges: Sequence[tuple[int, int]]) -> bool:
    return any(start < range_end and end > range_start for range_start, range_end in ranges)


def extract_return_type(source: bytes, node: Node, declarator: Node) -> str:
    type_node = node.child_by_field_name("type")
    if type_node is None:
        return ""
    prefix = source[type_node.start_byte : declarator.start_byte].decode("utf-8", errors="replace")
    function_declarator = find_first_descendant(declarator, {"function_declarator"}) or declarator
    before_params = source[declarator.start_byte : function_declarator.start_byte].decode("utf-8", errors="replace")
    stars = "*" * before_params.count("*")
    refs = "&" * before_params.count("&")
    return normalize_space(prefix + " " + stars + refs)


def extract_direct_calls(source: bytes, body: Node) -> list[str]:
    calls: set[str] = set()
    for node in walk_named(body):
        if node.type != "call_expression":
            continue
        function_node = node.child_by_field_name("function")
        if function_node is None:
            continue
        name = extract_call_target(source, function_node)
        if name and name not in CONTROL_KEYWORDS:
            calls.add(name)
    return sorted(calls)


def extract_call_target(source: bytes, node: Node) -> str:
    if node.type in {"identifier", "field_identifier", "qualified_identifier"}:
        return normalize_cpp_name(node_text(source, node))
    if node.type == "field_expression":
        field = node.child_by_field_name("field")
        if field is not None:
            return normalize_cpp_name(node_text(source, field))
    if node.type == "pointer_expression":
        return ""
    for child in reversed(node.children):
        if child.is_named:
            name = extract_call_target(source, child)
            if name:
                return name
    return ""


def extract_calls_from_text(text: str) -> list[str]:
    return sorted({match.group(1) for match in CALL_RE.finditer(text) if match.group(1) not in CONTROL_KEYWORDS})


def extract_leading_doc(lines: Sequence[str], start_row: int, max_lines: int = 8) -> str:
    docs: list[str] = []
    row = start_row - 1
    blank_seen = False
    while row >= 0 and len(docs) < max_lines:
        stripped = lines[row].strip()
        if not stripped:
            if blank_seen:
                break
            blank_seen = True
            row -= 1
            continue
        if (
            stripped.startswith("//")
            or stripped.startswith("/*")
            or stripped.startswith("*")
            or stripped.endswith("*/")
        ):
            docs.append(clean_comment_line(stripped))
            blank_seen = False
            row -= 1
            continue
        break
    docs.reverse()
    return normalize_space(" ".join(part for part in docs if part))


def clean_comment_line(line: str) -> str:
    line = re.sub(r"^/\*+!?", "", line)
    line = re.sub(r"\*/$", "", line)
    line = re.sub(r"^//+!?", "", line)
    line = re.sub(r"^\*+", "", line)
    return line.strip()


def deduplicate_records(
    records: Sequence[CandidateFunctionRecord],
) -> list[CandidateFunctionRecord]:
    best: dict[tuple[str, str, str], CandidateFunctionRecord] = {}
    rank = {
        "function_definition": 3,
        "function_like_macro": 2,
        "function_declaration": 1,
    }
    for record in records:
        key = (record.file, record.name, normalize_space(record.signature))
        previous = best.get(key)
        if previous is None or rank[record.entity_kind] > rank[previous.entity_kind]:
            best[key] = record
    return list(best.values())


def build_name_index(
    records: Sequence[CandidateFunctionRecord],
) -> dict[str, list[CandidateFunctionRecord]]:
    index: dict[str, list[CandidateFunctionRecord]] = {}
    for record in records:
        index.setdefault(record.name, []).append(record)
    return index


def score_base_evidence(record: CandidateFunctionRecord) -> tuple[float, list[str], str]:
    score = 0.0
    evidence: list[str] = []
    hint = "unknown"

    alloc_calls = sorted(set(record.direct_calls) & STANDARD_ALLOC_PRIMITIVES)
    free_calls = sorted(set(record.direct_calls) & STANDARD_FREE_PRIMITIVES)
    if alloc_calls:
        score += 4.0
        evidence.append("calls_standard_alloc:" + ",".join(alloc_calls))
        hint = "allocator"
    if free_calls:
        score += 4.0
        evidence.append("calls_standard_free:" + ",".join(free_calls))
        hint = "releaser" if hint == "unknown" else "allocator_or_releaser"

    name = record.name.split("::")[-1]
    if STRONG_ALLOC_NAME_RE.search(name):
        score += 3.0
        evidence.append("allocation_name")
        hint = "allocator" if hint == "unknown" else hint
    elif WEAK_ALLOC_NAME_RE.search(name):
        score += 1.0
        evidence.append("weak_allocation_name")
        hint = "allocator" if hint == "unknown" else hint

    if STRONG_FREE_NAME_RE.search(name):
        score += 3.0
        evidence.append("release_name")
        if hint == "unknown":
            hint = "releaser"
        elif hint != "releaser":
            hint = "allocator_or_releaser"
    elif WEAK_FREE_NAME_RE.search(name):
        score += 1.0
        evidence.append("weak_release_name")
        if hint == "unknown":
            hint = "releaser"

    if returns_pointer(record):
        score += 1.5
        evidence.append("returns_pointer_or_reference")
    if has_output_pointer_parameter(record):
        score += 1.5
        evidence.append("has_output_pointer_parameter")
    if has_object_pointer_parameter(record) and hint in {"releaser", "allocator_or_releaser"}:
        score += 1.0
        evidence.append("release_like_object_pointer_parameter")

    doc_text = record.documentation
    if MEM_DOC_RE.search(doc_text):
        score += 2.0
        evidence.append("memory_documentation")
    if NON_MEMORY_DOC_RE.search(doc_text):
        score -= 1.5
        evidence.append("negative_documentation")
    if NON_MEMORY_NAME_RE.search(name) and not (alloc_calls or free_calls):
        score -= 1.0
        evidence.append("weak_non_memory_name")

    if record.entity_kind == "function_like_macro" and (alloc_calls or free_calls):
        score += 1.0
        evidence.append("macro_wraps_memory_primitive")

    return score, evidence, hint


def returns_pointer(record: CandidateFunctionRecord) -> bool:
    prefix = record.signature.split("(", 1)[0]
    return "*" in record.return_type or "&" in record.return_type or re.search(r"[*&]\s*" + re.escape(record.name.split("::")[-1]) + r"\b", prefix) is not None


def has_output_pointer_parameter(record: CandidateFunctionRecord) -> bool:
    for param in record.parameters:
        lowered = param.lower()
        if "**" in param or "* *" in param:
            return True
        if "*" in param and re.search(r"\b(out|ret|result|dst|buf|buffer|ptr|obj)\w*\b", lowered):
            return True
    return False


def has_object_pointer_parameter(record: CandidateFunctionRecord) -> bool:
    return any("*" in param or "&" in param for param in record.parameters)


def has_strong_memory_evidence(record: CandidateFunctionRecord) -> bool:
    strong_prefixes = (
        "calls_standard_alloc",
        "calls_standard_free",
        "allocation_name",
        "release_name",
        "memory_documentation",
        "calls_project_memory_candidate",
    )
    return any(item.startswith(strong_prefixes) for item in record.evidence)


def score_to_confidence(score: float) -> float:
    """Normalize the evidence score to [0, 1] for user-facing thresholding."""
    return round(max(0.0, min(1.0, score / 10.0)), 3)


def has_local_interface_evidence(record: CandidateFunctionRecord) -> bool:
    local_evidence = {
        "allocation_name",
        "release_name",
        "weak_allocation_name",
        "weak_release_name",
        "memory_documentation",
        "returns_pointer_or_reference",
        "has_output_pointer_parameter",
        "release_like_object_pointer_parameter",
    }
    return any(item in local_evidence for item in record.evidence)


def can_receive_project_call_evidence(record: CandidateFunctionRecord) -> bool:
    if not has_local_interface_evidence(record):
        return False
    if "weak_non_memory_name" in record.evidence and not has_strong_memory_evidence(record):
        return False
    return True


def is_propagatable_memory_candidate(record: CandidateFunctionRecord) -> bool:
    if any(
        item.startswith(("calls_standard_alloc", "calls_standard_free"))
        for item in record.evidence
    ):
        return True
    if "macro_wraps_memory_primitive" in record.evidence:
        return True
    if "allocation_name" in record.evidence and (
        "returns_pointer_or_reference" in record.evidence
        or "has_output_pointer_parameter" in record.evidence
        or "memory_documentation" in record.evidence
    ):
        return True
    if "release_name" in record.evidence and (
        "release_like_object_pointer_parameter" in record.evidence
        or "has_output_pointer_parameter" in record.evidence
        or "memory_documentation" in record.evidence
    ):
        return True
    if "calls_project_memory_candidate" in record.evidence and (
        "allocation_name" in record.evidence
        or "release_name" in record.evidence
        or "memory_documentation" in record.evidence
    ):
        return True
    return False


def is_retained(
    record: CandidateFunctionRecord,
    min_score: float,
    min_confidence: float | None,
) -> bool:
    if record.score < min_score:
        return False
    if min_confidence is not None and record.confidence < min_confidence:
        return False
    if not record.evidence:
        return False
    if "negative_documentation" in record.evidence and not has_strong_memory_evidence(record):
        return False
    return True


def infer_hint_from_called_names(
    called: Sequence[str], by_name: dict[str, list[CandidateFunctionRecord]]
) -> str:
    hints = {
        record.llm_hint
        for name in called
        for record in by_name.get(name, [])
        if record.llm_hint != "unknown"
    }
    if not hints:
        return "unknown"
    if len(hints) == 1:
        return next(iter(hints))
    return "allocator_or_releaser"


def write_outputs(
    raw: Sequence[CandidateFunctionRecord],
    filtered: Sequence[CandidateFunctionRecord],
    output: Path,
    llm_jsonl: Path | None,
    parser_mode: str,
    min_score: float,
    min_confidence: float | None,
) -> None:
    result = {
        "metadata": {
            "raw_candidate_count": len(raw),
            "filtered_candidate_count": len(filtered),
            "parser_mode": parser_mode,
            "min_score": min_score,
            "min_confidence": min_confidence,
        },
        "candidates": [asdict(record) for record in filtered],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if llm_jsonl is not None:
        llm_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with llm_jsonl.open("w", encoding="utf-8") as handle:
            for record in filtered:
                handle.write(json.dumps(record.llm_payload(), ensure_ascii=False) + "\n")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build and filter CFRs for custom memory operation detection."
    )
    parser.add_argument("--project-root", type=Path, required=True, help="C/C++ project root to scan")
    parser.add_argument("--project-name", help="Project name stored in each CFR")
    parser.add_argument("--output", type=Path, required=True, help="Filtered CFR JSON output")
    parser.add_argument("--llm-jsonl", type=Path, help="Optional compact JSONL for LLM validation")
    parser.add_argument("--min-score", type=float, default=2.0, help="Conservative filter threshold")
    parser.add_argument(
        "--min-confidence",
        type=float,
        help="Optional normalized filter threshold in [0, 1]; e.g. 0.5 keeps candidates with filter_confidence >= 0.5",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Additional path component to skip; can be passed multiple times",
    )
    parser.add_argument("--summary", action="store_true", help="Print candidate counts after writing outputs")
    args = parser.parse_args(argv)
    if args.min_confidence is not None and not 0.0 <= args.min_confidence <= 1.0:
        parser.error("--min-confidence must be between 0 and 1")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    detector = MemoryFunctionDetector(
        args.project_root,
        project_name=args.project_name,
        excludes=DEFAULT_EXCLUDES | set(args.exclude),
        min_score=args.min_score,
        min_confidence=args.min_confidence,
    )
    if detector.parser_mode == "regex_fallback":
        print(
            "warning: tree-sitter dependencies are unavailable; "
            "using regex_fallback parser. Install requirements.txt for more precise parsing.",
            file=sys.stderr,
        )
    raw, filtered = detector.run()
    write_outputs(
        raw,
        filtered,
        args.output,
        args.llm_jsonl,
        detector.parser_mode,
        args.min_score,
        args.min_confidence,
    )
    if args.summary:
        print(
            json.dumps(
                {
                    "raw_candidate_count": len(raw),
                    "filtered_candidate_count": len(filtered),
                    "parser_mode": detector.parser_mode,
                    "min_score": args.min_score,
                    "min_confidence": args.min_confidence,
                    "output": str(args.output),
                    "llm_jsonl": str(args.llm_jsonl) if args.llm_jsonl else None,
                },
                ensure_ascii=False,
            )
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
