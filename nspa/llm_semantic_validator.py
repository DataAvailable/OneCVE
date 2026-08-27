"""Validate memory-operation CFRs with an OpenAI-compatible LLM API."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import random
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence


VALID_CATEGORIES = {
    "allocator",
    "releaser",
    "destroyer",
    "non_memory",
}
MEMORY_CATEGORIES = {
    "allocator",
    "releaser",
    "destroyer",
}
DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_CHAT_PATH = "/chat/completions"
RETRYABLE_HTTP_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}
RETRYABLE_NETWORK_ERRORS = (
    urllib.error.URLError,
    http.client.RemoteDisconnected,
    http.client.IncompleteRead,
    http.client.HTTPException,
    TimeoutError,
    ConnectionError,
    ConnectionResetError,
    socket.timeout,
)


SYSTEM_PROMPT = """You are validating C/C++ project-specific memory operation functions.

Classify each Candidate Function Record (CFR) into exactly one category:
- allocator: creates/acquires dynamic memory or an owned object and returns/transfers it to the caller through a return value or output parameter.
- releaser: releases/deallocates caller-owned memory, object fields, references, or handles passed to the function.
- destroyer: ends the lifetime of a whole object/container/resource and may release nested memory; use this when the function's interface is object destruction rather than a simple free wrapper.
- non_memory: not a custom allocation/release/destroy interface. This includes functions that only allocate temporary memory internally and release it before returning.

Return JSON only, with this schema:
{"results":[{"id":"...","category":"allocator|releaser|destroyer|non_memory","confidence":0.0-1.0,"reason":"short reason"}]}"""


@dataclass(slots=True)
class ValidationResult:
    id: str
    project: str
    file: str
    name: str
    signature: str
    category: str
    confidence: float
    reason: str
    cfr: dict[str, Any]

    @property
    def is_memory_function(self) -> bool:
        return self.category in MEMORY_CATEGORIES

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "project": self.project,
            "file": self.file,
            "name": self.name,
            "signature": self.signature,
            "category": self.category,
            "confidence": self.confidence,
            "reason": self.reason,
            "cfr": self.cfr,
        }


class OpenAICompatibleClient:
    """Tiny client for /chat/completions-compatible APIs."""

    def __init__(
        self,
        *,
        api_key: str | None,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        temperature: float = 0.0,
        timeout: float = 60.0,
        max_retries: int = 3,
        json_mode: bool = True,
        chat_path: str = DEFAULT_CHAT_PATH,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self.json_mode = json_mode
        self.chat_path = "/" + chat_path.strip("/")

    @property
    def chat_url(self) -> str:
        return f"{self.base_url}{self.chat_path}"

    def complete_json(self, messages: Sequence[dict[str, str]]) -> dict[str, Any]:
        payload = {
            "model": self.model,
            "messages": list(messages),
            "temperature": self.temperature,
        }
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}
        body = json.dumps(payload).encode("utf-8")

        last_error: Exception | None = None
        last_detail = ""
        for attempt in range(self.max_retries + 1):
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            request = urllib.request.Request(
                self.chat_url,
                data=body,
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    raw = response.read().decode("utf-8")
                data = json.loads(raw)
                content = data["choices"][0]["message"]["content"]
                return parse_json_object(content)
            except urllib.error.HTTPError as exc:
                last_error = exc
                last_detail = read_http_error_body(exc)
                if exc.code not in RETRYABLE_HTTP_STATUS:
                    break
                if attempt >= self.max_retries:
                    break
                sleep_before_retry(attempt)
            except RETRYABLE_NETWORK_ERRORS as exc:
                last_error = exc
                if attempt >= self.max_retries:
                    break
                sleep_before_retry(attempt)
            except (KeyError, json.JSONDecodeError) as exc:
                last_error = exc
                break
        raise RuntimeError(format_api_error(self.chat_url, last_error, last_detail)) from last_error


class HeuristicClient:
    """Deterministic local validator for tests and dry runs."""

    def complete_json(self, messages: Sequence[dict[str, str]]) -> dict[str, Any]:
        user_payload = parse_json_object(messages[-1]["content"])
        results = []
        for cfr in user_payload["candidates"]:
            category, confidence, reason = classify_heuristically(cfr)
            results.append(
                {
                    "id": cfr["id"],
                    "category": category,
                    "confidence": confidence,
                    "reason": reason,
                }
            )
        return {"results": results}


def classify_heuristically(cfr: dict[str, Any]) -> tuple[str, float, str]:
    name = str(cfr.get("name", "")).lower()
    hint = str(cfr.get("candidate_hint", "")).lower()
    evidence = " ".join(str(item).lower() for item in cfr.get("filter_evidence", []))
    calls = set(cfr.get("direct_calls", []))

    if "calls_standard_alloc" in evidence or hint == "allocator" or any(
        call in calls for call in {"malloc", "calloc", "realloc", "strdup"}
    ):
        return "allocator", 0.82, "Allocation evidence in calls, hint, or filter evidence."
    if any(token in name for token in ("destroy", "delete", "dispose", "teardown")):
        return "destroyer", 0.78, "Name indicates object lifetime destruction."
    if "calls_standard_free" in evidence or hint == "releaser" or "release_name" in evidence:
        return "releaser", 0.78, "Release evidence in calls, hint, or filter evidence."
    return "non_memory", 0.55, "Insufficient ownership-transfer or lifecycle evidence."


def load_cfr_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            record.setdefault("id", cfr_id(record))
            records.append(record)
    return records


def cfr_id(record: dict[str, Any]) -> str:
    return "|".join(
        [
            str(record.get("project", "")),
            str(record.get("file", "")),
            str(record.get("name", "")),
            str(record.get("signature", "")),
        ]
    )


def compact_cfr(record: dict[str, Any]) -> dict[str, Any]:
    keep = {
        "id",
        "project",
        "file",
        "name",
        "entity_kind",
        "signature",
        "return_type",
        "parameters",
        "direct_calls",
        "documentation",
        "macro_value",
        "filter_evidence",
        "filter_score",
        "filter_confidence",
        "candidate_hint",
    }
    compact = {key: record.get(key) for key in keep if key in record}
    compact.setdefault("id", cfr_id(record))
    return compact


def batched(items: Sequence[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    for index in range(0, len(items), size):
        yield list(items[index : index + size])


def build_messages(batch: Sequence[dict[str, Any]]) -> list[dict[str, str]]:
    payload = {"candidates": [compact_cfr(record) for record in batch]}
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        },
    ]


def parse_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if match is None:
            raise
        return json.loads(match.group(0))


def read_http_error_body(error: urllib.error.HTTPError, limit: int = 2000) -> str:
    try:
        body = error.read().decode("utf-8", errors="replace")
    except Exception:
        return ""
    body = body.strip()
    if len(body) > limit:
        return body[:limit] + "...<truncated>"
    return body


def sleep_before_retry(attempt: int) -> None:
    delay = min(2**attempt, 10) + random.uniform(0.0, 0.25)
    time.sleep(delay)


def format_api_error(url: str, error: Exception | None, detail: str) -> str:
    lines = ["LLM API request failed."]
    lines.append(f"request_url: {url}")
    if isinstance(error, urllib.error.HTTPError):
        lines.append(f"http_status: {error.code} {error.reason}")
        if detail:
            lines.append(f"response_body: {detail}")
        if error.code == 404:
            lines.append(
                "hint: 404 usually means the endpoint path is wrong or the model name is unavailable on this provider. "
                "Check --base-url, --chat-path, and --model."
            )
    elif error is not None:
        lines.append(f"error_type: {type(error).__name__}")
        lines.append(f"error: {error}")
        if isinstance(error, RETRYABLE_NETWORK_ERRORS):
            lines.append(
                "hint: This is a retryable network/provider disconnection. "
                "Try smaller --batch-size, larger --max-retries, or --request-delay if it persists."
            )
    lines.append("hint: For providers that reject response_format, add --no-json-mode.")
    return "\n".join(lines)


def normalize_category(value: Any) -> str:
    category = str(value or "non_memory").strip().lower()
    aliases = {
        "allocation": "allocator",
        "alloc": "allocator",
        "memory_allocation": "allocator",
        "free": "releaser",
        "release": "releaser",
        "deallocator": "releaser",
        "destructor": "destroyer",
        "destroy": "destroyer",
        "none": "non_memory",
        "non-memory": "non_memory",
        "not_memory": "non_memory",
    }
    category = aliases.get(category, category)
    return category if category in VALID_CATEGORIES else "non_memory"


def normalize_confidence(value: Any) -> float:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, min(1.0, confidence)), 3)


def validation_results_from_response(
    response: dict[str, Any],
    cfr_by_id: dict[str, dict[str, Any]],
) -> list[ValidationResult]:
    raw_results = response.get("results", [])
    if not isinstance(raw_results, list):
        raise ValueError("LLM response must contain a results array")

    parsed: list[ValidationResult] = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        result_id = str(item.get("id", ""))
        cfr = cfr_by_id.get(result_id)
        if cfr is None:
            continue
        parsed.append(
            ValidationResult(
                id=result_id,
                project=str(cfr.get("project", "")),
                file=str(cfr.get("file", "")),
                name=str(cfr.get("name", "")),
                signature=str(cfr.get("signature", "")),
                category=normalize_category(item.get("category")),
                confidence=normalize_confidence(item.get("confidence")),
                reason=str(item.get("reason", "")).strip(),
                cfr=cfr,
            )
        )
    return parsed


def load_checkpoint(path: Path | None) -> dict[str, ValidationResult]:
    if path is None or not path.exists():
        return {}
    results: dict[str, ValidationResult] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            data = json.loads(line)
            result = ValidationResult(
                id=str(data["id"]),
                project=str(data.get("project", "")),
                file=str(data.get("file", "")),
                name=str(data.get("name", "")),
                signature=str(data.get("signature", "")),
                category=normalize_category(data.get("category")),
                confidence=normalize_confidence(data.get("confidence")),
                reason=str(data.get("reason", "")),
                cfr=dict(data.get("cfr", {})),
            )
            results[result.id] = result
    return results


def append_checkpoint(path: Path | None, results: Iterable[ValidationResult]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")


def validate_records(
    records: Sequence[dict[str, Any]],
    client: Any,
    *,
    batch_size: int,
    checkpoint: Path | None,
    min_batch_size: int = 1,
    request_delay: float = 0.0,
    progress: bool = False,
) -> list[ValidationResult]:
    completed = load_checkpoint(checkpoint)
    pending = [record for record in records if record["id"] not in completed]
    cfr_by_id = {record["id"]: record for record in records}
    processed = len(records) - len(pending)

    for batch in batched(pending, batch_size):
        results = validate_batch_resilient(
            batch,
            client,
            cfr_by_id,
            min_batch_size=min_batch_size,
        )
        if not results:
            continue
        append_checkpoint(checkpoint, results)
        completed.update({result.id: result for result in results})
        processed += len(results)
        if progress:
            print(
                f"validated {processed}/{len(records)} CFRs; checkpoint={checkpoint}",
                file=sys.stderr,
                flush=True,
            )
        if request_delay > 0:
            time.sleep(request_delay)

    return [completed[record["id"]] for record in records if record["id"] in completed]


def validate_batch_resilient(
    batch: Sequence[dict[str, Any]],
    client: Any,
    cfr_by_id: dict[str, dict[str, Any]],
    *,
    min_batch_size: int,
) -> list[ValidationResult]:
    try:
        response = client.complete_json(build_messages(batch))
        return validation_results_from_response(response, cfr_by_id)
    except RuntimeError:
        if len(batch) <= max(1, min_batch_size):
            raise
        midpoint = len(batch) // 2
        return validate_batch_resilient(
            batch[:midpoint],
            client,
            cfr_by_id,
            min_batch_size=min_batch_size,
        ) + validate_batch_resilient(
            batch[midpoint:],
            client,
            cfr_by_id,
            min_batch_size=min_batch_size,
        )


def write_validation_output(
    results: Sequence[ValidationResult],
    output: Path,
    *,
    include_non_memory: bool,
    min_llm_confidence: float,
    model: str,
    base_url: str,
    checkpoint: Path | None,
) -> None:
    kept = [
        result
        for result in results
        if result.confidence >= min_llm_confidence
        and (include_non_memory or result.is_memory_function)
    ]
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": {
            "validated_count": len(results),
            "kept_count": len(kept),
            "min_llm_confidence": min_llm_confidence,
            "model": model,
            "base_url": redact_base_url(base_url),
            "checkpoint": str(checkpoint) if checkpoint else None,
        },
        "functions": [result.to_dict() for result in kept],
    }
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def redact_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate filtered CFR JSONL with an OpenAI-compatible LLM API."
    )
    parser.add_argument("--input", type=Path, required=True, help="Filtered CFR JSONL from memory_function_detector")
    parser.add_argument("--output", type=Path, required=True, help="Final validated memory-function JSON")
    parser.add_argument("--checkpoint-jsonl", type=Path, help="Resume file for per-record LLM validation results")
    parser.add_argument("--model", default=os.environ.get("NSPA_LLM_MODEL", DEFAULT_MODEL))
    parser.add_argument("--base-url", default=os.environ.get("NSPA_LLM_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument(
        "--chat-path",
        default=os.environ.get("NSPA_LLM_CHAT_PATH", DEFAULT_CHAT_PATH),
        help="Chat completions path appended to --base-url; default: /chat/completions",
    )
    parser.add_argument("--api-key-env", default="OPENAI_API_KEY", help="Environment variable containing the API key")
    parser.add_argument("--batch-size", type=int, default=8, help="Number of CFRs per LLM request")
    parser.add_argument(
        "--min-batch-size",
        type=int,
        default=1,
        help="Smallest batch size used when automatically splitting failed batches",
    )
    parser.add_argument(
        "--request-delay",
        type=float,
        default=0.0,
        help="Seconds to sleep after each successful batch; useful for rate-limited providers",
    )
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument(
        "--no-json-mode",
        action="store_true",
        help="Do not send response_format=json_object for APIs that do not support it",
    )
    parser.add_argument("--limit", type=int, help="Validate only the first N input records")
    parser.add_argument("--min-llm-confidence", type=float, default=0.5, help="Keep LLM results with confidence >= this value")
    parser.add_argument("--include-non-memory", action="store_true", help="Keep non_memory classifications in the output")
    parser.add_argument("--dry-run", action="store_true", help="Use a deterministic local heuristic instead of calling an API")
    parser.add_argument("--progress", action="store_true", help="Print checkpoint progress to stderr after each batch")
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args(argv)

    if args.batch_size < 1:
        parser.error("--batch-size must be >= 1")
    if args.min_batch_size < 1:
        parser.error("--min-batch-size must be >= 1")
    if args.min_batch_size > args.batch_size:
        parser.error("--min-batch-size must be <= --batch-size")
    if args.request_delay < 0:
        parser.error("--request-delay must be >= 0")
    if not 0.0 <= args.min_llm_confidence <= 1.0:
        parser.error("--min-llm-confidence must be between 0 and 1")
    return args


def make_client(args: argparse.Namespace) -> Any:
    if args.dry_run:
        return HeuristicClient()
    api_key = os.environ.get(args.api_key_env)
    if not api_key:
        raise SystemExit(
            f"Missing API key. Set {args.api_key_env}, or pass --dry-run for local heuristic validation."
        )
    return OpenAICompatibleClient(
        api_key=api_key,
        base_url=args.base_url,
        model=args.model,
        temperature=args.temperature,
        timeout=args.timeout,
        max_retries=args.max_retries,
        json_mode=not args.no_json_mode,
        chat_path=args.chat_path,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    records = load_cfr_jsonl(args.input)
    if args.limit is not None:
        records = records[: args.limit]

    checkpoint = args.checkpoint_jsonl
    if checkpoint is None:
        checkpoint = args.output.with_suffix(args.output.suffix + ".checkpoint.jsonl")

    client = make_client(args)
    try:
        results = validate_records(
            records,
            client,
            batch_size=args.batch_size,
            checkpoint=checkpoint,
            min_batch_size=args.min_batch_size,
            request_delay=args.request_delay,
            progress=args.progress,
        )
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    write_validation_output(
        results,
        args.output,
        include_non_memory=args.include_non_memory,
        min_llm_confidence=args.min_llm_confidence,
        model=args.model if not args.dry_run else "dry-run-heuristic",
        base_url=args.base_url,
        checkpoint=checkpoint,
    )

    kept_count = sum(
        1
        for result in results
        if result.confidence >= args.min_llm_confidence
        and (args.include_non_memory or result.is_memory_function)
    )
    if args.summary:
        print(
            json.dumps(
                {
                    "input_count": len(records),
                    "validated_count": len(results),
                    "kept_count": kept_count,
                    "output": str(args.output),
                    "checkpoint_jsonl": str(checkpoint),
                    "dry_run": args.dry_run,
                },
                ensure_ascii=False,
            )
        )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
