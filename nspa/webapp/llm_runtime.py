from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from urllib.parse import urlunparse

from nspa.llm_semantic_validator import (
    DEFAULT_BASE_URL,
    DEFAULT_CHAT_PATH,
    DEFAULT_MODEL,
)


@dataclass(frozen=True, slots=True)
class LLMRuntime:
    model: str
    base_url: str
    chat_path: str
    api_key_env: str
    api_key: str | None
    timeout: float
    local_endpoint: bool
    custom_endpoint: bool
    configured: bool

    @property
    def authenticated(self) -> bool:
        return bool(self.api_key)


ENVIRONMENT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def is_environment_variable_name(value: str) -> bool:
    return bool(ENVIRONMENT_NAME_RE.fullmatch(value))


def docker_host_url(base_url: str) -> str:
    """Map host loopback URLs to Docker Desktop's host gateway."""
    if not Path("/.dockerenv").exists():
        return base_url
    try:
        parsed = urlparse(base_url)
        hostname = (parsed.hostname or "").lower()
        address = ipaddress.ip_address(hostname) if hostname else None
    except (ValueError, OSError):
        address = None
        hostname = (urlparse(base_url).hostname or "").lower()
    if hostname != "localhost" and not (address and address.is_loopback):
        return base_url
    port = f":{parsed.port}" if parsed.port else ""
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        userinfo += "@"
    return urlunparse(parsed._replace(netloc=f"{userinfo}host.docker.internal{port}"))


def is_local_llm_endpoint(base_url: str) -> bool:
    """Return whether an HTTP endpoint belongs to the local/private network."""
    try:
        hostname = (urlparse(base_url).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    if not hostname:
        return False
    if hostname in {"localhost", "host.docker.internal"} or hostname.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        # A single-label host is normally a Docker Compose service name.
        return "." not in hostname
    return address.is_loopback or address.is_private or address.is_link_local


def resolve_llm_runtime(settings: dict[str, str]) -> LLMRuntime:
    model = (
        settings.get("llm_model")
        or os.environ.get("NSPA_LLM_MODEL")
        or DEFAULT_MODEL
    ).strip()
    base_url = docker_host_url((
        settings.get("llm_base_url")
        or os.environ.get("NSPA_LLM_BASE_URL")
        or DEFAULT_BASE_URL
    ).strip().rstrip("/"))
    chat_path = (
        settings.get("llm_chat_path")
        or os.environ.get("NSPA_LLM_CHAT_PATH")
        or DEFAULT_CHAT_PATH
    ).strip()
    configured_key = settings.get("llm_api_key", "").strip()
    raw_api_key_env = settings.get("llm_api_key_env", "OPENAI_API_KEY").strip()
    # Older UI versions accidentally encouraged users to paste the literal
    # key into the environment-variable field.  Keep those local settings
    # working while the API migrates them to llm_api_key.
    legacy_literal_key = (
        raw_api_key_env if raw_api_key_env and not is_environment_variable_name(raw_api_key_env) else ""
    )
    api_key_env = "" if legacy_literal_key else raw_api_key_env
    api_key = configured_key or legacy_literal_key or None
    if not api_key and api_key_env:
        api_key = os.environ.get(api_key_env)
    try:
        timeout = float(settings.get("llm_timeout", "120"))
    except (TypeError, ValueError):
        timeout = 120.0
    local_endpoint = is_local_llm_endpoint(base_url)
    custom_endpoint = base_url.rstrip("/") != DEFAULT_BASE_URL.rstrip("/")
    # The stock OpenAI endpoint still requires a key.  A custom endpoint is
    # allowed to use no authentication, as is common for Ollama, vLLM, LM
    # Studio and other locally deployed OpenAI-compatible services.
    configured = bool(model and base_url and chat_path) and bool(
        api_key or local_endpoint or custom_endpoint
    )
    return LLMRuntime(
        model=model,
        base_url=base_url,
        chat_path=chat_path,
        api_key_env=api_key_env,
        api_key=api_key,
        timeout=timeout,
        local_endpoint=local_endpoint,
        custom_endpoint=custom_endpoint,
        configured=configured,
    )
