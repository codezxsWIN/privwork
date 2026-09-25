"""Opt-in Groq analyst transport; never used to drive scans or scoring."""

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from vulnassess.errors import ConfigError, LLMUnavailable

MODEL = "openai/gpt-oss-120b"
ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
MAX_PROMPT_BYTES = 20 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MAX_COMPLETION_TOKENS = 800


def load_api_key() -> str:
    value = os.environ.get("GROQ_API_KEY", "").strip()
    if value:
        return value
    path = Path(__file__).resolve().parents[1] / ".env"
    if not path.is_file():
        return ""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ConfigError("Cannot read the local .env file") from error
    for line in lines:
        if line.startswith("GROQ_API_KEY="):
            return line.partition("=")[2].strip().strip("\"'")
    return ""


class GroqClient:
    model = MODEL
    source = "groq_gpt_oss_120b_grounded_analysis"

    def __init__(self, api_key: str | None = None, timeout: float = 120.0) -> None:
        if not 0 < timeout <= 120:
            raise ConfigError("Groq timeout must be in (0, 120] seconds")
        self.key = api_key if api_key is not None else load_api_key()
        self.timeout = timeout

    def available(self) -> bool:
        if not self.key:
            raise LLMUnavailable("GROQ_API_KEY is missing; add it to the local .env file")
        return True

    def generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any],
        *,
        num_predict: int = MAX_COMPLETION_TOKENS,
        num_ctx: int = 16384,
        on_progress: Callable[[int], None] | None = None,
    ) -> dict[str, Any]:
        self.available()
        if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise ConfigError("Groq analyst prompt exceeds its byte budget")
        if not 1 <= num_predict <= MAX_COMPLETION_TOKENS:
            raise ConfigError("Groq completion token budget exceeded")
        if not 512 <= num_ctx <= 131072:
            raise ConfigError("Groq context budget is invalid")
        body = {
            "model": MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "vulnassess_analysis", "strict": True, "schema": schema},
            },
            "reasoning_effort": "low",
            "max_completion_tokens": num_predict,
            "temperature": 0,
            "stream": False,
        }
        request = urllib.request.Request(
            ENDPOINT,
            data=json.dumps(body, ensure_ascii=True).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
                "User-Agent": "VulnAssess/0.1",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            if error.code == 429:
                raise LLMUnavailable("Groq rate limit reached; no automatic retry") from error
            if error.code in (401, 403):
                raise LLMUnavailable("Groq rejected the API key or account access") from error
            raise LLMUnavailable(
                f"Groq request failed with HTTP {error.code}; no automatic retry"
            ) from error
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            raise LLMUnavailable("Groq is unavailable; no automatic retry") from error
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LLMUnavailable("Groq response exceeded the byte budget")
        if on_progress is not None:
            on_progress(len(raw))
        try:
            envelope = json.loads(raw)
            content = envelope["choices"][0]["message"]["content"]
            result = json.loads(content) if isinstance(content, str) else content
        except (ValueError, TypeError, KeyError, IndexError) as error:
            raise LLMUnavailable("Groq returned an invalid structured response") from error
        if not isinstance(result, dict):
            raise LLMUnavailable("Groq analyst response must be a JSON object")
        return result
