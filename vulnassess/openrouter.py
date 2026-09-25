"""Opt-in, bounded OpenRouter analyst transport. Never used by scanner or scorer."""

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

from vulnassess.ai_boundary import SYSTEM_BOUNDARY_PROMPT
from vulnassess.errors import ConfigError, LLMUnavailable

MODEL = "deepseek/deepseek-v4-flash-0731:free"
ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MAX_RESPONSE_BYTES = 64 * 1024
MAX_PROMPT_BYTES = 20 * 1024
MAX_COMPLETION_TOKENS = 1200


def load_api_key() -> str:
    """Read a local ignored .env at request time so adding a key needs no restart."""
    value = os.environ.get("OPENROUTER_API_KEY", "").strip()
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
        if line.startswith("OPENROUTER_API_KEY="):
            return line.partition("=")[2].strip().strip("\"'")
    return ""


class OpenRouterClient:
    model = MODEL
    source = "openrouter_deepseek_grounded_analysis"

    def __init__(self, api_key: str | None = None, timeout: float = 120.0) -> None:
        if not 0 < timeout <= 120:
            raise ConfigError("OpenRouter timeout must be in (0, 120] seconds")
        self.key = api_key if api_key is not None else load_api_key()
        self.timeout = timeout

    def available(self) -> bool:
        if not self.key:
            raise LLMUnavailable("OPENROUTER_API_KEY is missing; add it to the local .env file")
        return True

    def generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any],
        *,
        num_predict: int = MAX_COMPLETION_TOKENS,
        num_ctx: int = 16384,
        on_progress: Callable[[int], None] | None = None,
        on_raw: Callable[[bytes], None] | None = None,
    ) -> dict[str, Any]:
        self.available()
        if len(prompt.encode("utf-8")) > MAX_PROMPT_BYTES:
            raise ConfigError("OpenRouter analyst prompt exceeds its byte budget")
        if not 1 <= num_predict <= MAX_COMPLETION_TOKENS:
            raise ConfigError("OpenRouter completion token budget exceeded")
        if not 512 <= num_ctx <= 131072:
            raise ConfigError("OpenRouter context budget is invalid")
        body = {
            "model": MODEL,
            "messages": [
                {"role": "system", "content": SYSTEM_BOUNDARY_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "vulnassess_analysis", "strict": True, "schema": schema},
            },
            "provider": {"data_collection": "deny", "require_parameters": True},
            "max_completion_tokens": num_predict,
            "temperature": 0,
            "stream": False,
        }
        request = urllib.request.Request(
            ENDPOINT,
            data=json.dumps(body, ensure_ascii=True).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.key}", "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            if error.code == 429:
                raise LLMUnavailable(
                    "DeepSeek free-model rate limit reached; local analysis remains available"
                ) from error
            if error.code == 404:
                try:
                    detail = json.loads(error.read(4096)).get("error", {}).get("message", "")
                except (ValueError, TypeError, AttributeError):
                    detail = ""
                if "unavailable for free" in detail:
                    raise LLMUnavailable(
                        "OpenRouter reports DeepSeek V4 Flash 0731 is unavailable for free. "
                        "Its paid endpoint was not used."
                    ) from error
                raise LLMUnavailable(
                    "DeepSeek free model has no available endpoint; no paid fallback attempted"
                ) from error
            if error.code in (401, 403):
                raise LLMUnavailable("OpenRouter rejected the API key or privacy policy") from error
            raise LLMUnavailable(
                f"OpenRouter request failed with HTTP {error.code}; no paid fallback attempted"
            ) from error
        except (urllib.error.URLError, OSError, TimeoutError) as error:
            raise LLMUnavailable(
                "OpenRouter is unavailable; no retry or paid fallback attempted"
            ) from error
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LLMUnavailable("OpenRouter response exceeded the byte budget")
        if on_progress is not None:
            on_progress(len(raw))
        if on_raw is not None:
            on_raw(raw)
        try:
            envelope = json.loads(raw)
            content = envelope["choices"][0]["message"]["content"]
            result = json.loads(content) if isinstance(content, str) else content
        except (ValueError, TypeError, KeyError, IndexError) as error:
            raise LLMUnavailable("OpenRouter returned an invalid structured response") from error
        if not isinstance(result, dict):
            raise LLMUnavailable("OpenRouter analyst response must be a JSON object")
        return result
