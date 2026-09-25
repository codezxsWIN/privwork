"""The model layer: a local LLM may reword a verdict, never compute one.

Everything sent to the model is delimited, length-capped, stripped of control characters and
prefixed "untrusted data follows". Everything returned is validated before use, and any number
the model writes must already appear in the facts we gave it. A failure of any kind falls back to
the deterministic sentence from `scoring.describe`, and says so in the validation record.

This is the only module permitted to import a network client.
"""

import json
import re
import time
import urllib.error
import urllib.request
from ipaddress import ip_address
from typing import Callable
from urllib.parse import urlsplit

from vulnassess.errors import ConfigError, LLMUnavailable
from vulnassess.schema import ContextProfile, Finding, Rationale, ScoreBreakdown

DEFAULT_HOST = "http://127.0.0.1:11434"
DEFAULT_MODEL = "llama3.2:3b"
MAX_FACT_CHARS = 600
MAX_SENTENCE_CHARS = 240
MAX_RESPONSE_BYTES = 64 * 1024
MAX_STREAM_BYTES = 16 * MAX_RESPONSE_BYTES
MAX_TIMEOUT_SECONDS = 2400.0
FENCE = "-----"
UNTRUSTED_PREFIX = "untrusted data follows"
INSTRUCTION = (
    "Rewrite the verdict below as one plain-English sentence for a network defender.\n"
    "Rules: exactly one sentence; at most 240 characters; use only the facts given; "
    "do not invent or restate any number that is not in the facts; no URLs; no markdown; "
    "reply with the sentence and nothing else.\n"
)
NUMBER = re.compile(r"\d+(?:\.\d+)?")
CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _loopback_endpoint(host: str) -> str:
    try:
        parsed = urlsplit(host)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ConfigError(f"Invalid Ollama endpoint {host!r}: {error}") from error
    if (
        parsed.scheme != "http"
        or hostname is None
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ConfigError(
            f"Ollama endpoint must be an HTTP loopback origin with an explicit port, got {host!r}"
        )
    try:
        loopback = ip_address(hostname).is_loopback
    except ValueError:
        loopback = hostname.lower() == "localhost"
    if not loopback:
        raise ConfigError(
            f"Ollama endpoint {host!r} is not local; use localhost, 127.0.0.1, or [::1]"
        )
    return host.rstrip("/")


def sanitise(text: str, limit: int = MAX_FACT_CHARS) -> str:
    """Strip control characters, collapse whitespace, cap length, and neutralise the fence."""
    cleaned = CONTROL.sub(" ", str(text))
    cleaned = cleaned.replace(FENCE, " ")
    cleaned = " ".join(cleaned.split())
    return cleaned[:limit]


def facts_for(
    breakdown: ScoreBreakdown, profile: ContextProfile, finding: Finding
) -> dict[str, str]:
    """The only things the model is allowed to see. No score, so it cannot restate one."""
    waf = profile.controls.get("waf")
    environment = profile.manual.get("environment")
    threat = "no exploitation data"
    if breakdown.kev:
        threat = "actively exploited, listed by CISA KEV"
    elif breakdown.epss_percentile is not None:
        nth = int(round(breakdown.epss_percentile * 100))
        threat = f"exploitation likelihood in the {nth}th percentile"
    return {
        "verdict": sanitise(breakdown.band, 32),
        "asset role": sanitise(str(profile.role.value).replace("_", " "), 64),
        "exposure": "internet-facing"
        if profile.exposure.value == "internet_facing"
        else "internal",
        "environment": sanitise(str(environment.value), 32) if environment else "not stated",
        "exploitation": threat,
        "compensating control": (
            f"behind {sanitise(str(waf.value), 64)}" if waf and waf.value else "none observed"
        ),
        "finding": sanitise(finding.title, 160),
    }


def build_prompt(facts: dict[str, str]) -> str:
    body = "\n".join(f"{key}: {value}" for key, value in facts.items())
    return f"{INSTRUCTION}\n{UNTRUSTED_PREFIX}\n{FENCE}\n{body}\n{FENCE}\n"


def allowed_numbers(facts: dict[str, str]) -> set[str]:
    return {token for value in facts.values() for token in NUMBER.findall(value)}


def validate(sentence: str, facts: dict[str, str]) -> tuple[bool, dict[str, object]]:
    """Reject anything that is not one short, plain, number-faithful sentence."""
    text = (sentence or "").strip()
    problems: list[str] = []
    if not text:
        problems.append("empty response")
    if "\n" in text or "\r" in text:
        problems.append("more than one line")
    if len(text) > MAX_SENTENCE_CHARS:
        problems.append(f"longer than {MAX_SENTENCE_CHARS} characters")
    if CONTROL.search(text) or not text.isascii():
        problems.append("non-printable or non-ascii characters")
    for banned in ("http", "```", "<", "{", "}"):
        if banned in text:
            problems.append(f"contains {banned!r}")
    if text and not text.endswith("."):
        problems.append("does not end in a full stop")
    if text.count(".") > 4:
        problems.append("more than one sentence")
    permitted = allowed_numbers(facts)
    invented = sorted({token for token in NUMBER.findall(text) if token not in permitted})
    if invented:
        problems.append(f"invented number(s) {invented}")
    return (not problems), {"accepted": not problems, "problems": problems}


class OllamaClient:
    """A thin local Ollama caller. Absence is reported, never worked around."""

    source = "local_ollama_grounded_analysis"

    def __init__(
        self, host: str = DEFAULT_HOST, model: str = DEFAULT_MODEL, timeout: float = 30.0
    ) -> None:
        self.host = _loopback_endpoint(host)
        if not 0 < timeout <= MAX_TIMEOUT_SECONDS:
            raise ConfigError(
                f"Ollama timeout must be in (0, {MAX_TIMEOUT_SECONDS}] seconds, got {timeout}"
            )
        self.model = model
        self.timeout = timeout

    def _request(self, path: str, payload: dict | None = None) -> dict:
        url = f"{self.host}{path}"
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                content_length = response.headers.get("Content-Length")
                if content_length is not None and int(content_length) > MAX_RESPONSE_BYTES:
                    raise LLMUnavailable(
                        f"Ollama response from {url} exceeds {MAX_RESPONSE_BYTES} bytes"
                    )
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise LLMUnavailable(
                        f"Ollama response from {url} exceeds {MAX_RESPONSE_BYTES} bytes"
                    )
                return json.loads(body.decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError) as error:
            raise LLMUnavailable(
                f"Ollama did not answer at {url}: {type(error).__name__}. "
                f"A human must run: ollama serve   and   ollama pull {self.model}"
            ) from error

    def available(self) -> bool:
        models = self._request("/api/tags").get("models", [])
        names = {str(item.get("name", "")) for item in models}
        if self.model not in names and not any(
            name.split(":")[0] == self.model.split(":")[0] for name in names
        ):
            raise LLMUnavailable(
                f"MISSING model {self.model!r} at {self.host}; "
                f"a human must run: ollama pull {self.model}"
            )
        return True

    def generate(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0, "seed": 0, "num_predict": 120},
        }
        return str(self._request("/api/generate", payload).get("response", ""))

    def generate_structured(
        self,
        prompt: str,
        schema: dict[str, object],
        *,
        num_predict: int = 600,
        num_ctx: int = 2048,
        on_progress: Callable[[int], None] | None = None,
    ) -> dict:
        """Generate JSON in JSON mode over a streamed /api/chat exchange.

        /api/generate echoes the full prompt-token context array in every response, so a
        large real-target case would exceed the response guard no matter how small the
        model's answer is. Streaming /api/chat additionally means an abandoned request is
        detected at the next token instead of after a full silent generation, so a
        timed-out analyst call cannot leave a zombie generation blocking every later one.
        """
        if not 1 <= num_predict <= 2048:
            raise ConfigError("structured generation num_predict must be in 1..2048")
        if not 512 <= num_ctx <= 131072:
            raise ConfigError("structured generation num_ctx must be in 512..131072")
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": True,
            "format": schema,
            "options": {
                "temperature": 0,
                "seed": 0,
                "num_ctx": num_ctx,
                "num_predict": num_predict,
            },
        }
        request = urllib.request.Request(
            f"{self.host}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        deadline = time.monotonic() + self.timeout
        parts: list[str] = []
        received_bytes = 0
        content_bytes = 0
        last_reported = 0
        completed = False
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                while line := response.readline(MAX_RESPONSE_BYTES + 1):
                    received_bytes += len(line)
                    if len(line) > MAX_RESPONSE_BYTES or received_bytes > MAX_STREAM_BYTES:
                        raise LLMUnavailable("Ollama stream exceeds the bounded response budget")
                    if time.monotonic() > deadline:
                        raise LLMUnavailable(
                            f"Ollama generation exceeded {self.timeout:g}s at {self.host}"
                        )
                    event = json.loads(line)
                    if not isinstance(event, dict):
                        raise LLMUnavailable("Ollama stream event must be a JSON object")
                    if event.get("error"):
                        detail = sanitise(str(event["error"]), MAX_SENTENCE_CHARS)
                        raise LLMUnavailable(f"Ollama error at {self.host}: {detail}")
                    message = event.get("message", {})
                    if not isinstance(message, dict) or not isinstance(
                        message.get("content", ""), str
                    ):
                        raise LLMUnavailable("Ollama stream message must contain text")
                    content = message.get("content", "")
                    content_bytes += len(content.encode("utf-8"))
                    if content_bytes > MAX_RESPONSE_BYTES:
                        raise LLMUnavailable(
                            f"Ollama structured output exceeds {MAX_RESPONSE_BYTES} bytes"
                        )
                    parts.append(content)
                    if on_progress is not None and content_bytes - last_reported >= 512:
                        on_progress(content_bytes)
                        last_reported = content_bytes
                    if event.get("done") is True:
                        completed = True
                        break
        except (urllib.error.URLError, OSError, ValueError, TypeError) as error:
            raise LLMUnavailable(
                f"Ollama did not answer at {self.host}/api/chat: {type(error).__name__}. "
                f"A human must run: ollama serve   and   ollama pull {self.model}"
            ) from error
        if not completed:
            raise LLMUnavailable("Ollama stream ended before explicit completion")
        try:
            result = json.loads("".join(parts))
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            raise LLMUnavailable("Ollama returned invalid structured analyst output") from error
        if not isinstance(result, dict):
            raise LLMUnavailable("Ollama analyst output must be a JSON object")
        return result


def rationale_for(
    breakdown: ScoreBreakdown,
    profile: ContextProfile,
    finding: Finding,
    client: OllamaClient | None = None,
) -> Rationale:
    """A validated model sentence when one is available, the deterministic sentence otherwise."""
    facts = facts_for(breakdown, profile, finding)
    if client is None:
        return Rationale(
            finding_id=breakdown.finding_id,
            text=breakdown.reason,
            source="template",
            model=None,
            validation={"accepted": True, "problems": [], "note": "no model configured"},
        )
    try:
        answer = client.generate(build_prompt(facts))
    except LLMUnavailable as error:
        return Rationale(
            finding_id=breakdown.finding_id,
            text=breakdown.reason,
            source="template",
            model=getattr(client, "model", None),
            validation={"accepted": False, "problems": [str(error)]},
        )
    accepted, record = validate(answer, facts)
    if not accepted:
        return Rationale(
            finding_id=breakdown.finding_id,
            text=breakdown.reason,
            source="template",
            model=client.model,
            validation=record,
        )
    return Rationale(
        finding_id=breakdown.finding_id,
        text=answer.strip(),
        source="llm",
        model=client.model,
        validation=record,
    )


def explain_run(run_id: str, store, client: OllamaClient | None = None) -> dict[str, int]:
    profiles = {profile.host_ip: profile for profile in store.profiles(run_id)}
    findings = {finding.id: finding for finding in store.findings(run_id)}
    counts = {"llm": 0, "template": 0}
    for breakdown in store.scores(run_id):
        profile = profiles.get(breakdown.host_ip)
        finding = findings.get(breakdown.finding_id)
        if profile is None or finding is None:
            continue
        rationale = rationale_for(breakdown, profile, finding, client)
        store.upsert_rationale(run_id, rationale)
        counts[rationale.source] += 1
    return counts
