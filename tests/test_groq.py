"""Groq transport contract: bounded, explicit, and secret-safe."""

import json
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from vulnassess.errors import LLMUnavailable
from vulnassess.groq import MODEL, GroqClient


class Response:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def read(self, *_):
        return json.dumps({"choices": [{"message": {"content": '{"summary":"ok"}'}}]}).encode()


def test_groq_uses_bounded_structured_request():
    client = GroqClient(api_key="test-only")
    with patch("vulnassess.groq.urllib.request.urlopen", return_value=Response()) as send:
        assert client.generate_structured("case", {"type": "object"}) == {"summary": "ok"}
    request = send.call_args.args[0]
    body = json.loads(request.data)
    assert request.full_url == "https://api.groq.com/openai/v1/chat/completions"
    assert request.get_header("User-agent") == "VulnAssess/0.1"
    assert body["model"] == MODEL
    assert body["model"] == "openai/gpt-oss-120b"
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["max_completion_tokens"] <= 800
    assert "test-only" not in json.dumps(body)


def test_groq_rate_limit_does_not_echo_key():
    client = GroqClient(api_key="test-only")
    error = HTTPError(
        "https://api.groq.com/openai/v1/chat/completions", 429, "rate limit", {}, None
    )
    with patch("vulnassess.groq.urllib.request.urlopen", side_effect=error):
        with pytest.raises(LLMUnavailable, match="rate limit") as caught:
            client.generate_structured("case", {"type": "object"})
    assert "test-only" not in str(caught.value)
