"""The cloud analyst never needs a real key or network for contract tests."""

import io
import json
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from vulnassess.errors import LLMUnavailable
from vulnassess.openrouter import MODEL, OpenRouterClient


class Response:
    def __init__(self, payload):
        self.body = io.BytesIO(json.dumps(payload).encode())
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, size):
        return self.body.read(size)


def test_fixed_free_model_and_bounded_structured_request():
    expected = {"summary": "Synthetic only"}
    with patch(
        "vulnassess.openrouter.urllib.request.urlopen",
        return_value=Response({"choices": [{"message": {"content": json.dumps(expected)}}]}),
    ) as send:
        client = OpenRouterClient(api_key="synthetic-test-key")
        assert client.available()
        assert (
            client.generate_structured("synthetic prompt", {"type": "object"}, num_ctx=16384)
            == expected
        )
    request = send.call_args.args[0]
    body = json.loads(request.data)
    assert body["model"] == MODEL
    assert body["provider"]["data_collection"] == "deny"
    assert body["response_format"]["type"] == "json_schema"
    assert body["stream"] is False
    assert request.get_header("Authorization") == "Bearer synthetic-test-key"


def test_rate_limit_fails_once_without_retry_or_paid_fallback():
    error = HTTPError(
        "https://openrouter.ai/api/v1/chat/completions", 429, "Too Many Requests", {}, None
    )
    with patch("vulnassess.openrouter.urllib.request.urlopen", side_effect=error) as send:
        with pytest.raises(LLMUnavailable, match="rate limit"):
            OpenRouterClient(api_key="synthetic-test-key").generate_structured(
                "x", {"type": "object"}
            )
    assert send.call_count == 1


def test_missing_free_endpoint_never_switches_to_paid_model():
    error = HTTPError("https://openrouter.ai/api/v1/chat/completions", 404, "Not Found", {}, None)
    with patch("vulnassess.openrouter.urllib.request.urlopen", side_effect=error) as send:
        with pytest.raises(LLMUnavailable, match="no available endpoint"):
            OpenRouterClient(api_key="synthetic-test-key").generate_structured(
                "x", {"type": "object"}
            )
    assert send.call_count == 1


def test_free_model_404_explains_paid_only_response_without_leaking_envelope():
    error = HTTPError(
        "https://openrouter.ai/api/v1/chat/completions",
        404,
        "Not Found",
        {},
        io.BytesIO(
            json.dumps(
                {
                    "error": {
                        "message": "This model is unavailable for free. The paid version is available now"
                    },
                    "user_id": "private-account-id",
                }
            ).encode()
        ),
    )
    with patch("vulnassess.openrouter.urllib.request.urlopen", side_effect=error):
        with pytest.raises(LLMUnavailable, match="unavailable for free") as raised:
            OpenRouterClient(api_key="synthetic-test-key").generate_structured(
                "x", {"type": "object"}
            )
    assert "private-account-id" not in str(raised.value)


def test_missing_key_fails_before_network():
    with patch(
        "vulnassess.openrouter.urllib.request.urlopen", side_effect=AssertionError("network")
    ):
        with pytest.raises(LLMUnavailable, match="OPENROUTER_API_KEY"):
            OpenRouterClient(api_key="").available()
