"""Pure, shared accessors for stored context facts."""

from typing import Any


def interpreted_control(record: dict[str, Any]) -> dict[str, Any]:
    """Read legacy 'none observed' rules as unknown without rewriting history."""
    feature = dict(record)
    if (
        feature.get("value") is False
        and feature.get("source") == "rule"
        and feature.get("evidence") == "none observed"
    ):
        feature["value"] = None
        feature["confidence"] = 0.0
    return feature
