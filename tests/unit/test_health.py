"""Tests for SugiSOC application health."""

from sugisoc.core.health import get_health


def test_application_health() -> None:
    result = get_health()
    assert result["application"] == "SugiSOC"
    assert result["status"] == "ok"
    assert result["version"] == "0.1.0"
