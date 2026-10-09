"""Core application health information."""


def get_health() -> dict[str, str]:
    """Return the current application health status."""
    return {"application": "SugiSOC", "status": "ok", "version": "0.1.0"}
