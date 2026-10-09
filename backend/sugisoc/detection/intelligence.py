"""Safe offline indicator context; never labels unverified IPs as malicious."""

import ipaddress
import json
from pathlib import Path


def load_indicators(path: Path) -> dict[str, str]:
    """Load explicitly attributed, locally reviewed IP indicators only."""
    content = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(content, list) or len(content) > 10000:
        raise ValueError("Indicators must be a bounded list")
    result = {}
    for row in content:
        if not isinstance(row, dict) or set(row) != {"ip", "source", "context"}:
            raise ValueError("Each indicator needs ip, source and context")
        address = str(ipaddress.ip_address(row["ip"]))
        source, context = row["source"], row["context"]
        if not all(isinstance(v, str) and 1 <= len(v) <= 250 for v in (source, context)):
            raise ValueError("Attribution and context required")
        if address in result:
            raise ValueError("Duplicate indicator")
        result[address] = f"{context} (source: {source})"
    return result


def lookup_ip(ip: str, indicators: dict[str, str]) -> dict[str, str | bool]:
    """A match is only context, not proof of a real attack."""
    normalized = str(ipaddress.ip_address(ip))
    detail = indicators.get(normalized)
    return {
        "ip": normalized,
        "matched": detail is not None,
        "context": detail or "No match in the provided offline indicator set",
    }
