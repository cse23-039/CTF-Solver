from __future__ import annotations

from collections import defaultdict
from typing import Any

from .crypto import CRYPTO_TOOLS
from .pwn import PWN_TOOLS
from .web import WEB_TOOLS


CATEGORY_ORDER = ("web", "pwn", "crypto", "other")


def categorize_tool(name: str) -> str:
    if name in WEB_TOOLS:
        return "web"
    if name in PWN_TOOLS:
        return "pwn"
    if name in CRYPTO_TOOLS:
        return "crypto"
    return "other"


def build_tool_registry(tools: list[dict[str, Any]], tool_map: dict[str, Any]) -> dict[str, Any]:
    by_name = {t.get("name", ""): t for t in tools if isinstance(t, dict) and t.get("name")}
    grouped: dict[str, list[str]] = defaultdict(list)
    for name in by_name:
        grouped[categorize_tool(name)].append(name)

    for cat in grouped:
        grouped[cat].sort()

    return {
        "tools": by_name,
        "tool_map": tool_map,
        "grouped": {k: grouped.get(k, []) for k in CATEGORY_ORDER},
    }


def enabled_tools(registry: dict[str, Any], enabled_names: set[str]) -> list[dict[str, Any]]:
    by_name = registry.get("tools", {})
    out = []
    for name in enabled_names:
        if name in by_name:
            out.append(by_name[name])
    return out
