from __future__ import annotations

from collections import defaultdict
import importlib.util
import shutil
from typing import Any

from .crypto import CRYPTO_TOOLS
from .pwn import PWN_TOOLS
from .web import WEB_TOOLS


CATEGORY_ORDER = ("web", "pwn", "crypto", "other")

_TOOL_CAPABILITIES: dict[str, dict[str, list[str]]] = {
    "sqlmap": {"commands": ["sqlmap"]},
    "ffuf": {"commands": ["ffuf"]},
    "ghidra_decompile": {"commands": ["analyzeHeadless", "ghidra_headless"]},
    "angr_solve": {"python": ["angr"]},
    "frida_trace": {"python": ["frida"]},
    "volatility": {"commands": ["vol"]},
    "apk_analyze": {"commands": ["apktool", "jadx"]},
    "apk_resign": {"commands": ["apktool", "apksigner", "jarsigner"]},
    "android_vuln": {"commands": ["adb"]},
    "ios_vuln": {"python": ["frida"]},
    "ipa_analyze": {"commands": ["unzip"]},
    "one_gadget": {"commands": ["one_gadget"]},
    "sdr_analyze": {"commands": ["sox"]},
    "tshark": {"commands": ["tshark"]},
}


def _command_available(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _python_mod_available(mod: str) -> bool:
    try:
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


def _capability_health(name: str) -> dict[str, Any]:
    caps = _TOOL_CAPABILITIES.get(name, {})
    checks: list[dict[str, Any]] = []
    for cmd in caps.get("commands", []):
        checks.append({"type": "command", "name": cmd, "ok": _command_available(cmd)})
    for mod in caps.get("python", []):
        checks.append({"type": "python", "name": mod, "ok": _python_mod_available(mod)})
    available = all(c["ok"] for c in checks) if checks else True
    return {"available": available, "checks": checks}


def categorize_tool(name: str) -> str:
    if name in WEB_TOOLS:
        return "web"
    if name in PWN_TOOLS:
        return "pwn"
    if name in CRYPTO_TOOLS:
        return "crypto"
    return "other"


def build_tool_registry(tools: list[dict[str, Any]], tool_map: dict[str, Any]) -> dict[str, Any]:
    by_name = {t.get("name", ""): dict(t) for t in tools if isinstance(t, dict) and t.get("name")}
    for name, tool_def in by_name.items():
        tool_def["x_health"] = _capability_health(name)
        tool_def["x_capabilities"] = _TOOL_CAPABILITIES.get(name, {})
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
    tool_map = registry.get("tool_map", {}) if isinstance(registry.get("tool_map", {}), dict) else {}
    out = []
    for name in enabled_names:
        if name not in by_name:
            continue
        item = dict(by_name[name])
        if name not in tool_map:
            item["x_disabled_reason"] = "missing_runtime_mapping"
            continue
        health = item.get("x_health", {})
        if isinstance(health, dict) and not health.get("available", True):
            item["x_health_unavailable"] = True
        out.append(item)
    return out
