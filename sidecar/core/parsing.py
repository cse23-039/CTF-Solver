from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, Callable


class PromptBuildBuffer:
    def __init__(self) -> None:
        self._parts: list[str] = []

    def add(self, text: str = "") -> None:
        self._parts.append(text)

    def add_line(self, text: str = "") -> None:
        self._parts.append(text + "\n")

    def build(self) -> str:
        return "".join(self._parts)


class TokenizationCache:
    def __init__(self, max_size: int = 256) -> None:
        self._cache: dict[str, int] = {}
        self._max_size = max_size
        self._lock = threading.Lock()

    def _key(self, messages: list[dict[str, Any]], system: str) -> str:
        payload = {
            "system": system,
            "messages": messages[-18:],
        }
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()

    def estimate(self, messages: list[dict[str, Any]], system: str, estimator: Callable[[list[dict[str, Any]], str], int]) -> int:
        key = self._key(messages, system)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
        val = int(estimator(messages, system))
        with self._lock:
            if len(self._cache) >= self._max_size:
                oldest_key = next(iter(self._cache), None)
                if oldest_key is not None:
                    self._cache.pop(oldest_key, None)
            self._cache[key] = val
        return val
