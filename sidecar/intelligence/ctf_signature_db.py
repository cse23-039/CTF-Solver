"""Data-driven signature store with lightweight retraining support."""
from __future__ import annotations

import json
import os
import time
from collections import Counter, defaultdict
from typing import Any


def _tok(text: str) -> list[str]:
    out = []
    cur = []
    for ch in (text or "").lower():
        if ch.isalnum() or ch == "_":
            cur.append(ch)
        elif cur:
            out.append("".join(cur))
            cur = []
    if cur:
        out.append("".join(cur))
    return out


def load_db(path: str) -> dict[str, Any]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"samples": [], "model": {}, "updated_at": 0.0}


def save_db(path: str, db: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)


def add_sample(db: dict[str, Any], text: str, label: str, meta: dict[str, Any] | None = None) -> None:
    db.setdefault("samples", []).append({
        "text": text,
        "label": label,
        "meta": meta or {},
        "ts": time.time(),
    })


def retrain(db: dict[str, Any], min_count: int = 1) -> dict[str, Any]:
    by_label = defaultdict(Counter)
    for s in db.get("samples", []):
        label = str(s.get("label", "unknown"))
        for t in _tok(str(s.get("text", ""))):
            by_label[label][t] += 1

    model = {}
    for label, cnt in by_label.items():
        total = sum(cnt.values())
        weights = {k: v / total for k, v in cnt.items() if v >= min_count}
        model[label] = dict(sorted(weights.items(), key=lambda x: x[1], reverse=True)[:300])

    db["model"] = model
    db["updated_at"] = time.time()
    return db


def predict(db: dict[str, Any], text: str, top_k: int = 5) -> list[dict[str, Any]]:
    toks = Counter(_tok(text))
    scores = []
    for label, weights in db.get("model", {}).items():
        score = 0.0
        for t, c in toks.items():
            score += c * float(weights.get(t, 0.0))
        scores.append({"label": label, "score": score})
    scores.sort(key=lambda x: x["score"], reverse=True)
    return scores[: max(1, int(top_k))]


def run(input_data: Any = None, **kwargs: Any) -> dict[str, Any]:
    op = kwargs.get("operation", "predict")
    path = kwargs.get("path", os.path.expanduser("~/.ctf-solver/signatures.json"))
    db = load_db(path)
    if op == "add":
        add_sample(db, str(kwargs.get("text", "")), str(kwargs.get("label", "unknown")), kwargs.get("meta", {}))
        save_db(path, db)
        return {"status": "added", "samples": len(db.get("samples", []))}
    if op == "retrain":
        retrain(db, min_count=int(kwargs.get("min_count", 1)))
        save_db(path, db)
        return {"status": "retrained", "labels": len(db.get("model", {}))}
    if op == "predict":
        return {"predictions": predict(db, str(kwargs.get("text", "")), top_k=int(kwargs.get("top_k", 5)))}
    return {"status": "noop", "operation": op}
