"""Policy versioning, baseline snapshots, and automatic rollback on regression."""
from __future__ import annotations

import json
import os
import time
from typing import Any


def _safe_load(path: str, fallback: Any) -> Any:
    if not path or not os.path.exists(path):
        return fallback
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return fallback


def _safe_save(path: str, data: Any) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _history_path(policy_dir: str) -> str:
    return os.path.join(policy_dir, "policy_versions.json")


def snapshot_policy(policy_dir: str, priors_path: str, benchmark_path: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    versions = _safe_load(_history_path(policy_dir), [])
    priors = _safe_load(priors_path, {})
    benchmark = _safe_load(benchmark_path, [])
    ts = int(time.time())
    version = {
        "version_id": f"v{ts}",
        "ts": ts,
        "priors": priors,
        "benchmark_tail": benchmark[-25:] if isinstance(benchmark, list) else [],
        "metadata": metadata or {},
    }
    versions.append(version)
    _safe_save(_history_path(policy_dir), versions[-120:])
    return version


def latest_good_snapshot(policy_dir: str) -> dict[str, Any] | None:
    versions = _safe_load(_history_path(policy_dir), [])
    if not isinstance(versions, list) or not versions:
        return None
    for rec in reversed(versions):
        meta = rec.get("metadata", {}) if isinstance(rec.get("metadata", {}), dict) else {}
        if bool(meta.get("benchmark_pass", False)):
            return rec
    return versions[-1]


def latest_good_snapshot_for_cohort(policy_dir: str, category: str, difficulty: str) -> dict[str, Any] | None:
    versions = _safe_load(_history_path(policy_dir), [])
    if not isinstance(versions, list) or not versions:
        return None
    cat = str(category or "").strip().lower()
    diff = str(difficulty or "").strip().lower()
    for rec in reversed(versions):
        meta = rec.get("metadata", {}) if isinstance(rec.get("metadata", {}), dict) else {}
        if str(meta.get("category", "")).strip().lower() != cat:
            continue
        if str(meta.get("difficulty", "")).strip().lower() != diff:
            continue
        if bool(meta.get("benchmark_pass", False)):
            return rec
    return None


def rollback_to_snapshot(policy_dir: str, priors_path: str, snapshot: dict[str, Any]) -> bool:
    if not snapshot or not isinstance(snapshot, dict):
        return False
    priors = snapshot.get("priors", {})
    if not isinstance(priors, dict):
        return False
    _safe_save(priors_path, priors)

    events_path = os.path.join(policy_dir, "policy_rollbacks.jsonl")
    os.makedirs(policy_dir, exist_ok=True)
    with open(events_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "ts": int(time.time()),
            "restored_version": snapshot.get("version_id", ""),
            "reason": "benchmark_regression",
        }, ensure_ascii=False) + "\n")
    return True
