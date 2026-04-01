"""Memory v2 retrieval and injection helpers."""
from __future__ import annotations


def _memory_v2_path() -> str:
    return memory_store.memory_v2_path()


def _tokenize_simple(text: str) -> set[str]:
    return memory_store.tokenize_simple(text)


def _challenge_fingerprint(challenge: dict, ctf_name: str = "") -> str:
    return memory_store.challenge_fingerprint(challenge, ctf_name)


def _load_memory_v2(limit: int = 800) -> list[dict]:
    return memory_store.load_memory_v2(limit=limit)


def _build_memory_injection(memory_hits: list[dict]) -> str:
    return memory_store.build_memory_injection(memory_hits)


def _memory_trust_score(rec: dict, ctf_name: str = "", category: str = "", query_fingerprint: str = "") -> float:
    return memory_store.memory_trust_score(rec, ctf_name=ctf_name, category=category, query_fingerprint=query_fingerprint)


def _analyze_memory_consistency(memory_hits: list[dict]) -> dict:
    return memory_store.analyze_memory_consistency(memory_hits)


def _retrieve_memory_v2(challenge: dict, ctf_name: str = "", top_k: int = 3) -> list[dict]:
    return memory_store.retrieve_memory_v2(challenge, ctf_name=ctf_name, top_k=top_k)


def _store_memory_v2(record: dict) -> None:
    memory_store.store_memory_v2(record)


def _store_failure_path(challenge: dict, ctf_name: str, failed_approaches: list[str], category: str, difficulty: str) -> None:
    memory_store.store_failure_path(challenge, ctf_name, failed_approaches, category, difficulty)


def _retrieve_failure_paths(challenge: dict, ctf_name: str = "", top_k: int = 3) -> list[str]:
    return memory_store.retrieve_failure_paths(challenge, ctf_name=ctf_name, top_k=top_k)

