"""Bounded auto-solve queue with worker heartbeat."""
from __future__ import annotations

import json
import os
import queue
import threading
import time
from typing import Any, Callable


class AutoSolveQueue:
    def __init__(
        self,
        maxsize: int,
        emit_cb: Callable[..., Any],
        run_cb: Callable[[dict[str, Any]], Any],
        heartbeat_seconds: float = 15.0,
        persist_dir: str = "",
        max_retries: int = 2,
    ) -> None:
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=max(1, int(maxsize)))
        self._emit = emit_cb
        self._run = run_cb
        self._heartbeat_seconds = max(3.0, float(heartbeat_seconds))
        self._persist_dir = str(persist_dir or "").strip()
        self._max_retries = max(0, int(max_retries))
        self._stop = threading.Event()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._heartbeat = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._started = False

    def _pending_path(self) -> str:
        return os.path.join(self._persist_dir, "auto_solve_queue_pending.jsonl")

    def _dlq_path(self) -> str:
        return os.path.join(self._persist_dir, "auto_solve_queue_dlq.jsonl")

    def _append_jsonl(self, path: str, row: dict[str, Any]) -> None:
        if not self._persist_dir:
            return
        os.makedirs(self._persist_dir, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    def _rewrite_pending_without(self, lease_id: str) -> None:
        if not self._persist_dir:
            return
        path = self._pending_path()
        if not os.path.exists(path):
            return
        kept: list[str] = []
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if not s:
                        continue
                    try:
                        rec = json.loads(s)
                    except Exception:
                        continue
                    if str(rec.get("lease_id", "")) == lease_id:
                        continue
                    kept.append(s)
            with open(path, "w", encoding="utf-8") as f:
                for row in kept:
                    f.write(row + "\n")
        except Exception:
            return

    def _recover_pending(self) -> None:
        if not self._persist_dir:
            return
        path = self._pending_path()
        if not os.path.exists(path):
            return
        recovered = 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if not s:
                        continue
                    try:
                        job = json.loads(s)
                    except Exception:
                        continue
                    try:
                        self._queue.put_nowait(job)
                        recovered += 1
                    except queue.Full:
                        break
            self._emit("auto_solve_queue", event="recovered", recovered=recovered, size=self._queue.qsize())
        except Exception as e:
            self._emit("auto_solve_queue", event="recover_error", error=str(e))

    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self._recover_pending()
        self._worker.start()
        self._heartbeat.start()

    def stop(self) -> None:
        self._stop.set()

    def enqueue(self, job: dict[str, Any]) -> bool:
        lease_id = str(job.get("lease_id", "") or f"{int(time.time()*1000)}-{threading.get_ident()}")
        job = {**job, "lease_id": lease_id, "retry_count": int(job.get("retry_count", 0) or 0)}
        try:
            self._queue.put_nowait(job)
            self._append_jsonl(self._pending_path(), job)
            self._emit("auto_solve_queue", event="enqueued", size=self._queue.qsize(), challenge=job.get("challenge_name", ""))
            return True
        except queue.Full:
            self._emit("auto_solve_queue", event="dropped_full", size=self._queue.qsize(), challenge=job.get("challenge_name", ""))
            return False

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._emit("auto_solve_queue", event="start_job", size=self._queue.qsize(), challenge=job.get("challenge_name", ""))
                self._run(job)
                self._emit("auto_solve_queue", event="done_job", size=self._queue.qsize(), challenge=job.get("challenge_name", ""))
                self._rewrite_pending_without(str(job.get("lease_id", "")))
            except Exception as e:
                retries = int(job.get("retry_count", 0) or 0)
                if retries < self._max_retries and not self._stop.is_set():
                    retry_job = {**job, "retry_count": retries + 1}
                    try:
                        self._queue.put_nowait(retry_job)
                        self._emit(
                            "auto_solve_queue",
                            event="job_retry",
                            challenge=job.get("challenge_name", ""),
                            retry_count=retry_job.get("retry_count", 0),
                            size=self._queue.qsize(),
                            error=str(e),
                        )
                    except queue.Full:
                        self._append_jsonl(self._dlq_path(), {**job, "error": str(e), "failed_ts": int(time.time())})
                        self._rewrite_pending_without(str(job.get("lease_id", "")))
                        self._emit("auto_solve_queue", event="dlq_full", error=str(e), challenge=job.get("challenge_name", ""))
                else:
                    self._append_jsonl(self._dlq_path(), {**job, "error": str(e), "failed_ts": int(time.time())})
                    self._rewrite_pending_without(str(job.get("lease_id", "")))
                    self._emit("auto_solve_queue", event="job_error", error=str(e), challenge=job.get("challenge_name", ""), retries=retries)
            finally:
                self._queue.task_done()

    def _heartbeat_loop(self) -> None:
        while not self._stop.is_set():
            self._emit("auto_solve_queue", event="heartbeat", size=self._queue.qsize())
            time.sleep(self._heartbeat_seconds)
