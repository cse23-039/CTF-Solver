# CTF-Solver Flow Map (Runtime)

This maps the live execution path and where failures are surfaced.

## 1) UI → Tauri invoke
- Frontend calls `solve_challenge` (Rust) with:
  - `python_path`
  - `solver_path`
  - challenge payload/config

## 2) Rust preflight + process spawn
- File: `src-tauri/src/main.rs`
- `resolve_solver_path(...)` now:
  - normalizes bad `sidecarsolver.py` typo to `sidecar/solver.py`
  - expands `~/...` paths
  - tries relative and absolute variants
  - returns explicit "Tried: ..." error if not found
- Rust spawns: `<python_path> <solver_path>`
- Rust streams stdout/stderr lines to UI log events.

## 3) Sidecar entrypoint
- File: `sidecar/solver.py`
- Reads full JSON from stdin, selects mode:
  - `solve` -> `run_solve(payload)`
  - `import` -> `run_import(payload)`
  - `benchmark` -> `run_benchmark(payload)`
- New hardening:
  - any unhandled exception in mode dispatch emits:
    - `type=error` event
    - terminal `{"type":"result","status":"failed"...}`
  - prevents raw traceback-only failure mode.

## 4) Engine orchestration
- File: `sidecar/solver/engine.py`
- `run_solve(payload)` now:
  - bootstraps runtime context
  - lazily resolves `core_orchestrator`
  - catches orchestration crashes and emits failed result cleanly
- `_run_solve_impl(payload)` performs iterative strategy/tool loop.

## 5) Result propagation
- Sidecar emits JSON `type=result` on stdout.
- Rust collects final status/flag and returns to frontend.
- UI marks challenge solved/failed.

## 6) Error propagation (after crash)
- If Python throws inside solve/import and exits before emitting a result event:
  - Rust now logs a flow marker:
    - solve: `[flow] Sidecar exited before emitting result event ...`
    - import: `[flow] Import sidecar exited before emitting import_result ...`
  - Rust includes exit status + last stderr tail in that message.
  - Frontend receives failed terminal state instead of hanging/ambiguous behavior.

---

## Fast triage by stage

### A) Path/launch stage failures
Symptoms:
- `python3: can't open file ...`
Action:
- verify solver path points to `.../sidecar/solver.py`
- if typo appears as `sidecarsolver.py`, latest Rust preflight should auto-correct

### B) Entrypoint/runtime stage failures
Symptoms:
- traceback from `solver.py` / `engine.py`
Action:
- latest sidecar now converts uncaught exceptions to structured failure event
- inspect first `error` message for exact failing symbol/module

### C) Solve-loop stage failures
Symptoms:
- starts solving, then immediate fail with tool/import/model errors
Action:
- read emitted `err`/`warn` logs around first failed iteration
- fix missing dependency/module in sidecar env

---

## Critical files for this path
- `src-tauri/src/main.rs`
- `sidecar/solver.py`
- `sidecar/solver/engine.py`
