// src-tauri/src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, State};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::Mutex as AsyncMutex;

// ─── State ────────────────────────────────────────────────────────────────────

pub struct SolverState {
    pub active_pids: Mutex<HashSet<u32>>,
}

// ─── Event types emitted to frontend ──────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SolverLogEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub tag: String,
    pub msg: String,
    pub cls: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SolveResult {
    pub status: String,
    pub flag: Option<String>,
    pub reason: Option<String>,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn emit_log(app: &AppHandle, tag: &str, msg: &str, cls: &str) {
    let event = SolverLogEvent {
        event_type: "log".to_string(),
        tag: tag.to_string(),
        msg: msg.to_string(),
        cls: cls.to_string(),
    };
    app.emit_all("solver-log", event).ok();
}

fn resolve_solver_path(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Solver path is empty. Set Settings → Solver Path to sidecar/solver.py.".to_string());
    }

    let mut candidates: Vec<PathBuf> = vec![PathBuf::from(trimmed)];

    if trimmed.contains("sidecarsolver.py") {
        candidates.push(PathBuf::from(trimmed.replace("sidecarsolver.py", "sidecar/solver.py")));
    }
    if trimmed.contains("sidecar\\solver.py") {
        candidates.push(PathBuf::from(trimmed.replace("sidecar\\solver.py", "sidecar/solver.py")));
    }
    if trimmed.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            candidates.push(PathBuf::from(home).join(trimmed.trim_start_matches("~/")));
        }
    }

    let mut seen = HashSet::new();
    let mut tried: Vec<String> = Vec::new();

    for path in candidates {
        let display = path.to_string_lossy().to_string();
        if !seen.insert(display.clone()) {
            continue;
        }
        tried.push(display.clone());

        if path.exists() {
            return Ok(display);
        }

        if path.is_relative() {
            if let Ok(cwd) = std::env::current_dir() {
                let abs = cwd.join(&path);
                let abs_display = abs.to_string_lossy().to_string();
                if seen.insert(abs_display.clone()) {
                    tried.push(abs_display.clone());
                }
                if abs.exists() {
                    return Ok(abs_display);
                }
            }
        }
    }

    Err(format!(
        "Solver script not found. Tried: {}",
        tried.join(" | ")
    ))
}

fn kill_pid_tree(pid: u32) {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("pkill")
            .args(["-TERM", "-P", &pid.to_string()])
            .output();
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
        let _ = std::process::Command::new("pkill")
            .args(["-KILL", "-P", &pid.to_string()])
            .output();
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output();
    }
}

// ─── Commands ─────────────────────────────────────────────────────────────────

/// Spawn the Python solver, stream log events back, return final result.
#[tauri::command]
async fn solve_challenge(
    app: AppHandle,
    state: State<'_, SolverState>,
    challenge: serde_json::Value,
    api_key: String,
    python_path: String,
    solver_path: String,
    model: String,
    max_iterations: u32,
    platform: serde_json::Value,
    base_dir: String,
    ctf_name: String,
    extra_config: serde_json::Value,
) -> Result<String, String> {
    let solver_path = resolve_solver_path(&solver_path)?;

    let payload = serde_json::json!({
        "mode":           "solve",
        "challenge":      challenge,
        "api_key":        api_key,
        "model":          model,
        "max_iterations": max_iterations,
        "platform":       platform,
        "base_dir":       base_dir,
        "ctf_name":       ctf_name,
        "extraConfig":    extra_config,
    })
    .to_string();

    // Spawn Python
    let mut child = Command::new(&python_path)
        .arg(&solver_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            format!(
                "Failed to start Python at '{}': {}. Check Settings → Python Path.",
                python_path, e
            )
        })?;

    // Store PID so we can kill it from cancel_solve
    let child_pid = child.id();
    if let Some(pid) = child_pid {
        state.active_pids.lock().unwrap().insert(pid);
    }

    // Write payload to stdin then close pipe
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| format!("Failed to write stdin: {}", e))?;
        // drop closes the pipe → Python gets EOF → starts processing
    }

    // Read stdout line by line, forward log events
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();

    let stderr_tail = Arc::new(AsyncMutex::new(Vec::<String>::new()));
    let stderr_task = if let Some(stderr) = child.stderr.take() {
        let app_for_stderr = app.clone();
        let tail_for_stderr = Arc::clone(&stderr_tail);
        Some(tokio::spawn(async move {
            let mut err_lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = err_lines.next_line().await {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                {
                    let mut tail = tail_for_stderr.lock().await;
                    if tail.len() >= 3 {
                        tail.remove(0);
                    }
                    tail.push(line.clone());
                }
                emit_log(&app_for_stderr, "err", &format!("[python stderr] {}", line), "red");
            }
        }))
    } else {
        None
    };

    let mut final_status = "failed".to_string();
    let mut final_flag: Option<String> = None;
    let mut final_reason: Option<String> = None;
    let mut saw_result_event = false;

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(event) => {
                let etype = event["type"].as_str().unwrap_or("log");
                match etype {
                    "result" => {
                        saw_result_event = true;
                        final_status = event["status"]
                            .as_str()
                            .unwrap_or("failed")
                            .to_string();
                        final_flag = event["flag"].as_str().map(String::from);
                        final_reason = event
                            .get("reason")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .or_else(|| {
                                event
                                    .get("message")
                                    .and_then(|v| v.as_str())
                                    .map(String::from)
                            });
                    }
                    _ => {
                        // Forward log/tool events verbatim to frontend
                        app.emit_all("solver-log", &event).ok();
                    }
                }
            }
            Err(_) => {
                // Plain text line from Python (e.g. traceback) — emit as error
                emit_log(&app, "err", &line, "red");
            }
        }
    }

    let exit_status = child.wait().await.ok();
    if let Some(task) = stderr_task {
        let _ = task.await;
    }
    if let Some(pid) = child_pid {
        state.active_pids.lock().unwrap().remove(&pid);
    }

    let stderr_tail = stderr_tail.lock().await.clone();

    if !saw_result_event {
        let exit_txt = exit_status
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let tail = if stderr_tail.is_empty() {
            "(no stderr captured)".to_string()
        } else {
            stderr_tail.join(" | ")
        };
        let flow_msg = format!(
            "[flow] Sidecar exited before emitting result event (exit: {}). Last stderr: {}",
            exit_txt, tail
        );
        final_reason = Some(flow_msg.clone());
        emit_log(
            &app,
            "err",
            &flow_msg,
            "red",
        );
    }

    let result = serde_json::json!({
        "status": final_status,
        "flag":   final_flag,
        "reason": final_reason,
    });

    Ok(result.to_string())
}

/// Kill the running Python solver process.
#[tauri::command]
fn cancel_solve(state: State<'_, SolverState>) -> Result<(), String> {
    let pids: Vec<u32> = {
        let mut guard = state.active_pids.lock().unwrap();
        let out = guard.iter().copied().collect::<Vec<u32>>();
        guard.clear();
        out
    };
    for pid in pids {
        kill_pid_tree(pid);
    }
    Ok(())
}

/// Check if the given Python executable exists and return its version string.
#[tauri::command]
async fn check_python(python_path: String) -> Result<String, String> {
    let output = Command::new(&python_path)
        .arg("--version")
        .output()
        .await
        .map_err(|e| format!("Cannot run '{}': {}", python_path, e))?;

    let version = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr).to_string();
    Ok(version.trim().to_string())
}

/// Return the directory this binary lives in (useful for locating solver.py).
#[tauri::command]
fn get_bin_dir() -> Result<String, String> {
    std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .ok_or_else(|| "Cannot determine binary directory".to_string())
}

/// Open a folder in the native file explorer (Explorer on Windows, Finder on Mac, etc.)
#[tauri::command]
fn open_folder(path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer")
            .arg(&path)
            .spawn()
            .map_err(|e| format!("Failed to open Explorer: {}", e))?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&path)
            .spawn()
            .map_err(|e| format!("Failed to open Finder: {}", e))?;
    }
    #[cfg(target_os = "linux")]
    {
        // Try common file managers in order
        let managers = ["xdg-open", "nautilus", "dolphin", "thunar", "nemo"];
        let mut opened = false;
        for mgr in &managers {
            if std::process::Command::new(mgr).arg(&path).spawn().is_ok() {
                opened = true;
                break;
            }
        }
        if !opened {
            return Err("No file manager found. Install xdg-utils or a file manager.".to_string());
        }
    }
    Ok(())
}

/// Run the Python solver in import mode — fetches challenges from a CTF platform.
#[tauri::command]
async fn import_challenges(
    app: AppHandle,
    state: State<'_, SolverState>,
    platform: serde_json::Value,
    base_dir: String,
    ctf_name: String,
    api_key: String,
    model: String,
    watch_new_challenges: bool,
    watch_interval_seconds: u32,
    watch_cycles: u32,
    auto_queue_policy: bool,
    auto_start_solve_on_new: bool,
    max_auto_starts_per_cycle: u32,
    single_active_solve_lock: bool,
    single_active_solve_lock_ttl_seconds: u32,
    auto_solve_queue_size: u32,
    auto_solve_queue_heartbeat_seconds: f64,
    auto_solve_max_retries: u32,
    extra_config: serde_json::Value,
    python_path: String,
    solver_path: String,
) -> Result<String, String> {
    let solver_path = resolve_solver_path(&solver_path)?;

    let payload = serde_json::json!({
        "mode":     "import",
        "platform": platform,
        "base_dir": base_dir,
        "ctf_name": ctf_name,
        "api_key": api_key,
        "model": model,
        "watchNewChallenges": watch_new_challenges,
        "watchIntervalSeconds": watch_interval_seconds,
        "watchCycles": watch_cycles,
        "autoQueuePolicy": auto_queue_policy,
        "autoStartSolveOnNew": auto_start_solve_on_new,
        "maxAutoStartsPerCycle": max_auto_starts_per_cycle,
        "singleActiveSolveLock": single_active_solve_lock,
        "singleActiveSolveLockTtlSeconds": single_active_solve_lock_ttl_seconds,
        "autoSolveQueueSize": auto_solve_queue_size,
        "autoSolveQueueHeartbeatSeconds": auto_solve_queue_heartbeat_seconds,
        "autoSolveMaxRetries": auto_solve_max_retries,
        "extraConfig": extra_config,
    })
    .to_string();

    let mut child = Command::new(&python_path)
        .arg(&solver_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start Python at '{}': {}", python_path, e))?;

    let child_pid = child.id();
    if let Some(pid) = child_pid {
        state.active_pids.lock().unwrap().insert(pid);
    }

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(payload.as_bytes()).await
            .map_err(|e| format!("stdin write failed: {}", e))?;
    }

    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let mut import_result = String::new();
    let mut saw_import_result = false;
    let stderr_tail = Arc::new(AsyncMutex::new(Vec::<String>::new()));
    let stderr_task = if let Some(stderr) = child.stderr.take() {
        let app_for_stderr = app.clone();
        let tail_for_stderr = Arc::clone(&stderr_tail);
        Some(tokio::spawn(async move {
            let mut err_lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = err_lines.next_line().await {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                {
                    let mut tail = tail_for_stderr.lock().await;
                    if tail.len() >= 3 {
                        tail.remove(0);
                    }
                    tail.push(line.clone());
                }
                emit_log(&app_for_stderr, "err", &format!("[python stderr] {}", line), "red");
            }
        }))
    } else {
        None
    };

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() { continue; }
        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(event) => {
                let etype = event["type"].as_str().unwrap_or("log");
                if etype == "import_result" {
                    saw_import_result = true;
                    import_result = line.clone();
                } else {
                    app.emit_all("solver-log", &event).ok();
                }
            }
            Err(_) => {
                emit_log(&app, "err", &line, "red");
            }
        }
    }

    let exit_status = child.wait().await.ok();
    if let Some(task) = stderr_task {
        let _ = task.await;
    }
    if let Some(pid) = child_pid {
        state.active_pids.lock().unwrap().remove(&pid);
    }

    let stderr_tail = stderr_tail.lock().await.clone();

    if !saw_import_result {
        let exit_txt = exit_status
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let tail = if stderr_tail.is_empty() {
            "(no stderr captured)".to_string()
        } else {
            stderr_tail.join(" | ")
        };
        emit_log(
            &app,
            "err",
            &format!(
                "[flow] Import sidecar exited before emitting import_result (exit: {}). Last stderr: {}",
                exit_txt, tail
            ),
            "red",
        );
    }

    Ok(import_result)
}

// ─── Entry point ──────────────────────────────────────────────────────────────

fn main() {
    tauri::Builder::default()
        .manage(SolverState {
            active_pids: Mutex::new(HashSet::new()),
        })
        .invoke_handler(tauri::generate_handler![
            solve_challenge,
            cancel_solve,
            check_python,
            get_bin_dir,
            open_folder,
            import_challenges,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
