// src-tauri/src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{AppHandle, Manager, State};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

// ─── State ────────────────────────────────────────────────────────────────────

pub struct SolverState {
    pub active_pid: Mutex<Option<u32>>,
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
    if let Some(pid) = child.id() {
        *state.active_pid.lock().unwrap() = Some(pid);
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

    let mut final_status = "failed".to_string();
    let mut final_flag: Option<String> = None;
    let mut saw_result_event = false;
    let mut stderr_tail: Vec<String> = Vec::new();

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

    // Collect stderr for debugging
    if let Some(stderr) = child.stderr.take() {
        let mut err_lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = err_lines.next_line().await {
            let line = line.trim().to_string();
            if !line.is_empty() {
                if stderr_tail.len() >= 3 {
                    stderr_tail.remove(0);
                }
                stderr_tail.push(line.clone());
                emit_log(&app, "err", &format!("[python stderr] {}", line), "red");
            }
        }
    }

    let exit_status = child.wait().await.ok();
    *state.active_pid.lock().unwrap() = None;

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
        emit_log(
            &app,
            "err",
            &format!(
                "[flow] Sidecar exited before emitting result event (exit: {}). Last stderr: {}",
                exit_txt, tail
            ),
            "red",
        );
    }

    let result = serde_json::json!({
        "status": final_status,
        "flag":   final_flag,
    });

    Ok(result.to_string())
}

/// Kill the running Python solver process.
#[tauri::command]
fn cancel_solve(state: State<'_, SolverState>) -> Result<(), String> {
    let pid = state.active_pid.lock().unwrap().take();
    if let Some(pid) = pid {
        #[cfg(unix)]
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .output();
        }
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
    python_path: String,
    solver_path: String,
) -> Result<String, String> {
    let solver_path = resolve_solver_path(&solver_path)?;

    let payload = serde_json::json!({
        "mode":     "import",
        "platform": platform,
        "base_dir": base_dir,
        "ctf_name": ctf_name,
    })
    .to_string();

    let mut child = Command::new(&python_path)
        .arg(&solver_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start Python at '{}': {}", python_path, e))?;

    if let Some(pid) = child.id() {
        *state.active_pid.lock().unwrap() = Some(pid);
    }

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(payload.as_bytes()).await
            .map_err(|e| format!("stdin write failed: {}", e))?;
    }

    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let mut import_result = String::new();
    let mut saw_import_result = false;
    let mut stderr_tail: Vec<String> = Vec::new();

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

    if let Some(stderr) = child.stderr.take() {
        let mut err_lines = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = err_lines.next_line().await {
            let line = line.trim().to_string();
            if !line.is_empty() {
                if stderr_tail.len() >= 3 {
                    stderr_tail.remove(0);
                }
                stderr_tail.push(line.clone());
                emit_log(&app, "err", &format!("[python stderr] {}", line), "red");
            }
        }
    }

    let exit_status = child.wait().await.ok();
    *state.active_pid.lock().unwrap() = None;

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
            active_pid: Mutex::new(None),
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
