// src-tauri/src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
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
                emit_log(&app, "err", &format!("[python stderr] {}", line), "red");
            }
        }
    }

    child.wait().await.ok();
    *state.active_pid.lock().unwrap() = None;

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

    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() { continue; }
        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(event) => {
                let etype = event["type"].as_str().unwrap_or("log");
                if etype == "import_result" {
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

    child.wait().await.ok();
    *state.active_pid.lock().unwrap() = None;

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
