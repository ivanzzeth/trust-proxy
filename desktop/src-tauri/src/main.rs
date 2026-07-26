// trust-proxy desktop shell (macOS slice).
//
// Deliberately thin: the gateway is the Go binary, the console is the UI it
// already serves at 127.0.0.1:21585, and this process is a window plus a
// lifecycle. Nothing about policy or detection lives here — a second
// implementation of any of it would drift from the CLI within a week.
//
// Two things it must get right:
//
//  1. Never start a second gateway. Two `serve` processes on one data dir fight
//     over cache.db (bolt takes a single writer lock) and over the ports. So we
//     probe /api/health first: if a gateway is already there — installed as a
//     LaunchDaemon, or started by hand in a terminal — we attach to it and stay
//     out of the way. Only if nothing answers do we spawn our own.
//
//  2. Never leave an orphan. A child we spawned is killed when the app exits,
//     including the window-close path, so closing the window cannot leave a
//     headless data plane running that the user believes is gone. A daemon we
//     merely attached to is never touched.
//
// TUN needs root, which a GUI app should not have. That is what
// `trust-proxy service install` is for: launchd owns the daemon, this shell
// attaches to it. The splash offers that install, running the CLI through one
// admin prompt.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Manager, RunEvent, State, WebviewWindow};

const DEFAULT_API: &str = "127.0.0.1:21585";

/// Gateway is the child we spawned, if any. `None` means we attached to a
/// gateway somebody else owns.
struct Gateway(Mutex<Option<Child>>);

impl Gateway {
    fn take(&self) -> Option<Child> {
        self.0.lock().ok().and_then(|mut g| g.take())
    }
    /// Kill and reap. Called on every exit path; safe to call twice.
    fn shutdown(&self) {
        if let Some(mut child) = self.take() {
            // SIGKILL is enough here: serve persists as it goes, and its stores
            // are append-or-replace, so there is no shutdown flush to lose.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Serialize, Clone)]
struct Status {
    api: String,
    /// true when the gateway was already running and we attached to it.
    attached: bool,
    /// true when this app started the gateway.
    spawned: bool,
    healthy: bool,
    service_installed: bool,
    service_running: bool,
    binary: String,
    data_dir: String,
    error: Option<String>,
}

struct Runtime {
    api: String,
    data_dir: PathBuf,
    binary: PathBuf,
    status: Mutex<Status>,
}

fn main() {
    tauri::Builder::default()
        .manage(Gateway(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            status,
            open_console,
            install_service,
            uninstall_service
        ])
        .setup(|app| {
            let api = std::env::var("TP_API_ADDR").unwrap_or_else(|_| DEFAULT_API.to_string());
            let data_dir = data_dir();
            let binary = gateway_binary(app.handle());
            let (installed, running) = service_state(&binary);
            app.manage(Runtime {
                api: api.clone(),
                data_dir: data_dir.clone(),
                binary: binary.clone(),
                status: Mutex::new(Status {
                    api: api.clone(),
                    attached: false,
                    spawned: false,
                    healthy: false,
                    service_installed: installed,
                    service_running: running,
                    binary: binary.display().to_string(),
                    data_dir: data_dir.display().to_string(),
                    error: None,
                }),
            });

            let handle = app.handle().clone();
            // Off the UI thread: probing, spawning and waiting all block, and a
            // frozen splash is indistinguishable from a crash.
            std::thread::spawn(move || start_gateway(handle));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build the trust-proxy shell")
        .run(|app, event| {
            if let RunEvent::ExitRequested { .. } | RunEvent::Exit = event {
                app.state::<Gateway>().shutdown();
            }
        });
}

/// start_gateway attaches to a running gateway or spawns one, then points the
/// window at the console it serves.
fn start_gateway(app: AppHandle) {
    let rt = app.state::<Runtime>();
    let api = rt.api.clone();

    if healthy(&api, Duration::from_millis(700)) {
        set(&app, |s| {
            s.attached = true;
            s.healthy = true;
        });
        show_console(&app, &api);
        return;
    }

    match spawn_gateway(&rt) {
        Ok(child) => {
            if let Ok(mut slot) = app.state::<Gateway>().0.lock() {
                *slot = Some(child);
            }
            set(&app, |s| s.spawned = true);
        }
        Err(e) => {
            set(&app, |s| s.error = Some(e));
            return;
        }
    }

    // 20s: a cold start parses the config, builds the box and (in TUN mode) waits
    // on the interface. Report the child's own exit early rather than spinning.
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if healthy(&api, Duration::from_millis(500)) {
            set(&app, |s| s.healthy = true);
            show_console(&app, &api);
            return;
        }
        if let Ok(mut slot) = app.state::<Gateway>().0.lock() {
            if let Some(child) = slot.as_mut() {
                if let Ok(Some(exit)) = child.try_wait() {
                    let log = rt.data_dir.join("serve.log");
                    // Quote the gateway's own last error instead of pointing at a
                    // log file: the common failure is "port already in use"
                    // (another gateway, or another proxy app holding 21584), and
                    // that is fixable in ten seconds if we just say it.
                    let why = last_error_line(&log)
                        .map(|l| format!(": {l}"))
                        .unwrap_or_else(|| format!(". See {}", log.display()));
                    // A quarantined, un-notarized bundle is the other first-run
                    // failure, and its symptom is a silent SIGKILL of the sidecar
                    // with nothing in the log at all — measured on macOS 26, where
                    // approving the *app* does not extend to the binary it spawns.
                    // Guessing from "signal: 9" is not something a user should have
                    // to do, so name it and give the one command that fixes it.
                    let hint = quarantine_hint(&rt.binary, exit.code().is_none());
                    set(&app, |s| {
                        s.error = Some(format!("the gateway exited immediately ({exit}){why}{hint}"))
                    });
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    set(&app, |s| {
        s.error = Some(format!("the gateway did not answer on {api} within 20s"))
    });
}

fn spawn_gateway(rt: &Runtime) -> Result<Child, String> {
    if !rt.binary.exists() {
        return Err(format!(
            "gateway binary not found at {} — build it with `make desktop`",
            rt.binary.display()
        ));
    }
    std::fs::create_dir_all(&rt.data_dir)
        .map_err(|e| format!("create {}: {e}", rt.data_dir.display()))?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(rt.data_dir.join("serve.log"))
        .map_err(|e| format!("open log: {e}"))?;
    let errlog = log.try_clone().map_err(|e| format!("clone log: {e}"))?;

    Command::new(&rt.binary)
        .arg("serve")
        // No -c: the gateway defaults to <data>/config.json and seeds it on first
        // run. The shell used to pass a path and carry its own copy of the default
        // config, which is how the CLI and the app ended up on different files.
        .arg("--data")
        .arg(&rt.data_dir)
        .arg("--api-addr")
        .arg(&rt.api)
        // Belt and braces for the orphan case: killing this app on the exit path
        // is not enough, because a force-quit or a crash runs no handler at all —
        // measured, the gateway survived a SIGTERM to the shell. The child watches
        // our pid and shuts itself down when we disappear.
        .arg("--exit-with-pid")
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(errlog))
        .spawn()
        .map_err(|e| match e.kind() {
            ErrorKind::PermissionDenied => format!(
                "{} is not executable ({e})",
                rt.binary.display()
            ),
            _ => format!("spawn {}: {e}", rt.binary.display()),
        })
}

fn show_console(app: &AppHandle, api: &str) {
    if let Some(window) = app.get_webview_window("main") {
        let url = format!("http://{api}/");
        if let Ok(parsed) = url.parse() {
            // Navigate the existing window rather than opening a second one: the
            // console is the app, the splash was only ever a waiting room.
            let _ = WebviewWindow::navigate(&window, parsed);
        }
    }
}

/// quarantine_hint explains a Gatekeeper kill, when that is what happened.
///
/// killed_by_signal narrows it: an ordinary bad-config exit has a status code, a
/// Gatekeeper kill is SIGKILL with an empty log. The attribute is checked on the
/// enclosing .app, since that is where a browser puts it.
fn quarantine_hint(binary: &Path, killed_by_signal: bool) -> String {
    if !killed_by_signal {
        return String::new();
    }
    let bundle = binary
        .ancestors()
        .find(|p| p.extension().map(|e| e == "app").unwrap_or(false))
        .unwrap_or(binary);
    if !is_quarantined(bundle) {
        return String::new();
    }
    format!(
        "\n\nThis copy is still quarantined (it was downloaded, and this build is \
         not notarized), so macOS killed the gateway. Clear it once:\n\n    \
         xattr -dr com.apple.quarantine {}\n\nor allow the app under System \
         Settings → Privacy & Security.",
        shell_quote(&bundle.display().to_string())
    )
}

fn is_quarantined(path: &Path) -> bool {
    Command::new("xattr")
        .arg("-p")
        .arg("com.apple.quarantine")
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// last_error_line returns the most recent error the gateway logged, with the
/// ANSI colouring its console logger emits stripped out.
fn last_error_line(log: &Path) -> Option<String> {
    let text = std::fs::read_to_string(log).ok()?;
    let tail: Vec<&str> = text.lines().rev().take(80).collect();
    let line = tail.into_iter().find(|l| {
        let low = strip_ansi(l).to_lowercase();
        low.contains("error") || low.contains("failed") || low.contains("in use")
    })?;
    let clean = strip_ansi(line).trim().to_string();
    if clean.is_empty() {
        return None;
    }
    Some(clean.chars().take(300).collect())
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // CSI ... final byte in @-~; drop the whole sequence.
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

fn healthy(api: &str, timeout: Duration) -> bool {
    // A hand-rolled probe keeps an HTTP client out of the dependency tree for one
    // request: connect, ask, look for a 2xx status line.
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let addr = match api.parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let req = format!("GET /api/health HTTP/1.0\r\nHost: {api}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    head.starts_with("HTTP/1.") && (head.contains(" 200") || head.contains(" 204"))
}

fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("TP_DATA") {
        return PathBuf::from(dir);
    }
    // Same location the CLI uses, on purpose: the desktop app and `trust-proxy`
    // in a terminal must see one gateway with one set of policy. The rule lives in
    // internal/paths on the Go side; this mirrors it, and the mirror is asserted
    // against the CLI at runtime (see status()).
    if cfg!(target_os = "windows") {
        if let Ok(base) = std::env::var("LOCALAPPDATA") {
            return Path::new(&base).join("trust-proxy");
        }
    }
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".into());
    Path::new(&home).join(".trust-proxy")
}

/// gateway_binary is the sidecar inside the bundle, or an override for dev.
fn gateway_binary(app: &AppHandle) -> PathBuf {
    if let Ok(p) = std::env::var("TP_BINARY") {
        return PathBuf::from(p);
    }
    // Tauri strips the target triple from an externalBin, but *where* the result
    // lands differs per platform: next to the executable on Linux/Windows, in the
    // bundle's MacOS/ directory on macOS (a sibling of Resources/). Try both
    // rather than encoding one layout.
    let exe_name = if cfg!(target_os = "windows") {
        "trust-proxy.exe"
    } else {
        "trust-proxy"
    };
    if let Ok(dir) = app.path().resource_dir() {
        for candidate in [dir.join(format!("../MacOS/{exe_name}")), dir.join(exe_name)] {
            if let Ok(canon) = candidate.canonicalize() {
                return canon;
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let side = dir.join(exe_name);
            if side.exists() {
                return side;
            }
        }
    }
    PathBuf::from(exe_name)
}

fn service_state(binary: &Path) -> (bool, bool) {
    let out = Command::new(binary)
        .args(["service", "status", "--json"])
        .output();
    match out {
        Ok(o) => {
            let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap_or_default();
            (
                v.get("installed").and_then(|b| b.as_bool()).unwrap_or(false),
                v.get("running").and_then(|b| b.as_bool()).unwrap_or(false),
            )
        }
        Err(_) => (false, false),
    }
}

fn set(app: &AppHandle, f: impl FnOnce(&mut Status)) {
    let rt = app.state::<Runtime>();
    let locked = rt.status.lock();
    if let Ok(mut s) = locked {
        f(&mut s);
    };
}

// ---- commands the splash calls -------------------------------------------

#[tauri::command]
fn status(rt: State<Runtime>) -> Status {
    rt.status.lock().map(|s| s.clone()).unwrap_or_else(|_| Status {
        api: rt.api.clone(),
        attached: false,
        spawned: false,
        healthy: false,
        service_installed: false,
        service_running: false,
        binary: rt.binary.display().to_string(),
        data_dir: rt.data_dir.display().to_string(),
        error: Some("status unavailable".into()),
    })
}

#[tauri::command]
fn open_console(app: AppHandle, rt: State<Runtime>) {
    show_console(&app, &rt.api);
}

/// install_service hands the privileged half to the CLI, through exactly one
/// admin prompt. The shell itself never runs as root.
#[tauri::command]
fn install_service(rt: State<Runtime>) -> Result<String, String> {
    let cmd = format!(
        "{} service install -c {} --data {} --api-addr {} --json",
        shell_quote(&rt.binary.display().to_string()),
        shell_quote(&rt.data_dir.join("config.json").display().to_string()),
        shell_quote(&rt.data_dir.display().to_string()),
        shell_quote(&rt.api),
    );
    admin(&cmd)
}

#[tauri::command]
fn uninstall_service(rt: State<Runtime>) -> Result<String, String> {
    let cmd = format!(
        "{} service uninstall --json",
        shell_quote(&rt.binary.display().to_string())
    );
    admin(&cmd)
}

/// admin runs one shell command with an authorization prompt.
///
/// One shell, one elevation *mechanism per OS*: the same CLI command in all
/// cases, so what gets installed never depends on which shell asked. The shell
/// itself is never root — it asks the platform to run the CLI as root and reads
/// back the CLI's own JSON.
#[cfg(target_os = "macos")]
fn admin(cmd: &str) -> Result<String, String> {
    let script = format!(
        "do shell script {} with administrator privileges",
        applescript_string(cmd)
    );
    let out = Command::new("osascript")
        .args(["-e", &script])
        .output()
        .map_err(|e| format!("osascript: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Linux: pkexec is the desktop-native prompt (polkit), and it exists on every
/// desktop that has a graphical sudo at all. `sudo` is deliberately not a
/// fallback: from a GUI it has no terminal to ask on, so it would either fail
/// silently or, on a passwordless-sudo box, elevate with no prompt at all.
#[cfg(target_os = "linux")]
fn admin(cmd: &str) -> Result<String, String> {
    if which("pkexec").is_none() {
        return Err(format!(
            "no pkexec (polkit) on this system — run this in a terminal instead:\n  sudo {cmd}"
        ));
    }
    let argv = pkexec_argv(cmd);
    let out = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|e| format!("pkexec: {e}"))?;
    if !out.status.success() {
        // 126/127 are pkexec's own "not authorized" / "could not be executed".
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let msg = match out.status.code() {
            Some(126) => "authorization was declined".to_string(),
            Some(127) => format!("pkexec could not run it: {stderr}"),
            _ if stderr.is_empty() => "the command failed".to_string(),
            _ => stderr,
        };
        return Err(msg);
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Windows: UAC. Elevation happens through the shell's "runas" verb, which
/// cannot return the child's output — so the CLI is asked to write its JSON to a
/// file, and that is read back once the elevated process exits.
#[cfg(target_os = "windows")]
fn admin(cmd: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out_file = std::env::temp_dir().join(format!("trust-proxy-admin-{}.json", std::process::id()));
    let _ = std::fs::remove_file(&out_file);
    let ps = runas_script(cmd, &out_file);
    let status = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| format!("powershell: {e}"))?;
    let body = std::fs::read_to_string(&out_file).unwrap_or_default();
    let _ = std::fs::remove_file(&out_file);
    if !status.success() {
        // The CLI's own {"error": …} is far more useful than an exit code, so it
        // wins when it made it to the file.
        if body.contains("\"error\"") {
            return Err(body.trim().to_string());
        }
        return Err(match status.code() {
            Some(1223) => "the elevation prompt was declined".to_string(), // ERROR_CANCELLED
            Some(c) => format!("the command failed (exit {c})"),
            None => "the command failed".to_string(),
        });
    }
    Ok(body.trim().to_string())
}

/// pkexec runs a *program*, not a shell line, so the command goes to sh rather
/// than being re-split here — re-splitting is how a data directory with a space
/// in it turns into two arguments.
fn pkexec_argv(cmd: &str) -> Vec<String> {
    vec![
        "pkexec".to_string(),
        "/bin/sh".to_string(),
        "-c".to_string(),
        cmd.to_string(),
    ]
}

/// runas_script asks the Windows shell for elevation (the "runas" verb, i.e. the
/// UAC prompt). That verb cannot hand back the child's stdout across the
/// privilege boundary, so the CLI's JSON is redirected to a file we read after.
fn runas_script(cmd: &str, out_file: &Path) -> String {
    format!(
        "$p = Start-Process -FilePath cmd.exe -ArgumentList '/c',{} -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
        powershell_string(&format!("{cmd} > \"{}\"", out_file.display()))
    )
}

#[cfg(any(target_os = "linux", test))]
fn which(program: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(program))
            .find(|p| p.is_file())
    })
}

fn powershell_string(s: &str) -> String {
    // PowerShell single-quoted strings escape a quote by doubling it, and
    // interpolate nothing — which is what we want for a path.
    format!("'{}'", s.replace('\'', "''"))
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

#[cfg(any(target_os = "macos", test))]
fn applescript_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_survives_paths_with_spaces_and_quotes() {
        assert_eq!(shell_quote("/Users/a b/x"), "'/Users/a b/x'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(applescript_string(r#"say "hi""#), r#""say \"hi\"""#);
    }

    // Elevation is per-OS but the command must be identical, and it must survive a
    // path with a space — which is the normal case on a desktop.
    #[test]
    fn elevation_passes_one_unsplit_command() {
        let cmd = "'/Applications/Trust Proxy.app/tp' service install --data '/Users/a b/.trust-proxy'";
        let argv = pkexec_argv(cmd);
        assert_eq!(argv[0], "pkexec");
        // sh -c takes the whole line as ONE argument; splitting it would install
        // against the wrong data dir instead of failing loudly.
        assert_eq!(argv.len(), 4);
        assert_eq!(argv[3], cmd);

        let script = runas_script(cmd, Path::new(r"C:\Temp\a b\o.json"));
        assert!(script.contains("-Verb RunAs"), "{script}");
        assert!(
            script.contains("-Wait"),
            "without -Wait the result file is read before it exists: {script}"
        );
        assert!(script.contains(r"C:\Temp\a b\o.json"), "{script}");
    }

    #[test]
    fn powershell_quoting_closes_the_injection_hole() {
        // A single quote must not end the string and start code; single-quoted
        // PowerShell strings also interpolate nothing, which is what a path wants.
        assert_eq!(powershell_string("it's"), "'it''s'");
        assert_eq!(powershell_string("$env:PATH"), "'$env:PATH'");
    }

    #[test]
    fn which_finds_a_program_on_the_path_and_not_a_made_up_one() {
        assert!(which("sh").is_some());
        assert!(which("definitely-not-a-real-program-xyz").is_none());
    }

    #[test]
    fn the_gateways_own_error_is_quoted_not_a_log_path() {
        // The common first-run failure is a port already held by another proxy;
        // the shell must say that, not "see the log".
        let dir = std::env::temp_dir().join(format!("tp-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("serve.log");
        std::fs::write(
            &log,
            "\u{1b}[36mINFO\u{1b}[0m network: updated default interface en0\n\u{1b}[31mERROR\u{1b}[0m start inbound/mixed[mixed-in]: listen tcp 127.0.0.1:21584: bind: address already in use\n",
        )
        .unwrap();
        let got = last_error_line(&log).expect("an error line");
        assert!(got.contains("address already in use"), "got {got}");
        assert!(!got.contains('\u{1b}'), "ANSI escapes leaked into the UI: {got}");
        assert!(last_error_line(&dir.join("missing.log")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quarantine_hint_only_fires_for_a_signal_kill_on_a_quarantined_bundle() {
        let dir = std::env::temp_dir().join(format!("tp-q-{}", std::process::id()));
        let bundle = dir.join("Trust Proxy.app");
        let bin = bundle.join("Contents/MacOS/trust-proxy");
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();

        // Not quarantined: no hint, whatever the exit shape.
        assert_eq!(quarantine_hint(&bin, true), "");

        let marked = Command::new("xattr")
            .args(["-w", "com.apple.quarantine", "0083;0;test;"])
            .arg(&bundle)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if marked {
            // A plain non-zero exit is a config problem, not Gatekeeper.
            assert_eq!(quarantine_hint(&bin, false), "");
            let hint = quarantine_hint(&bin, true);
            assert!(hint.contains("xattr -dr com.apple.quarantine"), "got {hint}");
            assert!(hint.contains("Trust Proxy.app"), "hint must name the bundle: {hint}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn health_probe_rejects_a_dead_port() {
        // Port 1 on loopback: nothing listens, and the probe must not hang.
        let start = Instant::now();
        assert!(!healthy("127.0.0.1:1", Duration::from_millis(200)));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn health_probe_accepts_a_200_and_rejects_a_500() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        for (reply, want) in [
            ("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true),
            ("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n", false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let handle = std::thread::spawn(move || {
                if let Ok((mut sock, _)) = listener.accept() {
                    let mut buf = [0u8; 256];
                    let _ = sock.read(&mut buf);
                    let _ = sock.write_all(reply.as_bytes());
                }
            });
            assert_eq!(healthy(&addr, Duration::from_secs(2)), want, "reply {reply:?}");
            let _ = handle.join();
        }
    }
}
