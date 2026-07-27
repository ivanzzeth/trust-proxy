// trust-proxy desktop shell.
//
// Deliberately thin, and thinner than it used to be. The gateway is the Go
// binary, the console is the UI that gateway already serves on 127.0.0.1:21585,
// and this process is a window plus one authorization prompt.
//
// **It does not run a gateway of its own.** It used to: if nothing answered, it
// spawned the sidecar as the logged-in user and watched it. That gateway was a
// lie — it could not do TUN (that needs root), it died with the window, and the
// first time anyone ran the real thing with sudo it left a root-owned directory
// in the home it wanted to write, after which the app could not start at all.
// There is one gateway on a machine now, it belongs to the service manager, and
// this shell either attaches to it or offers to install it.
//
// Nothing here knows *where* anything lives. Every fact comes from
// `trust-proxy env --json`, and the privileged step is the CLI's own
// `trust-proxy install` run through one system prompt. Three mirrors of the Go
// rules used to live in this file — the data directory, the sidecar's location,
// a hand-rolled probe for whether the console existed — and a shell is the worst
// possible place for drift, because it shows a splash screen instead of an error.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State, WebviewWindow};

const DEFAULT_API: &str = "127.0.0.1:21585";

// ---- what the Go binary tells us ------------------------------------------

#[derive(Deserialize, Default, Clone)]
struct EnvService {
    supported: bool,
    installed: bool,
    running: bool,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    program_missing: bool,
}

#[derive(Deserialize, Default, Clone)]
struct EnvGateway {
    healthy: bool,
    console: bool,
    #[serde(default)]
    version: String,
    #[serde(default)]
    managed: bool,
    #[serde(default)]
    stale: bool,
}

#[derive(Deserialize, Default, Clone)]
struct Env {
    platform: String,
    data_dir: String,
    api_addr: String,
    console_url: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    elevation: String,
    /// What should happen next, decided by the Go side: attach | update |
    /// takeover | install | repair | unsupported.
    ///
    /// The shell deliberately does not work this out from the flags below. It used
    /// to decide with one question — "does anything answer?" — and attach whenever
    /// the answer was yes, which is right in one case out of four and silently
    /// wrong in two of them.
    #[serde(default)]
    action: String,
    #[serde(default)]
    service: EnvService,
    #[serde(default)]
    gateway: EnvGateway,
}

// ---- what the splash sees -------------------------------------------------

#[derive(Serialize, Clone, Default)]
struct Status {
    api: String,
    data_dir: String,
    platform: String,
    /// How this platform will ask for administrator rights ("osascript",
    /// "pkexec", "uac", or empty when there is no graphical way to ask).
    elevation: String,
    /// What the window should offer, straight from the Go side.
    action: String,
    service_supported: bool,
    service_installed: bool,
    service_running: bool,
    healthy: bool,
    /// The gateway answers but was built without the console in it.
    console_missing: bool,
    /// This build, and the build actually running — different means the app was
    /// upgraded and the daemon was not.
    app_version: String,
    gateway_version: String,
    busy: bool,
    error: Option<String>,
}

struct Runtime {
    binary: PathBuf,
    api: String,
    /// Where the console is, as the gateway itself reports it. Composing it here
    /// from the address would work today and be one more thing to keep in step.
    console_url: Mutex<String>,
    status: Mutex<Status>,
}

fn main() {
    // --print-config answers "what would you attach to, and with which sidecar"
    // without opening a window. It exists because a bundle left over from before
    // the ports were renumbered kept probing the old address, found nothing, and
    // sat on the splash forever — with every other test in the repo green,
    // because none of them ever looked at the .app. It is also the first thing to
    // ask when someone says "it will not open".
    if std::env::args().any(|a| a == "--print-config") {
        let binary = gateway_binary_standalone();
        let api = env_override("TP_API_ADDR").unwrap_or_else(|| DEFAULT_API.to_string());
        let env = probe_env(&binary, &api);
        let data = env.as_ref().map(|e| e.data_dir.clone()).unwrap_or_default();
        let action = env.as_ref().map(|e| e.action.clone()).unwrap_or_default();
        println!(
            "{{\"api\":\"{}\",\"data_dir\":\"{}\",\"sidecar\":\"{}\",\"action\":\"{}\"}}",
            env.as_ref().map(|e| e.api_addr.clone()).unwrap_or(api),
            data,
            binary.display(),
            action
        );
        return;
    }

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            status,
            open_console,
            refresh,
            setup,
            uninstall_service
        ])
        .setup(|app| {
            let binary = gateway_binary(app.handle());
            let api = env_override("TP_API_ADDR").unwrap_or_else(|| DEFAULT_API.to_string());
            app.manage(Runtime {
                binary,
                console_url: Mutex::new(format!("http://{api}/")),
                api: api.clone(),
                status: Mutex::new(Status {
                    api,
                    ..Default::default()
                }),
            });
            let handle = app.handle().clone();
            // Off the UI thread: probing and elevation both block, and a frozen
            // splash is indistinguishable from a crash.
            std::thread::spawn(move || bring_up(&handle));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build the trust-proxy shell")
        .run(|_app, _event| {});
}

/// bring_up decides, once, what this window is looking at.
///
/// Three outcomes and no others: attach to the gateway, ask for one prompt to
/// install it, or say why neither is possible. There is deliberately no fourth
/// where the shell quietly starts something of its own.
fn bring_up(app: &AppHandle) {
    let rt = app.state::<Runtime>();
    log(&format!(
        "asking {} about this machine",
        rt.binary.display()
    ));
    let env = match probe_env(&rt.binary, &rt.api) {
        Some(e) => e,
        None => {
            let why = sidecar_problem(&rt.binary);
            log(&format!("could not run the gateway binary: {why}"));
            set(app, |s| s.error = Some(why));
            return;
        }
    };
    apply_env(app, &env);
    log(&format!("next: {}", env.action));

    match env.action.as_str() {
        // The only path that opens the console by itself. Everything else has
        // something to say first, and saying it *before* navigating is the whole
        // point: once the window is on the console there is no splash left to put
        // an offer on.
        "attach" => {
            if !env.gateway.console {
                log("attached, but that gateway has no console in it");
                return;
            }
            open_the_console(app);
        }
        "unsupported" => set(app, |s| {
            s.error = Some(format!(
                "installing a system service is not implemented on {} yet — \
                 run the gateway under this machine's init system instead.",
                env.platform
            ))
        }),
        "repair" => {
            let detail = if env.service.program_missing {
                " — the program it points at is gone".to_string()
            } else if env.service.detail.is_empty() {
                String::new()
            } else {
                format!(" ({})", env.service.detail)
            };
            set(app, |s| {
                s.error = Some(format!(
                    "the gateway service is installed but not running{detail}. \
                     Reinstalling it is the repair."
                ))
            });
        }
        // "update", "takeover" and "install" are all offers; the splash renders
        // them from `action`, and each runs the same privileged command.
        _ => {}
    }
}

/// probe_env runs `trust-proxy env --json` and parses it. None means the binary
/// could not be run at all — a missing, unexecutable or Gatekeeper-killed sidecar.
fn probe_env(binary: &Path, api: &str) -> Option<Env> {
    let out = Command::new(binary)
        .args(["env", "--json", "--api-addr", api])
        .output()
        .ok()?;
    if !out.status.success() && out.stdout.is_empty() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

fn apply_env(app: &AppHandle, env: &Env) {
    if !env.console_url.is_empty() {
        if let Ok(mut u) = app.state::<Runtime>().console_url.lock() {
            *u = env.console_url.clone();
        }
    }
    set(app, |s| {
        s.api = env.api_addr.clone();
        s.data_dir = env.data_dir.clone();
        s.platform = env.platform.clone();
        s.elevation = env.elevation.clone();
        s.action = env.action.clone();
        s.app_version = env.version.clone();
        s.gateway_version = env.gateway.version.clone();
        s.service_supported = env.service.supported;
        s.service_installed = env.service.installed;
        s.service_running = env.service.running;
        s.healthy = env.gateway.healthy;
        s.console_missing = env.gateway.healthy && !env.gateway.console;
        s.error = None;
    });
}

/// open_the_console points the window at the gateway, logged in when it can be.
///
/// `auth ticket` turns the API key this user already has — the one `install`
/// wrote into their home directory — into a single-use URL that sets a session
/// cookie. When there is no key (someone else claimed this gateway, or the user
/// declined to claim it) the plain console URL is right: its own login page is
/// the correct thing to show.
fn open_the_console(app: &AppHandle) {
    let rt = app.state::<Runtime>();
    let url = match console_ticket(&rt.binary, &rt.api) {
        Some(u) => {
            log("opening the console with a session ticket");
            u
        }
        None => {
            log("no stored credential; opening the console's login page");
            rt.console_url
                .lock()
                .map(|u| u.clone())
                .unwrap_or_else(|_| format!("http://{}/", rt.api))
        }
    };
    show_console(app, &url);
}

fn console_ticket(binary: &Path, api: &str) -> Option<String> {
    let out = Command::new(binary)
        .args(["auth", "ticket", "--api-addr", api])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let url = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if url.starts_with("http://") || url.starts_with("https://") {
        Some(url)
    } else {
        None
    }
}

/// show_console navigates the existing window.
///
/// It hops to the main thread first. Everything that decides *whether* to
/// navigate runs on a worker thread because it blocks; but the webview is a
/// platform widget, and touching one from another thread is not an error, it
/// simply does nothing. That was the whole "stuck on the splash" bug: the shell
/// attached, called navigate, logged success, and the window never moved.
fn show_console(app: &AppHandle, url: &str) {
    let handle = app.clone();
    let target = url.to_string();
    if let Err(e) = app.run_on_main_thread(move || {
        let Some(window) = handle.get_webview_window("main") else {
            log("no window to navigate — the console cannot be shown");
            return;
        };
        match target.parse() {
            Ok(parsed) => {
                if let Err(e) = WebviewWindow::navigate(&window, parsed) {
                    log(&format!("navigate to {target} failed: {e}"));
                }
            }
            Err(e) => log(&format!("not a usable URL {target}: {e}")),
        }
    }) {
        log(&format!("could not reach the main thread to open {url}: {e}"));
    }
}

// ---- commands the splash calls -------------------------------------------

#[tauri::command]
fn status(rt: State<Runtime>) -> Status {
    rt.status
        .lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| Status {
            api: rt.api.clone(),
            error: Some("status unavailable".into()),
            ..Default::default()
        })
}

#[tauri::command]
fn refresh(app: AppHandle) {
    std::thread::spawn(move || bring_up(&app));
}

#[tauri::command]
fn open_console(app: AppHandle) {
    std::thread::spawn(move || open_the_console(&app));
}

/// setup is the one-click, and it is also the update and the takeover: all three
/// are the same privileged command, which is why there is one of it.
///
/// One system authorization prompt, then a gateway that belongs to this machine
/// and comes back after a reboot. `install` replaces the managed copy of the
/// binary and restarts the service, so running it again *is* the upgrade — which
/// is what makes "you opened a newer app than the daemon" a button rather than a
/// paragraph of instructions.
///
/// The command it elevates is the CLI's own, unmodified. An earlier version
/// assembled its own argument list here and passed `--data <home>` — which
/// silently undid the rule that a root daemon keeps its state out of anybody's
/// home, and produced exactly the root-owned directory this shell then had to
/// apologize for.
#[tauri::command]
fn setup(app: AppHandle, rt: State<Runtime>, mode: Option<String>) -> Result<String, String> {
    let owner = current_user().ok_or("could not work out which account to claim the gateway for")?;
    let mut cmd = format!(
        "{} install --api-addr {} --claim-for {} --takeover --json",
        shell_quote(&rt.binary.display().to_string()),
        shell_quote(&rt.api),
        shell_quote(&owner),
    );
    if let Some(m) = mode.as_deref().filter(|m| !m.is_empty()) {
        // -y because the confirmation the CLI would print has already been made in
        // the UI, and there is no terminal here to answer it on.
        cmd.push_str(&format!(" --mode {} -y", shell_quote(m)));
    }

    set(&app, |s| {
        s.busy = true;
        s.error = None;
    });
    let result = admin(&cmd);
    set(&app, |s| s.busy = false);

    match result {
        Ok(out) => {
            // Wait for the service to answer before showing anything: navigating to
            // a gateway that is still binding its ports gives a connection error
            // page, which reads as "the install failed" when it did not.
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline && !healthy(&rt.api, Duration::from_millis(500)) {
                std::thread::sleep(Duration::from_millis(300));
            }
            let app2 = app.clone();
            std::thread::spawn(move || bring_up(&app2));
            Ok(out)
        }
        Err(e) => {
            // Declined or failed. There is deliberately nothing to fall back to:
            // a user-level gateway would have no TUN, would die with this window,
            // and would leave state that the real install then has to clean up.
            set(&app, |s| s.error = Some(e.clone()));
            Err(e)
        }
    }
}

#[tauri::command]
fn uninstall_service(app: AppHandle, rt: State<Runtime>) -> Result<String, String> {
    let cmd = format!(
        "{} uninstall --json",
        shell_quote(&rt.binary.display().to_string())
    );
    let out = admin(&cmd)?;
    let app2 = app.clone();
    std::thread::spawn(move || bring_up(&app2));
    Ok(out)
}

// ---- elevation ------------------------------------------------------------

/// admin runs one shell command with an authorization prompt.
///
/// One elevation *mechanism per OS*, but the same CLI command in all three: what
/// gets installed never depends on which prompt asked. The shell itself is never
/// root — it asks the platform to run the CLI as root and reads back the CLI's
/// own JSON.
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
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        if stderr.contains("User canceled") || stderr.contains("(-128)") {
            return Err("the administrator prompt was cancelled".into());
        }
        return Err(stderr);
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
    let out_file =
        std::env::temp_dir().join(format!("trust-proxy-admin-{}.json", std::process::id()));
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
/// than being re-split here — re-splitting is how a path with a space in it turns
/// into two arguments.
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

// ---- odds and ends --------------------------------------------------------

/// current_user is who this window belongs to — the account `install` should
/// create the first admin for and leave the API key with.
///
/// Passed explicitly rather than left to SUDO_USER: the authorization prompts
/// this shell uses do not all set it, and a credential dropped in root's home is
/// a credential nobody at the keyboard will ever find.
fn current_user() -> Option<String> {
    for var in ["USER", "LOGNAME", "USERNAME"] {
        if let Some(v) = env_override(var) {
            return Some(v);
        }
    }
    None
}

fn healthy(api: &str, timeout: Duration) -> bool {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    let Ok(addr) = api.parse() else { return false };
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, timeout) else {
        return false;
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

/// sidecar_problem explains a gateway binary that would not run at all.
///
/// On macOS the usual cause is Gatekeeper: approving the *app* does not extend to
/// a binary it launches, and on macOS 26 that binary is SIGKILLed with nothing in
/// any log. Guessing from an empty failure is not something a user should have to
/// do, so the command that fixes it is named, with its path.
fn sidecar_problem(binary: &Path) -> String {
    if !binary.exists() {
        return format!(
            "the gateway binary is missing from this app ({}). This build is incomplete — \
             rebuild it with `make build`.",
            binary.display()
        );
    }
    let bundle = binary
        .ancestors()
        .find(|p| p.extension().map(|e| e == "app").unwrap_or(false))
        .unwrap_or(binary);
    if is_quarantined(bundle) {
        return format!(
            "macOS refused to run the gateway inside this app: the copy is still \
             quarantined, and this build is not notarized. Clear it once:\n\n    \
             xattr -dr com.apple.quarantine {}\n\nor allow the app under System \
             Settings → Privacy & Security.",
            shell_quote(&bundle.display().to_string())
        );
    }
    format!(
        "the gateway binary in this app could not be run ({}).",
        binary.display()
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

/// log writes one line to stderr, which is where someone running the binary from
/// a terminal will look, and where the platform's log viewer picks it up.
fn log(msg: &str) {
    eprintln!("[trust-proxy shell] {msg}");
}

fn set(app: &AppHandle, f: impl FnOnce(&mut Status)) {
    if let Ok(mut s) = app.state::<Runtime>().status.lock() {
        f(&mut s);
    }
}

/// env_override reads an environment variable, treating an empty value as absent.
///
/// `TP_API_ADDR=` is not a request to connect to nowhere — it is a variable
/// somebody cleared. Taking it literally produced a shell that probed the empty
/// string and could never attach.
fn env_override(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => None,
    }
}

/// sidecar_name is the gateway executable's file name inside the bundle.
fn sidecar_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "trust-proxy.exe"
    } else {
        "trust-proxy"
    }
}

/// gateway_binary is the sidecar inside the bundle, or an override for dev.
fn gateway_binary(app: &AppHandle) -> PathBuf {
    if let Some(p) = env_override("TP_BINARY") {
        return PathBuf::from(p);
    }
    // Tauri strips the target triple from an externalBin, but *where* the result
    // lands differs per platform: next to the executable on Linux/Windows, in the
    // bundle's MacOS/ directory on macOS (a sibling of Resources/). Try both
    // rather than encoding one layout.
    let exe_name = sidecar_name();
    if let Ok(dir) = app.path().resource_dir() {
        for candidate in [dir.join(format!("../MacOS/{exe_name}")), dir.join(exe_name)] {
            if let Ok(canon) = candidate.canonicalize() {
                return canon;
            }
        }
    }
    gateway_binary_standalone()
}

/// gateway_binary_standalone is the same lookup without a Tauri handle, for
/// --print-config (which runs before any app exists).
fn gateway_binary_standalone() -> PathBuf {
    if let Some(p) = env_override("TP_BINARY") {
        return PathBuf::from(p);
    }
    let exe_name = sidecar_name();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for candidate in [dir.join(exe_name), dir.join(format!("../MacOS/{exe_name}"))] {
                if candidate.exists() {
                    return candidate;
                }
            }
        }
    }
    PathBuf::from(exe_name)
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
        let cmd = "'/Applications/Trust Proxy.app/tp' install --claim-for 'a b'";
        let argv = pkexec_argv(cmd);
        assert_eq!(argv[0], "pkexec");
        // sh -c takes the whole line as ONE argument; splitting it would install
        // against the wrong arguments instead of failing loudly.
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

    // The shell must not carry its own idea of where anything is: every fact comes
    // out of `env --json`. This pins the field names, because a rename on the Go
    // side would otherwise leave the window silently showing defaults — empty
    // paths, "not installed", and a setup button that is wrong.
    #[test]
    fn the_env_contract_is_what_the_go_side_prints() {
        let raw = r#"{
            "platform":"linux","arch":"amd64","version":"v1","privileged":false,
            "can_tun":true,"data_dir":"/var/lib/trust-proxy",
            "managed_binary":"/usr/local/libexec/trust-proxy",
            "api_addr":"127.0.0.1:21585","console_url":"http://127.0.0.1:21585/",
            "elevation":"pkexec","action":"repair",
            "service":{"supported":true,"installed":true,"running":false,
                       "detail":"failed","program_missing":true},
            "gateway":{"healthy":false,"console":false,"version":"","managed":false,"stale":false}
        }"#;
        let env: Env = serde_json::from_str(raw).expect("the env contract must parse");
        assert_eq!(env.platform, "linux");
        assert_eq!(env.data_dir, "/var/lib/trust-proxy");
        assert_eq!(env.elevation, "pkexec");
        assert_eq!(env.action, "repair");
        assert!(env.service.installed && !env.service.running);
        assert!(env.service.program_missing);
        assert!(!env.gateway.healthy);
    }

    // The upgrade shape: a gateway that is up, is the managed copy, and is a
    // different build from the app that just opened. The shell must not treat this
    // as "attach" — that is the silent no-op upgrade, where the new app shows the
    // old daemon's console and nothing looks wrong.
    #[test]
    fn a_stale_daemon_arrives_as_an_update_not_an_attach() {
        let env: Env = serde_json::from_str(
            r#"{"platform":"darwin","data_dir":"/d","api_addr":"a:1","console_url":"http://a:1/",
                "version":"v2","action":"update",
                "service":{"supported":true,"installed":true,"running":true},
                "gateway":{"healthy":true,"console":true,"version":"v1","managed":true,"stale":true}}"#,
        )
        .expect("must parse");
        assert_eq!(env.action, "update");
        assert!(env.gateway.stale);
        assert_ne!(env.version, env.gateway.version);
        assert!(env.gateway.managed);
    }

    // A gateway that is up but console-less, and an older binary that does not
    // know some field yet, must both degrade to something usable rather than
    // failing to parse and leaving the window blank.
    #[test]
    fn a_partial_env_still_parses() {
        let env: Env = serde_json::from_str(
            r#"{"platform":"darwin","data_dir":"/d","api_addr":"a:1","console_url":"http://a:1/"}"#,
        )
        .expect("missing optional sections must default, not fail");
        assert!(!env.service.supported);
        assert!(!env.gateway.healthy);
        assert_eq!(env.elevation, "");
    }

    #[test]
    fn health_probe_rejects_a_dead_port_quickly() {
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
            (
                "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n",
                false,
            ),
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

    #[test]
    fn which_finds_a_program_on_the_path_and_not_a_made_up_one() {
        assert!(which("sh").is_some());
        assert!(which("definitely-not-a-real-program-xyz").is_none());
    }

    // A missing sidecar and a quarantined one are different failures with
    // different fixes, and neither is guessable from "the app will not open".
    #[test]
    fn a_missing_sidecar_says_so_rather_than_blaming_gatekeeper() {
        let msg = sidecar_problem(Path::new("/nowhere/trust-proxy"));
        assert!(msg.contains("missing"), "{msg}");
        assert!(!msg.contains("quarantine"), "{msg}");
    }
}
