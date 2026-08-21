//! Launch Windows 365 / AVD sessions through an upstream FreeRDP 3 client.
//!
//! This is the Linux integration boundary: rdpio authenticates and discovers
//! the workspace (its own W365 machinery), downloads Microsoft's current signed
//! `.rdp` resource, and hands it to an unmodified upstream FreeRDP. Everything
//! past this point — ARM gateway brokering, AAD/RDSAAD session authentication,
//! the RDP protocol, graphics, input, audio, clipboard, dynamic resize and the
//! MS-RDPECAM webcam channel — is FreeRDP's, not rdpio's.
//!
//! Contract kept by this module:
//!
//! - FreeRDP is invoked directly with an argv vector — never a shell;
//! - no tokens or other secrets ever enter argv or the environment;
//! - Microsoft's `.rdp` payload is written verbatim to a `0600` temp file and
//!   removed after the session exits;
//! - camera redirection is enabled only when the installed FreeRDP actually
//!   has the upstream RDPECAM client channel.

use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Candidate executables, best first: the SDL3 client is the maintained one
/// upstream recommends for AVD; the X11 client is the fallback.
const FREE_RDP_CANDIDATES: [&str; 4] = ["sdl-freerdp3", "sdl-freerdp", "xfreerdp3", "xfreerdp"];

/// A discovered FreeRDP 3 client.
#[derive(Debug, Clone)]
pub struct FreeRdp {
    pub exe: PathBuf,
    /// Parsed major.minor (e.g. `3.30`), when `/version` was readable.
    pub version: Option<(u32, u32)>,
}

/// Where RDPECAM support was detected (diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdpecamSupport {
    /// The RDPECAM client channel is compiled into this FreeRDP.
    Yes,
    /// This FreeRDP build lacks `CHANNEL_RDPECAM_CLIENT`.
    No,
    /// Could not determine (library not found / unreadable).
    Unknown,
}

impl FreeRdp {
    /// Locate an upstream FreeRDP 3 client: `$RDPIO_FREERDP`, then the usual
    /// binary names on `PATH`. Version is read once with `/version`.
    pub fn find() -> Option<FreeRdp> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(env_exe) = std::env::var("RDPIO_FREERDP") {
            if !env_exe.is_empty() {
                candidates.push(PathBuf::from(env_exe));
            }
        }
        candidates.extend(FREE_RDP_CANDIDATES.iter().map(PathBuf::from));

        for cand in candidates {
            let exe = if cand.is_absolute() || cand.components().count() > 1 {
                cand
            } else {
                // Search PATH like a shell would, without a shell.
                match which(&cand) {
                    Some(p) => p,
                    None => continue,
                }
            };
            if !exe.is_file() {
                continue;
            }
            let version = read_version(&exe);
            // FreeRDP 3.x owns the ARM gateway + AAD support this backend needs.
            match version {
                Some((major, _)) if major < 3 => {
                    tracing::warn!(exe = %exe.display(), "FreeRDP found but it is not 3.x; skipping");
                    continue;
                }
                _ => {}
            }
            return Some(FreeRdp { exe, version });
        }
        None
    }

    /// Whether this FreeRDP build includes the upstream MS-RDPECAM client
    /// channel (`CHANNEL_RDPECAM_CLIENT=ON`; upstream's default is OFF).
    ///
    /// Detection, most reliable first: a dynamic `rdpecam-client.so` channel
    /// plugin next to the executable, or the statically-linked channel inside
    /// the client library (distributions link channels into
    /// `libfreerdp-client3.so`). The static channel's log tags
    /// (`rdpecam-device.client`) only exist when it was compiled in.
    pub fn rdpecam_support(&self) -> RdpecamSupport {
        // 1. Dynamic plugin builds install channels as
        //    <prefix>/lib{,64}/freerdp*/<channel>-client.so.
        if let Some(prefix) = self.exe.parent().and_then(Path::parent) {
            for libdir in ["lib", "lib64"] {
                let dir = prefix.join(libdir);
                let Ok(rd) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for entry in rd.flatten() {
                    let p = entry.path();
                    let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    if name.starts_with("freerdp") && p.is_dir() {
                        if p.join("rdpecam-client.so").is_file() {
                            return RdpecamSupport::Yes;
                        }
                    }
                }
            }
        }

        // 2. Statically-linked channel: scan the client library the executable
        //    links (via ldd) for the rdpecam client's log tag.
        if let Some(lib) = self.client_library() {
            if let Ok(bytes) = std::fs::read(&lib) {
                return if contains_marker(&bytes, b"rdpecam-device.client") {
                    RdpecamSupport::Yes
                } else if contains_marker(&bytes, b"This build does not support [MS-RDPECAM]") {
                    // The .rdp loader's warning for builds without the channel.
                    RdpecamSupport::No
                } else {
                    RdpecamSupport::Unknown
                };
            }
        }
        RdpecamSupport::Unknown
    }

    /// Path of `libfreerdp-client3.so*` the executable links (via `ldd`).
    fn client_library(&self) -> Option<PathBuf> {
        if let Ok(lib) = std::env::var("RDPIO_FREERDP_CLIENT_LIB") {
            if !lib.is_empty() {
                return Some(PathBuf::from(lib));
            }
        }
        let out = Command::new("ldd")
            .arg(&self.exe)
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if !line.contains("libfreerdp-client") {
                continue;
            }
            // `<libname> => <path> (<addr>)` — take the mapped path.
            if let Some((_, rest)) = line.split_once("=>") {
                let path = rest.trim().split_whitespace().next()?;
                let p = PathBuf::from(path);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        None
    }
}

fn contains_marker(bytes: &[u8], marker: &[u8]) -> bool {
    if marker.is_empty() || bytes.len() < marker.len() {
        return false;
    }
    bytes.windows(marker.len()).any(|w| w == marker)
}

/// PATH lookup without a shell.
fn which(name: &Path) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

/// Parse `This is FreeRDP version 3.24.2 (n/a)` → `Some((3, 24))`.
fn parse_version(output: &str) -> Option<(u32, u32)> {
    let after = output.split("version").nth(1)?;
    let ver = after.trim().split_whitespace().next()?;
    let mut parts = ver.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().unwrap_or(0);
    Some((major, minor))
}

fn read_version(exe: &Path) -> Option<(u32, u32)> {
    let out = Command::new(exe).arg("/version").output().ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    parse_version(&text)
}

/// Build the FreeRDP argv for a W365 session. Pure (unit-testable); never a
/// shell string, never a secret — FreeRDP performs its own interactive AAD
/// sign-in for the ARM gateway and the RDSAAD session, so no token is passed.
///
/// Flags: `/gateway:type:arm` selects the AVD ARM broker, `/sec:aad` the Entra
/// ID session logon, `/dvc:rdpecam` the MS-RDPECAM camera channel. `extra`
/// appends user passthrough flags (e.g. `/multimon`) verbatim.
pub fn build_args(exe: &Path, rdp_path: &Path, camera: bool, extra: &[String]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![
        exe.as_os_str().to_os_string(),
        rdp_path.as_os_str().to_os_string(),
        "/gateway:type:arm".into(),
        "/sec:aad".into(),
    ];
    if camera {
        argv.push("/dvc:rdpecam".into());
    }
    argv.extend(extra.iter().map(Into::into));
    argv
}

/// Write Microsoft's exact `.rdp` payload to a fresh `0600` file in the runtime
/// dir (XDG_RUNTIME_DIR, else /tmp). The payload may contain signed fields and
/// is never modified here. Returns the path for [`run_session`] to clean up.
pub fn write_secure_rdp(contents: &str) -> io::Result<PathBuf> {
    let dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    let mut seed = [0u8; 4];
    let _ = crate::rng::fill(&mut seed);
    let name = format!(
        "rdpio-w365-{}-{}.rdp",
        std::process::id(),
        seed.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let path = dir.join(name);
    // create_new + mode 0600: never reuse or expose another file, even briefly.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(contents.as_bytes())?;
    Ok(path)
}

/// Shell-quote one word for `script -c`'s inner exec string (single-quote
/// wrapping; embedded quotes closed-reopened). FreeRDP argv words are paths
/// and `/flag:value` strings, but quote correctly regardless.
fn sh_quote(word: &OsStr) -> OsString {
    let text = word.to_string_lossy();
    if text.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b',' | b'+' | b'%' | b'@' | b'[' | b']'
            )
    }) {
        word.to_os_string()
    } else {
        let mut out = String::from("'");
        for c in text.chars() {
            if c == '\'' {
                out.push_str("'\\''");
            } else {
                out.push(c);
            }
        }
        out.push('\'');
        OsString::from(out)
    }
}

/// Run the FreeRDP session and remove the temporary `.rdp` afterwards.
///
/// FreeRDP's `/sec:aad` path prints its own AAD prompts on stdout —
/// `Browse to: <authorize url>` + `Paste redirect URL here:` — once per token
/// (ARM gateway, then the session host). With `auto_auth`, rdpio answers them
/// itself: the authorize URL is opened in the system browser (the user's
/// Microsoft session — MFA/consent — lives there), the resulting
/// `nativeclient?code=…` redirect is observed in the browser's local history,
/// and the code URL is fed to FreeRDP's stdin. A manual paste into this
/// terminal keeps working at any time (stdin is forwarded verbatim).
///
/// FreeRDP is run under a pty (`script -qec … /dev/null`) because its AAD
/// prompt reader (`freerdp_interruptible_get_line`) waits on terminal-ready
/// events and does not wake on a plain pipe — with piped stdin it stalls
/// before the first prompt (observed on 3.24 and 3.30 alike). `script` execs
/// the inner command itself; the words are shell-quoted in
/// [`sh_quote`] and carry no secrets.
///
/// Privacy: only URLs matching Microsoft's `oauth2/nativeclient?code=`
/// redirect are ever read out of the history files; nothing is logged.
pub fn run_session(
    freerdp: &FreeRdp,
    argv: &[OsString],
    auto_auth: bool,
) -> io::Result<std::process::ExitStatus> {
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;

    let histories = history_files();
    let auto = auto_auth && !histories.is_empty();
    if auto_auth && histories.is_empty() {
        tracing::warn!(
            "no browser history found (Chromium-family or Firefox) — answer FreeRDP's AAD prompts by pasting the redirect URL"
        );
    }

    // FreeRDP under a pty via `script -qec "<exe> <args…>" /dev/null` — its
    // AAD prompt reader does not wake on pipes (see the module doc).
    let mut inner = String::new();
    for (i, word) in argv.iter().enumerate() {
        if i > 0 {
            inner.push(' ');
        }
        inner.push_str(&sh_quote(word).to_string_lossy());
    }
    let mut cmd = Command::new("script");
    cmd.arg("-qec")
        .arg(&inner)
        .arg("/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    tracing::info!(
        exe = %freerdp.exe.display(),
        auto_auth = auto,
        "launching FreeRDP (AAD prompts answered from the browser when possible)"
    );
    let mut child = cmd.spawn()?;

    // FreeRDP's stdin is a pipe we own: the manual-paste forwarder and the
    // auto-answer write into it. Keeping it in an Option lets EOF on *our*
    // stdin close nothing (FreeRDP keeps waiting for its codes).
    let child_stdin: Arc<Mutex<Option<ChildStdin>>> = Arc::new(Mutex::new(child.stdin.take()));

    // Manual path: forward our stdin lines to FreeRDP verbatim (a user pasting
    // the redirect URL works exactly as before).
    {
        let child_stdin = child_stdin.clone();
        std::thread::spawn(move || {
            let mut line = String::new();
            loop {
                line.clear();
                match std::io::stdin().read_line(&mut line) {
                    Ok(0) | Err(_) => return, // our EOF: keep FreeRDP's stdin open
                    Ok(_) => {}
                }
                let mut guard = child_stdin.lock().unwrap_or_else(|p| p.into_inner());
                let Some(mut w) = guard.as_mut() else { return };
                if w.write_all(line.as_bytes())
                    .and_then(|_| w.flush())
                    .is_err()
                {
                    return; // session ended
                }
            }
        });
    }

    // Output pumps: tee FreeRDP's stdout/stderr through to ours, one line at a
    // time, and hand each line to the prompt scanner.
    let (line_tx, line_rx) = mpsc::channel::<String>();
    let streams: Vec<Box<dyn std::io::Read + Send>> = vec![
        Box::new(child.stdout.take().expect("stdout piped")),
        Box::new(child.stderr.take().expect("stderr piped")),
    ];
    for stream in streams {
        let tx = line_tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(line.as_bytes());
                let _ = out.write_all(b"\n");
                let _ = out.flush();
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
    }
    drop(line_tx);

    // Prompt scanner: track the latest `Browse to:` URL; when FreeRDP asks
    // for the redirect URL, auto-answer it (one attempt per prompt instance —
    // FreeRDP re-prints the prompt if it times out, which starts a new one).
    {
        let child_stdin = child_stdin.clone();
        let last_browse: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let active: Arc<Mutex<Option<(String, Instant)>>> = Arc::new(Mutex::new(None));
        std::thread::spawn(move || {
            while let Ok(line) = line_rx.recv() {
                if let Some(url) = browse_url_from_line(&line) {
                    *last_browse.lock().unwrap_or_else(|p| p.into_inner()) = Some(url.to_string());
                }
                if !line.contains(PASTE_MARKER) {
                    continue;
                }
                let Some(url) = last_browse
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone()
                    .filter(|u| u.starts_with("https://login.microsoftonline.com/"))
                else {
                    continue;
                };
                // One worker per prompt instance; FreeRDP's 25s re-prints of
                // the same prompt while the worker polls are ignored.
                {
                    let mut act = active.lock().unwrap_or_else(|p| p.into_inner());
                    if let Some((active_url, since)) = act.as_ref() {
                        if active_url == &url && since.elapsed() < Duration::from_secs(90) {
                            continue;
                        }
                    }
                    *act = Some((url.clone(), Instant::now()));
                }
                if !auto {
                    tracing::info!(
                        "FreeRDP AAD prompt: complete the sign-in in the browser, then paste the final redirect URL here"
                    );
                    continue;
                }
                let child_stdin = child_stdin.clone();
                std::thread::spawn(move || auto_answer_prompt(url, child_stdin));
            }
        });
    }

    let status = child.wait()?;
    // Defensive cleanup: callers also remove the file themselves.
    Ok(status)
}

/// FreeRDP's AAD prompt marker lines (`client.c`, `client_cli_get_avd_access_token`).
const BROWSE_PREFIX: &str = "Browse to: ";
const PASTE_MARKER: &str = "Paste redirect URL here";

/// `Browse to: <url>` → `<url>` (FreeRDP prints the authorize URL it built).
fn browse_url_from_line(line: &str) -> Option<&str> {
    line.strip_prefix(BROWSE_PREFIX)
        .map(str::trim)
        .filter(|u| u.starts_with("https://"))
}

/// Local browser history databases that may observe the sign-in redirect.
/// `$RDPIO_BROWSER_HISTORY` overrides everything; otherwise the usual
/// Chromium-family profiles and Firefox places databases are listed.
fn history_files() -> Vec<PathBuf> {
    if let Ok(p) = std::env::var("RDPIO_BROWSER_HISTORY") {
        if !p.is_empty() {
            return vec![PathBuf::from(p)];
        }
    }
    let Some(home) = std::env::var("HOME").ok().filter(|s| !s.is_empty()) else {
        return Vec::new();
    };
    let home = PathBuf::from(home);
    let mut out = Vec::new();
    // Chromium family: one `History` per profile dir (Default, Profile N, …).
    for base in [
        home.join(".config/google-chrome"),
        home.join(".config/chromium"),
        home.join(".var/app/com.google.Chrome/config/google-chrome"),
        home.join(".var/app/org.chromium.Chromium/config/chromium"),
    ] {
        if let Ok(rd) = std::fs::read_dir(&base) {
            for entry in rd.flatten() {
                let history = entry.path().join("History");
                if history.is_file() {
                    out.push(history);
                }
            }
        }
    }
    // Firefox: places.sqlite inside each profile dir.
    if let Ok(rd) = std::fs::read_dir(home.join(".mozilla/firefox")) {
        for entry in rd.flatten() {
            let places = entry.path().join("places.sqlite");
            if places.is_file() {
                out.push(places);
            }
        }
    }
    out
}

/// All Microsoft OAuth redirect code URLs currently present in the browser
/// histories. Queried through SQLite (a copy is taken first — the browser owns
/// the live file) because browsers store long URLs — AAD authorization codes
/// are ~1.5 KB — split across SQLite overflow pages, invisible to raw scans.
/// Only rows whose URL contains Microsoft's `nativeclient?code=` redirect are
/// ever selected; nothing else is read.
fn scan_code_urls() -> std::collections::HashSet<String> {
    use rusqlite::OpenFlags;
    use std::collections::HashSet;

    let mut out = HashSet::new();
    for path in history_files() {
        let Some(tmp) = copy_to_temp(&path) else {
            continue;
        };
        let conn = rusqlite::Connection::open_with_flags(&tmp, OpenFlags::SQLITE_OPEN_READ_ONLY);
        let Ok(conn) = conn else { continue };
        // Chrome/Chromium store visits in `urls`; Firefox in `moz_places`.
        for table in ["urls", "moz_places"] {
            let sql =
                format!("SELECT url FROM {table} WHERE url LIKE '%/oauth2/nativeclient?code=%'");
            let Ok(mut stmt) = conn.prepare(&sql) else {
                continue;
            };
            let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) else {
                continue;
            };
            for url in rows.flatten() {
                out.insert(url);
            }
        }
        let _ = std::fs::remove_file(&tmp);
    }
    out
}

/// Snapshot a browser database to a fresh temp file (the browser may hold the
/// original locked or mid-write; a copy is always safe to read).
fn copy_to_temp(path: &Path) -> Option<PathBuf> {
    let mut seed = [0u8; 4];
    if !crate::rng::fill(&mut seed) {
        return None;
    }
    let tmp = std::env::temp_dir().join(format!(
        "rdpio-hist-{}-{}",
        std::process::id(),
        seed.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    std::fs::copy(path, &tmp).ok()?;
    Some(tmp)
}

/// Open `url` where the user's Microsoft session lives, as reliably as
/// possible: a new tab in the already-running browser instance (launching
/// `google-chrome URL` with the same profile defers to the running singleton),
/// else the desktop portal (`xdg-open`), else a fresh browser window. The
/// portal alone is not enough — it can silently drop the request.
fn open_in_running_browser(url: &str) {
    for (bin, proc_name) in [
        ("google-chrome", "chrome"),
        ("google-chrome-stable", "chrome"),
        ("chromium", "chromium"),
        ("firefox", "firefox"),
    ] {
        // Only defer to the running instance when that browser is actually up
        // (its singleton owns the profile; a fresh launch would race it).
        let running = std::process::Command::new("pgrep")
            .arg("-x")
            .arg(proc_name)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if running {
            if let Ok(mut child) = Command::new(bin)
                .arg(url)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            {
                tracing::debug!(browser = bin, "opened authorize URL in the running browser");
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return;
            }
        }
    }
    crate::browser_auth::open_browser(None, url);
}

/// Answer one FreeRDP AAD prompt: open the browser at its authorize URL and
/// watch for a *new* redirect code (anything not present when this started —
/// codes are single-use, and old ones linger in the history for months).
/// The code URL is written to FreeRDP's stdin the moment it appears; nothing
/// about it is logged.
fn auto_answer_prompt(url: String, child_stdin: Arc<Mutex<Option<ChildStdin>>>) {
    use std::collections::HashSet;

    open_in_running_browser(&url);
    tracing::info!(
        "FreeRDP AAD prompt: browser opened — completing the sign-in (then this prompt answers itself)"
    );
    let baseline: HashSet<String> = scan_code_urls();
    for _ in 0..60 {
        std::thread::sleep(Duration::from_secs(2));
        let observed = scan_code_urls();
        let candidate = observed.into_iter().find(|u| !baseline.contains(u));
        let Some(code_url) = candidate else { continue };
        tracing::info!("FreeRDP AAD prompt answered automatically from the browser sign-in");
        let mut guard = child_stdin.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(mut w) = guard.as_mut() {
            let _ = w.write_all(code_url.as_bytes());
            let _ = w.write_all(b"\n");
            let _ = w.flush();
        }
        return;
    }
    tracing::warn!(
        "no sign-in redirect observed in the browser within 120s — complete the sign-in manually and paste the final URL here"
    );
}

// --- V4L camera detection ---------------------------------------------------

/// Count plausible local capture devices (`/dev/videoN` nodes). Diagnostics and
/// the auto-enable heuristic only — FreeRDP's own RDPECAM/V4L enumeration does
/// the real work at session time, so no device is opened or locked here.
pub fn camera_device_count() -> usize {
    std::fs::read_dir("/dev")
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().to_str().map(str::to_string))
                .filter(|n| n.starts_with("video") && n[5..].chars().all(|c| c.is_ascii_digit()))
                .count()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_camera_on_off() {
        let exe = Path::new("/usr/bin/sdl-freerdp3");
        let rdp = Path::new("/run/user/1000/rdpio-w365-1-2.rdp");
        let on = build_args(exe, rdp, true, &[]);
        let off = build_args(exe, rdp, false, &[]);
        assert_eq!(
            on,
            vec![
                "/usr/bin/sdl-freerdp3",
                "/run/user/1000/rdpio-w365-1-2.rdp",
                "/gateway:type:arm",
                "/sec:aad",
                "/dvc:rdpecam",
            ]
        );
        assert_eq!(
            off,
            vec![
                "/usr/bin/sdl-freerdp3",
                "/run/user/1000/rdpio-w365-1-2.rdp",
                "/gateway:type:arm",
                "/sec:aad",
            ]
        );
        // No token-shaped argument ever appears.
        assert!(!on.iter().any(|a| a.to_string_lossy().contains("Bearer")));
    }

    #[test]
    fn argv_appends_passthrough_flags_verbatim() {
        let argv = build_args(
            Path::new("/bin/xfreerdp3"),
            Path::new("/tmp/a.rdp"),
            false,
            &["/multimon".to_string(), "/microphone:sys:pulse".to_string()],
        );
        assert_eq!(
            argv.last().unwrap().to_string_lossy(),
            "/microphone:sys:pulse"
        );
        assert_eq!(argv.len(), 6);
    }

    #[test]
    fn version_parsed_from_freerdp_output() {
        let out = "This is FreeRDP version 3.24.2 (n/a)\n";
        assert_eq!(parse_version(out), Some((3, 24)));
        assert_eq!(parse_version("garbage"), None);
    }

    #[test]
    fn marker_found_in_bytes() {
        assert!(contains_marker(
            b"hello rdpecam-device.client world",
            b"rdpecam-device.client"
        ));
        assert!(!contains_marker(b"hello world", b"rdpecam-device.client"));
    }

    #[test]
    fn browse_url_extracted_from_freerdp_prompt_line() {
        assert_eq!(
            browse_url_from_line(
                "Browse to: https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x"
            ),
            Some("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x")
        );
        // Not a URL line / not https → None.
        assert_eq!(browse_url_from_line("Browse to: garbage"), None);
        assert_eq!(browse_url_from_line("Something else entirely"), None);
        assert_eq!(browse_url_from_line("Paste redirect URL here: "), None);
    }

    #[test]
    fn history_scan_reads_long_urls_across_overflow_pages() {
        // AAD codes are ~1.5 KB; SQLite splits such rows across overflow
        // pages. Build a real DB with one very long code URL and prove the
        // query returns it whole (the old raw byte scan truncated at 481).
        use rusqlite::OpenFlags;
        let mut seed = [0u8; 4];
        assert!(crate::rng::fill(&mut seed));
        let dir = std::env::temp_dir().join(format!(
            "rdpio-hist-test-{}-{}",
            std::process::id(),
            seed.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("History");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "PRAGMA page_size=512; CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT);",
        )
        .unwrap();
        let long_code = "0.".to_string() + &"AQoA".repeat(400); // ~1.6 KB
        let url = format!(
            "https://login.microsoftonline.com/common/oauth2/nativeclient?code={long_code}&session_state=x"
        );
        conn.execute("INSERT INTO urls(url) VALUES (?1)", [&url])
            .unwrap();
        drop(conn);

        let url_len = url.len();
        assert!(
            url_len > 1500,
            "test URL must be overflow-sized, got {url_len}"
        );
        std::env::set_var("RDPIO_BROWSER_HISTORY", &db);
        let scanned = scan_code_urls();
        std::env::remove_var("RDPIO_BROWSER_HISTORY");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned.iter().next().unwrap().len(), url_len);
    }

    #[test]
    fn history_scan_ignores_files_without_matching_urls() {
        use rusqlite::OpenFlags;
        let mut seed = [0u8; 4];
        assert!(crate::rng::fill(&mut seed));
        let dir = std::env::temp_dir().join(format!(
            "rdpio-hist-test2-{}-{}",
            std::process::id(),
            seed.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("History");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT);")
            .unwrap();
        conn.execute(
            "INSERT INTO urls(url) VALUES ('https://example.com/irrelevant')",
            [],
        )
        .unwrap();
        drop(conn);
        std::env::set_var("RDPIO_BROWSER_HISTORY", &db);
        let scanned = scan_code_urls();
        std::env::remove_var("RDPIO_BROWSER_HISTORY");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(scanned.is_empty());
    }

    #[test]
    fn plain_freerdp_words_pass_through_unquoted() {
        for word in [
            "/nix/store/x-freerdp-3.30.0/bin/sdl-freerdp",
            "/run/user/1000/rdpio-w365-1-ab.rdp",
            "/gateway:type:arm",
            "/sec:aad",
            "/dvc:rdpecam",
        ] {
            assert_eq!(sh_quote(OsStr::new(word)), OsString::from(word));
        }
    }

    #[test]
    fn spaces_and_quotes_are_shell_quoted() {
        assert_eq!(
            sh_quote(OsStr::new("/path/with space/freerdp")),
            OsString::from("'/path/with space/freerdp'")
        );
        assert_eq!(sh_quote(OsStr::new("it's")), OsString::from("'it'\\''s'"));
    }
}
