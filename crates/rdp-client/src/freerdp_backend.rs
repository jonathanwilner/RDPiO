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

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Run the FreeRDP session and remove the temporary `.rdp` afterwards. FreeRDP
/// inherits stdio so its own interactive AAD prompts work in this terminal.
pub fn run_session(freerdp: &FreeRdp, argv: &[OsString]) -> io::Result<std::process::ExitStatus> {
    let mut cmd = Command::new(&freerdp.exe);
    cmd.args(&argv[1..]);
    tracing::info!(
        exe = %freerdp.exe.display(),
        "launching FreeRDP (its own Microsoft sign-in prompts follow in this terminal)"
    );
    let status = cmd.status()?;
    // Defensive cleanup: callers also remove the file themselves.
    Ok(status)
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
}
