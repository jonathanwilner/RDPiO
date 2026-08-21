//! Reuse the teams-tui-go (~/src/newteams, `teams-tui-go`) login for W365.
//!
//! teams-tui-go signs in to Microsoft with two public-client flows:
//!
//! - **device** (`auth.go`): the OAuth2 device-code grant against the Office
//!   first-party registration (`client_id` in its `config.json`, default
//!   `d3590ed6-52b3-4102-aeff-aad2292ab01c`);
//! - **browser** (`auth_browser.go`): the authorization-code grant with PKCE
//!   and a `http://localhost:<port>` loopback redirect — the flow tenants use
//!   when Conditional Access blocks device codes (error 53003) — against a
//!   loopback-capable registration (`browser_client_id`, default
//!   `ac138a64-055b-4915-b670-31200c6235e6`).
//!
//! Its refresh token is cached in `~/.cache/teams-tui-go/token.json` together
//! with the `client_id` that acquired it. rdpio reuses that login **read-only**:
//! a refresh-token grant with the W365 scope mints a
//! `https://www.wvd.microsoft.com` access token with no browser and no MFA,
//! exactly how teams-tui-go itself refreshes. rdpio stores the result in its own
//! cache ([`crate::token_cache`]) and never writes to teams-tui-go's files.
//!
//! The same registrations also power rdpio's interactive fallbacks
//! ([`crate::browser_auth::authenticate_loopback`], device flow), so a tenant
//! that blocks the AVD client's nativeclient flow can still sign in.

use crate::w365::{self, AccessToken};

// Read the teams-tui-go configuration (~/.config/teams-tui-go/config.json).
// Only the auth-relevant keys are modeled; unknown keys are ignored. Every
// value carries teams-tui-go's own default so rdpio behaves identically when
// the file is absent.

/// teams-tui-go's default device-flow registration: the Microsoft Office
/// first-party public client.
const DEFAULT_TEAMS_CLIENT_ID: &str = "d3590ed6-52b3-4102-aeff-aad2292ab01c";
/// teams-tui-go's default browser-flow registration: a loopback-capable public
/// client shared with the ost/ttyms family of tools.
const DEFAULT_TEAMS_BROWSER_CLIENT_ID: &str = "ac138a64-055b-4915-b670-31200c6235e6";

/// The auth-relevant subset of teams-tui-go's `config.json`.
#[derive(Debug, Clone)]
pub struct TeamsCli {
    /// `auth_flow`: `"device"` (teams default) or `"browser"`.
    pub auth_flow: String,
    /// `browser_command`: how to open the login page (default `xdg-open`).
    pub browser_command: String,
    /// `client_id`: the device-flow registration.
    pub client_id: String,
    /// `browser_client_id`: the loopback browser-flow registration.
    pub browser_client_id: String,
}

impl Default for TeamsCli {
    fn default() -> Self {
        TeamsCli {
            auth_flow: "device".into(),
            browser_command: "xdg-open".into(),
            client_id: DEFAULT_TEAMS_CLIENT_ID.into(),
            browser_client_id: DEFAULT_TEAMS_BROWSER_CLIENT_ID.into(),
        }
    }
}

/// `$XDG_CONFIG_HOME | ~/.config` + `teams-tui-go/config.json`.
fn config_path() -> Option<std::path::PathBuf> {
    xdg_dir("XDG_CONFIG_HOME", ".config").map(|d| d.join("teams-tui-go").join("config.json"))
}

/// `$XDG_CACHE_HOME | ~/.cache` + `teams-tui-go/token.json`.
fn cache_path() -> Option<std::path::PathBuf> {
    xdg_dir("XDG_CACHE_HOME", ".cache").map(|d| d.join("teams-tui-go").join("token.json"))
}

/// Resolve an XDG base directory (`env_var` or `$HOME/fallback`).
fn xdg_dir(env_var: &str, fallback: &str) -> Option<std::path::PathBuf> {
    if let Ok(x) = std::env::var(env_var) {
        if !x.is_empty() {
            return Some(std::path::PathBuf::from(x));
        }
    }
    let home = std::env::var("HOME").ok().filter(|s| !s.is_empty())?;
    Some(std::path::PathBuf::from(home).join(fallback))
}

/// Load the teams-tui-go config. `Ok(None)` when there is no file (teams-tui-go
/// not installed / never configured) — callers then use rdpio's own defaults.
/// A present-but-unparseable file is an error worth surfacing, not hiding.
pub fn load_config() -> Result<Option<TeamsCli>, String> {
    let path = match config_path() {
        Some(p) => p,
        None => return Ok(None),
    };
    let raw = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("could not read {}: {e}", path.display())),
    };
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;

    let get = |key: &str, default: &str| -> String {
        v.get(key)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(String::from)
            .unwrap_or_else(|| default.to_string())
    };
    Ok(Some(TeamsCli {
        auth_flow: get("auth_flow", "device"),
        browser_command: get("browser_command", "xdg-open"),
        client_id: get("client_id", DEFAULT_TEAMS_CLIENT_ID),
        browser_client_id: get("browser_client_id", DEFAULT_TEAMS_BROWSER_CLIENT_ID),
    }))
}

/// The teams-tui-go token cache (`token.json`), parsed far enough to reuse the
/// login. Mirrors `TokenResponse` in teams-tui-go's `auth.go`: `client_id`
/// records which registration acquired the token so the refresh grant uses the
/// same one.
#[derive(Debug)]
struct TeamsToken {
    refresh_token: String,
    /// Registration that acquired the token (fallback: the device-flow default).
    client_id: String,
}

/// Read teams-tui-go's cached token. `None` when absent, unreadable, or the
/// file holds no refresh token (expired device-flow token, parse change…).
/// This is rdpio's read-only view: the file is never modified here.
fn load_token() -> Option<TeamsToken> {
    let path = cache_path()?;
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let refresh_token = v
        .get("refresh_token")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())?
        .to_string();
    let client_id = v
        .get("client_id")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| DEFAULT_TEAMS_CLIENT_ID.to_string());
    Some(TeamsToken {
        refresh_token,
        client_id,
    })
}

/// Try to mint a W365 access token from the teams-tui-go login, silently.
///
/// Sends the refresh-token grant to `login.microsoftonline.com` with the W365
/// scope, using the registration recorded in the teams token cache — the same
/// request teams-tui-go's `RefreshAccessToken` makes, with a different scope.
/// `openid profile` asks for an `id_token` so the username is known. Returns
/// `None` (with a logged reason) when there is no usable login or Entra
/// refuses the cross-scope refresh (e.g. consent); the caller then falls back
/// to an interactive flow. rdpio's own cache is written by the caller.
pub fn seed_w365_token(tenant: &str) -> Option<AccessToken> {
    let token = match load_token() {
        Some(t) => t,
        None => {
            tracing::debug!("no teams-tui-go token cache to reuse");
            return None;
        }
    };
    tracing::info!(
        client = %token.client_id,
        "reusing the teams-tui-go sign-in to obtain a Windows 365 token (no browser, no MFA)"
    );
    match w365::refresh_token(
        tenant,
        Some(&token.client_id),
        Some(w365::AUTH_CODE_SCOPE),
        &token.refresh_token,
    ) {
        Ok(mut access) => {
            if access.client_id.is_none() {
                access.client_id = Some(token.client_id);
            }
            Some(access)
        }
        Err(e) => {
            // Sanitized: AuthError::Failed carries Entra's error code +
            // description, never the token material.
            tracing::info!(
                error = %e,
                "the teams-tui-go refresh token could not mint a W365 token; falling back to interactive sign-in"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests mutate process-wide XDG env vars; serialize them.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    struct TempXdg {
        var: &'static str,
        dir: std::path::PathBuf,
    }
    impl TempXdg {
        fn new(var: &'static str, sub: &str) -> Self {
            let mut seed = [0u8; 4];
            crate::rng::fill(&mut seed);
            let dir = std::env::temp_dir().join(format!(
                "rdpio-teams-test-{}-{}",
                std::process::id(),
                seed.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ));
            std::fs::create_dir_all(dir.join(sub)).unwrap();
            std::env::set_var(var, &dir);
            TempXdg { var, dir }
        }
    }
    impl Drop for TempXdg {
        fn drop(&mut self) {
            std::env::remove_var(self.var);
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn missing_config_is_none() {
        let _env = lock_env();
        let _tmp = TempXdg::new("XDG_CONFIG_HOME", "teams-tui-go");
        assert!(load_config().unwrap().is_none());
    }

    #[test]
    fn config_parses_auth_fields() {
        let _env = lock_env();
        let tmp = TempXdg::new("XDG_CONFIG_HOME", "teams-tui-go");
        std::fs::write(
            config_path().unwrap(),
            r#"{
                "client_id": "11111111-2222-3333-4444-555555555555",
                "auth_flow": "browser",
                "browser_command": "firefox --new-window",
                "browser_client_id": "66666666-7777-8888-9999-000000000000",
                "unrelated_key": true
            }"#,
        )
        .unwrap();
        let cfg = load_config().unwrap().expect("config present");
        assert_eq!(cfg.auth_flow, "browser");
        assert_eq!(cfg.browser_command, "firefox --new-window");
        assert_eq!(cfg.client_id, "11111111-2222-3333-4444-555555555555");
        assert_eq!(
            cfg.browser_client_id,
            "66666666-7777-8888-9999-000000000000"
        );
        drop(tmp);
    }

    #[test]
    fn config_defaults_match_teams_cli() {
        let _env = lock_env();
        let tmp = TempXdg::new("XDG_CONFIG_HOME", "teams-tui-go");
        std::fs::write(config_path().unwrap(), "{}").unwrap();
        let cfg = load_config().unwrap().expect("config present");
        assert_eq!(cfg.auth_flow, "device");
        assert_eq!(cfg.browser_command, "xdg-open");
        assert_eq!(cfg.client_id, DEFAULT_TEAMS_CLIENT_ID);
        assert_eq!(cfg.browser_client_id, DEFAULT_TEAMS_BROWSER_CLIENT_ID);
        drop(tmp);
    }

    #[test]
    fn token_cache_round_trip_and_fallbacks() {
        let _env = lock_env();
        let tmp = TempXdg::new("XDG_CACHE_HOME", "teams-tui-go");
        let path = cache_path().unwrap();

        // Absent → None.
        assert!(load_token().is_none());

        // Present, with the minting client recorded (browser flow).
        std::fs::write(
            &path,
            r#"{"access_token":"x","refresh_token":"rt-1","expires_at":1,
                "client_id":"ac138a64-055b-4915-b670-31200c6235e6"}"#,
        )
        .unwrap();
        let t = load_token().expect("token parsed");
        assert_eq!(t.refresh_token, "rt-1");
        assert_eq!(t.client_id, "ac138a64-055b-4915-b670-31200c6235e6");

        // No client_id recorded → teams device-flow default.
        std::fs::write(&path, r#"{"access_token":"x","refresh_token":"rt-2"}"#).unwrap();
        let t = load_token().expect("token parsed");
        assert_eq!(t.client_id, DEFAULT_TEAMS_CLIENT_ID);

        // No refresh token (expired session) → None.
        std::fs::write(&path, r#"{"access_token":"x"}"#).unwrap();
        assert!(load_token().is_none());

        drop(tmp);
    }
}
