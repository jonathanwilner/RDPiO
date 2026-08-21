//! Encrypted on-disk cache for the W365 OAuth2 refresh token.
//!
//! Interactive W365 sign-in can require MFA on every launch. To avoid that, the
//! refresh token from a successful sign-in is cached and reused: the next launch
//! mints a fresh access token with the refresh-token grant (silent — no browser,
//! no MFA). Because the cache holds a long-lived credential, it is protected at
//! rest:
//!
//! - **Windows**: encrypted with DPAPI (`CryptProtectData`, per-user scope — the
//!   same primitive the Windows App uses) and stored under
//!   `%LOCALAPPDATA%\rdpio\`.
//! - **Linux**: the Linux Secret Service (gnome-keyring / KWallet via the
//!   `keyring` crate) when available, with a fallback to a permission-restricted
//!   (`0600`) file under `$XDG_STATE_HOME/rdpio/`.
//!
//! The cache document format is identical on every platform (see [`store`]).

use std::io;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::w365::{self, AccessToken};

const CACHE_FILE: &str = "w365_token.bin";
/// Secret Service entry: service + account name. The account distinguishes
/// tenant/client-id pairs so a `--tenant` switch does not cross-pollinate.
#[cfg(not(windows))]
const KEYRING_SERVICE: &str = "rdpio";
#[cfg(not(windows))]
fn keyring_account(tenant: &str, client_id: Option<&str>) -> String {
    format!("w365-token:{tenant}:{}", client_id.unwrap_or("default"))
}
/// Treat an access token as expired this many seconds before its real expiry, so
/// a connection is never started with a token about to lapse mid-handshake.
const EXPIRY_MARGIN: u64 = 300;

fn cache_path() -> Option<PathBuf> {
    #[cfg(windows)]
    let dir = {
        let local = std::env::var("LOCALAPPDATA")
            .ok()
            .filter(|s| !s.is_empty())?;
        PathBuf::from(local).join("rdpio")
    };
    #[cfg(not(windows))]
    let dir = state_dir()?;
    let _ = std::fs::create_dir_all(&dir);
    Some(dir.join(CACHE_FILE))
}

/// XDG state directory (`$XDG_STATE_HOME` or `~/.local/state`) + `rdpio`.
#[cfg(not(windows))]
fn state_dir() -> Option<PathBuf> {
    if let Ok(x) = std::env::var("XDG_STATE_HOME") {
        if !x.is_empty() {
            return Some(PathBuf::from(x).join("rdpio"));
        }
    }
    let home = std::env::var("HOME").ok().filter(|s| !s.is_empty())?;
    Some(
        PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("rdpio"),
    )
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serialize the token into the cache document shared by every platform.
fn cache_doc(tenant: &str, client_id: Option<&str>, token: &AccessToken) -> String {
    let expires_at = now_unix() + token.expires_in.as_secs();
    serde_json::json!({
        "v": 1,
        "tenant": tenant,
        "client_id": client_id,
        // The registration that minted this token — may differ from the
        // requested `client_id` when the login was reused from the teams-cli
        // cache. A later refresh must use it, or Entra rejects the grant.
        "token_client_id": token.client_id,
        "refresh_token": token.refresh_token,
        "access_token": token.token,
        "expires_at": expires_at,
        "username": token.username,
    })
    .to_string()
}

// --- Windows: DPAPI-encrypted file ------------------------------------------

#[cfg(windows)]
pub(crate) fn dpapi_protect(plain: &[u8]) -> io::Result<Vec<u8>> {
    use core::ffi::c_void;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptProtectData, CRYPT_INTEGER_BLOB};
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plain.len() as u32,
            pbData: plain.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        CryptProtectData(&in_blob, PCWSTR::null(), None, None, None, 0, &mut out_blob)
            .map_err(|e| io::Error::other(format!("CryptProtectData: {e}")))?;
        let out = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut c_void)));
        Ok(out)
    }
}

#[cfg(windows)]
pub(crate) fn dpapi_unprotect(blob: &[u8]) -> io::Result<Vec<u8>> {
    use core::ffi::c_void;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    unsafe {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: blob.len() as u32,
            pbData: blob.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB::default();
        CryptUnprotectData(&in_blob, None, None, None, None, 0, &mut out_blob)
            .map_err(|e| io::Error::other(format!("CryptUnprotectData: {e}")))?;
        let out = std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(out_blob.pbData as *mut c_void)));
        Ok(out)
    }
}

/// Persist the cache document. Windows: DPAPI blob in the cache file.
#[cfg(windows)]
fn persist(tenant: &str, client_id: Option<&str>, token: &AccessToken) -> io::Result<()> {
    let path = cache_path().ok_or_else(|| io::Error::other("no cache directory"))?;
    let blob = dpapi_protect(cache_doc(tenant, client_id, token).as_bytes())?;
    std::fs::write(&path, blob)
}

/// Load the cache document. Windows: DPAPI blob from the cache file.
#[cfg(windows)]
fn restore(_tenant: &str, _client_id: Option<&str>) -> io::Result<Option<String>> {
    let path = cache_path().ok_or_else(|| io::Error::other("no cache directory"))?;
    let blob = std::fs::read(&path)?;
    dpapi_unprotect(&blob).map(|p| Some(String::from_utf8_lossy(&p).into_owned()))
}

/// Remove the Windows cache file.
#[cfg(windows)]
fn remove_persisted() -> io::Result<()> {
    match cache_path().map(|p| std::fs::remove_file(p)) {
        Some(Ok(())) | None => Ok(()),
        Some(Err(e)) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Some(Err(e)) => Err(e),
    }
}

// --- Linux: Secret Service with a 0600-file fallback -------------------------

#[cfg(not(windows))]
mod linux_storage {
    use super::cache_doc;
    use crate::w365::AccessToken;
    use std::io;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    /// Store in the Secret Service; on any failure fall back to the 0600 file.
    pub fn persist(tenant: &str, client_id: Option<&str>, token: &AccessToken) -> io::Result<()> {
        let doc = cache_doc(tenant, client_id, token);
        match keyring_entry(tenant, client_id) {
            Ok(Some(entry)) => match entry.set_password(&doc) {
                Ok(()) => {
                    // A stale fallback file must not shadow the fresh secret.
                    let _ = remove_file();
                    tracing::info!("cached W365 refresh token in the Secret Service");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Secret Service unavailable; using the token file")
                }
            },
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "no Secret Service; using the token file"),
        }
        write_file(&doc)
    }

    /// Load from the Secret Service, then from the fallback file.
    pub fn restore(tenant: &str, client_id: Option<&str>) -> io::Result<Option<String>> {
        if let Ok(Some(entry)) = keyring_entry(tenant, client_id) {
            match entry.get_password() {
                Ok(doc) => return Ok(Some(doc)),
                Err(keyring::Error::NoEntry) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "Secret Service read failed; trying the token file")
                }
            }
        }
        read_file()
    }

    pub fn remove(tenant: &str, client_id: Option<&str>) -> io::Result<()> {
        if let Ok(Some(entry)) = keyring_entry(tenant, client_id) {
            match entry.delete_password() {
                Ok(()) | Err(keyring::Error::NoEntry) => {}
                Err(e) => tracing::debug!(error = %e, "Secret Service delete failed"),
            }
        }
        remove_file()
    }

    fn keyring_entry(
        tenant: &str,
        client_id: Option<&str>,
    ) -> Result<Option<keyring::Entry>, keyring::Error> {
        Ok(Some(keyring::Entry::new(
            super::KEYRING_SERVICE,
            &super::keyring_account(tenant, client_id),
        )?))
    }

    fn file_path() -> io::Result<std::path::PathBuf> {
        super::cache_path().ok_or_else(|| io::Error::other("no state directory"))
    }

    /// The token document carries a long-lived refresh token: the file fallback
    /// is created `0600`, owner-only, and never broadened afterwards.
    fn write_file(doc: &str) -> io::Result<()> {
        let path = file_path()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?
            .write_all(doc.as_bytes())?;
        tracing::info!(path = %path.display(), "cached W365 refresh token (mode 0600)");
        Ok(())
    }

    fn read_file() -> io::Result<Option<String>> {
        let path = file_path()?;
        match std::fs::read_to_string(&path) {
            Ok(doc) => Ok(Some(doc)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn remove_file() -> io::Result<()> {
        match file_path() {
            Ok(p) => match std::fs::remove_file(p) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            },
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

// --- Shared cache logic -----------------------------------------------------

#[cfg(not(windows))]
use linux_storage::{persist, restore};

/// Persist the refresh (and current access) token for silent reuse. Best-effort:
/// failures are logged and ignored — caching is an optimisation, not required
/// for a working connection.
pub fn store(tenant: &str, client_id: Option<&str>, token: &AccessToken) {
    if token.refresh_token.is_none() {
        tracing::debug!("no refresh token in response; W365 credentials not cached");
        return;
    }
    match persist(tenant, client_id, token) {
        Ok(()) => {}
        Err(e) => tracing::warn!(error = %e, "could not cache W365 token"),
    }
}

/// Try to obtain a token without prompting the user, using the cached refresh
/// token. Returns `None` when there is no usable cache (so the caller falls back
/// to interactive sign-in). A still-valid cached access token is returned as-is;
/// otherwise the refresh-token grant is used and the cache is refreshed. A
/// rejected refresh token clears the cache and returns `None`.
pub fn load_silent(tenant: &str, client_id: Option<&str>) -> Option<AccessToken> {
    let plain = match restore(tenant, client_id) {
        Ok(Some(doc)) => doc,
        Ok(None) => return None,
        Err(e) => {
            tracing::debug!(error = %e, "cached W365 token could not be read; ignoring");
            return None;
        }
    };
    let doc: serde_json::Value = serde_json::from_str(&plain).ok()?;

    // Only reuse a cache minted for the same tenant; a different `--tenant` must
    // authenticate against that directory.
    if doc.get("tenant").and_then(|v| v.as_str()) != Some(tenant) {
        tracing::debug!("cached W365 token is for a different tenant; ignoring");
        return None;
    }

    let username = doc
        .get("username")
        .and_then(|v| v.as_str())
        .map(String::from);
    // The registration that minted the cached token: the new `token_client_id`
    // when present, else the doc's `client_id` (caches written before the
    // teams-cli reuse existed only ever used the requested client).
    let mint_client = doc
        .get("token_client_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            doc.get("client_id")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
        })
        .map(String::from);
    let expires_at = doc.get("expires_at").and_then(|v| v.as_u64()).unwrap_or(0);
    let refresh = doc.get("refresh_token").and_then(|v| v.as_str());

    // A still-valid access token can be used directly — no network at all.
    if let Some(access) = doc.get("access_token").and_then(|v| v.as_str()) {
        if !access.is_empty() && now_unix() + EXPIRY_MARGIN < expires_at {
            tracing::info!("reusing cached W365 access token (no sign-in / MFA needed)");
            return Some(AccessToken {
                token: access.to_string(),
                refresh_token: refresh.map(String::from),
                expires_in: Duration::from_secs(expires_at.saturating_sub(now_unix())),
                username,
                client_id: mint_client,
            });
        }
    }

    // Otherwise mint a fresh access token from the refresh token (silent).
    // The grant must use the registration that minted the cached token —
    // rdpio's AVD client for normal logins, the teams-cli registration for a
    // login reused from teams-tui-go.
    let refresh = refresh?;
    tracing::info!("refreshing W365 access token from cached refresh token (no MFA)");
    match w365::refresh_token(tenant, mint_client.as_deref(), None, refresh) {
        Ok(mut token) => {
            // Refresh responses may omit the id_token; keep the cached username.
            if token.username.is_none() {
                token.username = username;
            }
            store(tenant, client_id, &token);
            Some(token)
        }
        Err(e) => {
            tracing::warn!(error = %e, "cached refresh token rejected; interactive sign-in required");
            let _ = clear(tenant, client_id);
            None
        }
    }
}

/// Remove the cached token (e.g. `--w365-relogin`, or after the refresh token is
/// rejected). A missing cache is not an error. On Linux the Secret Service entry
/// is keyed by tenant/client-id, so both are required there.
pub fn clear(tenant: &str, client_id: Option<&str>) -> io::Result<()> {
    #[cfg(windows)]
    {
        let _ = (tenant, client_id);
        return remove_persisted();
    }
    #[cfg(not(windows))]
    {
        return linux_storage::remove(tenant, client_id);
    }
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    // These tests mutate process-wide XDG env vars; serialize them (and keep
    // them away from the teams_auth tests, which use different vars).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn token() -> AccessToken {
        AccessToken {
            token: "access-1".into(),
            refresh_token: Some("refresh-1".into()),
            expires_in: std::time::Duration::from_secs(3600),
            username: Some("nick@contoso.com".into()),
            client_id: None,
        }
    }

    fn tempdir() -> std::path::PathBuf {
        let mut seed = [0u8; 4];
        crate::rng::fill(&mut seed);
        let dir = std::env::temp_dir().join(format!(
            "rdpio-token-test-{}-{}",
            std::process::id(),
            seed.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Full store -> silent-load -> clear round-trip against the 0600-file
    /// fallback in a throwaway XDG_STATE_HOME (the Secret Service is skipped
    /// when unavailable in the test environment).
    #[test]
    fn file_fallback_round_trip() {
        let _env = lock_env();
        let tmp = tempdir();
        std::env::set_var("XDG_STATE_HOME", &tmp);
        let (tenant, client_id) = ("roundtrip-tenant", None::<&str>);

        store(tenant, client_id, &token());
        let path = tmp.join("rdpio").join(CACHE_FILE);
        assert!(path.is_file(), "fallback file written");

        // The fallback file must be owner-only.
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "token file must be 0600");
        }

        let cached = load_silent(tenant, client_id).expect("silent load");
        assert_eq!(cached.token, "access-1");
        assert_eq!(cached.username.as_deref(), Some("nick@contoso.com"));

        // Different tenant must not reuse the cache.
        assert!(load_silent("other-tenant", client_id).is_none());

        clear(tenant, client_id).unwrap();
        assert!(!path.is_file(), "cache removed");
        assert!(load_silent(tenant, client_id).is_none());

        std::env::remove_var("XDG_STATE_HOME");
    }

    /// The minting registration survives the round trip and is what a later
    /// silent refresh uses — the teams-cli-reused login must refresh with the
    /// teams registration, not rdpio's AVD client.
    #[test]
    fn minted_client_id_round_trip() {
        let _env = lock_env();
        let tmp = tempdir();
        std::env::set_var("XDG_STATE_HOME", &tmp);
        let (tenant, client_id) = ("mint-tenant", None::<&str>);

        let mut t = token();
        t.client_id = Some("d3590ed6-52b3-4102-aeff-aad2292ab01c".into());
        store(tenant, client_id, &t);

        let path = tmp.join("rdpio").join(CACHE_FILE);
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            doc["token_client_id"].as_str(),
            Some("d3590ed6-52b3-4102-aeff-aad2292ab01c")
        );

        // Cached access token still valid → returned with the minting client.
        let cached = load_silent(tenant, client_id).expect("silent load");
        assert_eq!(
            cached.client_id.as_deref(),
            Some("d3590ed6-52b3-4102-aeff-aad2292ab01c")
        );

        clear(tenant, client_id).unwrap();
        std::env::remove_var("XDG_STATE_HOME");
    }

    /// Pre-`token_client_id` caches (v1 doc with only `client_id`) still load,
    /// deriving the minting client from the legacy field.
    #[test]
    fn legacy_cache_without_minted_client() {
        let _env = lock_env();
        let tmp = tempdir();
        std::env::set_var("XDG_STATE_HOME", &tmp);
        let dir = tmp.join("rdpio");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(CACHE_FILE),
            serde_json::json!({
                "v": 1,
                "tenant": "legacy",
                "client_id": "a85cf173-4192-42f8-81fa-777a763e6e2c",
                "access_token": "legacy-access",
                "refresh_token": "legacy-refresh",
                "expires_at": now_unix() + 3600,
                "username": "nick@contoso.com"
            })
            .to_string(),
        )
        .unwrap();

        let cached = load_silent("legacy", None).expect("legacy cache loads");
        assert_eq!(cached.token, "legacy-access");
        assert_eq!(
            cached.client_id.as_deref(),
            Some("a85cf173-4192-42f8-81fa-777a763e6e2c")
        );

        clear("legacy", None).unwrap();
        std::env::remove_var("XDG_STATE_HOME");
    }
}
