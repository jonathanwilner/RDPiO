//! Windows 365 / Azure Virtual Desktop modern authentication.
//!
//! W365 does not use CredSSP/NTLM. Instead the client obtains an OAuth2 access
//! token (via device-code flow) and passes it to the RDP stack, typically
//! through the RDWeb feed and then as the logon password in the Client Info PDU.
//!
//! This module implements the device-code grant from RFC 8628 against the
//! Microsoft identity platform. It is intentionally synchronous so it fits the
//! existing CLI/GUI startup flow without pulling in an async runtime.

use std::thread;
use std::time::{Duration, Instant};

// Azure Virtual Desktop / Windows 365 client application ID. This is the
// first-party app used by the Windows App / Microsoft Remote Desktop clients
// when authenticating to AVD/W365 resources. It can be overridden with
// `--client-id` if a tenant requires a different registration.
const DEFAULT_CLIENT_ID: &str = "a85cf173-4192-42f8-81fa-777a763e6e2c";
// The AVD/W365 feed needs a token for the Windows Virtual Desktop resource
// (app id 9cdead84-a844-4324-93f2-b2e6bb768d07, identifier URI
// https://www.wvd.microsoft.com), NOT Azure Resource Manager. The Remote
// Desktop client (DEFAULT_CLIENT_ID) is preauthorized for this resource, so
// `.default` works without an admin consent prompt.
const DEFAULT_SCOPE: &str = "https://www.wvd.microsoft.com/.default offline_access";

/// Result of a completed authentication (device-code or authorization-code).
#[derive(Debug, Clone)]
pub struct AccessToken {
    pub token: String,
    pub refresh_token: Option<String>,
    #[allow(dead_code)]
    pub expires_in: Duration,
    /// User principal name parsed from the `id_token`, when an OpenID Connect
    /// scope (`openid profile`) was requested. Used to default the RDSTLS logon
    /// username so the user need not pass `--user`.
    pub username: Option<String>,
    /// Tenant GUID parsed from the `id_token` (`tid` claim). Some first-party
    /// grants return an **opaque** access token (not a JWT), so the tenant
    /// cannot be derived from it later — it is captured here at exchange time
    /// for the ARM feed-discovery request.
    pub tenant_id: Option<String>,
    /// The app registration that actually minted this token (the `client_id`
    /// sent to the token endpoint). Tokens can be acquired through different
    /// registrations (rdpio's AVD client, or the teams-tui-go login reused via
    /// [`crate::teams_auth`]); a later refresh-token grant must use the same
    /// one or Entra rejects it. Mirrors teams-tui-go's `TokenResponse.ClientID`.
    pub client_id: Option<String>,
}

/// In-flight OAuth2 device-code flow. The caller displays `verification_uri`
/// (optionally with `user_code` pre-filled) to the user and polls
/// [`DeviceCodeFlow::poll`] until it returns a token or expires.
#[derive(Debug, Clone)]
pub struct DeviceCodeFlow {
    pub user_code: String,
    pub verification_uri: String,
    pub device_code: String,
    pub expires_in: Duration,
    pub interval: Duration,
    tenant: String,
    client_id: String,
    #[allow(dead_code)]
    scope: String,
}

impl DeviceCodeFlow {
    /// Poll the token endpoint once. Returns `Ok(None)` while the user has not
    /// yet completed the prompt; returns `Ok(Some(token))` once authentication
    /// succeeds. Errors are terminal.
    pub fn poll_once(&self) -> Result<Option<AccessToken>, AuthError> {
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant
        );

        // Microsoft returns HTTP 400 while the user has not yet completed the
        // prompt, with an `error` field such as `authorization_pending`. We must
        // read the body in that case instead of treating the status as fatal.
        let http_resp = ureq::post(&token_url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&form_encode(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", &self.client_id),
                ("device_code", &self.device_code),
            ]));

        let token_resp: serde_json::Value = match http_resp {
            Ok(r) => r.into_json()?,
            Err(ureq::Error::Status(code, r)) => {
                let body = r.into_string().unwrap_or_default();
                tracing::debug!(status = code, %body, "token poll returned non-success status");
                serde_json::from_str(&body)?
            }
            Err(e) => return Err(e.into()),
        };

        if let Some(err) = token_resp.get("error") {
            match err.as_str() {
                Some("authorization_pending") => return Ok(None),
                Some("authorization_declined") => {
                    return Err(AuthError::Failed("authorization declined".into()));
                }
                Some("expired_token") => {
                    tracing::error!("device code expired before authentication completed");
                    return Err(AuthError::Expired);
                }
                Some("bad_verification_code") => return Ok(None),
                Some(other) => {
                    let desc = token_resp["error_description"].as_str().unwrap_or("");
                    tracing::error!(error = %other, %desc, "token endpoint returned a terminal error");
                    return Err(AuthError::Failed(format!("{other}: {desc}")));
                }
                None => return Err(AuthError::Failed("unknown token error".into())),
            }
        }

        let token = token_resp["access_token"]
            .as_str()
            .ok_or_else(|| AuthError::Failed("missing access_token".into()))?
            .to_string();
        let refresh_token = token_resp["refresh_token"].as_str().map(String::from);
        let expires_in = token_resp["expires_in"].as_u64().unwrap_or(3600);

        Ok(Some(AccessToken {
            token,
            refresh_token,
            expires_in: Duration::from_secs(expires_in),
            username: token_resp["id_token"].as_str().and_then(parse_id_token_upn),
            tenant_id: id_token_tid(&token_resp),
            client_id: Some(self.client_id.clone()),
        }))
    }

    /// Block and poll the token endpoint until the user completes the prompt
    /// or the flow expires.
    pub fn poll(&self) -> Result<AccessToken, AuthError> {
        let deadline = Instant::now() + self.expires_in;
        loop {
            thread::sleep(self.interval);
            if Instant::now() > deadline {
                return Err(AuthError::Expired);
            }
            if let Some(token) = self.poll_once()? {
                return Ok(token);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("network error during authentication: {0}")]
    Network(#[from] ureq::Error),
    #[error("I/O error reading authentication response: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("authentication failed: {0}")]
    Failed(String),
    #[error("device code expired before authentication completed")]
    Expired,
    #[allow(dead_code)]
    #[error("authorization pending; user has not completed the prompt")]
    Pending,
}

/// Authenticate via OAuth2 device-code flow.
///
/// `tenant` is the Microsoft tenant id or `common`/`organizations`. The default
/// `client_id` is the Windows Virtual Desktop / Microsoft Remote Desktop client
/// id; override it if your tenant requires a different application registration.
///
/// This function blocks, prints the user code/verification URL via `tracing`,
/// and polls the token endpoint until the user completes the prompt or the code
/// expires.
pub fn authenticate_device_code(
    tenant: &str,
    client_id: Option<&str>,
    scope: Option<&str>,
) -> Result<AccessToken, AuthError> {
    let flow = start_device_code_flow(tenant, client_id, scope)?;
    tracing::info!(
        user_code = %flow.user_code,
        verification_uri = %flow.verification_uri,
        "complete authentication in your browser, then return to rdpio"
    );
    flow.poll()
}

/// Start an OAuth2 device-code flow and return the in-flight context.
///
/// The caller is responsible for showing `verification_uri` to the user (with
/// `user_code` pre-filled if desired) and calling [`DeviceCodeFlow::poll`].
pub fn start_device_code_flow(
    tenant: &str,
    client_id: Option<&str>,
    scope: Option<&str>,
) -> Result<DeviceCodeFlow, AuthError> {
    let client_id = client_id.unwrap_or(DEFAULT_CLIENT_ID).to_string();
    let scope = scope.unwrap_or(DEFAULT_SCOPE).to_string();

    let device_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode");

    tracing::info!(%device_url, %client_id, %scope, "requesting OAuth2 device code");

    let http_resp = ureq::post(&device_url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&form_encode(&[
            ("client_id", &client_id),
            ("scope", &scope),
        ]));

    let resp: serde_json::Value = match http_resp {
        Ok(r) => r.into_json()?,
        Err(ureq::Error::Status(code, r)) => {
            let body = r.into_string().unwrap_or_default();
            tracing::error!(status = code, %body, "device-code endpoint returned an error");
            return Err(AuthError::Failed(format!(
                "device-code endpoint returned {code}: {body}"
            )));
        }
        Err(e) => return Err(e.into()),
    };

    if let Some(err) = resp.get("error") {
        let desc = resp["error_description"].as_str().unwrap_or("");
        tracing::error!(error = %err, %desc, "device-code endpoint returned OAuth error");
        return Err(AuthError::Failed(format!(
            "{}: {}",
            err.as_str().unwrap_or("unknown"),
            desc
        )));
    }

    Ok(DeviceCodeFlow {
        user_code: resp["user_code"]
            .as_str()
            .ok_or_else(|| AuthError::Failed("missing user_code".into()))?
            .to_string(),
        device_code: resp["device_code"]
            .as_str()
            .ok_or_else(|| AuthError::Failed("missing device_code".into()))?
            .to_string(),
        verification_uri: resp["verification_uri"]
            .as_str()
            .ok_or_else(|| AuthError::Failed("missing verification_uri".into()))?
            .to_string(),
        expires_in: Duration::from_secs(resp["expires_in"].as_u64().unwrap_or(900)),
        interval: Duration::from_secs(resp["interval"].as_u64().unwrap_or(5).max(1)),
        tenant: tenant.to_string(),
        client_id,
        scope,
    })
}

fn form_encode(items: &[(&str, &str)]) -> String {
    items
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub(crate) fn url_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// The authorization-code scope used by every rdpio flow (feed token plus
/// `id_token` and refresh token). Shared with the loopback browser flow.
pub(crate) const AUTH_CODE_SCOPE: &str =
    "https://www.wvd.microsoft.com/.default openid profile offline_access";

/// Refresh an access token with the refresh token, if available.
///
/// `scope` is forwarded to the token endpoint when given; omitted it means
/// "the scopes this refresh token was originally granted", which is what
/// rdpio's own cache wants. Cross-registration reuse (the teams-tui-go login)
/// must pass the W365 scope explicitly so Entra mints a `www.wvd.microsoft.com`
/// audience instead of the originally-granted Microsoft Graph one.
pub fn refresh_token(
    tenant: &str,
    client_id: Option<&str>,
    scope: Option<&str>,
    refresh: &str,
) -> Result<AccessToken, AuthError> {
    let client_id = client_id.unwrap_or(DEFAULT_CLIENT_ID);
    let token_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");

    let mut form = vec![
        ("grant_type", "refresh_token"),
        ("client_id", client_id),
        ("refresh_token", refresh),
    ];
    if let Some(scope) = scope {
        form.push(("scope", scope));
    }

    let resp: serde_json::Value = ureq::post(&token_url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&form_encode(&form))?
        .into_json()?;

    if let Some(err) = resp.get("error") {
        return Err(AuthError::Failed(err.as_str().unwrap_or("unknown").into()));
    }

    Ok(AccessToken {
        token: resp["access_token"]
            .as_str()
            .ok_or_else(|| AuthError::Failed("missing access_token".into()))?
            .to_string(),
        refresh_token: resp["refresh_token"].as_str().map(String::from),
        expires_in: Duration::from_secs(resp["expires_in"].as_u64().unwrap_or(3600)),
        username: resp["id_token"].as_str().and_then(parse_id_token_upn),
        tenant_id: id_token_tid(&resp),
        client_id: Some(client_id.to_string()),
    })
}

// --- OAuth2 authorization-code flow (RFC 6749 §4.1) -------------------------
//
// The AVD/W365 first-party client (`DEFAULT_CLIENT_ID`) is registered as a
// public client for the authorization-code grant with the native redirect URI
// below, but it does NOT have the device-code (mobile & desktop) grant enabled —
// a device-code token request is rejected with `invalid_client` (AADSTS7000218).
// FreeRDP and the Windows App therefore use the authorization-code flow: the
// login page is shown in an embedded WebView, the browser is redirected to the
// `nativeclient` URL carrying `?code=...`, and that code is exchanged for a
// token. No client secret and no PKCE — exactly as FreeRDP's `client.c` does.
//
// Tenants whose Conditional Access blocks both of those (e.g. device-code
// error 53003) can sign in through the teams-tui-go login instead (see
// [`crate::teams_auth`]): the PKCE + localhost-loopback browser flow that
// teams-tui-go uses, plus silent reuse of its token cache.

/// Native-client redirect URI registered for `DEFAULT_CLIENT_ID`. AAD redirects
/// the browser here with the authorization code; the WebView intercepts it.
pub const NATIVE_REDIRECT_URI: &str =
    "https://login.microsoftonline.com/common/oauth2/nativeclient";

/// Build the authorization-code request URL to load in the login WebView.
/// `state` is echoed back on the redirect; pass one when the caller can
/// verify it (the Linux browser flow does — the WebView2 flow intercepts the
/// redirect locally and skips it).
pub fn build_authorize_url(
    tenant: &str,
    client_id: Option<&str>,
    scope: Option<&str>,
    state: Option<&str>,
) -> String {
    let client_id = client_id.unwrap_or(DEFAULT_CLIENT_ID);
    let scope = scope.unwrap_or(AUTH_CODE_SCOPE);
    let state = state
        .map(|s| format!("&state={}", url_encode(s)))
        .unwrap_or_default();
    format!(
        "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize\
         ?client_id={cid}&response_type=code&scope={scope}&redirect_uri={redir}{state}",
        tenant = tenant,
        cid = url_encode(client_id),
        scope = url_encode(scope),
        redir = url_encode(NATIVE_REDIRECT_URI),
    )
}

/// Exchange an authorization `code` (captured from the `nativeclient` redirect)
/// for an access token at the token endpoint.
pub fn exchange_auth_code(
    tenant: &str,
    client_id: Option<&str>,
    scope: Option<&str>,
    code: &str,
) -> Result<AccessToken, AuthError> {
    exchange_auth_code_full(tenant, client_id, scope, code, NATIVE_REDIRECT_URI, None)
}

/// Exchange an authorization `code` for tokens against an arbitrary redirect
/// URI, optionally proving a PKCE `code_verifier` (RFC 7636). This is the
/// general form used by the localhost-loopback browser flow; the plain
/// [`exchange_auth_code`] keeps the FreeRDP-compatible nativeclient shape.
pub fn exchange_auth_code_full(
    tenant: &str,
    client_id: Option<&str>,
    scope: Option<&str>,
    code: &str,
    redirect_uri: &str,
    code_verifier: Option<&str>,
) -> Result<AccessToken, AuthError> {
    let client_id = client_id.unwrap_or(DEFAULT_CLIENT_ID);
    let scope = scope.unwrap_or(AUTH_CODE_SCOPE);
    let token_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");

    tracing::info!(%token_url, "exchanging authorization code for token");

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("client_id", client_id),
        ("scope", scope),
        ("redirect_uri", redirect_uri),
    ];
    if let Some(verifier) = code_verifier {
        form.push(("code_verifier", verifier));
    }

    let http_resp = ureq::post(&token_url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_string(&form_encode(&form));

    let resp: serde_json::Value = match http_resp {
        Ok(r) => r.into_json()?,
        Err(ureq::Error::Status(status, r)) => {
            let body = r.into_string().unwrap_or_default();
            tracing::error!(status, %body, "token endpoint rejected authorization code");
            serde_json::from_str(&body)?
        }
        Err(e) => return Err(e.into()),
    };

    if let Some(err) = resp.get("error") {
        let desc = resp["error_description"].as_str().unwrap_or("");
        return Err(AuthError::Failed(format!(
            "{}: {}",
            err.as_str().unwrap_or("unknown"),
            desc
        )));
    }

    Ok(AccessToken {
        token: resp["access_token"]
            .as_str()
            .ok_or_else(|| AuthError::Failed("missing access_token".into()))?
            .to_string(),
        refresh_token: resp["refresh_token"].as_str().map(String::from),
        expires_in: Duration::from_secs(resp["expires_in"].as_u64().unwrap_or(3600)),
        username: resp["id_token"].as_str().and_then(parse_id_token_upn),
        tenant_id: id_token_tid(&resp),
        client_id: Some(client_id.to_string()),
    })
}

/// Parse an intercepted navigation or pasted final URL. Returns
/// `Some(Ok(code))` when `uri` is the native-client redirect carrying an
/// authorization `code`, `Some(Err(msg))` when it carries an OAuth `error`,
/// and `None` for any other URL (the login pages themselves). Shared by the
/// WebView2 panel (Windows) and the system-browser flow (Linux).
pub fn parse_auth_redirect(uri: &str) -> Option<Result<String, String>> {
    let query = uri.strip_prefix(NATIVE_REDIRECT_URI)?;
    // The redirect is `<redirect_uri>?code=...` (or `?error=...`). Tolerate an
    // exact match with no query as "not yet".
    let query = query
        .strip_prefix('?')
        .or_else(|| query.strip_prefix('#'))?;
    let mut code = None;
    let mut error = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "code" => code = Some(url_decode(v)),
            "error" => error = Some(url_decode(v)),
            "error_description" if error.is_some() => {
                error = Some(format!("{}: {}", error.unwrap(), url_decode(v)));
            }
            _ => {}
        }
    }
    if let Some(c) = code {
        Some(Ok(c))
    } else {
        error.map(Err)
    }
}

/// Return one `application/x-www-form-urlencoded` query parameter from a URL
/// (decoded). Used to read back the OAuth `state` echoed on the redirect.
#[cfg_attr(windows, allow(dead_code))] // only the Linux browser flow sends state
pub fn query_param(uri: &str, key: &str) -> Option<String> {
    let start = uri.find('?').or_else(|| uri.find('#'))? + 1;
    for pair in uri[start..].split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            return Some(url_decode(v));
        }
    }
    None
}

pub fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    out.push((hi * 16 + lo) as u8);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extract the user principal name from an OIDC `id_token` (the unverified JWT
/// payload — we only read a display/login hint from it, we do not trust it for
/// authorization). Prefers `upn`, then `preferred_username`, then `email`.
fn parse_id_token_upn(id_token: &str) -> Option<String> {
    let claims = decode_jwt_claims(id_token)?;
    for key in ["upn", "preferred_username", "email", "unique_name"] {
        if let Some(v) = claims.get(key).and_then(|v| v.as_str()) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Decode the JWT payload claims of a Microsoft token (`id_token` or access
/// token). Unverified — only used for display hints (UPN) and routing data
/// (tenant id), never for authorization. Never log the token itself.
fn decode_jwt_claims(jwt: &str) -> Option<serde_json::Value> {
    let payload_b64 = jwt.split('.').nth(1)?;
    let bytes = crate::arm_broker::decode_b64(payload_b64)?;
    serde_json::from_slice(&bytes).ok()
}

/// Extract the tenant GUID (`tid`) from an OIDC `id_token`. Unlike the access
/// token (which some first-party grants return opaque), the id_token is always
/// a JWT carrying `tid`.
fn id_token_tid(resp: &serde_json::Value) -> Option<String> {
    resp.get("id_token")?
        .as_str()
        .and_then(decode_jwt_claims)?
        .get("tid")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

/// The tenant GUID the token was actually issued for (`tid` claim). When the
/// caller authenticated against `common`, the ARM feed-discovery endpoint wants
/// the concrete tenant id, so this derives it from the token itself.
pub fn token_tenant(token: &str) -> Option<String> {
    decode_jwt_claims(token)?
        .get("tid")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from)
}

// --- W365/AVD feed discovery -----------------------------------------------
// The modern AVD/W365 feed discovery endpoint is ARM-based. The non-ARM
// `/api/feeddiscovery` path returns 404/redirect for Entra-ID tenants.
const DEFAULT_FEED_URL: &str = "https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery";
/// The AVD web workspace identifies itself to the feed endpoints as the
/// first-party Remote Desktop client. The service gates on an approved
/// client: requests without a recognized `X-MS-User-Agent` are rejected with
/// `INCOMPATIBLE_CLIENT_VERSION` (HTTP 400). Verified live: `MSRDC` passes.
const FEED_USER_AGENT: &str = "MSRDC/10.0.0";

/// GET `url` with the AVD bearer token and the workspace user agent. Sanitized
/// logging: host + status + body length only — signed resource URLs carry auth
/// material in their query strings and must never be logged whole.
fn fetch_authenticated(url: &str, token: &str, authorized: bool) -> Result<String, AuthError> {
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_else(|| "<invalid-url>".to_string());
    let mut req = ureq::get(url)
        .set("Accept", "application/json, application/xml, text/*")
        .set("User-Agent", FEED_USER_AGENT)
        .set("X-MS-User-Agent", FEED_USER_AGENT);
    if authorized {
        req = req.set("Authorization", &format!("Bearer {token}"));
    }
    let resp = req.call()?;
    let status = resp.status();
    let body = resp.into_string()?;
    tracing::debug!(host = %host, status, len = body.len(), "fetched feed resource");
    Ok(body)
}

/// Some AVD discovery deployments answer the discovery URL with a small JSON
/// envelope pointing at the real workspace feed (`{"FeedUrl": ...}`) rather
/// than the feed document itself. Extract that follow-up URL when present.
fn extract_feed_url(body: &str) -> Option<String> {
    let trimmed = body.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    if v.get("error").is_some() {
        return None;
    }
    v.get("FeedUrl")
        .or_else(|| v.get("feedUrl"))
        .and_then(|u| u.as_str())
        .filter(|u| !u.is_empty())
        .map(String::from)
}

/// Extract every per-workspace `FeedURL` from a MS-TSWF `TenantFeedURLs`
/// discovery document (the real `feeddiscovery` response for ARM tenants:
/// one `TenantFeedURL` per subscribed workspace, each naming its regional
/// webfeed). Namespace-agnostic: the doc carries the tswfdiscovery xmlns.
fn extract_feed_urls(body: &str) -> Vec<String> {
    let Ok(doc) = roxmltree::Document::parse(body) else {
        return Vec::new();
    };
    doc.descendants()
        .filter(|n| n.has_tag_name("TenantFeedURL"))
        .filter_map(|n| n.attribute("FeedURL").map(String::from))
        .filter(|u| !u.is_empty())
        .collect()
}

/// Fetch the W365/AVD feed for `tenant_id` using the authenticated access token.
///
/// `client_id` is the AAD application id used for the feed request; `None`
/// uses the same default as device-code authentication.
pub fn fetch_feed(
    token: &AccessToken,
    tenant_id: &str,
    client_id: Option<&str>,
    feed_url: Option<&str>,
) -> Result<Vec<crate::feed::FeedEntry>, AuthError> {
    let client_id = client_id.unwrap_or(DEFAULT_CLIENT_ID);
    // `common` is only an auth-directory selector; the ARM discovery endpoint
    // wants the tenant the token was issued for. Derive it from the `tid`
    // claim instead of asking the user for a GUID.
    let tenant_id = if tenant_id.eq_ignore_ascii_case("common") || tenant_id.is_empty() {
        token
            .tenant_id
            .clone()
            .or_else(|| token_tenant(&token.token))
            .unwrap_or_else(|| tenant_id.to_string())
    } else {
        tenant_id.to_string()
    };

    let url = feed_url.map(String::from).unwrap_or_else(|| {
        format!(
            "{}?tenantId={}&appId={}",
            DEFAULT_FEED_URL,
            url_encode(&tenant_id),
            url_encode(client_id)
        )
    });

    tracing::info!(tenant = %tenant_id, "fetching W365 feed");
    let mut body = fetch_authenticated(&url, &token.token, true)?;
    if let Some(feed_url) = extract_feed_url(&body) {
        tracing::info!("discovery returned a feed envelope; following FeedUrl");
        body = fetch_authenticated(&feed_url, &token.token, true)?;
    }

    // ARM tenants answer discovery with a TenantFeedURLs document naming one
    // regional webfeed per subscribed workspace — follow each and merge.
    if body.contains("TenantFeedURL") {
        let feed_urls = extract_feed_urls(&body);
        tracing::info!(workspaces = feed_urls.len(), "discovery returned workspace feeds");
        let mut entries = Vec::new();
        for feed_url in &feed_urls {
            let feed_body = fetch_authenticated(feed_url, &token.token, true)?;
            let parsed = crate::feed::parse(&feed_body)
                .map_err(|e| AuthError::Failed(format!("feed parse error: {e}")))?;
            entries.extend(parsed);
        }
        return Ok(entries);
    }

    crate::feed::parse(&body).map_err(|e| AuthError::Failed(format!("feed parse error: {e}")))
}

/// Download Microsoft's current signed `.rdp` connection resource for a feed
/// entry's `rdp_url`.
///
/// The URL came from the authenticated feed, so the first request carries the
/// AVD bearer token (as the Windows App does). If the service answers 401/403 —
/// some deployments serve the pre-signed resource without any Authorization —
/// the request is retried without the token, but only when the URL is HTTPS on
/// known Microsoft AVD infrastructure. Bearer tokens are never sent anywhere
/// else, and signed URLs are never logged.
#[cfg_attr(windows, allow(dead_code))] // consumed by the Linux FreeRDP backend
pub fn fetch_rdp_file(token: &AccessToken, url: &str) -> Result<String, AuthError> {
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(String::from))
        .unwrap_or_default();
    tracing::info!(host = %host, "retrieving Microsoft .rdp resource");

    let body = match fetch_authenticated(url, &token.token, true) {
        Ok(body) => body,
        Err(AuthError::Network(ureq::Error::Status(code, _)))
            if (code == 401 || code == 403) && is_microsoft_avd_host(url) =>
        {
            tracing::info!(host = %host, status = code, "signed resource refused the bearer token; retrying without it");
            fetch_authenticated(url, &token.token, false)?
        }
        Err(e) => return Err(e.into()),
    };

    if let Err(reason) = looks_like_rdp(&body) {
        return Err(AuthError::Failed(format!(
            ".rdp download from {host} does not look like an RDP file ({reason})"
        )));
    }
    Ok(body)
}

/// Hosts that are allowed to receive a tokenless retry for `.rdp` downloads.
#[cfg_attr(windows, allow(dead_code))]
fn is_microsoft_avd_host(url: &str) -> bool {
    match url::Url::parse(url) {
        Ok(u) if u.scheme() == "https" => u
            .host_str()
            .map(|h| {
                h.eq_ignore_ascii_case("rdweb.wvd.microsoft.com")
                    || h.ends_with(".wvd.microsoft.com")
                    || h.ends_with(".microsoft.com") && h.starts_with("rdweb")
            })
            .unwrap_or(false),
        _ => false,
    }
}

/// Reject obviously-invalid `.rdp` downloads (e.g. an HTML login page served
/// in place of the resource). The payload is Microsoft's source of truth and is
/// stored verbatim; this only sanity-checks the shape.
#[cfg_attr(windows, allow(dead_code))]
fn looks_like_rdp(body: &str) -> Result<(), &'static str> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('<') {
        return Err("response is HTML/XML, not an RDP file");
    }
    if !body.contains("full address")
        && !body.contains("resourceprovider")
        && !body.contains("gatewayhostname")
    {
        return Err("no RDP connection settings found");
    }
    Ok(())
}

/// Package family name of the Microsoft "Windows App" (formerly Windows 365)
/// MSIX package. Its `LocalCache\ResourceCache` holds one signed ARM `.rdp` per
/// subscribed Cloud PC.
const WINDOWS_APP_PACKAGE: &str = "MicrosoftCorporationII.Windows365_8wekyb3d8bbwe";

/// Discover the user's Cloud PCs from the Windows App's local resource cache.
///
/// The Windows App stores every subscribed resource as `LocalCache\ResourceCache\
/// <id>.rdp`, each a JSON envelope `{"cached_item":"<.rdp contents>", ...}` whose
/// payload is a signed ARM Reverse-Connect `.rdp` (`resourceprovider:arm`,
/// `gatewayhostname`, `loadbalanceinfo`). We surface each as a [`FeedEntry`] whose
/// `rdp_file` carries the payload verbatim, so selection drives the same validated
/// ARM-broker path as `--rdp-file`. Returns an empty list if the Windows App is
/// not installed / has never subscribed. Duplicate entries (the same Cloud PC
/// cached under several ids) are collapsed by `loadbalanceinfo`.
pub fn discover_cached_cloud_pcs() -> Vec<crate::feed::FeedEntry> {
    let local_appdata = match std::env::var("LOCALAPPDATA") {
        Ok(p) if !p.is_empty() => p,
        _ => return Vec::new(),
    };
    let dir = std::path::Path::new(&local_appdata)
        .join("Packages")
        .join(WINDOWS_APP_PACKAGE)
        .join("LocalCache")
        .join("ResourceCache");

    let read_dir = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) => {
            tracing::debug!(dir = %dir.display(), error = %e, "no Windows App resource cache");
            return Vec::new();
        }
    };

    let mut entries = Vec::new();
    let mut seen_lbi = std::collections::HashSet::new();
    for dirent in read_dir.flatten() {
        let path = dirent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rdp") {
            continue;
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "skip unreadable cache file");
                continue;
            }
        };
        // The cache file is a JSON envelope; the actual `.rdp` is `cached_item`.
        let rdp_contents = match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) => v
                .get("cached_item")
                .and_then(|c| c.as_str())
                .map(String::from),
            // Tolerate a bare `.rdp` (some builds wrote them unwrapped).
            Err(_) if raw.contains("resourceprovider") => Some(raw.clone()),
            Err(_) => None,
        };
        let Some(rdp_contents) = rdp_contents else {
            continue;
        };

        let settings = crate::feed::parse_rdp_file(&rdp_contents);
        // Only ARM Reverse-Connect resources can be brokered by rdpio.
        if settings.get("resourceprovider").map(String::as_str) != Some("arm") {
            continue;
        }
        let lbi = match settings.get("loadbalanceinfo") {
            Some(l) if !l.is_empty() => l.clone(),
            _ => continue,
        };
        if !seen_lbi.insert(lbi.clone()) {
            continue; // same Cloud PC under a different cache id
        }

        let mut entry = crate::feed::FeedEntry::default();
        entry.display_name = settings
            .get("remotedesktopname")
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| "Cloud PC".to_string());
        // `remoteapplicationprogram` is `||<resourceId>`; the GUID distinguishes
        // Cloud PCs that share a SKU display name. Used only as a picker label.
        entry.resource_id = settings
            .get("remoteapplicationprogram")
            .map(|s| s.trim_start_matches('|').to_string())
            .unwrap_or_default();
        entry.tenant_id = settings.get("aadtenantid").cloned().unwrap_or_default();
        entry.gateway_fqdn = settings.get("gatewayhostname").cloned().unwrap_or_default();
        entry.load_balance_info = Some(lbi.into_bytes());
        entry.rdp_file = Some(rdp_contents);
        entries.push(entry);
    }

    entries.sort_by(|a, b| {
        a.display_name
            .cmp(&b.display_name)
            .then_with(|| a.resource_id.cmp(&b.resource_id))
    });
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encode_escapes_space_and_slash() {
        assert_eq!(url_encode("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn form_encode_joins_pairs() {
        assert_eq!(
            form_encode(&[("client_id", "id"), ("scope", "a b")]),
            "client_id=id&scope=a%20b"
        );
    }

    #[test]
    fn authorize_url_uses_code_flow_and_native_redirect() {
        let url = build_authorize_url("common", None, None, None);
        assert!(url.starts_with("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains(&format!("client_id={DEFAULT_CLIENT_ID}")));
        // redirect_uri is URL-encoded.
        assert!(url.contains(
            "redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient"
        ));
        // wvd scope present (encoded).
        assert!(url.contains("www.wvd.microsoft.com"));
        // No state requested → no state parameter.
        assert!(!url.contains("state="));
    }

    #[test]
    fn authorize_url_carries_state_when_given() {
        let url = build_authorize_url("common", None, None, Some("abc123 4"));
        assert!(url.contains("&state=abc123%204"));
    }

    #[test]
    fn redirect_with_code_is_captured() {
        let uri = format!("{}?code=ABC123&session_state=xyz", NATIVE_REDIRECT_URI);
        assert_eq!(parse_auth_redirect(&uri), Some(Ok("ABC123".to_string())));
    }

    #[test]
    fn redirect_with_error_is_reported() {
        let uri = format!(
            "{}?error=access_denied&error_description=user%20cancelled",
            NATIVE_REDIRECT_URI
        );
        assert_eq!(
            parse_auth_redirect(&uri),
            Some(Err("access_denied: user cancelled".to_string()))
        );
    }

    #[test]
    fn login_pages_are_not_treated_as_redirect() {
        assert_eq!(
            parse_auth_redirect("https://login.microsoftonline.com/common/login"),
            None
        );
        // The bare redirect URI with no query is not yet a result.
        assert_eq!(parse_auth_redirect(NATIVE_REDIRECT_URI), None);
    }

    #[test]
    fn query_param_reads_state() {
        let uri = format!("{}?code=x&state=s%20t", NATIVE_REDIRECT_URI);
        assert_eq!(query_param(&uri, "state").as_deref(), Some("s t"));
        assert_eq!(query_param(&uri, "code").as_deref(), Some("x"));
        assert_eq!(query_param(&uri, "missing"), None);
    }

    #[test]
    fn url_decode_handles_percent_and_plus() {
        assert_eq!(url_decode("a%20b+c%2Fd"), "a b c/d");
    }

    #[test]
    fn id_token_upn_parsed_from_jwt_payload() {
        // header.payload.signature — only the payload matters. Payload base64url
        // of {"preferred_username":"nick@contoso.com"} (no padding).
        let payload = "eyJwcmVmZXJyZWRfdXNlcm5hbWUiOiJuaWNrQGNvbnRvc28uY29tIn0";
        let jwt = format!("aaa.{payload}.bbb");
        assert_eq!(
            parse_id_token_upn(&jwt).as_deref(),
            Some("nick@contoso.com")
        );
    }

    #[test]
    fn token_tenant_reads_tid_claim() {
        // Payload base64url of {"tid":"9188040d-1c1c-4c2d-8ab7-2e5e0f123456"}
        let payload = "eyJ0aWQiOiI5MTg4MDQwZC0xYzFjLTRjMmQtOGFiNy0yZTVlMGYxMjM0NTYifQ";
        let jwt = format!("aaa.{payload}.bbb");
        assert_eq!(
            token_tenant(&jwt).as_deref(),
            Some("9188040d-1c1c-4c2d-8ab7-2e5e0f123456")
        );
        assert_eq!(token_tenant("not-a-jwt"), None);
    }

    #[test]
    fn rdp_payload_validation_rejects_html_and_empty() {
        let rdp = "screen mode id:i:2\nfull address:s:gw\nresourceprovider:s:arm\n";
        assert!(looks_like_rdp(rdp).is_ok());
        assert!(looks_like_rdp("<html><body>login</body></html>").is_err());
        assert!(looks_like_rdp("just some text").is_err());
    }

    #[test]
    fn tokenless_retry_only_for_microsoft_https_hosts() {
        assert!(is_microsoft_avd_host(
            "https://rdweb.wvd.microsoft.com/api/arm/v2/x.rdp?sig=secret"
        ));
        assert!(is_microsoft_avd_host(
            "https://rdweb-eu.wvd.microsoft.com/x.rdp"
        ));
        assert!(!is_microsoft_avd_host("https://evil.example.com/x.rdp"));
        assert!(!is_microsoft_avd_host(
            "http://rdweb.wvd.microsoft.com/x.rdp"
        ));
    }

    #[test]
    fn feed_url_envelope_extracted() {
        assert_eq!(
            extract_feed_url(
                "{\"FeedUrl\":\"https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery/a/b\"}"
            )
            .as_deref(),
            Some("https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery/a/b")
        );
        // A feed document itself (not an envelope) is not followed.
        assert_eq!(
            extract_feed_url("<?xml version=\"1.0\"?><ResourceCollection/>"),
            None
        );
        assert_eq!(extract_feed_url("{\"error\":\"x\"}"), None);
    }

    #[test]
    fn discovery_doc_yields_workspace_feed_urls() {
        let doc = "<?xml version=\"1.0\" encoding=\"utf-8\"?>
<TenantFeedURLs xmlns=\"http://schemas.microsoft.com/ts/2014/03/tswfdiscovery\">
  <TenantFeedURL TenantId=\"11111111-1111-1111-1111-111111111111\"
      FeedURL=\"https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery/tenants/aaa/webfeed?geo=US\">
    <Extensions><Extension ID=\"x\" Name=\"CloudPC\" BaseURL=\"https://windows365.microsoft.com\"/></Extensions>
  </TenantFeedURL>
  <TenantFeedURL TenantId=\"22222222-2222-2222-2222-222222222222\"
      FeedURL=\"https://rdweb.wvd.microsoft.com/api/arm/feeddiscovery/tenants/bbb/webfeed?geo=EU\"/>
</TenantFeedURLs>";
        let urls = extract_feed_urls(doc);
        assert_eq!(urls.len(), 2);
        assert!(urls[0].ends_with("webfeed?geo=US"));
        assert!(urls[1].contains("tenants/bbb"));
        // Non-discovery documents yield nothing.
        assert!(extract_feed_urls("<ResourceCollection/>").is_empty());
        assert!(extract_feed_urls("not xml").is_empty());
    }
}
