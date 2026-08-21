//! Linux authentication UI for Windows 365 / AVD.
//!
//! The portable OAuth machinery (URL construction, redirect parsing, token
//! exchange) lives in [`crate::w365`]; Windows shows it in a WebView2 panel
//! ([`crate::webview_auth`]). Linux has no embedded WebView here, so this
//! module implements the interactive flows with the system browser:
//!
//! - [`authenticate_loopback`] — the teams-tui-go login: authorization-code grant
//!   with PKCE and a `http://localhost:<port>` loopback redirect. The browser
//!   lands on a tiny local listener (no copy-paste needed); when the browser
//!   runs on another machine, the final redirect URL can be pasted instead.
//!   This is the flow for tenants whose Conditional Access blocks both the
//!   AVD nativeclient page and device codes.
//! - [`authenticate`] — the FreeRDP-compatible fallback: the AVD first-party
//!   client with the registered `nativeclient` redirect, final URL pasted
//!   back by the user (`--w365-auth paste`).
//!
//! No password is ever asked for, MFA/Conditional Access happen in the browser,
//! and no client secret is involved. This is deliberately interactive glue —
//! everything cryptographic or protocol-level is shared with Windows.

use std::io::{BufRead, Read, Write};

use crate::w365::{self, AccessToken, AuthError};

/// How long to wait for the user to complete the browser sign-in
/// (teams-tui-go's `browserFlowTimeout`).
const LOOPBACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// Open the system browser at `url` (best-effort; the URL is also printed).
/// `command` may be a multi-word shell-free command line (e.g. teams-tui-go's
/// `browser_command`); it is split on whitespace, never through a shell.
fn open_browser(command: Option<&str>, url: &str) {
    let default = "xdg-open".to_string();
    let command = command
        .map(String::from)
        .or_else(|| std::env::var("RDPIO_BROWSER_OPENER").ok())
        .filter(|s| !s.is_empty())
        .unwrap_or(default);
    let mut words = command.split_whitespace();
    let (Some(exe), args) = (words.next(), words.collect::<Vec<_>>()) else {
        tracing::warn!(command = %command, "empty browser command; open the URL manually");
        return;
    };
    match std::process::Command::new(exe).args(&args).arg(url).spawn() {
        Ok(mut child) => {
            // Reap to avoid a zombie while we wait for user input.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            tracing::debug!(command = %command, "browser opened");
        }
        Err(e) => tracing::warn!(
            error = %e,
            command = %command,
            "could not open the browser automatically; open the URL manually"
        ),
    }
}

/// Read one line from stdin (trimmed). `None` on EOF.
fn read_line(prompt: &str) -> Option<String> {
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{prompt}");
    let _ = stderr.flush();
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) => None,
        Ok(_) => Some(line.trim().to_string()),
        Err(_) => None,
    }
}

/// Random hex `state` from the OS CSPRNG (`None` if the RNG is unavailable —
/// the flow then runs without state, as the Windows WebView2 flow does).
fn new_state() -> Option<String> {
    let mut bytes = [0u8; 16];
    if !crate::rng::fill(&mut bytes) {
        return None;
    }
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// RFC 7636 code verifier + S256 challenge (`None` if the OS RNG is
/// unavailable — the caller should fall back to the no-PKCE paste flow).
fn new_pkce() -> Option<(String, String)> {
    use base64::Engine as _;
    let mut bytes = [0u8; 32]; // → 43-char base64url verifier (RFC minimum)
    if !crate::rng::fill(&mut bytes) {
        return None;
    }
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let challenge = pkce_s256(&verifier);
    Some((verifier, challenge))
}

/// The RFC 7636 §4.2 S256 transform of a verifier: base64url(SHA-256(verifier)).
fn pkce_s256(verifier: &str) -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    let sum = sha2::Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sum)
}

/// A captured authorization-code redirect: the `code`, the echoed `state`
/// (when present), or an OAuth `error`.
enum RedirectCapture {
    Code { code: String, state: Option<String> },
    Error(String),
}

/// Parse pasted sign-in input: a full redirect URL (the code in the query
/// string or, for `nativeclient`-style redirects, the URL fragment), or a
/// bare authorization code. Mirrors teams-tui-go's `parseAuthCodeInput`.
fn parse_pasted_redirect(raw: &str) -> Result<RedirectCapture, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty input".into());
    }
    if !raw.contains("://") && !raw.contains('=') {
        // Bare code pasted directly.
        return Ok(RedirectCapture::Code {
            code: raw.to_string(),
            state: None,
        });
    }
    // Loopback/native redirects carry the code in the query; some flows use
    // the fragment. Treat either as URL-encoded parameters.
    let params = if let Some(i) = raw.find('#') {
        &raw[i + 1..]
    } else {
        raw.find('?').map(|i| &raw[i + 1..]).unwrap_or("")
    };
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for pair in params.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = w365::url_decode(v);
        match k {
            "code" => code = Some(v),
            "state" => state = Some(v),
            "error" => error = Some(v),
            "error_description" if error.is_some() => {
                error = Some(format!("{}: {}", error.unwrap(), v));
            }
            _ => {}
        }
    }
    if let Some(code) = code.filter(|c| !c.is_empty()) {
        return Ok(RedirectCapture::Code { code, state });
    }
    if let Some(err) = error {
        return Ok(RedirectCapture::Error(err));
    }
    Err("no authorization code found in input".into())
}

/// Strictly parse `?code=…&state=…` (or `error=…`) query parameters — used for
/// the loopback listener, where every input is a request path and the lenient
/// bare-code heuristic must not apply. Returns `None` when there is no query
/// string or no `code`/`error` in it (favicon and style requests).
fn parse_query_redirect(target: &str) -> Option<RedirectCapture> {
    let params = target.split_once('?')?.1;
    let mut code = None;
    let mut state = None;
    let mut error = None;
    for pair in params.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = w365::url_decode(v);
        match k {
            "code" => code = Some(v),
            "state" => state = Some(v),
            "error" => error = Some(v),
            "error_description" if error.is_some() => {
                error = Some(format!("{}: {}", error.unwrap(), v));
            }
            _ => {}
        }
    }
    if let Some(code) = code.filter(|c| !c.is_empty()) {
        return Some(RedirectCapture::Code { code, state });
    }
    error.map(RedirectCapture::Error)
}

/// Serve one HTTP request on `stream` and extract `?code=…&state=…` from the
/// request line. Answers with a "close this tab" page so the browser does not
/// show a connection error. Returns `None` for requests without a code (e.g.
/// favicon) so the caller can keep accepting.
fn answer_loopback(stream: &mut std::net::TcpStream) -> Option<RedirectCapture> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).unwrap_or(0);
    let req = String::from_utf8_lossy(&buf[..n]);
    // Request line: GET /?code=…&state=… HTTP/1.1
    let target = req.split_whitespace().nth(1)?;
    let capture = parse_query_redirect(target)?;

    let body = match &capture {
        RedirectCapture::Code { .. } => concat(
            "<html><body><h2>rdpio sign-in complete</h2>",
            "<p>You can close this tab and return to the terminal.</p></body></html>",
        ),
        RedirectCapture::Error(_) => concat(
            "<html><body><h2>rdpio sign-in failed</h2>",
            "<p>Return to the terminal for details.</p></body></html>",
        ),
    };
    let _ = stream.write_all(
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes(),
    );
    let _ = stream.flush();
    Some(capture)
}

// Small helper so the HTML pieces above read as single literals.
fn concat(a: &str, b: &str) -> String {
    format!("{a}{b}")
}

/// Errors from the browser flows.
#[derive(Debug, thiserror::Error)]
pub enum BrowserAuthError {
    #[error("authentication error: {0}")]
    Auth(#[from] AuthError),
    #[error("no redirect URL was provided")]
    Cancelled,
    #[error("timed out waiting for the browser sign-in")]
    TimedOut,
    #[error("state mismatch in the redirect (possible CSRF) — please try again")]
    StateMismatch,
}

/// The teams-tui-go login for W365: authorization-code grant with PKCE against a
/// loopback-capable registration, racing a local HTTP listener against pasted
/// input. `client_id` is the loopback-capable public client (teams-tui-go's
/// `browser_client_id` by default — see [`crate::teams_auth`]);
/// `browser_command` optionally names the browser to open.
pub fn authenticate_loopback(
    tenant: &str,
    client_id: &str,
    browser_command: Option<&str>,
) -> Result<AccessToken, BrowserAuthError> {
    let Some((verifier, challenge)) = new_pkce() else {
        // No CSPRNG → no PKCE; the nativeclient paste flow still works.
        tracing::warn!("OS RNG unavailable; falling back to the paste flow");
        return authenticate(tenant, None);
    };
    let state = new_state();

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| AuthError::Failed(format!("could not start the local auth listener: {e}")))?;
    let port = listener
        .local_addr()
        .map_err(|e| AuthError::Failed(format!("local listener has no address: {e}")))?
        .port();
    let redirect_uri = format!("http://localhost:{port}");

    let mut url = format!(
        "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize\
         ?client_id={cid}&response_type=code&redirect_uri={redir}&scope={scope}\
         &code_challenge={challenge}&code_challenge_method=S256&prompt=select_account",
        cid = w365::url_encode(client_id),
        redir = w365::url_encode(&redirect_uri),
        scope = w365::url_encode(w365::AUTH_CODE_SCOPE),
    );
    if let Some(state) = &state {
        url.push_str(&format!("&state={}", w365::url_encode(state)));
    }

    println!("Sign in to Windows 365 with your browser (teams-tui-go login):");
    println!();
    println!("  {url}");
    println!();
    println!(
        "After signing in, the browser lands on this machine's {redirect_uri}\n\
         and the sign-in completes automatically. If the browser runs on another\n\
         machine, paste the final redirect URL (or the bare code) below instead."
    );
    open_browser(browser_command, &url);

    enum Outcome {
        Captured(RedirectCapture),
        StdinClosed,
    }
    let (tx, rx) = std::sync::mpsc::channel::<Outcome>();

    // Path 1: the loopback redirect captured by the local listener.
    let tx_listener = tx.clone();
    std::thread::spawn(move || {
        // Favicon/style requests without a code are answered and skipped.
        for _ in 0..8 {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    if let Some(capture) = answer_loopback(&mut stream) {
                        let _ = tx_listener.send(Outcome::Captured(capture));
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    // Path 2: the user pastes the redirect URL (or a bare code).
    std::thread::spawn(move || {
        let mut line = String::new();
        match std::io::stdin().lock().read_line(&mut line) {
            Ok(0) | Err(_) => {
                let _ = tx.send(Outcome::StdinClosed);
            }
            Ok(_) => match parse_pasted_redirect(&line) {
                Ok(capture) => {
                    let _ = tx.send(Outcome::Captured(capture));
                }
                Err(_) => {
                    let _ = tx.send(Outcome::StdinClosed);
                }
            },
        }
    });

    println!("\nWaiting for authentication... (paste redirect URL + Enter to complete manually)");
    let capture = match rx.recv_timeout(LOOPBACK_TIMEOUT) {
        Ok(Outcome::Captured(c)) => c,
        Ok(Outcome::StdinClosed) => return Err(BrowserAuthError::Cancelled),
        Err(_) => return Err(BrowserAuthError::TimedOut),
    };
    let code = match capture {
        RedirectCapture::Code { code, state: got } => {
            // Verify the echoed state when one was sent (a bare pasted code
            // carries none — allowed, like teams-tui-go).
            if let (Some(expected), Some(got)) = (&state, got) {
                if &got != expected {
                    return Err(BrowserAuthError::StateMismatch);
                }
            }
            code
        }
        RedirectCapture::Error(err) => {
            println!("Microsoft returned an OAuth error: {err}");
            return Err(BrowserAuthError::Cancelled);
        }
    };

    tracing::info!("authorization code captured; exchanging for tokens (PKCE)");
    Ok(w365::exchange_auth_code_full(
        tenant,
        Some(client_id),
        None,
        &code,
        &redirect_uri,
        Some(&verifier),
    )?)
}

/// Interactive system-browser sign-in with the AVD first-party client and the
/// registered `nativeclient` redirect — the FreeRDP-compatible paste flow
/// (`--w365-auth paste`, and the default when no teams-tui-go login is set up).
pub fn authenticate(
    tenant: &str,
    client_id: Option<&str>,
) -> Result<AccessToken, BrowserAuthError> {
    let state = new_state();
    let url = w365::build_authorize_url(tenant, client_id, None, state.as_deref());

    println!("Sign in to Windows 365 with your browser:");
    println!();
    println!("  {url}");
    println!();
    println!(
        "After signing in you will be redirected to a login.microsoftonline.com page\n\
         that starts with \"{redirect}\". Copy the FULL final URL from the address\n\
         bar and paste it below.",
        redirect = w365::NATIVE_REDIRECT_URI
    );
    open_browser(None, &url);

    for _ in 0..5 {
        let Some(pasted) = read_line("\nPaste the final redirect URL: ") else {
            return Err(BrowserAuthError::Cancelled);
        };
        match w365::parse_auth_redirect(&pasted) {
            Some(Ok(code)) => {
                // Verify the echoed state when we sent one.
                if let Some(expected) = &state {
                    match w365::query_param(&pasted, "state") {
                        Some(got) if &got == expected => {}
                        Some(_) => {
                            println!("state mismatch — that redirect URL is not from this sign-in attempt; paste the URL from THIS browser session");
                            continue;
                        }
                        None => {
                            println!("the redirect URL has no state; paste the URL from THIS sign-in session");
                            continue;
                        }
                    }
                }
                tracing::info!("authorization code captured; exchanging for tokens");
                let token = w365::exchange_auth_code(tenant, client_id, None, &code)?;
                return Ok(token);
            }
            Some(Err(err)) => {
                println!("Microsoft returned an OAuth error: {err}");
                return Err(BrowserAuthError::Cancelled);
            }
            None => {
                println!(
                    "that does not look like the redirect URL — it must start with\n\
                     \"{}\" and contain ?code=…",
                    w365::NATIVE_REDIRECT_URI
                );
            }
        }
    }
    Err(BrowserAuthError::Cancelled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_is_generated_from_os_rng() {
        let a = new_state();
        let b = new_state();
        assert!(a.is_some());
        assert_ne!(a, b);
        // Hex, 16 bytes → 32 chars.
        let a = a.unwrap();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// RFC 7636 appendix B.2 reference vector.
    #[test]
    fn pkce_s256_reference_vector() {
        assert_eq!(
            pkce_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn pkce_pair_is_url_safe_and_43_chars() {
        let (verifier, challenge) = new_pkce().expect("os rng");
        assert_eq!(verifier.len(), 43);
        assert!(verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_eq!(challenge, pkce_s256(&verifier));
        // Independent draws differ.
        let (v2, _) = new_pkce().expect("os rng");
        assert_ne!(verifier, v2);
    }

    #[test]
    fn pasted_full_query_url_is_parsed() {
        let c = parse_pasted_redirect(
            "http://localhost:8123/?code=0.AXQA...--wJZ&state=abc&session_state=x",
        )
        .unwrap();
        match c {
            RedirectCapture::Code { code, state } => {
                assert_eq!(code, "0.AXQA...--wJZ");
                assert_eq!(state.as_deref(), Some("abc"));
            }
            _ => panic!("expected code"),
        }
    }

    #[test]
    fn pasted_fragment_url_is_parsed() {
        let c = parse_pasted_redirect(
            "https://login.microsoftonline.com/common/oauth2/nativeclient#code=XYZ&state=s1",
        )
        .unwrap();
        match c {
            RedirectCapture::Code { code, state } => {
                assert_eq!(code, "XYZ");
                assert_eq!(state.as_deref(), Some("s1"));
            }
            _ => panic!("expected code"),
        }
    }

    #[test]
    fn pasted_bare_code_is_accepted_without_state() {
        let c = parse_pasted_redirect(" 0.AScAJhF-abc-def ").unwrap();
        match c {
            RedirectCapture::Code { code, state } => {
                assert_eq!(code, "0.AScAJhF-abc-def");
                assert_eq!(state, None);
            }
            _ => panic!("expected code"),
        }
    }

    #[test]
    fn pasted_error_is_reported() {
        let c = parse_pasted_redirect(
            "http://localhost:1/?error=access_denied&error_description=user%20cancelled",
        )
        .unwrap();
        match c {
            RedirectCapture::Error(e) => assert_eq!(e, "access_denied: user cancelled"),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn pasted_garbage_is_rejected() {
        assert!(parse_pasted_redirect("").is_err());
        assert!(parse_pasted_redirect("https://example.com/nothing-here").is_err());
    }

    #[test]
    fn loopback_listener_captures_code_and_answers_html() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            answer_loopback(&mut stream)
        });
        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client
            .write_all(b"GET /?code=C0DE&state=zz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("rdpio sign-in complete"));
        match t.join().unwrap().unwrap() {
            RedirectCapture::Code { code, state } => {
                assert_eq!(code, "C0DE");
                assert_eq!(state.as_deref(), Some("zz"));
            }
            _ => panic!("expected code"),
        }
    }

    #[test]
    #[test]
    fn loopback_listener_skips_requests_without_code() {
        for req in [
            "GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "GET /style.css?v=2 HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ] {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let addr = listener.local_addr().unwrap();
            let t = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                answer_loopback(&mut stream)
            });
            let mut client = std::net::TcpStream::connect(addr).unwrap();
            client.write_all(req.as_bytes()).unwrap();
            let mut sink = String::new();
            let _ = client.read_to_string(&mut sink);
            assert!(
                t.join().unwrap().is_none(),
                "request without a code must be skipped: {req}"
            );
        }
    }

    #[test]
    fn strict_query_parser_rejects_bare_paths() {
        assert!(parse_query_redirect("/favicon.ico").is_none());
        assert!(parse_query_redirect("/").is_none());
        assert!(parse_query_redirect("/x?code=").is_none());
        match parse_query_redirect("/?code=A&state=B").unwrap() {
            RedirectCapture::Code { code, state } => {
                assert_eq!(code, "A");
                assert_eq!(state.as_deref(), Some("B"));
            }
            _ => panic!("expected code"),
        }
        assert!(matches!(
            parse_query_redirect("/?error=denied"),
            Some(RedirectCapture::Error(_))
        ));
    }
}
