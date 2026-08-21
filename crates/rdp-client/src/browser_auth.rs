//! Linux authentication UI for Windows 365 / AVD.
//!
//! The portable OAuth machinery (URL construction, redirect parsing, token
//! exchange) lives in [`crate::w365`]; Windows shows it in a WebView2 panel
//! ([`crate::webview_auth`]). Linux has no embedded WebView here, so this
//! implements the same authorization-code flow with the system browser:
//!
//! 1. build the `authorize` URL (with a random OAuth `state`);
//! 2. open the default browser (`xdg-open`) and print the URL as fallback;
//! 3. after sign-in, Microsoft lands on the registered `nativeclient` redirect
//!    carrying `?code=…&state=…`;
//! 4. the user pastes that final URL back here (the address bar shows it);
//! 5. `state` is verified, then the existing [`w365::exchange_auth_code`] runs.
//!
//! No password is ever asked for, MFA/Conditional Access happen in the browser,
//! and no client secret is involved. This is deliberately interactive glue —
//! everything cryptographic or protocol-level is shared with Windows.

use std::io::{BufRead, Write};

use crate::w365::{self, AccessToken, AuthError};

/// Open the system browser at `url` (best-effort; the URL is also printed).
fn open_browser(url: &str) {
    let opener = std::env::var("RDPIO_BROWSER_OPENER").unwrap_or_else(|_| "xdg-open".into());
    match std::process::Command::new(&opener).arg(url).spawn() {
        Ok(mut child) => {
            // Reap to avoid a zombie while we wait for user input.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            tracing::debug!(opener = %opener, "browser opened");
        }
        Err(e) => tracing::warn!(
            error = %e,
            opener = %opener,
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

/// Errors from the browser flow.
#[derive(Debug, thiserror::Error)]
pub enum BrowserAuthError {
    #[error("authentication error: {0}")]
    Auth(#[from] AuthError),
    #[error("no redirect URL was provided")]
    Cancelled,
}

/// Interactive system-browser sign-in. Returns the exchanged access token.
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
    open_browser(&url);

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
}
