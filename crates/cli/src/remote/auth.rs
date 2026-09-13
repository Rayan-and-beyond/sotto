//! Server login: the loopback OAuth flow and session-token storage.
//!
//! `authorize` starts a one-shot `127.0.0.1` listener, sends the browser to the server's GitHub
//! login with that loopback as the redirect target, and captures what the server hands back: a
//! single-use code, swapped for the session in a POST body - or the session itself from a server too
//! old to speak codes. The pure pieces ([`authorize_url`], [`parse_callback`]) are unit-tested;
//! the socket loop is thin.
//! The session token is a bearer credential, so it lives in the OS keychain.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;

use sotto_core::random;

use crate::error::{Error, Result};
use crate::keychain::Keychain;

/// Keychain entry holding the server session bearer token.
const KC_SERVER_SESSION: &str = "server-session";

pub fn store_session(keychain: &dyn Keychain, token: &str) -> Result<()> {
    keychain.set(KC_SERVER_SESSION, token.as_bytes())
}

pub fn current_session(keychain: &dyn Keychain) -> Result<Option<String>> {
    match keychain.get(KC_SERVER_SESSION)? {
        // Fail loudly on corruption rather than `from_utf8_lossy`, which would silently swap in
        // replacement chars and hand back a wrong-but-plausible bearer token.
        Some(bytes) => Ok(Some(String::from_utf8(bytes).map_err(|_| {
            Error::Keychain("stored session token is not valid UTF-8".into())
        })?)),
        None => Ok(None),
    }
}

pub fn clear_session(keychain: &dyn Keychain) -> Result<()> {
    keychain.delete(KC_SERVER_SESSION)
}

/// What the loopback callback carried: a single-use code (current server) or the session
/// itself (a server too old to speak codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackGrant {
    Code(String),
    Session(String),
}

/// Build the server's GitHub-login URL with our loopback redirect + CSRF state, asking for the
/// code branch of the callback.
pub fn authorize_url(server: &str, port: u16, state: &str) -> Result<String> {
    let mut url = reqwest::Url::parse(&format!("{server}/auth/github/login"))
        .map_err(|e| Error::Input(format!("invalid server URL: {e}")))?;
    url.query_pairs_mut()
        .append_pair("redirect_uri", &format!("http://127.0.0.1:{port}/"))
        .append_pair("state", state)
        .append_pair("mode", "code");
    Ok(url.to_string())
}

/// Extract the grant from the loopback callback target (`/?code=…&state=…`, or `/?session=…` from
/// an older server), verifying the CSRF state matches. A callback carrying both takes the code
/// path: the exchange verifies the state again server-side.
pub fn parse_callback(target: &str, expected_state: &str) -> Result<CallbackGrant> {
    let url = reqwest::Url::parse(&format!("http://127.0.0.1{target}"))
        .map_err(|e| Error::Server(format!("invalid callback request: {e}")))?;
    let mut code = None;
    let mut session = None;
    let mut state = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "session" => session = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            _ => {}
        }
    }
    match state {
        Some(s) if s == expected_state => {}
        Some(_) => {
            return Err(Error::Server(
                "callback state mismatch (possible CSRF)".into(),
            ))
        }
        None => return Err(Error::Server("callback missing state".into())),
    }
    if let Some(code) = code {
        return Ok(CallbackGrant::Code(code));
    }
    session
        .map(CallbackGrant::Session)
        .ok_or_else(|| Error::Server("callback missing code or session".into()))
}

/// Swap a single-use login code for the session token, in a POST body and never as a URL
/// component. Transport encryption follows the configured server URL's scheme (S-15's
/// territory); this function's guarantee is only that the code never appears in a URL.
pub fn exchange_code(server: &str, code: &str, state: &str) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct ExchangeResponse {
        token: String,
    }
    // Unauthenticated endpoint, so a bare client rather than `HttpClient` (which always bears a
    // token); same timeouts.
    let http = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest client with static config builds");
    let resp = http
        .post(format!("{server}/auth/github/exchange"))
        .json(&serde_json::json!({"code": code, "state": state}))
        .send()
        .map_err(|e| Error::Network(e.to_string()))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(Error::Server(format!(
            "code exchange failed: {status}: {body}"
        )));
    }
    resp.json::<ExchangeResponse>()
        .map(|r| r.token)
        .map_err(|e| Error::Server(e.to_string()))
}

/// Run the loopback OAuth flow and return the session token (not yet stored).
pub fn authorize(server: &str) -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| Error::Io(e.to_string()))?;
    let port = listener
        .local_addr()
        .map_err(|e| Error::Io(e.to_string()))?
        .port();
    let state = random_state();
    let url = authorize_url(server, port, &state)?;

    eprintln!("Opening your browser to authorise Sotto…");
    eprintln!("If it doesn't open, visit:\n  {url}\n");
    open_browser(&url);

    resolve_grant(server, accept_callback(&listener, &state)?, &state)
}

/// Turn whatever the callback carried into the session token: a legacy session is used as-is,
/// a code is exchanged for one. A separate seam so tests pin this dispatch without a browser;
/// returning the code itself here would persist `sc_…` as the Bearer [REDACTED] and 401 every call.
fn resolve_grant(server: &str, grant: CallbackGrant, state: &str) -> Result<String> {
    match grant {
        CallbackGrant::Session(token) => Ok(token),
        CallbackGrant::Code(code) => exchange_code(server, &code, state),
    }
}

/// Accept exactly one loopback connection, capture the callback grant, and reply to the browser.
fn accept_callback(listener: &TcpListener, expected_state: &str) -> Result<CallbackGrant> {
    let (stream, _) = listener.accept().map_err(|e| Error::Io(e.to_string()))?;
    // `read()` may return the request only partially, so read just the first line: that's all we
    // need, and `read_line` keeps reading until the newline rather than risking a truncated parse.
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|e| Error::Io(e.to_string()))?;

    // Request line: `GET /?code=…&state=… HTTP/1.1` (or `?session=…` from an older server).
    let target = request_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Error::Server("malformed callback request".into()))?;
    let result = parse_callback(target, expected_state);

    let mut stream = reader.into_inner();
    let (status, body) = match result {
        Ok(_) => (
            "200 OK",
            "<html><body>Sotto: login complete - you can close this tab.</body></html>",
        ),
        Err(_) => (
            "400 Bad Request",
            "<html><body>Sotto: login failed.</body></html>",
        ),
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    result
}

/// Best-effort browser open; failure is fine (the URL is printed too).
fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let mut command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    let _ = command
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

fn random_state() -> String {
    random::bytes::<16>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::MemoryKeychain;

    #[test]
    fn session_round_trips_in_keychain() {
        let kc = MemoryKeychain::default();
        assert!(current_session(&kc).unwrap().is_none());
        store_session(&kc, "st_abc").unwrap();
        assert_eq!(current_session(&kc).unwrap().as_deref(), Some("st_abc"));
        clear_session(&kc).unwrap();
        assert!(current_session(&kc).unwrap().is_none());
    }

    #[test]
    fn authorize_url_encodes_redirect_and_state() {
        let url = authorize_url("https://api.sotto.dev", 51999, "abc123").unwrap();
        assert!(url.starts_with("https://api.sotto.dev/auth/github/login?"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A51999%2F"));
        assert!(url.contains("state=abc123"));
        assert!(url.contains("mode=code"));
    }

    #[test]
    fn parse_callback_extracts_code_or_session() {
        assert_eq!(
            parse_callback("/?code=sc_xyz&state=abc", "abc").unwrap(),
            CallbackGrant::Code("sc_xyz".into())
        );
        assert_eq!(
            parse_callback("/?session=st_xyz&state=abc", "abc").unwrap(),
            CallbackGrant::Session("st_xyz".into())
        );
        // Both present takes the code path; the exchange re-verifies the state server-side.
        assert_eq!(
            parse_callback("/?code=sc_xyz&session=st_xyz&state=abc", "abc").unwrap(),
            CallbackGrant::Code("sc_xyz".into())
        );
    }

    #[test]
    fn parse_callback_rejects_state_mismatch_and_missing_fields() {
        assert!(parse_callback("/?code=sc_xyz&state=evil", "abc").is_err());
        assert!(parse_callback("/?session=st_xyz&state=evil", "abc").is_err());
        assert!(parse_callback("/?state=abc", "abc").is_err());
        assert!(parse_callback("/?code=sc_xyz", "abc").is_err());
        assert!(parse_callback("/?session=st_xyz", "abc").is_err());
    }

    /// Answer one request with `response_body` verbatim, capturing the request line and body.
    fn serve_once(
        response_body: &'static str,
    ) -> (String, std::sync::mpsc::Receiver<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let base = format!("http://{}", listener.local_addr().expect("local addr"));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            let mut request_line = String::new();
            reader.read_line(&mut request_line).expect("read line");
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).expect("read head") <= 2 {
                    break;
                }
                // Header names are case-insensitive, and reqwest sends them in lowercase.
                let lower = line.to_ascii_lowercase();
                if let Some(n) = lower.strip_prefix("content-length:") {
                    content_length = n.trim().parse().expect("content length");
                }
            }
            let mut body = vec![0u8; content_length];
            std::io::Read::read_exact(&mut reader, &mut body).expect("read body");
            tx.send((request_line, String::from_utf8(body).expect("utf8")))
                .expect("send");
            let mut stream = reader.into_inner();
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
        });
        (base, rx)
    }

    #[test]
    fn resolve_grant_returns_a_legacy_session_untouched() {
        let token = resolve_grant(
            "https://api.sotto.dev",
            CallbackGrant::Session("st_old".into()),
            "cli-state",
        )
        .expect("session passes through");
        assert_eq!(token, "st_old");
    }

    #[test]
    fn resolve_grant_exchanges_a_code_instead_of_returning_it() {
        // An unparsable server URL means the exchange fails before any I/O, so this runs
        // anywhere with no socket; what matters is that the code arm routes into the
        // exchange (Err) rather than handing the code back as the token (Ok), which is
        // what this returns if the dispatch regresses to passing the code straight through.
        let err = resolve_grant(
            "not a url",
            CallbackGrant::Code("sc_abc".into()),
            "cli-state",
        )
        .expect_err("code arm must attempt the exchange");
        assert!(
            matches!(err, Error::Network(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn exchange_code_posts_code_and_state_and_returns_the_token() {
        let (base, rx) = serve_once(r#"{"token":"st_exchanged"}"#);
        let token = exchange_code(&base, "sc_abc", "cli-state").expect("exchange");
        assert_eq!(token, "st_exchanged");
        let (request_line, body) = rx.recv().expect("captured request");
        assert!(request_line.starts_with("POST /auth/github/exchange "));
        assert!(body.contains("\"code\":\"sc_abc\""), "code in body: {body}");
        assert!(
            body.contains("\"state\":\"cli-state\""),
            "state in body: {body}"
        );
    }
}
