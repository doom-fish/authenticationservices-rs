use authenticationservices::{WebAuthenticationCallback, WebAuthenticationSession};

#[test]
fn custom_scheme_callbacks_match_urls() {
    let callback = WebAuthenticationCallback::CustomScheme("demo".into());
    assert!(callback.matches_url("demo://callback?code=123").unwrap());
    assert!(!callback.matches_url("other://callback?code=123").unwrap());
}

#[test]
fn web_authentication_session_builder_preserves_configuration() {
    let session = WebAuthenticationSession::new("https://example.com/login", Some("demo"))
        .with_prefers_ephemeral_web_browser_session(true)
        .with_additional_header_field("X-Demo", "1");
    let debug = format!("{session:?}");
    assert!(debug.contains("https://example.com/login"));
    assert!(debug.contains("demo"));
    assert!(debug.contains("X-Demo"));
}
