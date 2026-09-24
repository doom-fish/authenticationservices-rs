use authenticationservices::{
    AuthenticationServicesError, WebAuthenticationCallback, WebAuthenticationSession,
};

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

#[test]
fn starting_a_session_off_the_main_thread_is_an_error() {
    let session = WebAuthenticationSession::new("https://example.com/login", Some("demo"));
    let error = session
        .start()
        .err()
        .expect("start must fail off the main thread");
    assert!(
        matches!(error, AuthenticationServicesError::MainThreadRequired(_)),
        "{error:?}"
    );
}

#[cfg(feature = "async")]
#[test]
fn starting_an_async_session_off_the_main_thread_is_an_error() {
    let session = WebAuthenticationSession::new("https://example.com/login", Some("demo"));
    let error = authenticationservices::async_api::AsyncWebAuthenticationSession::new(&session)
        .start()
        .expect_err("start must fail off the main thread");
    assert!(
        matches!(error, AuthenticationServicesError::MainThreadRequired(_)),
        "{error:?}"
    );
}
