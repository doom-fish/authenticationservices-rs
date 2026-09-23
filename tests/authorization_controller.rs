use authenticationservices::{
    Authorization, AuthorizationControllerRequestOptions, PasswordCredential,
};

#[test]
fn authorization_helpers_decode_password_results() {
    let authorization = Authorization {
        provider: "password".into(),
        user_identifier: Some("alice@example.com".into()),
        email: None,
        full_name: None,
        identity_token: None,
        authorization_code: None,
        real_user_status: None,
        user_age_range: None,
        password: Some("secret".into()),
        credential_id: None,
        raw_attestation_object: None,
        raw_authenticator_data: None,
        signature: None,
        user_id: None,
        attachment: None,
        used_app_id: None,
        transports: None,
        large_blob_result_kind: None,
        large_blob_data: None,
        large_blob_write_succeeded: None,
        large_blob_supported: None,
        prf_first: None,
        prf_second: None,
        prf_supported: None,
    };

    assert_eq!(
        authorization.password_credential(),
        Some(PasswordCredential {
            user: "alice@example.com".into(),
            password: "secret".into(),
        })
    );
    assert!(authorization.apple_id_credential().is_none());
}

#[test]
fn authorization_controller_request_options_behave_like_bitflags() {
    let options = AuthorizationControllerRequestOptions::empty()
        | AuthorizationControllerRequestOptions::PREFER_IMMEDIATELY_AVAILABLE_CREDENTIALS;
    assert!(options.contains(
        AuthorizationControllerRequestOptions::PREFER_IMMEDIATELY_AVAILABLE_CREDENTIALS
    ));
    assert_eq!(options.bits(), 1);
}

#[test]
fn debug_output_redacts_tokens_passwords_and_signatures() {
    let authorization = Authorization {
        provider: "apple_id".into(),
        user_identifier: Some("user-1".into()),
        email: None,
        full_name: None,
        identity_token: Some("eyJ-identity-token".into()),
        authorization_code: Some("auth-code-123".into()),
        real_user_status: None,
        user_age_range: None,
        password: Some("hunter2".into()),
        credential_id: None,
        raw_attestation_object: None,
        raw_authenticator_data: None,
        signature: Some("c2lnbmF0dXJl".into()),
        user_id: Some("dXNlci1oYW5kbGU=".into()),
        attachment: None,
        used_app_id: None,
        transports: None,
        large_blob_result_kind: None,
        large_blob_data: Some("YmxvYg==".into()),
        large_blob_write_succeeded: None,
        large_blob_supported: None,
        prf_first: Some("cHJmLWZpcnN0".into()),
        prf_second: None,
        prf_supported: None,
    };
    let rendered = format!("{authorization:?}");
    for secret in [
        "eyJ-identity-token",
        "auth-code-123",
        "hunter2",
        "c2lnbmF0dXJl",
        "dXNlci1oYW5kbGU=",
        "YmxvYg==",
        "cHJmLWZpcnN0",
    ] {
        assert!(!rendered.contains(secret), "{secret} leaked: {rendered}");
    }
    assert!(rendered.contains("user-1"));
    assert!(rendered.contains("<redacted>"));
    assert!(rendered.contains("prf_second: None"));

    let apple_id = authorization.apple_id_credential().expect("apple id");
    let rendered = format!("{apple_id:?}");
    assert!(!rendered.contains("eyJ-identity-token"), "{rendered}");
    assert!(!rendered.contains("auth-code-123"), "{rendered}");

    let password = PasswordCredential {
        user: "alice".into(),
        password: "hunter2".into(),
    };
    let rendered = format!("{password:?}");
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(rendered.contains("alice"), "{rendered}");
}
