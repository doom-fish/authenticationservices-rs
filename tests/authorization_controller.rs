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
        password: Some(String::from("secret").into()),
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
            password: String::from("secret").into(),
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
        identity_token: Some(String::from("eyJ-identity-token").into()),
        authorization_code: Some(String::from("auth-code-123").into()),
        real_user_status: None,
        user_age_range: None,
        password: Some(String::from("hunter2").into()),
        credential_id: None,
        raw_attestation_object: None,
        raw_authenticator_data: None,
        signature: Some("c2lnbmF0dXJl".into()),
        user_id: Some("dXNlci1oYW5kbGU=".into()),
        attachment: None,
        used_app_id: None,
        transports: None,
        large_blob_result_kind: None,
        large_blob_data: Some(String::from("YmxvYg==").into()),
        large_blob_write_succeeded: None,
        large_blob_supported: None,
        prf_first: Some(String::from("cHJmLWZpcnN0").into()),
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
        password: String::from("hunter2").into(),
    };
    let rendered = format!("{password:?}");
    assert!(!rendered.contains("hunter2"), "{rendered}");
    assert!(rendered.contains("alice"), "{rendered}");
}

#[test]
fn secret_fields_still_decide_equality() {
    let authorization = Authorization {
        provider: "apple_id".into(),
        user_identifier: Some("user-1".into()),
        email: None,
        full_name: None,
        identity_token: Some(String::from("token-a").into()),
        authorization_code: Some(String::from("code-a").into()),
        real_user_status: None,
        user_age_range: None,
        password: None,
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
        prf_first: Some(String::from("cHJm").into()),
        prf_second: None,
        prf_supported: None,
    };
    let same = authorization.clone();
    assert_eq!(authorization, same);

    let mut other_token = authorization.clone();
    other_token.identity_token = Some(String::from("token-b").into());
    assert_ne!(authorization, other_token);

    let mut shorter_code = authorization.clone();
    shorter_code.authorization_code = Some(String::from("code").into());
    assert_ne!(authorization, shorter_code);

    let mut no_prf = authorization.clone();
    no_prf.prf_first = None;
    assert_ne!(authorization, no_prf);

    let mut other_user = authorization.clone();
    other_user.user_identifier = Some("user-2".into());
    assert_ne!(authorization, other_user);

    let apple_id = authorization.apple_id_credential().expect("apple id");
    assert_eq!(Some(apple_id.clone()), same.apple_id_credential());
    assert_ne!(Some(apple_id), other_token.apple_id_credential());

    let password = PasswordCredential {
        user: "alice".into(),
        password: String::from("hunter2").into(),
    };
    assert_eq!(password, password.clone());
    assert_ne!(
        password,
        PasswordCredential {
            user: "alice".into(),
            password: String::from("hunter3").into(),
        }
    );
}
