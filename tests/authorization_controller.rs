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
