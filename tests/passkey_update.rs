use authenticationservices::{
    AuthenticationServicesError, LargeBlobRegistrationInput, LargeBlobSupportRequirement,
    PlatformCredentialDescriptor, PlatformPasskeyAssertionOptions,
    PlatformPasskeyRegistrationOptions, PlatformPublicKeyCredentialProvider, PrfRegistrationInput,
    PublicKeyCredentialParameters, SecurityKeyAssertionOptions, SecurityKeyCredentialDescriptor,
    SecurityKeyPublicKeyCredentialProvider, SecurityKeyRegistrationOptions,
};

fn assert_invalid_argument<T>(result: Result<T, AuthenticationServicesError>) {
    let error = result.err().expect("the call must be rejected");
    assert!(
        matches!(error, AuthenticationServicesError::InvalidArgument(_)),
        "{error:?}"
    );
}

#[test]
fn update_applies_user_identity_changes() {
    let platform = PlatformPublicKeyCredentialProvider::new("example.com");
    let registration = platform
        .create_registration_request(&[1; 32], b"user-1", "alice", Some("Alice"))
        .unwrap();
    let mut options = registration.configuration().unwrap();
    options.user_id = b"user-2".to_vec();
    options.user_name = "bob".into();
    options.user_display_name = Some("Bob".into());
    registration.update(&options).unwrap();
    let updated = registration.configuration().unwrap();
    assert_eq!(updated.user_id, b"user-2");
    assert_eq!(updated.user_name, "bob");
    assert_eq!(updated.user_display_name.as_deref(), Some("Bob"));
    assert_eq!(registration.kind().unwrap().user_name.as_deref(), Some("bob"));

    let security_key = SecurityKeyPublicKeyCredentialProvider::new("example.com");
    let security_registration = security_key
        .create_registration_request_with_options(&SecurityKeyRegistrationOptions {
            challenge: Some(vec![2; 32]),
            user_id: b"user-1".to_vec(),
            user_name: "alice".into(),
            user_display_name: Some("Alice".into()),
            ..SecurityKeyRegistrationOptions::default()
        })
        .unwrap();
    let mut options = security_registration.configuration().unwrap();
    options.user_id = b"user-2".to_vec();
    options.user_name = "bob".into();
    options.user_display_name = Some("Bob".into());
    security_registration.update(&options).unwrap();
    let updated = security_registration.configuration().unwrap();
    assert_eq!(updated.user_id, b"user-2");
    assert_eq!(updated.user_name, "bob");
    assert_eq!(updated.user_display_name.as_deref(), Some("Bob"));
}

#[test]
fn update_clears_inputs_that_are_left_out() {
    let platform = PlatformPublicKeyCredentialProvider::new("example.com");
    let registration = platform
        .create_registration_request_with_options(&PlatformPasskeyRegistrationOptions {
            challenge: Some(vec![1; 32]),
            user_id: b"user-1".to_vec(),
            user_name: "alice".into(),
            large_blob: Some(LargeBlobRegistrationInput {
                support_requirement: LargeBlobSupportRequirement::Required,
            }),
            prf: Some(PrfRegistrationInput {
                input_values: None,
                should_check_for_support: true,
            }),
            ..PlatformPasskeyRegistrationOptions::default()
        })
        .unwrap();
    let configured = registration.configuration().unwrap();
    assert!(configured.large_blob.is_some());
    assert!(configured.prf.is_some());
    registration
        .update(&PlatformPasskeyRegistrationOptions {
            large_blob: None,
            prf: None,
            ..configured
        })
        .unwrap();
    let cleared = registration.configuration().unwrap();
    assert_eq!(cleared.large_blob, None);
    assert_eq!(cleared.prf, None);

    let assertion = platform
        .create_assertion_request_with_options(&PlatformPasskeyAssertionOptions {
            challenge: Some(vec![2; 32]),
            allowed_credentials: vec![PlatformCredentialDescriptor {
                credential_id: vec![7; 16],
            }],
            ..PlatformPasskeyAssertionOptions::default()
        })
        .unwrap();
    assert_eq!(assertion.configuration().unwrap().allowed_credentials.len(), 1);
    assertion.update(&PlatformPasskeyAssertionOptions::default()).unwrap();
    assert!(assertion.configuration().unwrap().allowed_credentials.is_empty());

    let security_key = SecurityKeyPublicKeyCredentialProvider::new("example.com");
    let security_registration = security_key
        .create_registration_request_with_options(&SecurityKeyRegistrationOptions {
            challenge: Some(vec![3; 32]),
            user_id: b"user-1".to_vec(),
            user_name: "alice".into(),
            excluded_credentials: vec![SecurityKeyCredentialDescriptor {
                credential_id: vec![8; 16],
                transports: None,
            }],
            credential_parameters: vec![PublicKeyCredentialParameters { algorithm: -7 }],
            ..SecurityKeyRegistrationOptions::default()
        })
        .unwrap();
    let configured = security_registration.configuration().unwrap();
    assert_eq!(configured.excluded_credentials.len(), 1);
    assert_eq!(configured.credential_parameters.len(), 1);
    security_registration
        .update(&SecurityKeyRegistrationOptions {
            excluded_credentials: Vec::new(),
            credential_parameters: Vec::new(),
            ..configured
        })
        .unwrap();
    let cleared = security_registration.configuration().unwrap();
    assert!(cleared.excluded_credentials.is_empty());
    assert!(cleared.credential_parameters.is_empty());

    let security_assertion = security_key
        .create_assertion_request_with_options(&SecurityKeyAssertionOptions {
            challenge: Some(vec![4; 32]),
            app_id: Some("https://example.com/app-id.json".into()),
            ..SecurityKeyAssertionOptions::default()
        })
        .unwrap();
    assert_eq!(
        security_assertion.configuration().unwrap().app_id.as_deref(),
        Some("https://example.com/app-id.json")
    );
    security_assertion
        .update(&SecurityKeyAssertionOptions::default())
        .unwrap();
    assert_eq!(security_assertion.configuration().unwrap().app_id, None);
}

#[test]
fn user_ids_outside_the_webauthn_bounds_are_rejected() {
    let platform = PlatformPublicKeyCredentialProvider::new("example.com");
    assert_invalid_argument(platform.create_registration_request(&[1; 32], b"", "alice", None));
    assert_invalid_argument(platform.create_registration_request(&[1; 32], &[0; 65], "alice", None));
    let registration = platform
        .create_registration_request(&[1; 32], &[0; 64], "alice", None)
        .unwrap();
    let mut options = registration.configuration().unwrap();
    options.user_id.clear();
    assert_invalid_argument(registration.update(&options));
    assert_eq!(registration.configuration().unwrap().user_id, vec![0; 64]);

    let security_key = SecurityKeyPublicKeyCredentialProvider::new("example.com");
    assert_invalid_argument(security_key.create_registration_request_with_options(
        &SecurityKeyRegistrationOptions {
            challenge: Some(vec![2; 32]),
            user_name: "alice".into(),
            ..SecurityKeyRegistrationOptions::default()
        },
    ));
}
