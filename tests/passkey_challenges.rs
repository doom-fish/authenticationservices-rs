use authenticationservices::{
    AuthenticationServicesError, PlatformPasskeyAssertionOptions, PlatformPasskeyRegistrationOptions,
    PlatformPublicKeyCredentialProvider, PublicKeyCredentialClientData,
    PublicKeyCredentialClientDataCrossOriginValue, SecurityKeyAssertionOptions,
    SecurityKeyPublicKeyCredentialProvider, SecurityKeyRegistrationOptions,
};

fn assert_invalid_argument<T: std::fmt::Debug>(result: Result<T, AuthenticationServicesError>) {
    let error = result.expect_err("a missing challenge must be rejected");
    assert!(
        matches!(error, AuthenticationServicesError::InvalidArgument(_)),
        "{error:?}"
    );
}

fn registration_options() -> PlatformPasskeyRegistrationOptions {
    PlatformPasskeyRegistrationOptions {
        user_id: b"user-1".to_vec(),
        user_name: "alice".into(),
        ..PlatformPasskeyRegistrationOptions::default()
    }
}

fn security_key_registration_options() -> SecurityKeyRegistrationOptions {
    SecurityKeyRegistrationOptions {
        user_id: b"user-1".to_vec(),
        user_name: "alice".into(),
        ..SecurityKeyRegistrationOptions::default()
    }
}

#[test]
fn missing_or_empty_challenges_are_rejected() {
    let platform = PlatformPublicKeyCredentialProvider::new("example.com");
    assert_invalid_argument(platform.create_assertion_request(&[]));
    assert_invalid_argument(platform.create_registration_request(&[], b"user-1", "alice", None));
    assert_invalid_argument(
        platform.create_assertion_request_with_options(&PlatformPasskeyAssertionOptions::default()),
    );
    assert_invalid_argument(platform.create_registration_request_with_options(&registration_options()));
    assert_invalid_argument(platform.create_assertion_request_with_options(
        &PlatformPasskeyAssertionOptions {
            challenge: Some(Vec::new()),
            ..PlatformPasskeyAssertionOptions::default()
        },
    ));

    let security_key = SecurityKeyPublicKeyCredentialProvider::new("example.com");
    assert_invalid_argument(
        security_key.create_assertion_request_with_options(&SecurityKeyAssertionOptions::default()),
    );
    assert_invalid_argument(
        security_key.create_registration_request_with_options(&security_key_registration_options()),
    );
}

#[test]
fn challenges_survive_request_creation() {
    let platform = PlatformPublicKeyCredentialProvider::new("example.com");
    let request = platform
        .create_assertion_request_with_options(&PlatformPasskeyAssertionOptions {
            challenge: Some(vec![7; 32]),
            ..PlatformPasskeyAssertionOptions::default()
        })
        .unwrap();
    assert_eq!(request.configuration().unwrap().challenge, Some(vec![7; 32]));
}

#[test]
fn client_data_is_accepted_and_round_trips() {
    let client_data = PublicKeyCredentialClientData {
        challenge: vec![9; 32],
        origin: "https://example.com".into(),
        top_origin: Some("https://top.example.com".into()),
        cross_origin: PublicKeyCredentialClientDataCrossOriginValue::CrossOrigin,
    };

    let platform = PlatformPublicKeyCredentialProvider::new("example.com");
    let assertion = platform
        .create_assertion_request_with_options(&PlatformPasskeyAssertionOptions {
            client_data: Some(client_data.clone()),
            ..PlatformPasskeyAssertionOptions::default()
        })
        .unwrap();
    assert_eq!(
        assertion.configuration().unwrap().client_data,
        Some(client_data.clone())
    );

    let registration = platform
        .create_registration_request_with_options(&PlatformPasskeyRegistrationOptions {
            client_data: Some(client_data.clone()),
            ..registration_options()
        })
        .unwrap();
    let configuration = registration.configuration().unwrap();
    assert_eq!(configuration.client_data, Some(client_data.clone()));
    registration.update(&configuration).unwrap();

    let security_key = SecurityKeyPublicKeyCredentialProvider::new("example.com");
    let security_assertion = security_key
        .create_assertion_request_with_options(&SecurityKeyAssertionOptions {
            client_data: Some(client_data.clone()),
            ..SecurityKeyAssertionOptions::default()
        })
        .unwrap();
    assert_eq!(
        security_assertion.configuration().unwrap().client_data,
        Some(client_data)
    );
}

#[test]
fn a_challenge_that_contradicts_the_client_data_is_rejected() {
    let platform = PlatformPublicKeyCredentialProvider::new("example.com");
    assert_invalid_argument(platform.create_assertion_request_with_options(
        &PlatformPasskeyAssertionOptions {
            challenge: Some(vec![1; 32]),
            client_data: Some(PublicKeyCredentialClientData::new(
                vec![2; 32],
                "https://example.com",
            )),
            ..PlatformPasskeyAssertionOptions::default()
        },
    ));
    assert_invalid_argument(platform.create_assertion_request_with_options(
        &PlatformPasskeyAssertionOptions {
            client_data: Some(PublicKeyCredentialClientData::new(Vec::new(), "https://example.com")),
            ..PlatformPasskeyAssertionOptions::default()
        },
    ));
}
