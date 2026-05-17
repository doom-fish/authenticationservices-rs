use authenticationservices::{
    authorization_error_domain, credential_identity_store_error_domain, extension_error_domain,
    web_authentication_session_error_domain, AppleIdButton, AppleIdButtonStyle,
    AppleIdButtonType, Authorization, AuthorizationControllerDelegate,
    AuthorizationControllerPresentationContextProviding, AuthorizationCredential,
    AuthorizationRequest, CredentialIdentityRecord, CredentialServiceIdentifier, Image,
    OpenIdRequest, OpenIdRequestConfiguration, PasskeyAssertionCredential,
    PasskeyRegistrationCredential, PasswordCredential, PasswordCredentialIdentity,
    PasswordProvider, PresentationAnchor, PublicKeyCredential,
    PublicKeyCredentialAssertion, PublicKeyCredentialRegistration,
    PublicKeyCredentialUserVerificationPreference, UserAgeRange, UserDetectionStatus,
    ViewController,
};

struct DummyAuthorizationDelegate;

impl AuthorizationControllerDelegate for DummyAuthorizationDelegate {
    fn did_complete_with_authorization(&mut self, _authorization: &Authorization) {}

    fn did_complete_with_error(&mut self, _message: &str) {}
}

struct DummyPresentationContext;

impl AuthorizationControllerPresentationContextProviding for DummyPresentationContext {
    fn presentation_anchor_for_authorization_controller(&self) -> PresentationAnchor {
        std::ptr::null_mut()
    }
}

fn credential_id_len<T: PublicKeyCredential>(credential: &T) -> usize {
    credential.credential_id().len()
}

fn assertion_sig_len<T: PublicKeyCredentialAssertion>(credential: &T) -> usize {
    credential.signature().len()
}

fn registration_attestation_len<T: PublicKeyCredentialRegistration>(credential: &T) -> usize {
    credential.raw_attestation_object().map_or(0, <[u8]>::len)
}

#[test]
fn apple_id_button_and_aliases_are_available() {
    let mut button = AppleIdButton::new(AppleIdButtonType::Continue, AppleIdButtonStyle::Black);
    button.set_corner_radius(12.0);
    assert_eq!(button.button_type(), AppleIdButtonType::Continue);
    assert_eq!(button.style(), AppleIdButtonStyle::Black);
    assert!((button.corner_radius() - 12.0).abs() < f64::EPSILON);

    let open_id_request: Option<OpenIdRequest> = None;
    assert!(open_id_request.is_none());
    let open_id_configuration = OpenIdRequestConfiguration::default();
    assert_eq!(open_id_configuration.requested_scopes.len(), 2);
    let anchor: PresentationAnchor = std::ptr::null_mut();
    let image: Image = std::ptr::null_mut();
    let view_controller: ViewController = std::ptr::null_mut();
    assert!(anchor.is_null() && image.is_null() && view_controller.is_null());

    let mut delegate = DummyAuthorizationDelegate;
    let authorization = Authorization {
        provider: "password".into(),
        user_identifier: Some("user".into()),
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
    delegate.did_complete_with_authorization(&authorization);
    delegate.did_complete_with_error("noop");

    let presentation_context = DummyPresentationContext;
    assert_eq!(
        presentation_context.presentation_anchor_for_authorization_controller(),
        std::ptr::null_mut()
    );
}

#[test]
fn apple_id_authorization_payload_decodes_age_and_detection_status() {
    let authorization: Authorization = serde_json::from_str(
        r#"{
            "provider": "apple_id",
            "userIdentifier": "user-1",
            "realUserStatus": "likely_real",
            "userAgeRange": "child"
        }"#,
    )
    .unwrap();

    let credential = authorization.apple_id_credential().unwrap();
    assert_eq!(credential.real_user_status, Some(UserDetectionStatus::LikelyReal));
    assert_eq!(credential.user_age_range, Some(UserAgeRange::Child));
}

#[test]
fn base_traits_and_domain_helpers_are_available() {
    let password_request = PasswordProvider::new().create_request().unwrap();
    assert_eq!(AuthorizationRequest::provider_identifier(&password_request), "password");

    let password_credential = PasswordCredential::new("user", "secret").unwrap();
    assert_eq!(AuthorizationCredential::provider_identifier(&password_credential), "password");

    let assertion = PasskeyAssertionCredential::new(
        b"user-handle".to_vec(),
        "example.com",
        b"signature".to_vec(),
        b"client-data-hash".to_vec(),
        b"authenticator-data".to_vec(),
        b"credential-id".to_vec(),
    );
    let registration = PasskeyRegistrationCredential::new(
        "example.com",
        b"client-data-hash".to_vec(),
        b"credential-id".to_vec(),
        b"attestation-object".to_vec(),
    );

    assert_eq!(credential_id_len(&assertion), b"credential-id".len());
    assert_eq!(assertion_sig_len(&assertion), b"signature".len());
    assert_eq!(registration_attestation_len(&registration), b"attestation-object".len());

    let identity = PasswordCredentialIdentity {
        service_identifier: CredentialServiceIdentifier::domain("example.com"),
        user: "user".into(),
        record_identifier: Some("record-1".into()),
        rank: 42,
    };
    assert_eq!(CredentialIdentityRecord::record_identifier(&identity), Some("record-1"));
    assert_eq!(CredentialIdentityRecord::rank(&identity), 42);

    assert!(!authorization_error_domain().unwrap().is_empty());
    assert!(!credential_identity_store_error_domain().unwrap().is_empty());
    assert!(!extension_error_domain().unwrap().is_empty());
    assert!(!web_authentication_session_error_domain().unwrap().is_empty());

    assert!(matches!(
        PublicKeyCredentialUserVerificationPreference::Preferred,
        PublicKeyCredentialUserVerificationPreference::Preferred
    ));
}
