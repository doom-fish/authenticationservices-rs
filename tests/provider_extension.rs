use std::collections::BTreeMap;

use authenticationservices::{
    HttpResponse, ProviderExtensionAuthenticationMethod,
    ProviderExtensionAuthorizationOperation, ProviderExtensionAuthorizationRequest,
    ProviderExtensionAuthorizationRequestHandler, ProviderExtensionAuthorizationResult,
    ProviderExtensionEncryptionAlgorithm, ProviderExtensionFederationType,
    ProviderExtensionKerberosMapping, ProviderExtensionKeyType,
    ProviderExtensionLoginConfiguration, ProviderExtensionLoginManager,
    ProviderExtensionPlatformSsoProtocolVersion, ProviderExtensionRegistrationHandler,
    ProviderExtensionRegistrationResult, ProviderExtensionRequestOptions,
    ProviderExtensionSigningAlgorithm, ProviderExtensionSupportedGrantTypes,
    ProviderExtensionUserLoginConfiguration, ProviderExtensionUserSecureEnclaveKeyBiometricPolicy,
    QueryItem,
};

struct DummyAuthorizationHandler;

impl ProviderExtensionAuthorizationRequestHandler for DummyAuthorizationHandler {
    fn begin_authorization_with_request(
        &mut self,
        request: &mut ProviderExtensionAuthorizationRequest,
    ) {
        request.complete();
    }
}

struct DummyRegistrationHandler;

impl ProviderExtensionRegistrationHandler for DummyRegistrationHandler {
    fn begin_device_registration(
        &mut self,
        login_manager: &mut ProviderExtensionLoginManager,
        _options: ProviderExtensionRequestOptions,
    ) -> ProviderExtensionRegistrationResult {
        login_manager.device_registered = true;
        ProviderExtensionRegistrationResult::Success
    }

    fn begin_user_registration(
        &mut self,
        login_manager: &mut ProviderExtensionLoginManager,
        user_name: Option<&str>,
        authentication_method: ProviderExtensionAuthenticationMethod,
        _options: ProviderExtensionRequestOptions,
    ) -> ProviderExtensionRegistrationResult {
        login_manager.user_registered = user_name.is_some();
        login_manager.authentication_method = Some(authentication_method);
        ProviderExtensionRegistrationResult::Success
    }

    fn supported_grant_types(&self) -> ProviderExtensionSupportedGrantTypes {
        ProviderExtensionSupportedGrantTypes::PASSWORD
            | ProviderExtensionSupportedGrantTypes::JWT_BEARER
            | ProviderExtensionSupportedGrantTypes::SAML1_1
            | ProviderExtensionSupportedGrantTypes::SAML2_0
    }

    fn protocol_version(&self) -> ProviderExtensionPlatformSsoProtocolVersion {
        ProviderExtensionPlatformSsoProtocolVersion::V2_0
    }

    fn supported_device_signing_algorithms(&self) -> Vec<ProviderExtensionSigningAlgorithm> {
        vec![
            ProviderExtensionSigningAlgorithm::Es256,
            ProviderExtensionSigningAlgorithm::Es384,
            ProviderExtensionSigningAlgorithm::Ed25519,
        ]
    }

    fn supported_device_encryption_algorithms(&self) -> Vec<ProviderExtensionEncryptionAlgorithm> {
        vec![
            ProviderExtensionEncryptionAlgorithm::EcdheA256Gcm,
            ProviderExtensionEncryptionAlgorithm::HpkeP256Sha256AesGcm256,
            ProviderExtensionEncryptionAlgorithm::HpkeP384Sha384AesGcm256,
            ProviderExtensionEncryptionAlgorithm::HpkeCurve25519Sha256ChachaPoly,
        ]
    }
}

#[allow(clippy::too_many_lines)]
#[test]
fn provider_extension_models_capture_platform_sso_state() {
    let mut user_login = ProviderExtensionUserLoginConfiguration::new("person@example.com");
    user_login.set_custom_login_request_header_claims(BTreeMap::from([(
        "x-test".into(),
        serde_json::Value::String("1".into()),
    )]));

    let mut login = ProviderExtensionLoginConfiguration::new(
        "client-id",
        "issuer",
        "https://example.com/token",
        "https://example.com/jwks",
        Some("audience".into()),
    );
    login.invalid_credential_predicate = Some("status == 401".into());
    login.account_display_name = Some("Example".into());
    login.additional_scopes = Some("openid profile".into());
    login.additional_authorization_scopes = Some("email".into());
    login.custom_nonce_request_values.push(QueryItem::new("nonce", Some("1".into())));
    login.kerberos_ticket_mappings.push(ProviderExtensionKerberosMapping {
        ticket_key_path: Some("tickets.primary".into()),
        message_buffer_key_name: Some("message".into()),
        realm_key_name: Some("realm".into()),
        service_name_key_name: Some("service".into()),
        client_name_key_name: Some("client".into()),
        encryption_key_type_key_name: Some("etype".into()),
        session_key_key_name: Some("session".into()),
    });
    login.federation_type = ProviderExtensionFederationType::DynamicWsTrust;
    login.user_secure_enclave_key_biometric_policy =
        ProviderExtensionUserSecureEnclaveKeyBiometricPolicy::TOUCH_ID_OR_WATCH_CURRENT_SET
            | ProviderExtensionUserSecureEnclaveKeyBiometricPolicy::PASSWORD_FALLBACK;
    login.set_custom_login_request_body_claims(BTreeMap::from([(
        "claim".into(),
        serde_json::Value::String("value".into()),
    )]));

    let mut login_manager = ProviderExtensionLoginManager::new();
    login_manager.registration_token = Some("token".into());
    login_manager.save_user_login_configuration(user_login.clone());
    login_manager.save_login_configuration(login.clone());
    login_manager.save_certificate(vec![1, 2, 3], ProviderExtensionKeyType::UserDeviceSigning);
    login_manager.set_key(ProviderExtensionKeyType::UserDeviceSigning, vec![9, 9, 9]);
    assert_eq!(
        login_manager.copy_key(ProviderExtensionKeyType::UserDeviceSigning),
        Some(vec![9, 9, 9])
    );
    assert!(login_manager
        .begin_key_rotation(ProviderExtensionKeyType::UserDeviceSigning)
        .is_some());
    login_manager.complete_key_rotation(ProviderExtensionKeyType::UserDeviceSigning);
    assert!(login_manager
        .attest_key(ProviderExtensionKeyType::UserDeviceSigning, b"hash")
        .is_some());

    let mut handler = DummyRegistrationHandler;
    let options = ProviderExtensionRequestOptions::USER_INTERACTION_ENABLED
        | ProviderExtensionRequestOptions::REGISTRATION_REPAIR
        | ProviderExtensionRequestOptions::REGISTRATION_SHARED_DEVICE_KEYS
        | ProviderExtensionRequestOptions::REGISTRATION_DEVICE_KEY_MIGRATION
        | ProviderExtensionRequestOptions::STRONGER_KEY_AVAILABLE
        | ProviderExtensionRequestOptions::USER_KEY_INVALID
        | ProviderExtensionRequestOptions::SETUP_ASSISTANT;
    assert!(options.contains(ProviderExtensionRequestOptions::USER_INTERACTION_ENABLED));
    assert_eq!(
        handler.begin_device_registration(&mut login_manager, options),
        ProviderExtensionRegistrationResult::Success
    );
    assert_eq!(
        handler.begin_user_registration(
            &mut login_manager,
            Some("person@example.com"),
            ProviderExtensionAuthenticationMethod::SmartCard,
            options,
        ),
        ProviderExtensionRegistrationResult::Success
    );
    assert!(login_manager.device_registered);
    assert!(login_manager.user_registered);
    assert_eq!(
        handler.protocol_version(),
        ProviderExtensionPlatformSsoProtocolVersion::V2_0
    );
    assert!(handler
        .supported_grant_types()
        .contains(ProviderExtensionSupportedGrantTypes::SAML2_0));
    assert_eq!(handler.supported_device_signing_algorithms().len(), 3);
    assert_eq!(handler.supported_device_encryption_algorithms().len(), 4);

    let mut request = ProviderExtensionAuthorizationRequest::new(
        "https://example.com/login",
        ProviderExtensionAuthorizationOperation::DirectRequest,
    );
    request.http_headers.insert("Accept".into(), "application/json".into());
    request.http_body = br#"{"username":"person@example.com"}"#.to_vec();
    request.realm = Some("Example Realm".into());
    request.login_manager = Some(login_manager.clone());

    let mut auth_handler = DummyAuthorizationHandler;
    auth_handler.begin_authorization_with_request(&mut request);
    assert!(matches!(request.outcome(), authenticationservices::ProviderExtensionAuthorizationOutcome::CompletedWithoutOutput));

    let headers = BTreeMap::from([("Authorization".into(), "Bearer token".into())]);
    let result = ProviderExtensionAuthorizationResult::from_http_authorization_headers(headers.clone());
    let response = HttpResponse::new("https://example.com/callback", 200)
        .with_header("Content-Type", "application/json");
    request.complete_with_http_authorization_headers(headers);
    request.complete_with_http_response(response, Some(br"{}".to_vec()));
    request.complete_with_authorization_result(result);
    request.cancel();
    request.do_not_handle();
    assert!(request.present_authorization_view_controller().is_ok());

    login_manager.user_needs_reauthentication();
    login_manager.device_registrations_need_repair = true;
    login_manager.user_registrations_need_repair = true;
    login_manager.decryption_keys_need_repair = true;
    login_manager.reset_device_keys();
    login_manager.reset_user_secure_enclave_key();
    login_manager.reset_keys();

    assert_eq!(
        ProviderExtensionRegistrationResult::FailedNoRetry,
        ProviderExtensionRegistrationResult::FailedNoRetry
    );
    assert!(matches!(
        ProviderExtensionAuthenticationMethod::UserSecureEnclaveKey,
        ProviderExtensionAuthenticationMethod::UserSecureEnclaveKey
    ));
    assert!(matches!(
        ProviderExtensionKeyType::UserSmartCard,
        ProviderExtensionKeyType::UserSmartCard
    ));
    assert!(matches!(
        ProviderExtensionAuthorizationOperation::ConfigurationRemoved,
        ProviderExtensionAuthorizationOperation::ConfigurationRemoved
    ));
    assert!(matches!(
        ProviderExtensionFederationType::WsTrust,
        ProviderExtensionFederationType::WsTrust
    ));
}
