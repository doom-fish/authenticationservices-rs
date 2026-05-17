use authenticationservices::{
    CredentialIdentityRecord, CredentialProviderExtensionContext,
    CredentialProviderExtensionRequestOutcome, CredentialProviderPreparation,
    CredentialProviderViewController, CredentialRequest, CredentialRequestType,
    CredentialServiceIdentifier, CoseAlgorithmIdentifier, CoseEllipticCurveIdentifier,
    ExtensionErrorCode, LargeBlobAssertionInput, LargeBlobAssertionOperation,
    LargeBlobAssertionOutput, LargeBlobAssertionOutputResult, LargeBlobRegistrationInput,
    LargeBlobRegistrationOutput, LargeBlobSupportRequirement, OneTimeCodeCredential,
    OneTimeCodeCredentialIdentity, OneTimeCodeCredentialRequest,
    PasskeyAssertionCredential, PasskeyAssertionCredentialExtensionInput,
    PasskeyAssertionCredentialExtensionOutput, PasskeyCredentialRequest,
    PasskeyCredentialRequestParameters, PasskeyCredentialIdentity,
    PasskeyRegistrationCredential, PasskeyRegistrationCredentialExtensionInput,
    PasskeyRegistrationCredentialExtensionOutput, PasswordCredential,
    PasswordCredentialIdentity, PasswordCredentialRequest, PlatformCredentialDescriptor,
    PublicKeyCredential, PublicKeyCredentialAssertion, PublicKeyCredentialClientData,
    PublicKeyCredentialClientDataCrossOriginValue,
    PublicKeyCredentialRegistration, PublicKeyCredentialUserVerificationPreference,
};

fn request_type<R: CredentialRequest>(request: &R) -> CredentialRequestType {
    request.request_type()
}

fn credential_id<T: PublicKeyCredential>(credential: &T) -> &[u8] {
    credential.credential_id()
}

fn assertion_signature<T: PublicKeyCredentialAssertion>(credential: &T) -> &[u8] {
    credential.signature()
}

fn registration_attestation<T: PublicKeyCredentialRegistration>(credential: &T) -> Option<&[u8]> {
    credential.raw_attestation_object()
}

#[allow(clippy::too_many_lines)]
#[test]
fn credential_provider_request_and_response_models_are_available() {
    assert_eq!(CoseAlgorithmIdentifier::ES256.0, -7);
    assert_eq!(CoseEllipticCurveIdentifier::P256.0, 1);
    assert!(matches!(
        ExtensionErrorCode::UserInteractionRequired,
        ExtensionErrorCode::UserInteractionRequired
    ));

    let password_identity = PasswordCredentialIdentity {
        service_identifier: CredentialServiceIdentifier::domain("example.com"),
        user: "user@example.com".into(),
        record_identifier: Some("password-record".into()),
        rank: 10,
    };
    assert_eq!(CredentialIdentityRecord::record_identifier(&password_identity), Some("password-record"));

    let one_time_code_identity = OneTimeCodeCredentialIdentity {
        service_identifier: CredentialServiceIdentifier::domain("example.com"),
        label: "Example OTP".into(),
        record_identifier: Some("otp-record".into()),
        rank: 5,
    };
    let one_time_code_credential = OneTimeCodeCredential::new("123456");
    let one_time_code_request = OneTimeCodeCredentialRequest::new(one_time_code_identity);
    assert_eq!(request_type(&one_time_code_request), CredentialRequestType::OneTimeCode);
    assert_eq!(one_time_code_credential.code, "123456");

    let password_request = PasswordCredentialRequest::new(password_identity);
    assert_eq!(request_type(&password_request), CredentialRequestType::Password);

    let passkey_identity = PasskeyCredentialIdentity {
        relying_party_identifier: "example.com".into(),
        user_name: "user@example.com".into(),
        credential_id: b"credential-id".to_vec(),
        user_handle: Some(b"user-handle".to_vec()),
        record_identifier: Some("passkey-record".into()),
        rank: 20,
    };

    let passkey_request_parameters = PasskeyCredentialRequestParameters::new(
        "example.com",
        b"client-data-hash".to_vec(),
        PublicKeyCredentialUserVerificationPreference::Required,
    );
    assert_eq!(passkey_request_parameters.relying_party_identifier, "example.com");

    let registration_input = PasskeyRegistrationCredentialExtensionInput::new(Some(
        LargeBlobRegistrationInput {
            support_requirement: LargeBlobSupportRequirement::Required,
        },
    ));
    let assertion_input = PasskeyAssertionCredentialExtensionInput::new(Some(
        LargeBlobAssertionInput {
            operation: LargeBlobAssertionOperation::Read,
        },
    ));
    let registration_output = PasskeyRegistrationCredentialExtensionOutput::new(Some(
        LargeBlobRegistrationOutput { is_supported: true },
    ));
    let assertion_output = PasskeyAssertionCredentialExtensionOutput::new(Some(
        LargeBlobAssertionOutput {
            result: LargeBlobAssertionOutputResult::Write(true),
        },
    ));

    let descriptor = PlatformCredentialDescriptor::new(b"credential-id".to_vec()).unwrap();
    let assertion_request = PasskeyCredentialRequest::new_assertion_with_extensions(
        passkey_identity.clone(),
        b"client-data-hash".to_vec(),
        PublicKeyCredentialUserVerificationPreference::Preferred,
        Some(assertion_input),
    );
    let registration_request = PasskeyCredentialRequest::new_registration_with_extensions(
        passkey_identity,
        b"client-data-hash".to_vec(),
        PublicKeyCredentialUserVerificationPreference::Required,
        vec![CoseAlgorithmIdentifier::ES256],
        vec![descriptor],
        Some(registration_input),
    );
    assert_eq!(request_type(&assertion_request), CredentialRequestType::PasskeyAssertion);
    assert_eq!(request_type(&registration_request), CredentialRequestType::PasskeyRegistration);

    let assertion_credential = PasskeyAssertionCredential::new(
        b"user-handle".to_vec(),
        "example.com",
        b"signature".to_vec(),
        b"client-data-hash".to_vec(),
        b"authenticator-data".to_vec(),
        b"credential-id".to_vec(),
    )
    .with_extension_output(Some(assertion_output));
    let registration_credential = PasskeyRegistrationCredential::new(
        "example.com",
        b"client-data-hash".to_vec(),
        b"credential-id".to_vec(),
        b"attestation-object".to_vec(),
    )
    .with_extension_output(Some(registration_output));
    assert_eq!(credential_id(&assertion_credential), b"credential-id");
    assert_eq!(assertion_signature(&assertion_credential), b"signature");
    assert_eq!(registration_attestation(&registration_credential), Some(b"attestation-object".as_slice()));

    let mut client_data = PublicKeyCredentialClientData::new(
        b"challenge".to_vec(),
        "https://example.com",
    );
    client_data.top_origin = Some("https://app.example.com".into());
    client_data.cross_origin = PublicKeyCredentialClientDataCrossOriginValue::SameOriginWithAncestors;
    assert_eq!(client_data.origin, "https://example.com");

    let mut context = CredentialProviderExtensionContext::default();
    context.complete_request_with_selected_credential(
        PasswordCredential::new("user@example.com", "secret").unwrap(),
    );
    context.complete_assertion_request_with_selected_passkey_credential(assertion_credential);
    context.complete_registration_request_with_selected_passkey_credential(
        registration_credential,
    );
    context.complete_one_time_code_request_with_selected_credential(one_time_code_credential);
    context.complete_extension_configuration_request();
    assert!(matches!(
        context.last_outcome(),
        Some(CredentialProviderExtensionRequestOutcome::ExtensionConfiguration)
    ));

    let mut view_controller = CredentialProviderViewController::new();
    view_controller.prepare_credential_list_for_service_identifiers(vec![
        CredentialServiceIdentifier::domain("example.com"),
    ]);
    view_controller.prepare_credential_list_for_service_identifiers_with_request_parameters(
        vec![CredentialServiceIdentifier::domain("example.com")],
        passkey_request_parameters,
    );
    view_controller.prepare_one_time_code_credential_list_for_service_identifiers(vec![
        CredentialServiceIdentifier::domain("example.com"),
    ]);
    view_controller.provide_credential_without_user_interaction_for_request(&password_request);
    view_controller.prepare_interface_to_provide_credential_for_request(&assertion_request);
    view_controller.prepare_interface_for_extension_configuration();
    view_controller.prepare_interface_for_passkey_registration(&registration_request);
    view_controller.perform_passkey_registration_without_user_interaction_if_possible(
        &registration_request,
    );
    assert!(matches!(
        view_controller.last_preparation(),
        Some(CredentialProviderPreparation::ConditionalPasskeyRegistration { .. })
    ));
}
