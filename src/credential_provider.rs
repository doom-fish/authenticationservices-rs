//! Credential-provider extension and passkey-request helpers.

use crate::authorization_passkey::{
    LargeBlobAssertionInput, LargeBlobAssertionOutput, LargeBlobRegistrationInput,
    LargeBlobRegistrationOutput, PlatformCredentialDescriptor,
    PublicKeyCredentialUserVerificationPreference,
};
use crate::authorization_types::{
    AuthorizationCredential, CredentialIdentityRecord, PublicKeyCredential,
    PublicKeyCredentialAssertion, PublicKeyCredentialRegistration,
};
use crate::credential_identity_store::{
    CredentialServiceIdentifier, OneTimeCodeCredentialIdentity, PasskeyCredentialIdentity,
    PasswordCredentialIdentity,
};
use crate::error::AuthenticationServicesError;
use crate::password_credential::PasswordCredential;

/// `ASCOSEAlgorithmIdentifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoseAlgorithmIdentifier(pub i64);

impl CoseAlgorithmIdentifier {
    pub const ES256: Self = Self(-7);
}

/// `ASCOSEEllipticCurveIdentifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoseEllipticCurveIdentifier(pub i64);

impl CoseEllipticCurveIdentifier {
    pub const P256: Self = Self(1);
}

/// `ASCredentialRequestType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRequestType {
    Password,
    PasskeyAssertion,
    PasskeyRegistration,
    OneTimeCode,
}

/// Rust trait mirroring `ASCredentialRequest`.
pub trait CredentialRequest {
    fn request_type(&self) -> CredentialRequestType;

    fn record_identifier(&self) -> Option<&str>;
}

/// `ASExtensionErrorCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionErrorCode {
    Failed,
    UserCanceled,
    UserInteractionRequired,
    CredentialIdentityNotFound,
    MatchedExcludedCredential,
}

/// `ASPublicKeyCredentialClientDataCrossOriginValue`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyCredentialClientDataCrossOriginValue {
    NotSet,
    CrossOrigin,
    SameOriginWithAncestors,
}

/// `ASPublicKeyCredentialClientData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyCredentialClientData {
    pub challenge: Vec<u8>,
    pub origin: String,
    pub top_origin: Option<String>,
    pub cross_origin: PublicKeyCredentialClientDataCrossOriginValue,
}

impl PublicKeyCredentialClientData {
    #[must_use]
    pub fn new(challenge: Vec<u8>, origin: impl Into<String>) -> Self {
        Self {
            challenge,
            origin: origin.into(),
            top_origin: None,
            cross_origin: PublicKeyCredentialClientDataCrossOriginValue::NotSet,
        }
    }
}

/// `ASPasskeyAssertionCredentialExtensionInput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAssertionCredentialExtensionInput {
    pub large_blob: Option<LargeBlobAssertionInput>,
}

impl PasskeyAssertionCredentialExtensionInput {
    #[must_use]
    pub const fn new(large_blob: Option<LargeBlobAssertionInput>) -> Self {
        Self { large_blob }
    }
}

/// `ASPasskeyAssertionCredentialExtensionOutput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAssertionCredentialExtensionOutput {
    pub large_blob: Option<LargeBlobAssertionOutput>,
}

impl PasskeyAssertionCredentialExtensionOutput {
    #[must_use]
    pub const fn new(large_blob: Option<LargeBlobAssertionOutput>) -> Self {
        Self { large_blob }
    }
}

/// `ASPasskeyRegistrationCredentialExtensionInput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRegistrationCredentialExtensionInput {
    pub large_blob: Option<LargeBlobRegistrationInput>,
}

impl PasskeyRegistrationCredentialExtensionInput {
    #[must_use]
    pub const fn new(large_blob: Option<LargeBlobRegistrationInput>) -> Self {
        Self { large_blob }
    }
}

/// `ASPasskeyRegistrationCredentialExtensionOutput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRegistrationCredentialExtensionOutput {
    pub large_blob: Option<LargeBlobRegistrationOutput>,
}

impl PasskeyRegistrationCredentialExtensionOutput {
    #[must_use]
    pub const fn new(large_blob: Option<LargeBlobRegistrationOutput>) -> Self {
        Self { large_blob }
    }
}

/// `ASPasskeyCredentialRequestParameters`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCredentialRequestParameters {
    pub relying_party_identifier: String,
    pub client_data_hash: Vec<u8>,
    pub user_verification_preference: PublicKeyCredentialUserVerificationPreference,
    pub allowed_credentials: Vec<Vec<u8>>,
    pub extension_input: Option<PasskeyAssertionCredentialExtensionInput>,
}

impl PasskeyCredentialRequestParameters {
    #[must_use]
    pub fn new(
        relying_party_identifier: impl Into<String>,
        client_data_hash: Vec<u8>,
        user_verification_preference: PublicKeyCredentialUserVerificationPreference,
    ) -> Self {
        Self {
            relying_party_identifier: relying_party_identifier.into(),
            client_data_hash,
            user_verification_preference,
            allowed_credentials: Vec::new(),
            extension_input: None,
        }
    }
}

/// `ASOneTimeCodeCredential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimeCodeCredential {
    pub code: String,
}

impl OneTimeCodeCredential {
    #[must_use]
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }
}

/// `ASOneTimeCodeCredentialRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimeCodeCredentialRequest {
    pub credential_identity: OneTimeCodeCredentialIdentity,
}

impl OneTimeCodeCredentialRequest {
    #[must_use]
    pub const fn new(credential_identity: OneTimeCodeCredentialIdentity) -> Self {
        Self { credential_identity }
    }
}

/// `ASPasswordCredentialRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordCredentialRequest {
    pub credential_identity: PasswordCredentialIdentity,
}

impl PasswordCredentialRequest {
    #[must_use]
    pub const fn new(credential_identity: PasswordCredentialIdentity) -> Self {
        Self { credential_identity }
    }
}

/// `ASPasskeyCredentialRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyCredentialRequest {
    pub request_type: CredentialRequestType,
    pub credential_identity: PasskeyCredentialIdentity,
    pub client_data_hash: Vec<u8>,
    pub user_verification_preference: PublicKeyCredentialUserVerificationPreference,
    pub supported_algorithms: Vec<CoseAlgorithmIdentifier>,
    pub excluded_credentials: Vec<PlatformCredentialDescriptor>,
    pub assertion_extension_input: Option<PasskeyAssertionCredentialExtensionInput>,
    pub registration_extension_input: Option<PasskeyRegistrationCredentialExtensionInput>,
}

impl PasskeyCredentialRequest {
    #[must_use]
    pub const fn new_assertion(
        credential_identity: PasskeyCredentialIdentity,
        client_data_hash: Vec<u8>,
        user_verification_preference: PublicKeyCredentialUserVerificationPreference,
    ) -> Self {
        Self {
            request_type: CredentialRequestType::PasskeyAssertion,
            credential_identity,
            client_data_hash,
            user_verification_preference,
            supported_algorithms: Vec::new(),
            excluded_credentials: Vec::new(),
            assertion_extension_input: None,
            registration_extension_input: None,
        }
    }

    #[must_use]
    pub fn new_assertion_with_extensions(
        credential_identity: PasskeyCredentialIdentity,
        client_data_hash: Vec<u8>,
        user_verification_preference: PublicKeyCredentialUserVerificationPreference,
        assertion_extension_input: Option<PasskeyAssertionCredentialExtensionInput>,
    ) -> Self {
        let mut request = Self::new_assertion(
            credential_identity,
            client_data_hash,
            user_verification_preference,
        );
        request.assertion_extension_input = assertion_extension_input;
        request
    }

    #[must_use]
    pub const fn new_registration(
        credential_identity: PasskeyCredentialIdentity,
        client_data_hash: Vec<u8>,
        user_verification_preference: PublicKeyCredentialUserVerificationPreference,
        supported_algorithms: Vec<CoseAlgorithmIdentifier>,
    ) -> Self {
        Self {
            request_type: CredentialRequestType::PasskeyRegistration,
            credential_identity,
            client_data_hash,
            user_verification_preference,
            supported_algorithms,
            excluded_credentials: Vec::new(),
            assertion_extension_input: None,
            registration_extension_input: None,
        }
    }

    #[must_use]
    pub fn new_registration_with_extensions(
        credential_identity: PasskeyCredentialIdentity,
        client_data_hash: Vec<u8>,
        user_verification_preference: PublicKeyCredentialUserVerificationPreference,
        supported_algorithms: Vec<CoseAlgorithmIdentifier>,
        excluded_credentials: Vec<PlatformCredentialDescriptor>,
        registration_extension_input: Option<PasskeyRegistrationCredentialExtensionInput>,
    ) -> Self {
        let mut request = Self::new_registration(
            credential_identity,
            client_data_hash,
            user_verification_preference,
            supported_algorithms,
        );
        request.excluded_credentials = excluded_credentials;
        request.registration_extension_input = registration_extension_input;
        request
    }
}

/// `ASPasskeyAssertionCredential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyAssertionCredential {
    pub user_handle: Vec<u8>,
    pub relying_party: String,
    pub signature: Vec<u8>,
    pub client_data_hash: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub extension_output: Option<PasskeyAssertionCredentialExtensionOutput>,
}

impl PasskeyAssertionCredential {
    #[must_use]
    pub fn new(
        user_handle: Vec<u8>,
        relying_party: impl Into<String>,
        signature: Vec<u8>,
        client_data_hash: Vec<u8>,
        authenticator_data: Vec<u8>,
        credential_id: Vec<u8>,
    ) -> Self {
        Self {
            user_handle,
            relying_party: relying_party.into(),
            signature,
            client_data_hash,
            authenticator_data,
            credential_id,
            extension_output: None,
        }
    }

    #[must_use]
    pub fn with_extension_output(
        mut self,
        extension_output: Option<PasskeyAssertionCredentialExtensionOutput>,
    ) -> Self {
        self.extension_output = extension_output;
        self
    }
}

/// `ASPasskeyRegistrationCredential`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRegistrationCredential {
    pub relying_party: String,
    pub client_data_hash: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub extension_output: Option<PasskeyRegistrationCredentialExtensionOutput>,
}

impl PasskeyRegistrationCredential {
    #[must_use]
    pub fn new(
        relying_party: impl Into<String>,
        client_data_hash: Vec<u8>,
        credential_id: Vec<u8>,
        attestation_object: Vec<u8>,
    ) -> Self {
        Self {
            relying_party: relying_party.into(),
            client_data_hash,
            credential_id,
            attestation_object,
            extension_output: None,
        }
    }

    #[must_use]
    pub const fn with_extension_output(
        mut self,
        extension_output: Option<PasskeyRegistrationCredentialExtensionOutput>,
    ) -> Self {
        self.extension_output = extension_output;
        self
    }
}

/// Outcome captured by the Rust-side `ASCredentialProviderExtensionContext` wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialProviderExtensionRequestOutcome {
    Password(PasswordCredential),
    PasskeyAssertion(PasskeyAssertionCredential),
    PasskeyRegistration(PasskeyRegistrationCredential),
    OneTimeCode(OneTimeCodeCredential),
    ExtensionConfiguration,
    Cancelled(String),
}

/// `ASCredentialProviderExtensionContext`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialProviderExtensionContext {
    last_outcome: Option<CredentialProviderExtensionRequestOutcome>,
}

impl CredentialProviderExtensionContext {
    pub fn complete_request_with_selected_credential(
        &mut self,
        credential: PasswordCredential,
    ) {
        self.last_outcome = Some(CredentialProviderExtensionRequestOutcome::Password(credential));
    }

    pub fn complete_assertion_request_with_selected_passkey_credential(
        &mut self,
        credential: PasskeyAssertionCredential,
    ) {
        self.last_outcome = Some(CredentialProviderExtensionRequestOutcome::PasskeyAssertion(
            credential,
        ));
    }

    pub fn complete_registration_request_with_selected_passkey_credential(
        &mut self,
        credential: PasskeyRegistrationCredential,
    ) {
        self.last_outcome = Some(CredentialProviderExtensionRequestOutcome::PasskeyRegistration(
            credential,
        ));
    }

    pub fn complete_one_time_code_request_with_selected_credential(
        &mut self,
        credential: OneTimeCodeCredential,
    ) {
        self.last_outcome = Some(CredentialProviderExtensionRequestOutcome::OneTimeCode(
            credential,
        ));
    }

    pub fn complete_extension_configuration_request(&mut self) {
        self.last_outcome = Some(CredentialProviderExtensionRequestOutcome::ExtensionConfiguration);
    }

    pub fn cancel_request_with_error(&mut self, error: &AuthenticationServicesError) {
        self.last_outcome = Some(CredentialProviderExtensionRequestOutcome::Cancelled(
            error.to_string(),
        ));
    }

    #[must_use]
    pub const fn last_outcome(&self) -> Option<&CredentialProviderExtensionRequestOutcome> {
        self.last_outcome.as_ref()
    }
}

/// UI-preparation state captured by the Rust-side `ASCredentialProviderViewController` wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialProviderPreparation {
    CredentialList {
        service_identifiers: Vec<CredentialServiceIdentifier>,
        request_parameters: Option<PasskeyCredentialRequestParameters>,
    },
    OneTimeCodeCredentialList {
        service_identifiers: Vec<CredentialServiceIdentifier>,
    },
    ProvideWithoutUserInteraction {
        request_type: CredentialRequestType,
        record_identifier: Option<String>,
    },
    ProvideInterface {
        request_type: CredentialRequestType,
        record_identifier: Option<String>,
    },
    ExtensionConfiguration,
    PasskeyRegistration {
        record_identifier: Option<String>,
    },
    ConditionalPasskeyRegistration {
        record_identifier: Option<String>,
    },
}

/// `ASCredentialProviderViewController`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialProviderViewController {
    extension_context: CredentialProviderExtensionContext,
    last_preparation: Option<CredentialProviderPreparation>,
}

impl CredentialProviderViewController {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn extension_context(&self) -> &CredentialProviderExtensionContext {
        &self.extension_context
    }

    pub fn extension_context_mut(&mut self) -> &mut CredentialProviderExtensionContext {
        &mut self.extension_context
    }

    pub fn prepare_credential_list_for_service_identifiers(
        &mut self,
        service_identifiers: Vec<CredentialServiceIdentifier>,
    ) {
        self.last_preparation = Some(CredentialProviderPreparation::CredentialList {
            service_identifiers,
            request_parameters: None,
        });
    }

    pub fn prepare_credential_list_for_service_identifiers_with_request_parameters(
        &mut self,
        service_identifiers: Vec<CredentialServiceIdentifier>,
        request_parameters: PasskeyCredentialRequestParameters,
    ) {
        self.last_preparation = Some(CredentialProviderPreparation::CredentialList {
            service_identifiers,
            request_parameters: Some(request_parameters),
        });
    }

    pub fn prepare_one_time_code_credential_list_for_service_identifiers(
        &mut self,
        service_identifiers: Vec<CredentialServiceIdentifier>,
    ) {
        self.last_preparation = Some(
            CredentialProviderPreparation::OneTimeCodeCredentialList { service_identifiers },
        );
    }

    pub fn provide_credential_without_user_interaction_for_request<R: CredentialRequest>(
        &mut self,
        credential_request: &R,
    ) {
        self.last_preparation = Some(CredentialProviderPreparation::ProvideWithoutUserInteraction {
            request_type: credential_request.request_type(),
            record_identifier: credential_request.record_identifier().map(str::to_owned),
        });
    }

    pub fn prepare_interface_to_provide_credential_for_request<R: CredentialRequest>(
        &mut self,
        credential_request: &R,
    ) {
        self.last_preparation = Some(CredentialProviderPreparation::ProvideInterface {
            request_type: credential_request.request_type(),
            record_identifier: credential_request.record_identifier().map(str::to_owned),
        });
    }

    pub fn prepare_interface_for_extension_configuration(&mut self) {
        self.last_preparation = Some(CredentialProviderPreparation::ExtensionConfiguration);
    }

    pub fn prepare_interface_for_passkey_registration<R: CredentialRequest>(
        &mut self,
        registration_request: &R,
    ) {
        self.last_preparation = Some(CredentialProviderPreparation::PasskeyRegistration {
            record_identifier: registration_request.record_identifier().map(str::to_owned),
        });
    }

    pub fn perform_passkey_registration_without_user_interaction_if_possible(
        &mut self,
        registration_request: &PasskeyCredentialRequest,
    ) {
        self.last_preparation = Some(
            CredentialProviderPreparation::ConditionalPasskeyRegistration {
                record_identifier: registration_request.record_identifier().map(str::to_owned),
            },
        );
    }

    #[must_use]
    pub const fn last_preparation(&self) -> Option<&CredentialProviderPreparation> {
        self.last_preparation.as_ref()
    }
}

impl AuthorizationCredential for OneTimeCodeCredential {
    fn provider_identifier(&self) -> &'static str {
        "one_time_code"
    }
}

impl AuthorizationCredential for PasskeyAssertionCredential {
    fn provider_identifier(&self) -> &'static str {
        "passkey_assertion"
    }
}

impl AuthorizationCredential for PasskeyRegistrationCredential {
    fn provider_identifier(&self) -> &'static str {
        "passkey_registration"
    }
}

impl PublicKeyCredential for PasskeyAssertionCredential {
    fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

impl PublicKeyCredential for PasskeyRegistrationCredential {
    fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

impl PublicKeyCredentialAssertion for PasskeyAssertionCredential {
    fn raw_authenticator_data(&self) -> &[u8] {
        &self.authenticator_data
    }

    fn user_id(&self) -> &[u8] {
        &self.user_handle
    }

    fn signature(&self) -> &[u8] {
        &self.signature
    }
}

impl PublicKeyCredentialRegistration for PasskeyRegistrationCredential {
    fn raw_attestation_object(&self) -> Option<&[u8]> {
        Some(&self.attestation_object)
    }
}

impl CredentialRequest for OneTimeCodeCredentialRequest {
    fn request_type(&self) -> CredentialRequestType {
        CredentialRequestType::OneTimeCode
    }

    fn record_identifier(&self) -> Option<&str> {
        self.credential_identity.record_identifier()
    }
}

impl CredentialRequest for PasswordCredentialRequest {
    fn request_type(&self) -> CredentialRequestType {
        CredentialRequestType::Password
    }

    fn record_identifier(&self) -> Option<&str> {
        self.credential_identity.record_identifier()
    }
}

impl CredentialRequest for PasskeyCredentialRequest {
    fn request_type(&self) -> CredentialRequestType {
        self.request_type
    }

    fn record_identifier(&self) -> Option<&str> {
        self.credential_identity.record_identifier()
    }
}
