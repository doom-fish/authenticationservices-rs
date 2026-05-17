//! Platform SSO / provider-extension helpers.

use std::collections::BTreeMap;
use std::ops::{BitOr, BitOrAssign};

use serde_json::Value;

use crate::error::AuthenticationServicesError;
use crate::foundation_types::{HttpResponse, QueryItem};

/// JSON-serializable custom claims used by provider-extension request builders.
pub type JsonClaims = BTreeMap<String, Value>;

/// `ASAuthorizationProviderAuthorizationOperation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderExtensionAuthorizationOperation {
    ConfigurationRemoved,
    DirectRequest,
    Other(String),
}

/// `ASAuthorizationProviderExtensionEncryptionAlgorithm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderExtensionEncryptionAlgorithm {
    EcdheA256Gcm,
    HpkeP256Sha256AesGcm256,
    HpkeP384Sha384AesGcm256,
    HpkeCurve25519Sha256ChachaPoly,
    Other(String),
}

/// `ASAuthorizationProviderExtensionSigningAlgorithm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderExtensionSigningAlgorithm {
    Es256,
    Es384,
    Ed25519,
    Other(String),
}

/// `ASAuthorizationProviderExtensionFederationType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderExtensionFederationType {
    None,
    WsTrust,
    DynamicWsTrust,
}

/// `ASAuthorizationProviderExtensionAuthenticationMethod`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderExtensionAuthenticationMethod {
    Password,
    UserSecureEnclaveKey,
    SmartCard,
}

/// `ASAuthorizationProviderExtensionKeyType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProviderExtensionKeyType {
    UserDeviceSigning,
    UserDeviceEncryption,
    UserSecureEnclaveKey,
    SharedDeviceSigning,
    SharedDeviceEncryption,
    CurrentDeviceSigning,
    CurrentDeviceEncryption,
    UserSmartCard,
}

/// `ASAuthorizationProviderExtensionRegistrationResult`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderExtensionRegistrationResult {
    Success,
    Failed,
    UserInterfaceRequired,
    FailedNoRetry,
}

/// `ASAuthorizationProviderExtensionPlatformSSOProtocolVersion`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderExtensionPlatformSsoProtocolVersion {
    V1_0,
    V2_0,
}

/// `ASAuthorizationProviderExtensionUserSecureEnclaveKeyBiometricPolicy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderExtensionUserSecureEnclaveKeyBiometricPolicy(u64);

impl ProviderExtensionUserSecureEnclaveKeyBiometricPolicy {
    pub const NONE: Self = Self(0);
    pub const TOUCH_ID_OR_WATCH_CURRENT_SET: Self = Self(1 << 0);
    pub const TOUCH_ID_OR_WATCH_ANY: Self = Self(1 << 1);
    pub const REUSE_DURING_UNLOCK: Self = Self(1 << 2);
    pub const PASSWORD_FALLBACK: Self = Self(1 << 3);

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for ProviderExtensionUserSecureEnclaveKeyBiometricPolicy {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ProviderExtensionUserSecureEnclaveKeyBiometricPolicy {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// `ASAuthorizationProviderExtensionRequestOptions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderExtensionRequestOptions(u64);

impl ProviderExtensionRequestOptions {
    pub const NONE: Self = Self(0);
    pub const USER_INTERACTION_ENABLED: Self = Self(1 << 0);
    pub const REGISTRATION_REPAIR: Self = Self(1 << 1);
    pub const REGISTRATION_SHARED_DEVICE_KEYS: Self = Self(1 << 2);
    pub const REGISTRATION_DEVICE_KEY_MIGRATION: Self = Self(1 << 3);
    pub const STRONGER_KEY_AVAILABLE: Self = Self(1 << 4);
    pub const USER_KEY_INVALID: Self = Self(1 << 5);
    pub const SETUP_ASSISTANT: Self = Self(1 << 6);

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for ProviderExtensionRequestOptions {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ProviderExtensionRequestOptions {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// `ASAuthorizationProviderExtensionSupportedGrantTypes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProviderExtensionSupportedGrantTypes(u64);

impl ProviderExtensionSupportedGrantTypes {
    pub const NONE: Self = Self(0);
    pub const PASSWORD: Self = Self(1 << 0);
    pub const JWT_BEARER: Self = Self(1 << 1);
    pub const SAML1_1: Self = Self(1 << 2);
    pub const SAML2_0: Self = Self(1 << 3);

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for ProviderExtensionSupportedGrantTypes {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ProviderExtensionSupportedGrantTypes {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// `ASAuthorizationProviderExtensionKerberosMapping`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderExtensionKerberosMapping {
    pub ticket_key_path: Option<String>,
    pub message_buffer_key_name: Option<String>,
    pub realm_key_name: Option<String>,
    pub service_name_key_name: Option<String>,
    pub client_name_key_name: Option<String>,
    pub encryption_key_type_key_name: Option<String>,
    pub session_key_key_name: Option<String>,
}

/// `ASAuthorizationProviderExtensionUserLoginConfiguration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderExtensionUserLoginConfiguration {
    pub login_user_name: String,
    pub custom_assertion_request_header_claims: JsonClaims,
    pub custom_assertion_request_body_claims: JsonClaims,
    pub custom_login_request_header_claims: JsonClaims,
    pub custom_login_request_body_claims: JsonClaims,
}

impl ProviderExtensionUserLoginConfiguration {
    #[must_use]
    pub fn new(login_user_name: impl Into<String>) -> Self {
        Self {
            login_user_name: login_user_name.into(),
            custom_assertion_request_header_claims: BTreeMap::new(),
            custom_assertion_request_body_claims: BTreeMap::new(),
            custom_login_request_header_claims: BTreeMap::new(),
            custom_login_request_body_claims: BTreeMap::new(),
        }
    }

    pub fn set_custom_assertion_request_header_claims(&mut self, claims: JsonClaims) {
        self.custom_assertion_request_header_claims = claims;
    }

    pub fn set_custom_assertion_request_body_claims(&mut self, claims: JsonClaims) {
        self.custom_assertion_request_body_claims = claims;
    }

    pub fn set_custom_login_request_header_claims(&mut self, claims: JsonClaims) {
        self.custom_login_request_header_claims = claims;
    }

    pub fn set_custom_login_request_body_claims(&mut self, claims: JsonClaims) {
        self.custom_login_request_body_claims = claims;
    }
}

/// `ASAuthorizationProviderExtensionLoginConfiguration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderExtensionLoginConfiguration {
    pub invalid_credential_predicate: Option<String>,
    pub account_display_name: Option<String>,
    pub client_id: String,
    pub issuer: String,
    pub audience: Option<String>,
    pub token_endpoint_url: String,
    pub jwks_endpoint_url: String,
    pub jwks_trusted_root_certificates: Vec<Vec<u8>>,
    pub device_context: Option<Vec<u8>>,
    pub user_secure_enclave_key_biometric_policy: ProviderExtensionUserSecureEnclaveKeyBiometricPolicy,
    pub nonce_endpoint_url: Option<String>,
    pub nonce_response_keypath: Option<String>,
    pub server_nonce_claim_name: Option<String>,
    pub custom_nonce_request_values: Vec<QueryItem>,
    pub custom_assertion_request_header_claims: JsonClaims,
    pub custom_assertion_request_body_claims: JsonClaims,
    pub additional_scopes: Option<String>,
    pub additional_authorization_scopes: Option<String>,
    pub include_previous_refresh_token_in_login_request: bool,
    pub previous_refresh_token_claim_name: Option<String>,
    pub custom_request_jwt_parameter_name: Option<String>,
    pub custom_login_request_values: Vec<QueryItem>,
    pub custom_login_request_header_claims: JsonClaims,
    pub custom_login_request_body_claims: JsonClaims,
    pub unique_identifier_claim_name: Option<String>,
    pub group_request_claim_name: Option<String>,
    pub group_response_claim_name: Option<String>,
    pub kerberos_ticket_mappings: Vec<ProviderExtensionKerberosMapping>,
    pub refresh_endpoint_url: Option<String>,
    pub custom_refresh_request_values: Vec<QueryItem>,
    pub custom_refresh_request_header_claims: JsonClaims,
    pub custom_refresh_request_body_claims: JsonClaims,
    pub federation_type: ProviderExtensionFederationType,
    pub federation_request_urn: Option<String>,
    pub federation_mex_url: Option<String>,
    pub federation_user_preauthentication_url: Option<String>,
    pub federation_mex_url_keypath: Option<String>,
    pub federation_predicate: Option<String>,
    pub custom_federation_user_preauthentication_request_values: Vec<QueryItem>,
    pub login_request_encryption_public_key: Option<Vec<u8>>,
    pub login_request_encryption_apv_prefix: Option<Vec<u8>>,
    pub login_request_encryption_algorithm: Option<ProviderExtensionEncryptionAlgorithm>,
    pub login_request_hpke_pre_shared_key: Option<Vec<u8>>,
    pub login_request_hpke_pre_shared_key_id: Option<Vec<u8>>,
    pub key_endpoint_url: Option<String>,
    pub custom_key_exchange_request_values: Vec<QueryItem>,
    pub custom_key_exchange_request_header_claims: JsonClaims,
    pub custom_key_exchange_request_body_claims: JsonClaims,
    pub custom_key_request_values: Vec<QueryItem>,
    pub custom_key_request_header_claims: JsonClaims,
    pub custom_key_request_body_claims: JsonClaims,
    pub hpke_pre_shared_key: Option<Vec<u8>>,
    pub hpke_pre_shared_key_id: Option<Vec<u8>>,
    pub hpke_auth_public_key: Option<Vec<u8>>,
}

impl ProviderExtensionLoginConfiguration {
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        issuer: impl Into<String>,
        token_endpoint_url: impl Into<String>,
        jwks_endpoint_url: impl Into<String>,
        audience: Option<String>,
    ) -> Self {
        Self {
            invalid_credential_predicate: None,
            account_display_name: None,
            client_id: client_id.into(),
            issuer: issuer.into(),
            audience,
            token_endpoint_url: token_endpoint_url.into(),
            jwks_endpoint_url: jwks_endpoint_url.into(),
            jwks_trusted_root_certificates: Vec::new(),
            device_context: None,
            user_secure_enclave_key_biometric_policy:
                ProviderExtensionUserSecureEnclaveKeyBiometricPolicy::NONE,
            nonce_endpoint_url: None,
            nonce_response_keypath: None,
            server_nonce_claim_name: None,
            custom_nonce_request_values: Vec::new(),
            custom_assertion_request_header_claims: BTreeMap::new(),
            custom_assertion_request_body_claims: BTreeMap::new(),
            additional_scopes: None,
            additional_authorization_scopes: None,
            include_previous_refresh_token_in_login_request: false,
            previous_refresh_token_claim_name: None,
            custom_request_jwt_parameter_name: None,
            custom_login_request_values: Vec::new(),
            custom_login_request_header_claims: BTreeMap::new(),
            custom_login_request_body_claims: BTreeMap::new(),
            unique_identifier_claim_name: None,
            group_request_claim_name: None,
            group_response_claim_name: None,
            kerberos_ticket_mappings: Vec::new(),
            refresh_endpoint_url: None,
            custom_refresh_request_values: Vec::new(),
            custom_refresh_request_header_claims: BTreeMap::new(),
            custom_refresh_request_body_claims: BTreeMap::new(),
            federation_type: ProviderExtensionFederationType::None,
            federation_request_urn: None,
            federation_mex_url: None,
            federation_user_preauthentication_url: None,
            federation_mex_url_keypath: None,
            federation_predicate: None,
            custom_federation_user_preauthentication_request_values: Vec::new(),
            login_request_encryption_public_key: None,
            login_request_encryption_apv_prefix: None,
            login_request_encryption_algorithm: None,
            login_request_hpke_pre_shared_key: None,
            login_request_hpke_pre_shared_key_id: None,
            key_endpoint_url: None,
            custom_key_exchange_request_values: Vec::new(),
            custom_key_exchange_request_header_claims: BTreeMap::new(),
            custom_key_exchange_request_body_claims: BTreeMap::new(),
            custom_key_request_values: Vec::new(),
            custom_key_request_header_claims: BTreeMap::new(),
            custom_key_request_body_claims: BTreeMap::new(),
            hpke_pre_shared_key: None,
            hpke_pre_shared_key_id: None,
            hpke_auth_public_key: None,
        }
    }

    pub fn set_custom_assertion_request_header_claims(&mut self, claims: JsonClaims) {
        self.custom_assertion_request_header_claims = claims;
    }

    pub fn set_custom_assertion_request_body_claims(&mut self, claims: JsonClaims) {
        self.custom_assertion_request_body_claims = claims;
    }

    pub fn set_custom_login_request_header_claims(&mut self, claims: JsonClaims) {
        self.custom_login_request_header_claims = claims;
    }

    pub fn set_custom_login_request_body_claims(&mut self, claims: JsonClaims) {
        self.custom_login_request_body_claims = claims;
    }

    pub fn set_custom_refresh_request_header_claims(&mut self, claims: JsonClaims) {
        self.custom_refresh_request_header_claims = claims;
    }

    pub fn set_custom_refresh_request_body_claims(&mut self, claims: JsonClaims) {
        self.custom_refresh_request_body_claims = claims;
    }

    pub fn set_custom_key_exchange_request_header_claims(&mut self, claims: JsonClaims) {
        self.custom_key_exchange_request_header_claims = claims;
    }

    pub fn set_custom_key_exchange_request_body_claims(&mut self, claims: JsonClaims) {
        self.custom_key_exchange_request_body_claims = claims;
    }

    pub fn set_custom_key_request_header_claims(&mut self, claims: JsonClaims) {
        self.custom_key_request_header_claims = claims;
    }

    pub fn set_custom_key_request_body_claims(&mut self, claims: JsonClaims) {
        self.custom_key_request_body_claims = claims;
    }
}

/// `ASAuthorizationProviderExtensionLoginManager`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderExtensionLoginManager {
    pub device_registered: bool,
    pub user_registered: bool,
    pub registration_token: Option<String>,
    pub authentication_method: Option<ProviderExtensionAuthenticationMethod>,
    pub extension_data: BTreeMap<String, String>,
    pub login_user_name: Option<String>,
    pub user_login_configuration: Option<ProviderExtensionUserLoginConfiguration>,
    pub sso_tokens: BTreeMap<String, String>,
    pub login_configuration: Option<ProviderExtensionLoginConfiguration>,
    certificates: BTreeMap<ProviderExtensionKeyType, Vec<u8>>,
    keys: BTreeMap<ProviderExtensionKeyType, Vec<u8>>,
    pending_keys: BTreeMap<ProviderExtensionKeyType, Vec<u8>>,
    pub device_registrations_need_repair: bool,
    pub user_registrations_need_repair: bool,
    pub decryption_keys_need_repair: bool,
}

impl ProviderExtensionLoginManager {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            device_registered: false,
            user_registered: false,
            registration_token: None,
            authentication_method: None,
            extension_data: BTreeMap::new(),
            login_user_name: None,
            user_login_configuration: None,
            sso_tokens: BTreeMap::new(),
            login_configuration: None,
            certificates: BTreeMap::new(),
            keys: BTreeMap::new(),
            pending_keys: BTreeMap::new(),
            device_registrations_need_repair: false,
            user_registrations_need_repair: false,
            decryption_keys_need_repair: false,
        }
    }

    pub fn save_user_login_configuration(
        &mut self,
        user_login_configuration: ProviderExtensionUserLoginConfiguration,
    ) {
        self.login_user_name = Some(user_login_configuration.login_user_name.clone());
        self.user_login_configuration = Some(user_login_configuration);
    }

    pub fn save_login_configuration(
        &mut self,
        login_configuration: ProviderExtensionLoginConfiguration,
    ) {
        self.login_configuration = Some(login_configuration);
    }

    pub fn save_certificate(
        &mut self,
        certificate: Vec<u8>,
        key_type: ProviderExtensionKeyType,
    ) {
        self.certificates.insert(key_type, certificate);
    }

    #[must_use]
    pub fn copy_key(&self, key_type: ProviderExtensionKeyType) -> Option<Vec<u8>> {
        self.keys.get(&key_type).cloned()
    }

    #[must_use]
    pub fn copy_identity(&self, key_type: ProviderExtensionKeyType) -> Option<Vec<u8>> {
        self.certificates.get(&key_type).cloned()
    }

    pub fn set_key(&mut self, key_type: ProviderExtensionKeyType, key: Vec<u8>) {
        self.keys.insert(key_type, key);
    }

    #[must_use]
    pub fn begin_key_rotation(&mut self, key_type: ProviderExtensionKeyType) -> Option<Vec<u8>> {
        let pending_key = self.keys.get(&key_type).cloned().or_else(|| Some(Vec::new()))?;
        self.pending_keys.insert(key_type, pending_key.clone());
        Some(pending_key)
    }

    pub fn complete_key_rotation(&mut self, key_type: ProviderExtensionKeyType) {
        if let Some(key) = self.pending_keys.remove(&key_type) {
            self.keys.insert(key_type, key);
        }
    }

    pub fn user_needs_reauthentication(&mut self) {
        self.user_registered = false;
    }

    pub fn reset_keys(&mut self) {
        self.keys.clear();
        self.pending_keys.clear();
    }

    pub fn reset_device_keys(&mut self) {
        self.keys.retain(|key_type, _| {
            !matches!(
                key_type,
                ProviderExtensionKeyType::UserSecureEnclaveKey | ProviderExtensionKeyType::UserSmartCard
            )
        });
    }

    pub fn reset_user_secure_enclave_key(&mut self) {
        self.keys
            .remove(&ProviderExtensionKeyType::UserSecureEnclaveKey);
    }

    #[must_use]
    pub fn attest_key(
        &self,
        key_type: ProviderExtensionKeyType,
        client_data_hash: &[u8],
    ) -> Option<Vec<Vec<u8>>> {
        self.keys.get(&key_type).map(|key| vec![client_data_hash.to_vec(), key.clone()])
    }

    #[must_use]
    pub fn attest_pending_key(
        &self,
        key_type: ProviderExtensionKeyType,
        client_data_hash: &[u8],
    ) -> Option<Vec<Vec<u8>>> {
        self.pending_keys
            .get(&key_type)
            .map(|key| vec![client_data_hash.to_vec(), key.clone()])
    }

    pub fn present_registration_view_controller(&self) -> Result<(), AuthenticationServicesError> {
        if self.device_registered || self.user_registered {
            Ok(())
        } else {
            Err(AuthenticationServicesError::NotSupported(
                "registration UI is not available until the login manager is registered".into(),
            ))
        }
    }
}

/// `ASAuthorizationProviderExtensionAuthorizationResult`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProviderExtensionAuthorizationResult {
    pub http_authorization_headers: BTreeMap<String, String>,
    pub http_response: Option<HttpResponse>,
    pub http_body: Option<Vec<u8>>,
    pub private_keys: Vec<String>,
}

impl ProviderExtensionAuthorizationResult {
    #[must_use]
    pub const fn from_http_authorization_headers(
        http_authorization_headers: BTreeMap<String, String>,
    ) -> Self {
        Self {
            http_authorization_headers,
            http_response: None,
            http_body: None,
            private_keys: Vec::new(),
        }
    }

    #[must_use]
    pub const fn from_http_response(http_response: HttpResponse, http_body: Option<Vec<u8>>) -> Self {
        Self {
            http_authorization_headers: BTreeMap::new(),
            http_response: Some(http_response),
            http_body,
            private_keys: Vec::new(),
        }
    }
}

/// Final disposition captured by the Rust-side provider-extension authorization-request wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderExtensionAuthorizationOutcome {
    Pending,
    NotHandled,
    Cancelled,
    CompletedWithoutOutput,
    CompletedWithHeaders(BTreeMap<String, String>),
    CompletedWithHttpResponse {
        response: HttpResponse,
        body: Option<Vec<u8>>,
    },
    CompletedWithResult(ProviderExtensionAuthorizationResult),
    Failed(AuthenticationServicesError),
}

/// `ASAuthorizationProviderExtensionAuthorizationRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderExtensionAuthorizationRequest {
    pub url: String,
    pub requested_operation: ProviderExtensionAuthorizationOperation,
    pub http_headers: BTreeMap<String, String>,
    pub http_body: Vec<u8>,
    pub realm: Option<String>,
    pub extension_data: BTreeMap<String, String>,
    pub caller_bundle_identifier: Option<String>,
    pub authorization_options: BTreeMap<String, String>,
    pub caller_managed: bool,
    pub caller_team_identifier: Option<String>,
    pub localized_caller_display_name: Option<String>,
    pub caller_audit_token: Option<Vec<u8>>,
    pub user_interface_enabled: bool,
    pub login_manager: Option<ProviderExtensionLoginManager>,
    outcome: ProviderExtensionAuthorizationOutcome,
}

impl ProviderExtensionAuthorizationRequest {
    #[must_use]
    pub fn new(
        url: impl Into<String>,
        requested_operation: ProviderExtensionAuthorizationOperation,
    ) -> Self {
        Self {
            url: url.into(),
            requested_operation,
            http_headers: BTreeMap::new(),
            http_body: Vec::new(),
            realm: None,
            extension_data: BTreeMap::new(),
            caller_bundle_identifier: None,
            authorization_options: BTreeMap::new(),
            caller_managed: false,
            caller_team_identifier: None,
            localized_caller_display_name: None,
            caller_audit_token: None,
            user_interface_enabled: true,
            login_manager: None,
            outcome: ProviderExtensionAuthorizationOutcome::Pending,
        }
    }

    pub fn do_not_handle(&mut self) {
        self.outcome = ProviderExtensionAuthorizationOutcome::NotHandled;
    }

    pub fn cancel(&mut self) {
        self.outcome = ProviderExtensionAuthorizationOutcome::Cancelled;
    }

    pub fn complete(&mut self) {
        self.outcome = ProviderExtensionAuthorizationOutcome::CompletedWithoutOutput;
    }

    pub fn complete_with_http_authorization_headers(
        &mut self,
        http_authorization_headers: BTreeMap<String, String>,
    ) {
        self.outcome = ProviderExtensionAuthorizationOutcome::CompletedWithHeaders(
            http_authorization_headers,
        );
    }

    pub fn complete_with_http_response(
        &mut self,
        http_response: HttpResponse,
        http_body: Option<Vec<u8>>,
    ) {
        self.outcome = ProviderExtensionAuthorizationOutcome::CompletedWithHttpResponse {
            response: http_response,
            body: http_body,
        };
    }

    pub fn complete_with_authorization_result(
        &mut self,
        authorization_result: ProviderExtensionAuthorizationResult,
    ) {
        self.outcome =
            ProviderExtensionAuthorizationOutcome::CompletedWithResult(authorization_result);
    }

    pub fn complete_with_error(&mut self, error: AuthenticationServicesError) {
        self.outcome = ProviderExtensionAuthorizationOutcome::Failed(error);
    }

    pub fn present_authorization_view_controller(&self) -> Result<(), AuthenticationServicesError> {
        if self.user_interface_enabled {
            Ok(())
        } else {
            Err(AuthenticationServicesError::FrameworkError(
                "authorization UI is disabled for this request".into(),
            ))
        }
    }

    #[must_use]
    pub const fn outcome(&self) -> &ProviderExtensionAuthorizationOutcome {
        &self.outcome
    }
}

/// Rust trait mirroring `ASAuthorizationProviderExtensionAuthorizationRequestHandler`.
pub trait ProviderExtensionAuthorizationRequestHandler {
    fn begin_authorization_with_request(
        &mut self,
        request: &mut ProviderExtensionAuthorizationRequest,
    );

    fn cancel_authorization_with_request(
        &mut self,
        _request: &mut ProviderExtensionAuthorizationRequest,
    ) {
    }
}

/// Rust trait mirroring `ASAuthorizationProviderExtensionRegistrationHandler`.
pub trait ProviderExtensionRegistrationHandler {
    fn begin_device_registration(
        &mut self,
        login_manager: &mut ProviderExtensionLoginManager,
        options: ProviderExtensionRequestOptions,
    ) -> ProviderExtensionRegistrationResult;

    fn begin_user_registration(
        &mut self,
        login_manager: &mut ProviderExtensionLoginManager,
        user_name: Option<&str>,
        authentication_method: ProviderExtensionAuthenticationMethod,
        options: ProviderExtensionRequestOptions,
    ) -> ProviderExtensionRegistrationResult;

    fn registration_did_complete(&mut self) {}

    fn registration_did_cancel(&mut self) {}

    fn supported_grant_types(&self) -> ProviderExtensionSupportedGrantTypes {
        ProviderExtensionSupportedGrantTypes::NONE
    }

    fn protocol_version(&self) -> ProviderExtensionPlatformSsoProtocolVersion {
        ProviderExtensionPlatformSsoProtocolVersion::V1_0
    }

    fn supported_device_signing_algorithms(&self) -> Vec<ProviderExtensionSigningAlgorithm> {
        Vec::new()
    }

    fn supported_device_encryption_algorithms(&self) -> Vec<ProviderExtensionEncryptionAlgorithm> {
        Vec::new()
    }

    fn supported_user_secure_enclave_key_signing_algorithms(
        &self,
    ) -> Vec<ProviderExtensionSigningAlgorithm> {
        Vec::new()
    }

    fn key_will_rotate(
        &mut self,
        _key_type: ProviderExtensionKeyType,
        _new_key: &[u8],
        _login_manager: &mut ProviderExtensionLoginManager,
    ) -> bool {
        true
    }

    fn display_names_for_groups(
        &self,
        groups: &[String],
        _login_manager: &ProviderExtensionLoginManager,
    ) -> BTreeMap<String, String> {
        groups
            .iter()
            .map(|group| (group.clone(), group.clone()))
            .collect()
    }

    fn profile_picture_for_user_using_login_manager(
        &self,
        _login_manager: &ProviderExtensionLoginManager,
    ) -> Option<Vec<u8>> {
        None
    }
}
