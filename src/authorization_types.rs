//! Shared authorization traits and aliases.

use serde::{Deserialize, Serialize};

use crate::authorization_apple_id_provider::{AppleIdOperation, AppleIdRequest, AppleIdRequestConfiguration};
use crate::authorization_controller::{AppleIdCredential, Authorization};
use crate::authorization_passkey::{
    PasskeyAssertionRequest, PasskeyRegistrationRequest, PlatformCredentialDescriptor,
    PlatformPublicKeyCredentialAssertion, PlatformPublicKeyCredentialRegistration,
    SecurityKeyAssertionRequest, SecurityKeyCredentialDescriptor,
    SecurityKeyPublicKeyCredentialAssertion, SecurityKeyPublicKeyCredentialRegistration,
    SecurityKeyRegistrationRequest,
};
use crate::authorization_provider::PasswordRequest;
use crate::credential_identity_store::{
    OneTimeCodeCredentialIdentity, PasskeyCredentialIdentity, PasswordCredentialIdentity,
};
use crate::foundation_types::PresentationAnchor;
use crate::password_credential::PasswordCredential;

/// `ASUserDetectionStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserDetectionStatus {
    #[serde(rename = "unsupported")]
    Unsupported,
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "likely_real")]
    LikelyReal,
}

/// `ASUserAgeRange`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserAgeRange {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "child")]
    Child,
    #[serde(rename = "not_child")]
    NotChild,
}

/// Public alias for `ASAuthorizationOpenIDRequest`.
pub type OpenIdRequest = AppleIdRequest;

/// Public alias for `ASAuthorizationOpenIDRequest` configuration.
pub type OpenIdRequestConfiguration = AppleIdRequestConfiguration;

/// Public alias for `ASAuthorizationOpenIDOperation`.
pub type OpenIdOperation = AppleIdOperation;

/// Rust trait mirroring `ASAuthorizationControllerDelegate`.
pub trait AuthorizationControllerDelegate {
    fn did_complete_with_authorization(&mut self, authorization: &Authorization);

    fn did_complete_with_error(&mut self, message: &str);
}

/// Rust trait mirroring `ASAuthorizationControllerPresentationContextProviding`.
pub trait AuthorizationControllerPresentationContextProviding {
    fn presentation_anchor_for_authorization_controller(&self) -> PresentationAnchor;
}

/// Rust trait mirroring `ASAuthorizationCredential`.
pub trait AuthorizationCredential {
    fn provider_identifier(&self) -> &'static str;
}

/// Rust trait mirroring `ASAuthorizationRequest`.
pub trait AuthorizationRequest {
    fn provider_identifier(&self) -> &'static str;
}

/// Rust trait mirroring `ASPublicKeyCredential`.
pub trait PublicKeyCredential: AuthorizationCredential {
    fn credential_id(&self) -> &[u8];

    fn raw_client_data_json(&self) -> Option<&[u8]> {
        None
    }
}

/// Rust trait mirroring `ASAuthorizationPublicKeyCredentialAssertion`.
pub trait PublicKeyCredentialAssertion: PublicKeyCredential {
    fn raw_authenticator_data(&self) -> &[u8];

    fn user_id(&self) -> &[u8];

    fn signature(&self) -> &[u8];
}

/// Rust trait mirroring `ASAuthorizationPublicKeyCredentialRegistration`.
pub trait PublicKeyCredentialRegistration: PublicKeyCredential {
    fn raw_attestation_object(&self) -> Option<&[u8]>;
}

/// Rust trait mirroring `ASAuthorizationPublicKeyCredentialDescriptor`.
pub trait PublicKeyCredentialDescriptor {
    fn credential_id(&self) -> &[u8];
}

/// Rust trait mirroring `ASAuthorizationPublicKeyCredentialAssertionRequest`.
pub trait PublicKeyCredentialAssertionRequest: AuthorizationRequest {}

/// Rust trait mirroring `ASAuthorizationPublicKeyCredentialRegistrationRequest`.
pub trait PublicKeyCredentialRegistrationRequest: AuthorizationRequest {}

/// Rust trait mirroring `ASCredentialIdentity`.
pub trait CredentialIdentityRecord {
    fn record_identifier(&self) -> Option<&str>;

    fn rank(&self) -> i64;
}

impl AuthorizationCredential for Authorization {
    fn provider_identifier(&self) -> &'static str {
        "authorization"
    }
}

impl AuthorizationCredential for AppleIdCredential {
    fn provider_identifier(&self) -> &'static str {
        "apple_id"
    }
}

impl AuthorizationCredential for PasswordCredential {
    fn provider_identifier(&self) -> &'static str {
        "password"
    }
}

impl AuthorizationCredential for PlatformPublicKeyCredentialRegistration {
    fn provider_identifier(&self) -> &'static str {
        "platform_public_key_credential_registration"
    }
}

impl AuthorizationCredential for PlatformPublicKeyCredentialAssertion {
    fn provider_identifier(&self) -> &'static str {
        "platform_public_key_credential_assertion"
    }
}

impl AuthorizationCredential for SecurityKeyPublicKeyCredentialRegistration {
    fn provider_identifier(&self) -> &'static str {
        "security_key_public_key_credential_registration"
    }
}

impl AuthorizationCredential for SecurityKeyPublicKeyCredentialAssertion {
    fn provider_identifier(&self) -> &'static str {
        "security_key_public_key_credential_assertion"
    }
}

impl AuthorizationRequest for AppleIdRequest {
    fn provider_identifier(&self) -> &'static str {
        "apple_id"
    }
}

impl AuthorizationRequest for PasswordRequest {
    fn provider_identifier(&self) -> &'static str {
        "password"
    }
}

impl AuthorizationRequest for PasskeyRegistrationRequest {
    fn provider_identifier(&self) -> &'static str {
        "platform_public_key_credential_registration"
    }
}

impl AuthorizationRequest for PasskeyAssertionRequest {
    fn provider_identifier(&self) -> &'static str {
        "platform_public_key_credential_assertion"
    }
}

impl AuthorizationRequest for SecurityKeyRegistrationRequest {
    fn provider_identifier(&self) -> &'static str {
        "security_key_public_key_credential_registration"
    }
}

impl AuthorizationRequest for SecurityKeyAssertionRequest {
    fn provider_identifier(&self) -> &'static str {
        "security_key_public_key_credential_assertion"
    }
}

impl PublicKeyCredential for PlatformPublicKeyCredentialRegistration {
    fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

impl PublicKeyCredential for PlatformPublicKeyCredentialAssertion {
    fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

impl PublicKeyCredential for SecurityKeyPublicKeyCredentialRegistration {
    fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

impl PublicKeyCredential for SecurityKeyPublicKeyCredentialAssertion {
    fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

impl PublicKeyCredentialAssertion for PlatformPublicKeyCredentialAssertion {
    fn raw_authenticator_data(&self) -> &[u8] {
        &self.raw_authenticator_data
    }

    fn user_id(&self) -> &[u8] {
        &self.user_id
    }

    fn signature(&self) -> &[u8] {
        &self.signature
    }
}

impl PublicKeyCredentialAssertion for SecurityKeyPublicKeyCredentialAssertion {
    fn raw_authenticator_data(&self) -> &[u8] {
        &self.raw_authenticator_data
    }

    fn user_id(&self) -> &[u8] {
        &self.user_id
    }

    fn signature(&self) -> &[u8] {
        &self.signature
    }
}

impl PublicKeyCredentialRegistration for PlatformPublicKeyCredentialRegistration {
    fn raw_attestation_object(&self) -> Option<&[u8]> {
        self.raw_attestation_object.as_deref()
    }
}

impl PublicKeyCredentialRegistration for SecurityKeyPublicKeyCredentialRegistration {
    fn raw_attestation_object(&self) -> Option<&[u8]> {
        self.raw_attestation_object.as_deref()
    }
}

impl PublicKeyCredentialDescriptor for PlatformCredentialDescriptor {
    fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

impl PublicKeyCredentialDescriptor for SecurityKeyCredentialDescriptor {
    fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
}

impl PublicKeyCredentialAssertionRequest for PasskeyAssertionRequest {}
impl PublicKeyCredentialAssertionRequest for SecurityKeyAssertionRequest {}
impl PublicKeyCredentialRegistrationRequest for PasskeyRegistrationRequest {}
impl PublicKeyCredentialRegistrationRequest for SecurityKeyRegistrationRequest {}

impl CredentialIdentityRecord for PasswordCredentialIdentity {
    fn record_identifier(&self) -> Option<&str> {
        self.record_identifier.as_deref()
    }

    fn rank(&self) -> i64 {
        self.rank
    }
}

impl CredentialIdentityRecord for PasskeyCredentialIdentity {
    fn record_identifier(&self) -> Option<&str> {
        self.record_identifier.as_deref()
    }

    fn rank(&self) -> i64 {
        self.rank
    }
}

impl CredentialIdentityRecord for OneTimeCodeCredentialIdentity {
    fn record_identifier(&self) -> Option<&str> {
        self.record_identifier.as_deref()
    }

    fn rank(&self) -> i64 {
        self.rank
    }
}
