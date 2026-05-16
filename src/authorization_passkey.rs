#![allow(
    clippy::derivable_impls,
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::trivially_copy_pass_by_ref
)]

//! Passkey / public-key-credential wrappers.

use core::ffi::c_void;
use std::ffi::CString;
use std::ptr;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::authorization_provider::RequestKind;
use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

/// `ASAuthorizationPublicKeyCredentialAttachment`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyCredentialAttachment {
    Platform,
    CrossPlatform,
}

/// `ASAuthorizationPublicKeyCredentialAttestationKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyCredentialAttestationKind {
    None,
    Direct,
    Indirect,
    Enterprise,
}

/// `ASAuthorizationPublicKeyCredentialResidentKeyPreference`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyCredentialResidentKeyPreference {
    Discouraged,
    Preferred,
    Required,
}

/// `ASAuthorizationPublicKeyCredentialUserVerificationPreference`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicKeyCredentialUserVerificationPreference {
    Discouraged,
    Preferred,
    Required,
}

/// `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest.RequestStyle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformPasskeyRequestStyle {
    Standard,
    Conditional,
}

/// `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityKeyTransport {
    Usb,
    Nfc,
    Bluetooth,
    AllSupported,
}

/// `ASAuthorizationPlatformPublicKeyCredentialDescriptor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCredentialDescriptor {
    pub credential_id: Vec<u8>,
}

/// `ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityKeyCredentialDescriptor {
    pub credential_id: Vec<u8>,
    pub transports: Option<Vec<SecurityKeyTransport>>,
}

/// `ASAuthorizationPublicKeyCredentialParameters`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeyCredentialParameters {
    pub algorithm: i32,
}

/// `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput.SupportRequirement`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LargeBlobSupportRequirement {
    Preferred,
    Required,
}

/// `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LargeBlobRegistrationInput {
    pub support_requirement: LargeBlobSupportRequirement,
}

/// `ASAuthorizationPublicKeyCredentialLargeBlobRegistrationOutput`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LargeBlobRegistrationOutput {
    pub is_supported: bool,
}

/// `ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.Operation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LargeBlobAssertionOperation {
    Read,
    Write(Vec<u8>),
}

/// `ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargeBlobAssertionInput {
    pub operation: LargeBlobAssertionOperation,
}

/// `ASAuthorizationPublicKeyCredentialLargeBlobAssertionOutput.OperationResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LargeBlobAssertionOutputResult {
    Read(Vec<u8>),
    Write(bool),
}

/// `ASAuthorizationPublicKeyCredentialLargeBlobAssertionOutput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LargeBlobAssertionOutput {
    pub result: LargeBlobAssertionOutputResult,
}

/// Shared PRF input salts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfInputValues {
    pub salt_input1: Vec<u8>,
    pub salt_input2: Option<Vec<u8>>,
}

/// `ASAuthorizationPublicKeyCredentialPRFRegistrationInput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfRegistrationInput {
    pub input_values: Option<PrfInputValues>,
    pub should_check_for_support: bool,
}

/// Per-credential PRF assertion salts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfAssertionPerCredentialInput {
    pub credential_id: Vec<u8>,
    pub input_values: PrfInputValues,
}

/// `ASAuthorizationPublicKeyCredentialPRFAssertionInput`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfAssertionInput {
    pub input_values: Option<PrfInputValues>,
    pub per_credential_input_values: Vec<PrfAssertionPerCredentialInput>,
}

/// Shared PRF output shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrfOutput {
    pub first: Option<Vec<u8>>,
    pub second: Option<Vec<u8>>,
    pub is_supported: Option<bool>,
}

/// Full platform-registration request configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformPasskeyRegistrationOptions {
    pub challenge: Option<Vec<u8>>,
    pub client_data: Option<Vec<u8>>,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: Option<String>,
    pub request_style: Option<PlatformPasskeyRequestStyle>,
    pub user_verification_preference: Option<PublicKeyCredentialUserVerificationPreference>,
    pub attestation_preference: Option<PublicKeyCredentialAttestationKind>,
    pub large_blob: Option<LargeBlobRegistrationInput>,
    pub prf: Option<PrfRegistrationInput>,
}

/// Full platform-assertion request configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformPasskeyAssertionOptions {
    pub challenge: Option<Vec<u8>>,
    pub client_data: Option<Vec<u8>>,
    pub allowed_credentials: Vec<PlatformCredentialDescriptor>,
    pub user_verification_preference: Option<PublicKeyCredentialUserVerificationPreference>,
    pub large_blob: Option<LargeBlobAssertionInput>,
    pub prf: Option<PrfAssertionInput>,
}

/// Full security-key registration request configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityKeyRegistrationOptions {
    pub challenge: Option<Vec<u8>>,
    pub client_data: Option<Vec<u8>>,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: Option<String>,
    pub user_verification_preference: Option<PublicKeyCredentialUserVerificationPreference>,
    pub attestation_preference: Option<PublicKeyCredentialAttestationKind>,
    pub excluded_credentials: Vec<SecurityKeyCredentialDescriptor>,
    pub credential_parameters: Vec<PublicKeyCredentialParameters>,
    pub resident_key_preference: Option<PublicKeyCredentialResidentKeyPreference>,
}

/// Full security-key assertion request configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityKeyAssertionOptions {
    pub challenge: Option<Vec<u8>>,
    pub client_data: Option<Vec<u8>>,
    pub allowed_credentials: Vec<SecurityKeyCredentialDescriptor>,
    pub user_verification_preference: Option<PublicKeyCredentialUserVerificationPreference>,
    pub app_id: Option<String>,
}

/// `ASAuthorizationPlatformPublicKeyCredentialRegistration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformPublicKeyCredentialRegistration {
    pub credential_id: Vec<u8>,
    pub raw_attestation_object: Option<Vec<u8>>,
    pub attachment: Option<PublicKeyCredentialAttachment>,
    pub large_blob: Option<LargeBlobRegistrationOutput>,
    pub prf: Option<PrfOutput>,
}

/// `ASAuthorizationPlatformPublicKeyCredentialAssertion`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformPublicKeyCredentialAssertion {
    pub credential_id: Vec<u8>,
    pub raw_authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_id: Vec<u8>,
    pub attachment: Option<PublicKeyCredentialAttachment>,
    pub large_blob: Option<LargeBlobAssertionOutput>,
    pub prf: Option<PrfOutput>,
}

/// `ASAuthorizationSecurityKeyPublicKeyCredentialRegistration`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityKeyPublicKeyCredentialRegistration {
    pub credential_id: Vec<u8>,
    pub raw_attestation_object: Option<Vec<u8>>,
    pub transports: Option<Vec<SecurityKeyTransport>>,
}

/// `ASAuthorizationSecurityKeyPublicKeyCredentialAssertion`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityKeyPublicKeyCredentialAssertion {
    pub credential_id: Vec<u8>,
    pub raw_authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_id: Vec<u8>,
    pub used_app_id: Option<bool>,
}

impl Default for PlatformPasskeyRegistrationOptions {
    fn default() -> Self {
        Self {
            challenge: None,
            client_data: None,
            user_id: Vec::new(),
            user_name: String::new(),
            user_display_name: None,
            request_style: None,
            user_verification_preference: None,
            attestation_preference: None,
            large_blob: None,
            prf: None,
        }
    }
}

impl Default for PlatformPasskeyAssertionOptions {
    fn default() -> Self {
        Self {
            challenge: None,
            client_data: None,
            allowed_credentials: Vec::new(),
            user_verification_preference: None,
            large_blob: None,
            prf: None,
        }
    }
}

impl Default for SecurityKeyRegistrationOptions {
    fn default() -> Self {
        Self {
            challenge: None,
            client_data: None,
            user_id: Vec::new(),
            user_name: String::new(),
            user_display_name: None,
            user_verification_preference: None,
            attestation_preference: None,
            excluded_credentials: Vec::new(),
            credential_parameters: Vec::new(),
            resident_key_preference: None,
        }
    }
}

impl Default for SecurityKeyAssertionOptions {
    fn default() -> Self {
        Self {
            challenge: None,
            client_data: None,
            allowed_credentials: Vec::new(),
            user_verification_preference: None,
            app_id: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PlatformCredentialDescriptorPayload {
    #[serde(rename = "credentialID")]
    credential_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecurityKeyCredentialDescriptorPayload {
    #[serde(rename = "credentialID")]
    credential_id: String,
    transports: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrfInputValuesPayload {
    #[serde(rename = "saltInput1")]
    salt_input1: String,
    #[serde(rename = "saltInput2")]
    salt_input2: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrfAssertionPerCredentialInputPayload {
    #[serde(rename = "credentialID")]
    credential_id: String,
    #[serde(rename = "inputValues")]
    input_values: PrfInputValuesPayload,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrfAssertionInputPayload {
    #[serde(rename = "inputValues")]
    input_values: Option<PrfInputValuesPayload>,
    #[serde(rename = "perCredentialInputValues")]
    per_credential_input_values: Option<Vec<PrfAssertionPerCredentialInputPayload>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LargeBlobRegistrationInputPayload {
    #[serde(rename = "supportRequirement")]
    support_requirement: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LargeBlobAssertionInputPayload {
    operation: String,
    data: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlatformRegistrationRequestPayload {
    #[serde(rename = "relyingPartyIdentifier")]
    relying_party_identifier: String,
    challenge: Option<String>,
    #[serde(rename = "clientData")]
    client_data: Option<String>,
    #[serde(rename = "userID")]
    user_id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "requestStyle")]
    request_style: Option<String>,
    #[serde(rename = "userVerificationPreference")]
    user_verification_preference: Option<String>,
    #[serde(rename = "attestationPreference")]
    attestation_preference: Option<String>,
    #[serde(rename = "largeBlob")]
    large_blob: Option<LargeBlobRegistrationInputPayload>,
    prf: Option<PrfInputValuesPayload>,
    #[serde(rename = "prfShouldCheckForSupport")]
    prf_should_check_for_support: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PlatformAssertionRequestPayload {
    #[serde(rename = "relyingPartyIdentifier")]
    relying_party_identifier: String,
    challenge: Option<String>,
    #[serde(rename = "clientData")]
    client_data: Option<String>,
    #[serde(rename = "allowedCredentials")]
    allowed_credentials: Option<Vec<PlatformCredentialDescriptorPayload>>,
    #[serde(rename = "userVerificationPreference")]
    user_verification_preference: Option<String>,
    #[serde(rename = "largeBlob")]
    large_blob: Option<LargeBlobAssertionInputPayload>,
    prf: Option<PrfAssertionInputPayload>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecurityKeyRegistrationRequestPayload {
    #[serde(rename = "relyingPartyIdentifier")]
    relying_party_identifier: String,
    challenge: Option<String>,
    #[serde(rename = "clientData")]
    client_data: Option<String>,
    #[serde(rename = "userID")]
    user_id: String,
    name: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    #[serde(rename = "userVerificationPreference")]
    user_verification_preference: Option<String>,
    #[serde(rename = "attestationPreference")]
    attestation_preference: Option<String>,
    #[serde(rename = "excludedCredentials")]
    excluded_credentials: Option<Vec<SecurityKeyCredentialDescriptorPayload>>,
    #[serde(rename = "credentialParameters")]
    credential_parameters: Option<Vec<i32>>,
    #[serde(rename = "residentKeyPreference")]
    resident_key_preference: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SecurityKeyAssertionRequestPayload {
    #[serde(rename = "relyingPartyIdentifier")]
    relying_party_identifier: String,
    challenge: Option<String>,
    #[serde(rename = "clientData")]
    client_data: Option<String>,
    #[serde(rename = "allowedCredentials")]
    allowed_credentials: Option<Vec<SecurityKeyCredentialDescriptorPayload>>,
    #[serde(rename = "userVerificationPreference")]
    user_verification_preference: Option<String>,
    #[serde(rename = "appID")]
    app_id: Option<String>,
}

fn encode_bytes(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn decode_bytes(value: &str) -> Result<Vec<u8>, AuthenticationServicesError> {
    STANDARD
        .decode(value)
        .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))
}

fn encode_optional_bytes(bytes: Option<&Vec<u8>>) -> Option<String> {
    bytes.map(|bytes| encode_bytes(bytes))
}

fn decode_optional_bytes(value: Option<String>) -> Result<Option<Vec<u8>>, AuthenticationServicesError> {
    value.map(|value| decode_bytes(&value)).transpose()
}

fn attachment_from_raw(raw: i32) -> Result<PublicKeyCredentialAttachment, AuthenticationServicesError> {
    match raw {
        0 => Ok(PublicKeyCredentialAttachment::Platform),
        1 => Ok(PublicKeyCredentialAttachment::CrossPlatform),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown public-key attachment raw value: {other}"
        ))),
    }
}

fn attestation_to_str(kind: PublicKeyCredentialAttestationKind) -> &'static str {
    match kind {
        PublicKeyCredentialAttestationKind::None => "none",
        PublicKeyCredentialAttestationKind::Direct => "direct",
        PublicKeyCredentialAttestationKind::Indirect => "indirect",
        PublicKeyCredentialAttestationKind::Enterprise => "enterprise",
    }
}

fn parse_attestation(kind: &str) -> Result<PublicKeyCredentialAttestationKind, AuthenticationServicesError> {
    match kind {
        "none" => Ok(PublicKeyCredentialAttestationKind::None),
        "direct" => Ok(PublicKeyCredentialAttestationKind::Direct),
        "indirect" => Ok(PublicKeyCredentialAttestationKind::Indirect),
        "enterprise" => Ok(PublicKeyCredentialAttestationKind::Enterprise),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown attestation preference: {other}"
        ))),
    }
}

fn resident_key_to_str(kind: PublicKeyCredentialResidentKeyPreference) -> &'static str {
    match kind {
        PublicKeyCredentialResidentKeyPreference::Discouraged => "discouraged",
        PublicKeyCredentialResidentKeyPreference::Preferred => "preferred",
        PublicKeyCredentialResidentKeyPreference::Required => "required",
    }
}

fn parse_resident_key(kind: &str) -> Result<PublicKeyCredentialResidentKeyPreference, AuthenticationServicesError> {
    match kind {
        "discouraged" => Ok(PublicKeyCredentialResidentKeyPreference::Discouraged),
        "preferred" => Ok(PublicKeyCredentialResidentKeyPreference::Preferred),
        "required" => Ok(PublicKeyCredentialResidentKeyPreference::Required),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown resident-key preference: {other}"
        ))),
    }
}

fn user_verification_to_str(
    preference: PublicKeyCredentialUserVerificationPreference,
) -> &'static str {
    match preference {
        PublicKeyCredentialUserVerificationPreference::Discouraged => "discouraged",
        PublicKeyCredentialUserVerificationPreference::Preferred => "preferred",
        PublicKeyCredentialUserVerificationPreference::Required => "required",
    }
}

fn parse_user_verification(
    preference: &str,
) -> Result<PublicKeyCredentialUserVerificationPreference, AuthenticationServicesError> {
    match preference {
        "discouraged" => Ok(PublicKeyCredentialUserVerificationPreference::Discouraged),
        "preferred" => Ok(PublicKeyCredentialUserVerificationPreference::Preferred),
        "required" => Ok(PublicKeyCredentialUserVerificationPreference::Required),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown user-verification preference: {other}"
        ))),
    }
}

fn request_style_to_str(style: PlatformPasskeyRequestStyle) -> &'static str {
    match style {
        PlatformPasskeyRequestStyle::Standard => "standard",
        PlatformPasskeyRequestStyle::Conditional => "conditional",
    }
}

fn parse_request_style(style: &str) -> Result<PlatformPasskeyRequestStyle, AuthenticationServicesError> {
    match style {
        "standard" => Ok(PlatformPasskeyRequestStyle::Standard),
        "conditional" => Ok(PlatformPasskeyRequestStyle::Conditional),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown platform request style: {other}"
        ))),
    }
}

fn transport_to_str(transport: SecurityKeyTransport) -> &'static str {
    match transport {
        SecurityKeyTransport::Usb => "usb",
        SecurityKeyTransport::Nfc => "nfc",
        SecurityKeyTransport::Bluetooth => "bluetooth",
        SecurityKeyTransport::AllSupported => "allSupported",
    }
}

fn parse_transport(transport: &str) -> Result<SecurityKeyTransport, AuthenticationServicesError> {
    match transport {
        "usb" => Ok(SecurityKeyTransport::Usb),
        "nfc" => Ok(SecurityKeyTransport::Nfc),
        "bluetooth" => Ok(SecurityKeyTransport::Bluetooth),
        "allSupported" => Ok(SecurityKeyTransport::AllSupported),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown security-key transport: {other}"
        ))),
    }
}

fn large_blob_registration_to_payload(
    input: &LargeBlobRegistrationInput,
) -> LargeBlobRegistrationInputPayload {
    LargeBlobRegistrationInputPayload {
        support_requirement: match input.support_requirement {
            LargeBlobSupportRequirement::Preferred => "preferred".into(),
            LargeBlobSupportRequirement::Required => "required".into(),
        },
    }
}

fn large_blob_registration_from_payload(
    payload: LargeBlobRegistrationInputPayload,
) -> Result<LargeBlobRegistrationInput, AuthenticationServicesError> {
    let support_requirement = match payload.support_requirement.as_str() {
        "preferred" => LargeBlobSupportRequirement::Preferred,
        "required" => LargeBlobSupportRequirement::Required,
        other => {
            return Err(AuthenticationServicesError::Unknown(format!(
                "unknown large-blob support requirement: {other}"
            )))
        }
    };
    Ok(LargeBlobRegistrationInput { support_requirement })
}

fn large_blob_assertion_to_payload(input: &LargeBlobAssertionInput) -> LargeBlobAssertionInputPayload {
    match &input.operation {
        LargeBlobAssertionOperation::Read => LargeBlobAssertionInputPayload {
            operation: "read".into(),
            data: None,
        },
        LargeBlobAssertionOperation::Write(data) => LargeBlobAssertionInputPayload {
            operation: "write".into(),
            data: Some(encode_bytes(data)),
        },
    }
}

fn large_blob_assertion_from_payload(
    payload: LargeBlobAssertionInputPayload,
) -> Result<LargeBlobAssertionInput, AuthenticationServicesError> {
    let operation = match payload.operation.as_str() {
        "read" => LargeBlobAssertionOperation::Read,
        "write" => LargeBlobAssertionOperation::Write(decode_bytes(
            payload.data.as_deref().unwrap_or_default(),
        )?),
        other => {
            return Err(AuthenticationServicesError::Unknown(format!(
                "unknown large-blob assertion operation: {other}"
            )))
        }
    };
    Ok(LargeBlobAssertionInput { operation })
}

fn prf_input_values_to_payload(input: &PrfInputValues) -> PrfInputValuesPayload {
    PrfInputValuesPayload {
        salt_input1: encode_bytes(&input.salt_input1),
        salt_input2: encode_optional_bytes(input.salt_input2.as_ref()),
    }
}

fn prf_input_values_from_payload(
    payload: PrfInputValuesPayload,
) -> Result<PrfInputValues, AuthenticationServicesError> {
    Ok(PrfInputValues {
        salt_input1: decode_bytes(&payload.salt_input1)?,
        salt_input2: decode_optional_bytes(payload.salt_input2)?,
    })
}

fn platform_descriptor_to_payload(
    descriptor: &PlatformCredentialDescriptor,
) -> PlatformCredentialDescriptorPayload {
    PlatformCredentialDescriptorPayload {
        credential_id: encode_bytes(&descriptor.credential_id),
    }
}

fn platform_descriptor_from_payload(
    payload: PlatformCredentialDescriptorPayload,
) -> Result<PlatformCredentialDescriptor, AuthenticationServicesError> {
    Ok(PlatformCredentialDescriptor {
        credential_id: decode_bytes(&payload.credential_id)?,
    })
}

fn security_descriptor_to_payload(
    descriptor: &SecurityKeyCredentialDescriptor,
) -> SecurityKeyCredentialDescriptorPayload {
    SecurityKeyCredentialDescriptorPayload {
        credential_id: encode_bytes(&descriptor.credential_id),
        transports: descriptor
            .transports
            .as_ref()
            .map(|transports| transports.iter().copied().map(transport_to_str).map(str::to_owned).collect()),
    }
}

fn security_descriptor_from_payload(
    payload: SecurityKeyCredentialDescriptorPayload,
) -> Result<SecurityKeyCredentialDescriptor, AuthenticationServicesError> {
    Ok(SecurityKeyCredentialDescriptor {
        credential_id: decode_bytes(&payload.credential_id)?,
        transports: payload
            .transports
            .map(|transports| {
                transports
                    .iter()
                    .map(|transport| parse_transport(transport))
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?,
    })
}

fn platform_registration_options_to_payload(
    relying_party_identifier: &str,
    options: &PlatformPasskeyRegistrationOptions,
) -> PlatformRegistrationRequestPayload {
    PlatformRegistrationRequestPayload {
        relying_party_identifier: relying_party_identifier.to_owned(),
        challenge: options.challenge.as_deref().map(encode_bytes),
        client_data: options.client_data.as_deref().map(encode_bytes),
        user_id: encode_bytes(&options.user_id),
        name: options.user_name.clone(),
        display_name: options.user_display_name.clone(),
        request_style: options.request_style.map(request_style_to_str).map(str::to_owned),
        user_verification_preference: options
            .user_verification_preference
            .map(user_verification_to_str)
            .map(str::to_owned),
        attestation_preference: options
            .attestation_preference
            .map(attestation_to_str)
            .map(str::to_owned),
        large_blob: options.large_blob.as_ref().map(large_blob_registration_to_payload),
        prf: options
            .prf
            .as_ref()
            .and_then(|prf| prf.input_values.as_ref())
            .map(prf_input_values_to_payload),
        prf_should_check_for_support: options.prf.as_ref().map(|prf| prf.should_check_for_support),
    }
}

fn platform_registration_options_from_payload(
    payload: PlatformRegistrationRequestPayload,
) -> Result<(String, PlatformPasskeyRegistrationOptions), AuthenticationServicesError> {
    Ok((
        payload.relying_party_identifier,
        PlatformPasskeyRegistrationOptions {
            challenge: decode_optional_bytes(payload.challenge)?,
            client_data: decode_optional_bytes(payload.client_data)?,
            user_id: decode_bytes(&payload.user_id)?,
            user_name: payload.name,
            user_display_name: payload.display_name,
            request_style: payload.request_style.as_deref().map(parse_request_style).transpose()?,
            user_verification_preference: payload
                .user_verification_preference
                .as_deref()
                .map(parse_user_verification)
                .transpose()?,
            attestation_preference: payload
                .attestation_preference
                .as_deref()
                .map(parse_attestation)
                .transpose()?,
            large_blob: payload.large_blob.map(large_blob_registration_from_payload).transpose()?,
            prf: match (payload.prf, payload.prf_should_check_for_support) {
                (None, None) => None,
                (values, support) => Some(PrfRegistrationInput {
                    input_values: values.map(prf_input_values_from_payload).transpose()?,
                    should_check_for_support: support.unwrap_or(false),
                }),
            },
        },
    ))
}

fn platform_assertion_options_to_payload(
    relying_party_identifier: &str,
    options: &PlatformPasskeyAssertionOptions,
) -> PlatformAssertionRequestPayload {
    PlatformAssertionRequestPayload {
        relying_party_identifier: relying_party_identifier.to_owned(),
        challenge: options.challenge.as_deref().map(encode_bytes),
        client_data: options.client_data.as_deref().map(encode_bytes),
        allowed_credentials: (!options.allowed_credentials.is_empty()).then(|| {
            options
                .allowed_credentials
                .iter()
                .map(platform_descriptor_to_payload)
                .collect()
        }),
        user_verification_preference: options
            .user_verification_preference
            .map(user_verification_to_str)
            .map(str::to_owned),
        large_blob: options.large_blob.as_ref().map(large_blob_assertion_to_payload),
        prf: (!options.prf.as_ref().map_or(true, |prf| {
            prf.input_values.is_none() && prf.per_credential_input_values.is_empty()
        }))
        .then(|| PrfAssertionInputPayload {
            input_values: options
                .prf
                .as_ref()
                .and_then(|prf| prf.input_values.as_ref())
                .map(prf_input_values_to_payload),
            per_credential_input_values: options.prf.as_ref().map(|prf| {
                prf.per_credential_input_values
                    .iter()
                    .map(|entry| PrfAssertionPerCredentialInputPayload {
                        credential_id: encode_bytes(&entry.credential_id),
                        input_values: prf_input_values_to_payload(&entry.input_values),
                    })
                    .collect()
            }),
        }),
    }
}

fn platform_assertion_options_from_payload(
    payload: PlatformAssertionRequestPayload,
) -> Result<(String, PlatformPasskeyAssertionOptions), AuthenticationServicesError> {
    let prf = payload.prf.map(|payload| {
        Ok(PrfAssertionInput {
            input_values: payload.input_values.map(prf_input_values_from_payload).transpose()?,
            per_credential_input_values: payload
                .per_credential_input_values
                .unwrap_or_default()
                .into_iter()
                .map(|entry| {
                    Ok(PrfAssertionPerCredentialInput {
                        credential_id: decode_bytes(&entry.credential_id)?,
                        input_values: prf_input_values_from_payload(entry.input_values)?,
                    })
                })
                .collect::<Result<Vec<_>, AuthenticationServicesError>>()?,
        })
    }).transpose()?;
    Ok((
        payload.relying_party_identifier,
        PlatformPasskeyAssertionOptions {
            challenge: decode_optional_bytes(payload.challenge)?,
            client_data: decode_optional_bytes(payload.client_data)?,
            allowed_credentials: payload
                .allowed_credentials
                .unwrap_or_default()
                .into_iter()
                .map(platform_descriptor_from_payload)
                .collect::<Result<Vec<_>, _>>()?,
            user_verification_preference: payload
                .user_verification_preference
                .as_deref()
                .map(parse_user_verification)
                .transpose()?,
            large_blob: payload.large_blob.map(large_blob_assertion_from_payload).transpose()?,
            prf,
        },
    ))
}

fn security_registration_options_to_payload(
    relying_party_identifier: &str,
    options: &SecurityKeyRegistrationOptions,
) -> SecurityKeyRegistrationRequestPayload {
    SecurityKeyRegistrationRequestPayload {
        relying_party_identifier: relying_party_identifier.to_owned(),
        challenge: options.challenge.as_deref().map(encode_bytes),
        client_data: options.client_data.as_deref().map(encode_bytes),
        user_id: encode_bytes(&options.user_id),
        name: options.user_name.clone(),
        display_name: options.user_display_name.clone(),
        user_verification_preference: options
            .user_verification_preference
            .map(user_verification_to_str)
            .map(str::to_owned),
        attestation_preference: options
            .attestation_preference
            .map(attestation_to_str)
            .map(str::to_owned),
        excluded_credentials: (!options.excluded_credentials.is_empty()).then(|| {
            options
                .excluded_credentials
                .iter()
                .map(security_descriptor_to_payload)
                .collect()
        }),
        credential_parameters: (!options.credential_parameters.is_empty()).then(|| {
            options.credential_parameters.iter().map(|parameter| parameter.algorithm).collect()
        }),
        resident_key_preference: options
            .resident_key_preference
            .map(resident_key_to_str)
            .map(str::to_owned),
    }
}

fn security_registration_options_from_payload(
    payload: SecurityKeyRegistrationRequestPayload,
) -> Result<(String, SecurityKeyRegistrationOptions), AuthenticationServicesError> {
    Ok((
        payload.relying_party_identifier,
        SecurityKeyRegistrationOptions {
            challenge: decode_optional_bytes(payload.challenge)?,
            client_data: decode_optional_bytes(payload.client_data)?,
            user_id: decode_bytes(&payload.user_id)?,
            user_name: payload.name,
            user_display_name: payload.display_name,
            user_verification_preference: payload
                .user_verification_preference
                .as_deref()
                .map(parse_user_verification)
                .transpose()?,
            attestation_preference: payload
                .attestation_preference
                .as_deref()
                .map(parse_attestation)
                .transpose()?,
            excluded_credentials: payload
                .excluded_credentials
                .unwrap_or_default()
                .into_iter()
                .map(security_descriptor_from_payload)
                .collect::<Result<Vec<_>, _>>()?,
            credential_parameters: payload
                .credential_parameters
                .unwrap_or_default()
                .into_iter()
                .map(|algorithm| PublicKeyCredentialParameters { algorithm })
                .collect(),
            resident_key_preference: payload
                .resident_key_preference
                .as_deref()
                .map(parse_resident_key)
                .transpose()?,
        },
    ))
}

fn security_assertion_options_to_payload(
    relying_party_identifier: &str,
    options: &SecurityKeyAssertionOptions,
) -> SecurityKeyAssertionRequestPayload {
    SecurityKeyAssertionRequestPayload {
        relying_party_identifier: relying_party_identifier.to_owned(),
        challenge: options.challenge.as_deref().map(encode_bytes),
        client_data: options.client_data.as_deref().map(encode_bytes),
        allowed_credentials: (!options.allowed_credentials.is_empty()).then(|| {
            options
                .allowed_credentials
                .iter()
                .map(security_descriptor_to_payload)
                .collect()
        }),
        user_verification_preference: options
            .user_verification_preference
            .map(user_verification_to_str)
            .map(str::to_owned),
        app_id: options.app_id.clone(),
    }
}

fn security_assertion_options_from_payload(
    payload: SecurityKeyAssertionRequestPayload,
) -> Result<(String, SecurityKeyAssertionOptions), AuthenticationServicesError> {
    Ok((
        payload.relying_party_identifier,
        SecurityKeyAssertionOptions {
            challenge: decode_optional_bytes(payload.challenge)?,
            client_data: decode_optional_bytes(payload.client_data)?,
            allowed_credentials: payload
                .allowed_credentials
                .unwrap_or_default()
                .into_iter()
                .map(security_descriptor_from_payload)
                .collect::<Result<Vec<_>, _>>()?,
            user_verification_preference: payload
                .user_verification_preference
                .as_deref()
                .map(parse_user_verification)
                .transpose()?,
            app_id: payload.app_id,
        },
    ))
}

fn status_to_result(status: i32, err_ptr: *mut *mut core::ffi::c_char) -> Result<(), AuthenticationServicesError> {
    if status == ffi::status::OK {
        Ok(())
    } else {
        let message = unsafe {
            let err = *err_ptr;
            if err.is_null() {
                format!("AuthenticationServices passkey call failed with status {status}")
            } else {
                private::take_string(err)
            }
        };
        Err(AuthenticationServicesError::from_code(status, message))
    }
}

/// Validate and normalize a platform credential descriptor.
impl PlatformCredentialDescriptor {
    pub fn new(credential_id: impl Into<Vec<u8>>) -> Result<Self, AuthenticationServicesError> {
        let payload = PlatformCredentialDescriptorPayload {
            credential_id: encode_bytes(&credential_id.into()),
        };
        let json = serde_json::to_string(&payload)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_platform_credential_descriptor_create_from_json(json_c.as_ptr(), &mut err_ptr)
        };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "platform_credential_descriptor_create_from_json returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        let json_ptr = unsafe { ffi::authservices_platform_credential_descriptor_copy_json(handle) };
        unsafe { ffi::authservices_platform_credential_descriptor_release(handle) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "platform_credential_descriptor_copy_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payload: PlatformCredentialDescriptorPayload =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        platform_descriptor_from_payload(payload)
    }
}

impl SecurityKeyCredentialDescriptor {
    pub fn new(
        credential_id: impl Into<Vec<u8>>,
        transports: Option<Vec<SecurityKeyTransport>>,
    ) -> Result<Self, AuthenticationServicesError> {
        let payload = SecurityKeyCredentialDescriptorPayload {
            credential_id: encode_bytes(&credential_id.into()),
            transports: transports.as_ref().map(|transports| {
                transports
                    .iter()
                    .copied()
                    .map(transport_to_str)
                    .map(str::to_owned)
                    .collect()
            }),
        };
        let json = serde_json::to_string(&payload)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_security_key_credential_descriptor_create_from_json(
                json_c.as_ptr(),
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "security_key_credential_descriptor_create_from_json returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        let json_ptr = unsafe { ffi::authservices_security_key_credential_descriptor_copy_json(handle) };
        unsafe { ffi::authservices_security_key_credential_descriptor_release(handle) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "security_key_credential_descriptor_copy_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payload: SecurityKeyCredentialDescriptorPayload =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        security_descriptor_from_payload(payload)
    }
}

/// Wraps `ASAuthorizationPlatformPublicKeyCredentialProvider`.
#[derive(Debug, Clone)]
pub struct PlatformPublicKeyCredentialProvider {
    relying_party_identifier: String,
}

impl PlatformPublicKeyCredentialProvider {
    #[must_use]
    pub fn new(relying_party_identifier: impl Into<String>) -> Self {
        Self {
            relying_party_identifier: relying_party_identifier.into(),
        }
    }

    #[must_use]
    pub fn relying_party_identifier(&self) -> &str {
        &self.relying_party_identifier
    }

    pub fn create_registration_request(
        &self,
        challenge: &[u8],
        user_id: &[u8],
        user_name: &str,
        user_display_name: Option<&str>,
    ) -> Result<PasskeyRegistrationRequest, AuthenticationServicesError> {
        let rp_c = CString::new(self.relying_party_identifier.as_str())
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let challenge_c = CString::new(encode_bytes(challenge))
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let user_id_c = CString::new(encode_bytes(user_id))
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let user_name_c = CString::new(user_name)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let display_name_c = user_display_name
            .map(CString::new)
            .transpose()
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let display_name_ptr = display_name_c.as_ref().map_or(ptr::null(), |value| value.as_ptr());
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_passkey_registration_request_create(
                rp_c.as_ptr(),
                challenge_c.as_ptr(),
                user_id_c.as_ptr(),
                user_name_c.as_ptr(),
                display_name_ptr,
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "passkey_registration_request_create returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        Ok(PasskeyRegistrationRequest {
            ptr: handle,
            relying_party_identifier: self.relying_party_identifier.clone(),
        })
    }

    pub fn create_registration_request_with_options(
        &self,
        options: &PlatformPasskeyRegistrationOptions,
    ) -> Result<PasskeyRegistrationRequest, AuthenticationServicesError> {
        let request = self.create_registration_request(
            options.challenge.as_deref().unwrap_or_default(),
            &options.user_id,
            &options.user_name,
            options.user_display_name.as_deref(),
        )?;
        request.update(options)?;
        Ok(request)
    }

    pub fn create_assertion_request(
        &self,
        challenge: &[u8],
    ) -> Result<PasskeyAssertionRequest, AuthenticationServicesError> {
        let rp_c = CString::new(self.relying_party_identifier.as_str())
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let challenge_c = CString::new(encode_bytes(challenge))
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_passkey_assertion_request_create(
                rp_c.as_ptr(),
                challenge_c.as_ptr(),
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "passkey_assertion_request_create returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        Ok(PasskeyAssertionRequest {
            ptr: handle,
            relying_party_identifier: self.relying_party_identifier.clone(),
        })
    }

    pub fn create_assertion_request_with_options(
        &self,
        options: &PlatformPasskeyAssertionOptions,
    ) -> Result<PasskeyAssertionRequest, AuthenticationServicesError> {
        let request = self.create_assertion_request(options.challenge.as_deref().unwrap_or_default())?;
        request.update(options)?;
        Ok(request)
    }
}

/// Wraps `ASAuthorizationSecurityKeyPublicKeyCredentialProvider`.
#[derive(Debug, Clone)]
pub struct SecurityKeyPublicKeyCredentialProvider {
    relying_party_identifier: String,
}

impl SecurityKeyPublicKeyCredentialProvider {
    #[must_use]
    pub fn new(relying_party_identifier: impl Into<String>) -> Self {
        Self {
            relying_party_identifier: relying_party_identifier.into(),
        }
    }

    #[must_use]
    pub fn relying_party_identifier(&self) -> &str {
        &self.relying_party_identifier
    }

    pub fn create_registration_request_with_options(
        &self,
        options: &SecurityKeyRegistrationOptions,
    ) -> Result<SecurityKeyRegistrationRequest, AuthenticationServicesError> {
        let payload = security_registration_options_to_payload(&self.relying_party_identifier, options);
        let json = serde_json::to_string(&payload)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_security_key_registration_request_create_from_json(
                json_c.as_ptr(),
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "security_key_registration_request_create_from_json returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        Ok(SecurityKeyRegistrationRequest {
            ptr: handle,
            relying_party_identifier: self.relying_party_identifier.clone(),
        })
    }

    pub fn create_assertion_request_with_options(
        &self,
        options: &SecurityKeyAssertionOptions,
    ) -> Result<SecurityKeyAssertionRequest, AuthenticationServicesError> {
        let payload = security_assertion_options_to_payload(&self.relying_party_identifier, options);
        let json = serde_json::to_string(&payload)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_security_key_assertion_request_create_from_json(
                json_c.as_ptr(),
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "security_key_assertion_request_create_from_json returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        Ok(SecurityKeyAssertionRequest {
            ptr: handle,
            relying_party_identifier: self.relying_party_identifier.clone(),
        })
    }
}

/// Opaque handle to `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest`.
#[derive(Debug)]
pub struct PasskeyRegistrationRequest {
    pub(crate) ptr: *mut c_void,
    relying_party_identifier: String,
}

unsafe impl Send for PasskeyRegistrationRequest {}
unsafe impl Sync for PasskeyRegistrationRequest {}

impl Drop for PasskeyRegistrationRequest {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ffi::authservices_passkey_registration_request_release(self.ptr) };
        }
    }
}

impl PasskeyRegistrationRequest {
    pub fn kind(&self) -> Result<RequestKind, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_passkey_registration_request_kind_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "passkey_registration_request_kind_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))
    }

    pub fn configuration(&self) -> Result<PlatformPasskeyRegistrationOptions, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_passkey_registration_request_copy_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "passkey_registration_request_copy_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payload: PlatformRegistrationRequestPayload =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let (_, options) = platform_registration_options_from_payload(payload)?;
        Ok(options)
    }

    pub fn update(
        &self,
        options: &PlatformPasskeyRegistrationOptions,
    ) -> Result<(), AuthenticationServicesError> {
        let payload = platform_registration_options_to_payload(&self.relying_party_identifier, options);
        let json = serde_json::to_string(&payload)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_passkey_registration_request_update_from_json(
                self.ptr,
                json_c.as_ptr(),
                &mut err_ptr,
            )
        };
        status_to_result(status, &mut err_ptr)
    }
}

/// Opaque handle to `ASAuthorizationPlatformPublicKeyCredentialAssertionRequest`.
#[derive(Debug)]
pub struct PasskeyAssertionRequest {
    pub(crate) ptr: *mut c_void,
    relying_party_identifier: String,
}

unsafe impl Send for PasskeyAssertionRequest {}
unsafe impl Sync for PasskeyAssertionRequest {}

impl Drop for PasskeyAssertionRequest {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ffi::authservices_passkey_assertion_request_release(self.ptr) };
        }
    }
}

impl PasskeyAssertionRequest {
    pub fn kind(&self) -> Result<RequestKind, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_passkey_assertion_request_kind_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "passkey_assertion_request_kind_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))
    }

    pub fn configuration(&self) -> Result<PlatformPasskeyAssertionOptions, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_passkey_assertion_request_copy_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "passkey_assertion_request_copy_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payload: PlatformAssertionRequestPayload =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let (_, options) = platform_assertion_options_from_payload(payload)?;
        Ok(options)
    }

    pub fn update(
        &self,
        options: &PlatformPasskeyAssertionOptions,
    ) -> Result<(), AuthenticationServicesError> {
        let payload = platform_assertion_options_to_payload(&self.relying_party_identifier, options);
        let json = serde_json::to_string(&payload)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_passkey_assertion_request_update_from_json(
                self.ptr,
                json_c.as_ptr(),
                &mut err_ptr,
            )
        };
        status_to_result(status, &mut err_ptr)
    }
}

/// Opaque handle to `ASAuthorizationSecurityKeyPublicKeyCredentialRegistrationRequest`.
#[derive(Debug)]
pub struct SecurityKeyRegistrationRequest {
    pub(crate) ptr: *mut c_void,
    relying_party_identifier: String,
}

unsafe impl Send for SecurityKeyRegistrationRequest {}
unsafe impl Sync for SecurityKeyRegistrationRequest {}

impl Drop for SecurityKeyRegistrationRequest {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ffi::authservices_security_key_registration_request_release(self.ptr) };
        }
    }
}

impl SecurityKeyRegistrationRequest {
    pub fn configuration(&self) -> Result<SecurityKeyRegistrationOptions, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_security_key_registration_request_copy_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "security_key_registration_request_copy_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payload: SecurityKeyRegistrationRequestPayload =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let (_, options) = security_registration_options_from_payload(payload)?;
        Ok(options)
    }

    pub fn update(
        &self,
        options: &SecurityKeyRegistrationOptions,
    ) -> Result<(), AuthenticationServicesError> {
        let payload = security_registration_options_to_payload(&self.relying_party_identifier, options);
        let json = serde_json::to_string(&payload)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_security_key_registration_request_update_from_json(
                self.ptr,
                json_c.as_ptr(),
                &mut err_ptr,
            )
        };
        status_to_result(status, &mut err_ptr)
    }
}

/// Opaque handle to `ASAuthorizationSecurityKeyPublicKeyCredentialAssertionRequest`.
#[derive(Debug)]
pub struct SecurityKeyAssertionRequest {
    pub(crate) ptr: *mut c_void,
    relying_party_identifier: String,
}

unsafe impl Send for SecurityKeyAssertionRequest {}
unsafe impl Sync for SecurityKeyAssertionRequest {}

impl Drop for SecurityKeyAssertionRequest {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ffi::authservices_security_key_assertion_request_release(self.ptr) };
        }
    }
}

impl SecurityKeyAssertionRequest {
    pub fn configuration(&self) -> Result<SecurityKeyAssertionOptions, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_security_key_assertion_request_copy_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "security_key_assertion_request_copy_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payload: SecurityKeyAssertionRequestPayload =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let (_, options) = security_assertion_options_from_payload(payload)?;
        Ok(options)
    }

    pub fn update(
        &self,
        options: &SecurityKeyAssertionOptions,
    ) -> Result<(), AuthenticationServicesError> {
        let payload = security_assertion_options_to_payload(&self.relying_party_identifier, options);
        let json = serde_json::to_string(&payload)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_security_key_assertion_request_update_from_json(
                self.ptr,
                json_c.as_ptr(),
                &mut err_ptr,
            )
        };
        status_to_result(status, &mut err_ptr)
    }
}

impl PrfOutput {
    pub(crate) fn from_parts(
        first: Option<String>,
        second: Option<String>,
        is_supported: Option<bool>,
    ) -> Result<Option<Self>, AuthenticationServicesError> {
        if first.is_none() && second.is_none() && is_supported.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            first: decode_optional_bytes(first)?,
            second: decode_optional_bytes(second)?,
            is_supported,
        }))
    }
}

impl LargeBlobAssertionOutput {
    pub(crate) fn from_parts(
        kind: Option<String>,
        data: Option<String>,
        success: Option<bool>,
    ) -> Result<Option<Self>, AuthenticationServicesError> {
        match kind.as_deref() {
            None => Ok(None),
            Some("read") => Ok(Some(Self {
                result: LargeBlobAssertionOutputResult::Read(decode_bytes(data.as_deref().unwrap_or_default())?),
            })),
            Some("write") => Ok(Some(Self {
                result: LargeBlobAssertionOutputResult::Write(success.unwrap_or(false)),
            })),
            Some(other) => Err(AuthenticationServicesError::Unknown(format!(
                "unknown large-blob assertion result kind: {other}"
            ))),
        }
    }
}

impl PlatformPublicKeyCredentialRegistration {
    pub(crate) fn from_authorization(
        credential_id: Option<String>,
        raw_attestation_object: Option<String>,
        attachment: Option<i32>,
        large_blob_supported: Option<bool>,
        prf_first: Option<String>,
        prf_second: Option<String>,
        prf_supported: Option<bool>,
    ) -> Result<Option<Self>, AuthenticationServicesError> {
        let Some(credential_id) = credential_id else {
            return Ok(None);
        };
        Ok(Some(Self {
            credential_id: decode_bytes(&credential_id)?,
            raw_attestation_object: decode_optional_bytes(raw_attestation_object)?,
            attachment: attachment.map(attachment_from_raw).transpose()?,
            large_blob: large_blob_supported.map(|is_supported| LargeBlobRegistrationOutput { is_supported }),
            prf: PrfOutput::from_parts(prf_first, prf_second, prf_supported)?,
        }))
    }
}

impl PlatformPublicKeyCredentialAssertion {
    pub(crate) fn from_authorization(
        credential_id: Option<String>,
        raw_authenticator_data: Option<String>,
        signature: Option<String>,
        user_id: Option<String>,
        attachment: Option<i32>,
        large_blob_kind: Option<String>,
        large_blob_data: Option<String>,
        large_blob_write_succeeded: Option<bool>,
        prf_first: Option<String>,
        prf_second: Option<String>,
    ) -> Result<Option<Self>, AuthenticationServicesError> {
        let Some(credential_id) = credential_id else {
            return Ok(None);
        };
        Ok(Some(Self {
            credential_id: decode_bytes(&credential_id)?,
            raw_authenticator_data: decode_bytes(raw_authenticator_data.as_deref().unwrap_or_default())?,
            signature: decode_bytes(signature.as_deref().unwrap_or_default())?,
            user_id: decode_bytes(user_id.as_deref().unwrap_or_default())?,
            attachment: attachment.map(attachment_from_raw).transpose()?,
            large_blob: LargeBlobAssertionOutput::from_parts(
                large_blob_kind,
                large_blob_data,
                large_blob_write_succeeded,
            )?,
            prf: PrfOutput::from_parts(prf_first, prf_second, None)?,
        }))
    }
}

impl SecurityKeyPublicKeyCredentialRegistration {
    pub(crate) fn from_authorization(
        credential_id: Option<String>,
        raw_attestation_object: Option<String>,
        transports: Option<Vec<String>>,
    ) -> Result<Option<Self>, AuthenticationServicesError> {
        let Some(credential_id) = credential_id else {
            return Ok(None);
        };
        Ok(Some(Self {
            credential_id: decode_bytes(&credential_id)?,
            raw_attestation_object: decode_optional_bytes(raw_attestation_object)?,
            transports: transports
                .map(|transports| {
                    transports
                        .iter()
                        .map(|transport| parse_transport(transport))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?,
        }))
    }
}

impl SecurityKeyPublicKeyCredentialAssertion {
    pub(crate) fn from_authorization(
        credential_id: Option<String>,
        raw_authenticator_data: Option<String>,
        signature: Option<String>,
        user_id: Option<String>,
        used_app_id: Option<bool>,
    ) -> Result<Option<Self>, AuthenticationServicesError> {
        let Some(credential_id) = credential_id else {
            return Ok(None);
        };
        Ok(Some(Self {
            credential_id: decode_bytes(&credential_id)?,
            raw_authenticator_data: decode_bytes(raw_authenticator_data.as_deref().unwrap_or_default())?,
            signature: decode_bytes(signature.as_deref().unwrap_or_default())?,
            user_id: decode_bytes(user_id.as_deref().unwrap_or_default())?,
            used_app_id,
        }))
    }
}
