//! [`ASCredentialIdentityStore`] and related identity types.

use std::ops::{BitOr, BitOrAssign};
use std::{ptr};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

/// `ASCredentialServiceIdentifier.IdentifierType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialServiceIdentifierType {
    Domain,
    Url,
    App,
}

/// `ASCredentialServiceIdentifier`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialServiceIdentifier {
    pub identifier: String,
    pub identifier_type: CredentialServiceIdentifierType,
    pub display_name: Option<String>,
}

impl CredentialServiceIdentifier {
    #[must_use]
    pub fn domain(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            identifier_type: CredentialServiceIdentifierType::Domain,
            display_name: None,
        }
    }

    #[must_use]
    pub fn url(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            identifier_type: CredentialServiceIdentifierType::Url,
            display_name: None,
        }
    }

    #[must_use]
    pub fn app(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            identifier_type: CredentialServiceIdentifierType::App,
            display_name: None,
        }
    }
}

/// `ASPasswordCredentialIdentity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordCredentialIdentity {
    pub service_identifier: CredentialServiceIdentifier,
    pub user: String,
    pub record_identifier: Option<String>,
    pub rank: i64,
}

/// `ASPasskeyCredentialIdentity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCredentialIdentity {
    pub relying_party_identifier: String,
    pub user_name: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
    pub record_identifier: Option<String>,
    pub rank: i64,
}

/// `ASOneTimeCodeCredentialIdentity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimeCodeCredentialIdentity {
    pub service_identifier: CredentialServiceIdentifier,
    pub label: String,
    pub record_identifier: Option<String>,
    pub rank: i64,
}

/// A sum type covering the concrete credential identity classes surfaced by the framework.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialIdentity {
    Password(PasswordCredentialIdentity),
    Passkey(PasskeyCredentialIdentity),
    OneTimeCode(OneTimeCodeCredentialIdentity),
}

/// `ASCredentialIdentityStoreState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialIdentityStoreState {
    pub is_enabled: bool,
    pub supports_incremental_updates: bool,
}

/// Bitset wrapper mirroring `ASCredentialIdentityStore.IdentityTypes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CredentialIdentityTypes(u64);

impl CredentialIdentityTypes {
    pub const PASSWORD: Self = Self(1);
    pub const PASSKEY: Self = Self(2);
    pub const ONE_TIME_CODE: Self = Self(4);

    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for CredentialIdentityTypes {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for CredentialIdentityTypes {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CredentialServiceIdentifierPayload {
    identifier: String,
    #[serde(rename = "type")]
    type_name: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CredentialIdentityPayload {
    kind: String,
    #[serde(rename = "serviceIdentifier")]
    service_identifier: Option<CredentialServiceIdentifierPayload>,
    #[serde(rename = "relyingPartyIdentifier")]
    relying_party_identifier: Option<String>,
    user: Option<String>,
    #[serde(rename = "userName")]
    user_name: Option<String>,
    #[serde(rename = "credentialID")]
    credential_id: Option<String>,
    #[serde(rename = "userHandle")]
    user_handle: Option<String>,
    label: Option<String>,
    #[serde(rename = "recordIdentifier")]
    record_identifier: Option<String>,
    rank: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct CredentialIdentityStoreStatePayload {
    #[serde(rename = "isEnabled")]
    is_enabled: bool,
    #[serde(rename = "supportsIncrementalUpdates")]
    supports_incremental_updates: bool,
}

const fn service_identifier_type_to_string(identifier_type: CredentialServiceIdentifierType) -> &'static str {
    match identifier_type {
        CredentialServiceIdentifierType::Domain => "domain",
        CredentialServiceIdentifierType::Url => "url",
        CredentialServiceIdentifierType::App => "app",
    }
}

fn parse_service_identifier_type(
    identifier_type: &str,
) -> Result<CredentialServiceIdentifierType, AuthenticationServicesError> {
    match identifier_type {
        "domain" => Ok(CredentialServiceIdentifierType::Domain),
        "url" => Ok(CredentialServiceIdentifierType::Url),
        "app" => Ok(CredentialServiceIdentifierType::App),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown credential service identifier type: {other}"
        ))),
    }
}

fn service_identifier_to_payload(
    service_identifier: &CredentialServiceIdentifier,
) -> CredentialServiceIdentifierPayload {
    CredentialServiceIdentifierPayload {
        identifier: service_identifier.identifier.clone(),
        type_name: service_identifier_type_to_string(service_identifier.identifier_type).to_owned(),
        display_name: service_identifier.display_name.clone(),
    }
}

fn service_identifier_from_payload(
    payload: CredentialServiceIdentifierPayload,
) -> Result<CredentialServiceIdentifier, AuthenticationServicesError> {
    Ok(CredentialServiceIdentifier {
        identifier: payload.identifier,
        identifier_type: parse_service_identifier_type(&payload.type_name)?,
        display_name: payload.display_name,
    })
}

fn identity_to_payload(identity: &CredentialIdentity) -> CredentialIdentityPayload {
    match identity {
        CredentialIdentity::Password(identity) => CredentialIdentityPayload {
            kind: "password".into(),
            service_identifier: Some(service_identifier_to_payload(&identity.service_identifier)),
            relying_party_identifier: None,
            user: Some(identity.user.clone()),
            user_name: None,
            credential_id: None,
            user_handle: None,
            label: None,
            record_identifier: identity.record_identifier.clone(),
            rank: Some(identity.rank),
        },
        CredentialIdentity::Passkey(identity) => CredentialIdentityPayload {
            kind: "passkey".into(),
            service_identifier: None,
            relying_party_identifier: Some(identity.relying_party_identifier.clone()),
            user: None,
            user_name: Some(identity.user_name.clone()),
            credential_id: Some(STANDARD.encode(&identity.credential_id)),
            user_handle: identity.user_handle.as_ref().map(|user_handle| STANDARD.encode(user_handle)),
            label: None,
            record_identifier: identity.record_identifier.clone(),
            rank: Some(identity.rank),
        },
        CredentialIdentity::OneTimeCode(identity) => CredentialIdentityPayload {
            kind: "one_time_code".into(),
            service_identifier: Some(service_identifier_to_payload(&identity.service_identifier)),
            relying_party_identifier: None,
            user: None,
            user_name: None,
            credential_id: None,
            user_handle: None,
            label: Some(identity.label.clone()),
            record_identifier: identity.record_identifier.clone(),
            rank: Some(identity.rank),
        },
    }
}

fn identity_from_payload(payload: CredentialIdentityPayload) -> Result<CredentialIdentity, AuthenticationServicesError> {
    match payload.kind.as_str() {
        "password" => Ok(CredentialIdentity::Password(PasswordCredentialIdentity {
            service_identifier: service_identifier_from_payload(payload.service_identifier.ok_or_else(|| {
                AuthenticationServicesError::Unknown("password identity missing serviceIdentifier".into())
            })?)?,
            user: payload.user.ok_or_else(|| {
                AuthenticationServicesError::Unknown("password identity missing user".into())
            })?,
            record_identifier: payload.record_identifier,
            rank: payload.rank.unwrap_or_default(),
        })),
        "passkey" => Ok(CredentialIdentity::Passkey(PasskeyCredentialIdentity {
            relying_party_identifier: payload.relying_party_identifier.ok_or_else(|| {
                AuthenticationServicesError::Unknown("passkey identity missing relyingPartyIdentifier".into())
            })?,
            user_name: payload.user_name.ok_or_else(|| {
                AuthenticationServicesError::Unknown("passkey identity missing userName".into())
            })?,
            credential_id: STANDARD.decode(payload.credential_id.ok_or_else(|| {
                AuthenticationServicesError::Unknown("passkey identity missing credentialID".into())
            })?).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?,
            user_handle: payload
                .user_handle
                .map(|user_handle| STANDARD.decode(user_handle).map_err(|error| AuthenticationServicesError::Unknown(error.to_string())))
                .transpose()?,
            record_identifier: payload.record_identifier,
            rank: payload.rank.unwrap_or_default(),
        })),
        "one_time_code" => Ok(CredentialIdentity::OneTimeCode(OneTimeCodeCredentialIdentity {
            service_identifier: service_identifier_from_payload(payload.service_identifier.ok_or_else(|| {
                AuthenticationServicesError::Unknown("one-time-code identity missing serviceIdentifier".into())
            })?)?,
            label: payload.label.ok_or_else(|| {
                AuthenticationServicesError::Unknown("one-time-code identity missing label".into())
            })?,
            record_identifier: payload.record_identifier,
            rank: payload.rank.unwrap_or_default(),
        })),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown credential identity kind: {other}"
        ))),
    }
}

fn status_result(status: i32, err_ptr: *mut *mut core::ffi::c_char) -> Result<(), AuthenticationServicesError> {
    if status == ffi::status::OK {
        Ok(())
    } else {
        let message = unsafe {
            let err = *err_ptr;
            if err.is_null() {
                format!("AuthenticationServices credential identity store call failed with status {status}")
            } else {
                private::take_string(err)
            }
        };
        Err(AuthenticationServicesError::from_code(status, message))
    }
}

/// Static entry point for credential identity store operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct CredentialIdentityStore;

impl CredentialIdentityStore {
    #[must_use]
    pub const fn shared() -> Self {
        Self
    }

    #[must_use]
    pub fn is_supported() -> bool {
        unsafe { ffi::authservices_credential_identity_store_is_supported() != 0 }
    }

    pub fn state(&self) -> Result<CredentialIdentityStoreState, AuthenticationServicesError> {
        let mut err_ptr = ptr::null_mut();
        let json_ptr = unsafe { ffi::authservices_credential_identity_store_state_json(&mut err_ptr) };
        if json_ptr.is_null() {
            let message = if err_ptr.is_null() {
                "credential_identity_store_state_json returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payload: CredentialIdentityStoreStatePayload =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        Ok(CredentialIdentityStoreState {
            is_enabled: payload.is_enabled,
            supports_incremental_updates: payload.supports_incremental_updates,
        })
    }

    pub fn save_identities(
        &self,
        identities: &[CredentialIdentity],
    ) -> Result<(), AuthenticationServicesError> {
        let payloads: Vec<CredentialIdentityPayload> = identities.iter().map(identity_to_payload).collect();
        let json = serde_json::to_string(&payloads)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = std::ffi::CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_credential_identity_store_save_identities_json(json_c.as_ptr(), &mut err_ptr)
        };
        status_result(status, &mut err_ptr)
    }

    pub fn remove_identities(
        &self,
        identities: &[CredentialIdentity],
    ) -> Result<(), AuthenticationServicesError> {
        let payloads: Vec<CredentialIdentityPayload> = identities.iter().map(identity_to_payload).collect();
        let json = serde_json::to_string(&payloads)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = std::ffi::CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_credential_identity_store_remove_identities_json(
                json_c.as_ptr(),
                &mut err_ptr,
            )
        };
        status_result(status, &mut err_ptr)
    }

    pub fn replace_identities(
        &self,
        identities: &[CredentialIdentity],
    ) -> Result<(), AuthenticationServicesError> {
        let payloads: Vec<CredentialIdentityPayload> = identities.iter().map(identity_to_payload).collect();
        let json = serde_json::to_string(&payloads)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = std::ffi::CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_credential_identity_store_replace_identities_json(
                json_c.as_ptr(),
                &mut err_ptr,
            )
        };
        status_result(status, &mut err_ptr)
    }

    pub fn remove_all_identities(&self) -> Result<(), AuthenticationServicesError> {
        let mut err_ptr = ptr::null_mut();
        let status = unsafe { ffi::authservices_credential_identity_store_remove_all(&mut err_ptr) };
        status_result(status, &mut err_ptr)
    }

    pub fn credential_identities_for_service(
        &self,
        service_identifier: &CredentialServiceIdentifier,
        identity_types: CredentialIdentityTypes,
    ) -> Result<Vec<CredentialIdentity>, AuthenticationServicesError> {
        let payload = service_identifier_to_payload(service_identifier);
        let json = serde_json::to_string(&payload)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = std::ffi::CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let json_ptr = unsafe {
            ffi::authservices_credential_identity_store_identities_json(
                json_c.as_ptr(),
                identity_types.bits(),
                &mut err_ptr,
            )
        };
        if json_ptr.is_null() {
            let message = if err_ptr.is_null() {
                "credential_identity_store_identities_json returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payloads: Vec<CredentialIdentityPayload> =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        payloads.into_iter().map(identity_from_payload).collect()
    }
}
