//! [`ASAuthorizationProvider`] protocol helpers plus [`PasswordProvider`].

use core::ffi::c_void;
use std::ptr;

use serde::Deserialize;

use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

/// Information about an authorization request.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RequestKind {
    /// The request kind identifier.
    pub kind: String,
    /// For passkey requests: the relying party identifier.
    #[serde(rename = "relyingPartyIdentifier")]
    pub relying_party_identifier: Option<String>,
    /// For passkey requests: challenge bytes encoded as base64.
    pub challenge: Option<String>,
    /// For registration requests: user ID bytes encoded as base64.
    #[serde(rename = "userID")]
    pub user_id: Option<String>,
    /// For registration requests: user name.
    #[serde(rename = "userName")]
    pub user_name: Option<String>,
    /// For registration requests: user display name.
    #[serde(rename = "userDisplayName")]
    pub user_display_name: Option<String>,
}

/// Public authorization-provider kinds that this crate exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationProviderKind {
    AppleId,
    Password,
    PlatformPublicKeyCredential,
    SecurityKeyPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
struct ProviderDescriptorPayload {
    #[serde(rename = "protocolName")]
    _protocol_name: String,
    #[serde(rename = "supportedKinds")]
    supported_kinds: Vec<String>,
}

fn parse_provider_kind(kind: &str) -> Result<AuthorizationProviderKind, AuthenticationServicesError> {
    match kind {
        "apple_id" => Ok(AuthorizationProviderKind::AppleId),
        "password" => Ok(AuthorizationProviderKind::Password),
        "platform_public_key_credential" => Ok(AuthorizationProviderKind::PlatformPublicKeyCredential),
        "security_key_public_key_credential" => {
            Ok(AuthorizationProviderKind::SecurityKeyPublicKeyCredential)
        }
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown authorization provider kind: {other}"
        ))),
    }
}

/// Returns the bridged protocol name (`ASAuthorizationProvider`).
pub fn authorization_provider_protocol_name() -> Result<String, AuthenticationServicesError> {
    let ptr = unsafe { ffi::authservices_authorization_provider_protocol_name() };
    if ptr.is_null() {
        return Err(AuthenticationServicesError::Unknown(
            "authorization_provider_protocol_name returned null".into(),
        ));
    }
    Ok(unsafe { private::take_string(ptr) })
}

/// Returns the concrete provider kinds surfaced by this crate.
pub fn supported_authorization_provider_kinds(
) -> Result<Vec<AuthorizationProviderKind>, AuthenticationServicesError> {
    let ptr = unsafe { ffi::authservices_authorization_provider_supported_kinds_json() };
    if ptr.is_null() {
        return Err(AuthenticationServicesError::Unknown(
            "authorization_provider_supported_kinds_json returned null".into(),
        ));
    }
    let json = unsafe { private::take_string(ptr) };
    let payload: ProviderDescriptorPayload =
        serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
    payload
        .supported_kinds
        .iter()
        .map(|kind| parse_provider_kind(kind))
        .collect()
}

/// Opaque handle to an `ASAuthorizationPasswordRequest`.
#[derive(Debug)]
pub struct PasswordRequest {
    pub(crate) ptr: *mut c_void,
}

unsafe impl Send for PasswordRequest {}
unsafe impl Sync for PasswordRequest {}

impl Drop for PasswordRequest {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ffi::authservices_password_request_release(self.ptr) };
        }
    }
}

impl PasswordRequest {
    /// Returns metadata about this request kind.
    pub fn kind(&self) -> Result<RequestKind, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_password_request_kind_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "password_request_kind_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))
    }

    /// Returns the request's provider kind.
    #[must_use]
    pub const fn provider_kind(&self) -> AuthorizationProviderKind {
        AuthorizationProviderKind::Password
    }
}

/// Builds `ASAuthorizationPasswordRequest`s.
#[derive(Debug, Default, Clone)]
pub struct PasswordProvider;

impl PasswordProvider {
    /// Creates a new provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Create a password/keychain credential request.
    pub fn create_request(&self) -> Result<PasswordRequest, AuthenticationServicesError> {
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe { ffi::authservices_password_provider_create_request(&mut err_ptr) };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "password_provider_create_request returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        Ok(PasswordRequest { ptr: handle })
    }
}
