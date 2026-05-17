//! \[`ASAuthorizationAppleIDProvider`\] wrappers.

use core::ffi::c_void;
use std::ffi::CString;
use std::ptr;

use serde::{Deserialize, Serialize};

use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

/// `ASAuthorization.Scope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleIdScope {
    FullName,
    Email,
}

/// `ASAuthorization.OpenIDOperation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleIdOperation {
    Implicit,
    Login,
    Refresh,
    Logout,
}

/// `ASAuthorizationAppleIDProvider.CredentialState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleIdCredentialState {
    Authorized,
    Revoked,
    NotFound,
    Transferred,
}

/// User-configurable properties on `ASAuthorizationAppleIDRequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleIdRequestConfiguration {
    pub requested_scopes: Vec<AppleIdScope>,
    pub user: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub requested_operation: Option<AppleIdOperation>,
}

impl Default for AppleIdRequestConfiguration {
    fn default() -> Self {
        Self {
            requested_scopes: vec![AppleIdScope::FullName, AppleIdScope::Email],
            user: None,
            state: None,
            nonce: None,
            requested_operation: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AppleIdRequestPayload {
    #[serde(rename = "requestedScopes")]
    requested_scopes: Vec<String>,
    user: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    #[serde(rename = "requestedOperation")]
    requested_operation: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AppleIdCredentialStatePayload {
    state: String,
}

const fn scope_to_str(scope: AppleIdScope) -> &'static str {
    match scope {
        AppleIdScope::FullName => "fullName",
        AppleIdScope::Email => "email",
    }
}

fn parse_scope(scope: &str) -> Result<AppleIdScope, AuthenticationServicesError> {
    match scope {
        "fullName" => Ok(AppleIdScope::FullName),
        "email" => Ok(AppleIdScope::Email),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown Apple ID scope: {other}"
        ))),
    }
}

const fn operation_to_str(operation: AppleIdOperation) -> &'static str {
    match operation {
        AppleIdOperation::Implicit => "implicit",
        AppleIdOperation::Login => "login",
        AppleIdOperation::Refresh => "refresh",
        AppleIdOperation::Logout => "logout",
    }
}

fn parse_operation(operation: &str) -> Result<AppleIdOperation, AuthenticationServicesError> {
    match operation {
        "implicit" => Ok(AppleIdOperation::Implicit),
        "login" => Ok(AppleIdOperation::Login),
        "refresh" => Ok(AppleIdOperation::Refresh),
        "logout" => Ok(AppleIdOperation::Logout),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown Apple ID operation: {other}"
        ))),
    }
}

fn parse_credential_state(state: &str) -> Result<AppleIdCredentialState, AuthenticationServicesError> {
    match state {
        "authorized" => Ok(AppleIdCredentialState::Authorized),
        "revoked" => Ok(AppleIdCredentialState::Revoked),
        "not_found" => Ok(AppleIdCredentialState::NotFound),
        "transferred" => Ok(AppleIdCredentialState::Transferred),
        other => Err(AuthenticationServicesError::Unknown(format!(
            "unknown Apple ID credential state: {other}"
        ))),
    }
}

fn configuration_to_payload(configuration: &AppleIdRequestConfiguration) -> AppleIdRequestPayload {
    AppleIdRequestPayload {
        requested_scopes: configuration
            .requested_scopes
            .iter()
            .copied()
            .map(scope_to_str)
            .map(str::to_owned)
            .collect(),
        user: configuration.user.clone(),
        state: configuration.state.clone(),
        nonce: configuration.nonce.clone(),
        requested_operation: configuration.requested_operation.map(operation_to_str).map(str::to_owned),
    }
}

fn configuration_from_payload(
    payload: AppleIdRequestPayload,
) -> Result<AppleIdRequestConfiguration, AuthenticationServicesError> {
    Ok(AppleIdRequestConfiguration {
        requested_scopes: payload
            .requested_scopes
            .iter()
            .map(|scope| parse_scope(scope))
            .collect::<Result<_, _>>()?,
        user: payload.user,
        state: payload.state,
        nonce: payload.nonce,
        requested_operation: payload
            .requested_operation
            .as_deref()
            .map(parse_operation)
            .transpose()?,
    })
}

/// Opaque handle to an `ASAuthorizationAppleIDRequest`.
#[derive(Debug)]
pub struct AppleIdRequest {
    pub(crate) ptr: *mut c_void,
}

unsafe impl Send for AppleIdRequest {}
unsafe impl Sync for AppleIdRequest {}

impl Drop for AppleIdRequest {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { ffi::authservices_apple_id_request_release(self.ptr) };
        }
    }
}

impl AppleIdRequest {
    /// Returns metadata about the request kind.
    pub fn kind(&self) -> Result<crate::authorization_provider::RequestKind, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_apple_id_request_kind_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "apple_id_request_kind_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))
    }

    /// Returns the full mutable request configuration.
    pub fn configuration(&self) -> Result<AppleIdRequestConfiguration, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_apple_id_request_copy_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "apple_id_request_copy_json returned null".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payload: AppleIdRequestPayload =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        configuration_from_payload(payload)
    }

    /// Applies a new configuration to the existing request.
    pub fn update(
        &self,
        configuration: &AppleIdRequestConfiguration,
    ) -> Result<(), AuthenticationServicesError> {
        let payload = configuration_to_payload(configuration);
        let json = serde_json::to_string(&payload)
            .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        let json_c = CString::new(json)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let status = unsafe {
            ffi::authservices_apple_id_request_update_from_json(self.ptr, json_c.as_ptr(), &mut err_ptr)
        };
        if status == ffi::status::OK {
            Ok(())
        } else {
            let message = if err_ptr.is_null() {
                format!("apple_id_request_update_from_json failed with status {status}")
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            Err(AuthenticationServicesError::from_code(status, message))
        }
    }
}

/// Wraps `ASAuthorizationAppleIDProvider`.
#[derive(Debug, Default, Clone)]
pub struct AppleIdProvider;

impl AppleIdProvider {
    /// Creates a new provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Creates a new request asking for the given raw scope strings.
    ///
    /// Pass `None` to use `AuthenticationServices`' common `fullName`+`email` default.
    pub fn create_request(
        &self,
        scopes: Option<&[&str]>,
    ) -> Result<AppleIdRequest, AuthenticationServicesError> {
        let scopes_c = match scopes {
            Some(scopes) => {
                let json = serde_json::to_string(scopes)
                    .map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
                Some(CString::new(json)
                    .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?)
            }
            None => None,
        };
        let scopes_ptr = scopes_c.as_ref().map_or(ptr::null(), |value| value.as_ptr());
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_apple_id_provider_create_request(scopes_ptr, &mut err_ptr)
        };
        if handle.is_null() {
            let message = if err_ptr.is_null() {
                "apple_id_provider_create_request returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        Ok(AppleIdRequest { ptr: handle })
    }

    /// Creates a request and then applies the full request configuration.
    pub fn create_request_with_configuration(
        &self,
        configuration: &AppleIdRequestConfiguration,
    ) -> Result<AppleIdRequest, AuthenticationServicesError> {
        let request = self.create_request(None)?;
        request.update(configuration)?;
        Ok(request)
    }

    /// Queries the credential state for a previously issued Apple ID user identifier.
    pub fn credential_state(
        &self,
        user_identifier: &str,
    ) -> Result<AppleIdCredentialState, AuthenticationServicesError> {
        let user_c = CString::new(user_identifier)
            .map_err(|error| AuthenticationServicesError::InvalidArgument(error.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let json_ptr = unsafe {
            ffi::authservices_apple_id_provider_credential_state_json(user_c.as_ptr(), &mut err_ptr)
        };
        if json_ptr.is_null() {
            let message = if err_ptr.is_null() {
                "apple_id_provider_credential_state_json returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(message));
        }
        let json = unsafe { private::take_string(json_ptr) };
        let payload: AppleIdCredentialStatePayload =
            serde_json::from_str(&json).map_err(|error| AuthenticationServicesError::Unknown(error.to_string()))?;
        parse_credential_state(&payload.state)
    }

    /// Returns the Darwin notification name emitted when Apple ID credentials are revoked.
    pub fn credential_revoked_notification(&self) -> Result<String, AuthenticationServicesError> {
        let ptr = unsafe { ffi::authservices_apple_id_provider_credential_revoked_notification() };
        if ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "apple_id_provider_credential_revoked_notification returned null".into(),
            ));
        }
        Ok(unsafe { private::take_string(ptr) })
    }
}
