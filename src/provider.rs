//! Request-building providers: [`AppleIdProvider`], [`PasswordProvider`], [`PlatformPublicKeyCredentialProvider`].

use core::ffi::c_void;
use std::ffi::CString;
use std::ptr;

use serde::Deserialize;

use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;

/// Information about an authorization request.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestKind {
    /// `"apple_id"`, `"password"`, `"passkey_registration"`, or `"passkey_assertion"`.
    pub kind: String,
    /// For passkey requests: the relying party identifier.
    #[serde(rename = "relyingPartyIdentifier")]
    pub relying_party_identifier: Option<String>,
    /// For passkey requests: challenge bytes (base64).
    pub challenge: Option<String>,
    /// For passkey registration: user ID bytes (base64).
    #[serde(rename = "userID")]
    pub user_id: Option<String>,
    /// For passkey registration: user name.
    #[serde(rename = "userName")]
    pub user_name: Option<String>,
    /// For passkey registration: display name.
    #[serde(rename = "userDisplayName")]
    pub user_display_name: Option<String>,
}

/// Opaque handle to an `ASAuthorizationAppleIDRequest`.
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
    /// Returns metadata about this request kind.
    pub fn kind(&self) -> Result<RequestKind, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_apple_id_request_kind_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "null kind json".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        serde_json::from_str(&json).map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))
    }
}

/// Builds `ASAuthorizationAppleIDRequest`s.
#[derive(Debug, Default, Clone)]
pub struct AppleIdProvider;

impl AppleIdProvider {
    /// Creates a new provider.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Create a request asking for `scopes` (e.g. `["fullName", "email"]`).
    /// Pass `None` to use the default (`[fullName, email]`).
    pub fn create_request(
        &self,
        scopes: Option<&[&str]>,
    ) -> Result<AppleIdRequest, AuthenticationServicesError> {
        let scopes_c = match scopes {
            Some(s) => {
                let json = serde_json::to_string(s)
                    .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?;
                Some(
                    CString::new(json)
                        .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?,
                )
            }
            None => None,
        };
        let scopes_ptr = scopes_c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        let mut err_ptr = ptr::null_mut();
        let handle =
            unsafe { ffi::authservices_apple_id_provider_create_request(scopes_ptr, &mut err_ptr) };
        if handle.is_null() {
            let msg = if err_ptr.is_null() {
                "apple_id_provider_create_request returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(msg));
        }
        Ok(AppleIdRequest { ptr: handle })
    }
}

/// Opaque handle to an `ASAuthorizationPasswordRequest`.
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
                "null kind json".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        serde_json::from_str(&json).map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))
    }
}

/// Builds `ASAuthorizationPasswordRequest`s (keychain credential prompts).
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
            let msg = if err_ptr.is_null() {
                "password_provider_create_request returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(msg));
        }
        Ok(PasswordRequest { ptr: handle })
    }
}

/// Opaque handle to an `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest`.
pub struct PasskeyRegistrationRequest {
    pub(crate) ptr: *mut c_void,
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
    /// Returns metadata about this request kind.
    pub fn kind(&self) -> Result<RequestKind, AuthenticationServicesError> {
        let json_ptr =
            unsafe { ffi::authservices_passkey_registration_request_kind_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "null kind json".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        serde_json::from_str(&json).map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))
    }
}

/// Opaque handle to an `ASAuthorizationPlatformPublicKeyCredentialAssertionRequest`.
pub struct PasskeyAssertionRequest {
    pub(crate) ptr: *mut c_void,
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
    /// Returns metadata about this request kind.
    pub fn kind(&self) -> Result<RequestKind, AuthenticationServicesError> {
        let json_ptr = unsafe { ffi::authservices_passkey_assertion_request_kind_json(self.ptr) };
        if json_ptr.is_null() {
            return Err(AuthenticationServicesError::Unknown(
                "null kind json".into(),
            ));
        }
        let json = unsafe { private::take_string(json_ptr) };
        serde_json::from_str(&json).map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))
    }
}

/// Builds passkey registration and assertion requests via
/// `ASAuthorizationPlatformPublicKeyCredentialProvider`.
#[derive(Debug, Clone)]
pub struct PlatformPublicKeyCredentialProvider {
    relying_party_identifier: String,
}

impl PlatformPublicKeyCredentialProvider {
    /// Create a provider for the given relying-party identifier (e.g. `"example.com"`).
    #[must_use]
    pub fn new(relying_party_identifier: impl Into<String>) -> Self {
        Self {
            relying_party_identifier: relying_party_identifier.into(),
        }
    }

    /// Create a passkey registration request.
    pub fn create_registration_request(
        &self,
        challenge: &[u8],
        user_id: &[u8],
        user_name: &str,
        user_display_name: Option<&str>,
    ) -> Result<PasskeyRegistrationRequest, AuthenticationServicesError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let rp_c = CString::new(self.relying_party_identifier.as_str())
            .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?;
        let challenge_b64 = STANDARD.encode(challenge);
        let user_id_b64 = STANDARD.encode(user_id);
        let challenge_c = CString::new(challenge_b64)
            .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?;
        let user_id_c = CString::new(user_id_b64)
            .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?;
        let user_name_c = CString::new(user_name)
            .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?;
        let display_c = user_display_name
            .map(CString::new)
            .transpose()
            .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?;
        let display_ptr = display_c.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_passkey_registration_request_create(
                rp_c.as_ptr(),
                challenge_c.as_ptr(),
                user_id_c.as_ptr(),
                user_name_c.as_ptr(),
                display_ptr,
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let msg = if err_ptr.is_null() {
                "passkey_registration_request_create returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(msg));
        }
        Ok(PasskeyRegistrationRequest { ptr: handle })
    }

    /// Create a passkey assertion request.
    pub fn create_assertion_request(
        &self,
        challenge: &[u8],
    ) -> Result<PasskeyAssertionRequest, AuthenticationServicesError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let rp_c = CString::new(self.relying_party_identifier.as_str())
            .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?;
        let challenge_b64 = STANDARD.encode(challenge);
        let challenge_c = CString::new(challenge_b64)
            .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()))?;
        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_passkey_assertion_request_create(
                rp_c.as_ptr(),
                challenge_c.as_ptr(),
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let msg = if err_ptr.is_null() {
                "passkey_assertion_request_create returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(msg));
        }
        Ok(PasskeyAssertionRequest { ptr: handle })
    }
}
