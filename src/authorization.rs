//! [`Authorization`], [`AppleIdCredential`], and [`AuthorizationController`].

use core::ffi::c_void;
use std::ptr;
use std::sync::{Arc, Mutex};

use serde::Deserialize;

use crate::error::AuthenticationServicesError;
use crate::ffi;
use crate::private;
use crate::provider::{
    AppleIdRequest, PasskeyAssertionRequest, PasskeyRegistrationRequest, PasswordRequest,
};

/// Decoded Apple ID credential.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleIdCredential {
    /// The stable user identifier.
    #[serde(rename = "userIdentifier")]
    pub user_identifier: Option<String>,
    /// The user's email address (only on first authorization).
    pub email: Option<String>,
    /// The user's full name (only on first authorization).
    #[serde(rename = "fullName")]
    pub full_name: Option<String>,
    /// Raw identity token bytes encoded as base64.
    #[serde(rename = "identityToken")]
    pub identity_token: Option<String>,
    /// Raw authorization code bytes encoded as base64.
    #[serde(rename = "authorizationCode")]
    pub authorization_code: Option<String>,
}

/// Generic authorization result from any provider.
#[derive(Debug, Clone, Deserialize)]
pub struct Authorization {
    /// Which provider produced this credential.
    pub provider: String,
    /// Apple ID credential fields (present when `provider == "apple_id"`).
    #[serde(rename = "userIdentifier")]
    pub user_identifier: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "fullName")]
    pub full_name: Option<String>,
    #[serde(rename = "identityToken")]
    pub identity_token: Option<String>,
    #[serde(rename = "authorizationCode")]
    pub authorization_code: Option<String>,
    /// Passkey credential ID, base64.
    #[serde(rename = "credentialID")]
    pub credential_id: Option<String>,
    /// Passkey registration attestation object, base64.
    #[serde(rename = "rawAttestationObject")]
    pub raw_attestation_object: Option<String>,
    /// Passkey assertion authenticator data, base64.
    #[serde(rename = "rawAuthenticatorData")]
    pub raw_authenticator_data: Option<String>,
    /// Passkey assertion signature, base64.
    pub signature: Option<String>,
}

impl Authorization {
    /// Convenience: extract the Apple ID credential if this is an `"apple_id"` authorization.
    #[must_use]
    pub fn apple_id_credential(&self) -> Option<AppleIdCredential> {
        if self.provider == "apple_id" {
            Some(AppleIdCredential {
                user_identifier: self.user_identifier.clone(),
                email: self.email.clone(),
                full_name: self.full_name.clone(),
                identity_token: self.identity_token.clone(),
                authorization_code: self.authorization_code.clone(),
            })
        } else {
            None
        }
    }
}

struct CallbackState {
    result: Option<Result<Authorization, AuthenticationServicesError>>,
}

/// Guard that keeps the `AuthorizationController` alive and receives its result.
pub struct AuthorizationGuard {
    handle: *mut c_void,
    state: Arc<Mutex<CallbackState>>,
}

unsafe impl Send for AuthorizationGuard {}

impl Drop for AuthorizationGuard {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { ffi::authservices_authorization_controller_release(self.handle) };
        }
    }
}

impl AuthorizationGuard {
    /// Instruct the controller to perform its authorization requests.
    pub fn perform_requests(&self) {
        unsafe { ffi::authservices_authorization_controller_perform_requests(self.handle) };
    }

    /// Take the result if the asynchronous callback has already delivered one.
    #[must_use]
    pub fn take_result(&self) -> Option<Result<Authorization, AuthenticationServicesError>> {
        self.state.lock().ok()?.result.take()
    }
}

unsafe extern "C" fn on_success_trampoline(refcon: *mut c_void, json: *mut core::ffi::c_char) {
    let state = &*(refcon as *const Mutex<CallbackState>);
    let json_str = private::take_string(json);
    let result = serde_json::from_str(&json_str)
        .map_err(|e| AuthenticationServicesError::Unknown(e.to_string()));
    if let Ok(mut guard) = state.lock() {
        guard.result = Some(result);
    }
}

unsafe extern "C" fn on_error_trampoline(
    refcon: *mut c_void,
    code: i32,
    msg: *mut core::ffi::c_char,
) {
    let state = &*(refcon as *const Mutex<CallbackState>);
    let message = private::take_string(msg);
    let err = AuthenticationServicesError::from_code(code, message);
    if let Ok(mut guard) = state.lock() {
        guard.result = Some(Err(err));
    }
}

/// Wraps `ASAuthorizationController`.
#[derive(Debug, Default)]
pub struct AuthorizationController;

impl AuthorizationController {
    /// Create a new controller builder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Perform requests and return a guard that keeps the underlying objects alive.
    pub fn perform_requests(
        &self,
        apple_id: Option<&AppleIdRequest>,
        password: Option<&PasswordRequest>,
        passkey_reg: Option<&PasskeyRegistrationRequest>,
        passkey_assert: Option<&PasskeyAssertionRequest>,
    ) -> Result<AuthorizationGuard, AuthenticationServicesError> {
        let state = Arc::new(Mutex::new(CallbackState { result: None }));
        let state_ptr: *const Mutex<CallbackState> = Arc::as_ptr(&state);
        let refcon = state_ptr.cast_mut().cast::<c_void>();

        let apple_request_ptr = apple_id.map_or(ptr::null_mut(), |request| request.ptr);
        let password_request_ptr = password.map_or(ptr::null_mut(), |request| request.ptr);
        let registration_request_ptr = passkey_reg.map_or(ptr::null_mut(), |request| request.ptr);
        let assertion_request_ptr = passkey_assert.map_or(ptr::null_mut(), |request| request.ptr);

        let mut err_ptr = ptr::null_mut();
        let handle = unsafe {
            ffi::authservices_authorization_controller_create(
                apple_request_ptr,
                password_request_ptr,
                registration_request_ptr,
                assertion_request_ptr,
                refcon,
                Some(on_success_trampoline),
                Some(on_error_trampoline),
                &mut err_ptr,
            )
        };
        if handle.is_null() {
            let msg = if err_ptr.is_null() {
                "authorization_controller_create returned null".to_owned()
            } else {
                unsafe { private::take_string(err_ptr) }
            };
            return Err(AuthenticationServicesError::FrameworkError(msg));
        }
        let guard = AuthorizationGuard { handle, state };
        guard.perform_requests();
        Ok(guard)
    }
}
